// Copyright 2025 The dcSCTP Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::EventSink;
use crate::api::DcSctpSocket;
use crate::api::ErrorKind;
use crate::api::Message;
use crate::api::Metrics;
use crate::api::Options;
use crate::api::ResetStreamsStatus;
use crate::api::SctpImplementation;
use crate::api::SendOptions;
use crate::api::SendStatus;
use crate::api::SocketEvent;
use crate::api::SocketState;
use crate::api::SocketTime;
use crate::api::StreamId;
use crate::api::handover::HandoverReadiness;
use crate::api::handover::HandoverSocketState;
use crate::api::handover::SocketHandoverState;
use crate::events::Events;
use crate::logging::log_packet;
use crate::packet::chunk::Chunk;
use crate::packet::data_chunk;
use crate::packet::data_chunk::DataChunk;
use crate::packet::forward_tsn_chunk::ForwardTsnChunk;
use crate::packet::idata_chunk::IDataChunk;
use crate::packet::iforward_tsn_chunk::IForwardTsnChunk;
use crate::packet::sctp_packet;
use crate::packet::sctp_packet::SctpPacket;
use crate::socket::capabilities::Capabilities;
use crate::socket::transmission_control_block::TransmissionControlBlock;
use crate::timer::BackoffAlgorithm;
use crate::timer::Timer;
use crate::tx::send_queue::SendQueue;
use crate::types::Tsn;
#[cfg(not(test))]
use log::warn;
use rand::Rng;
use std::cell::RefCell;
#[cfg(test)]
use std::println as warn;
use std::rc::Rc;

pub mod capabilities;
pub mod state_cookie;
pub mod transmission_control_block;

pub(crate) mod context;
pub(crate) mod handlers;
pub(crate) mod metrics;
pub(crate) mod state;
pub(crate) mod util;

use context::Context;
use handlers::data;
use handlers::error as error_handler;
use handlers::handshake;
use handlers::heartbeat;
use handlers::reconfig;
use handlers::shutdown;
use metrics::SocketMetrics;
use state::CookieWaitState;
use state::State;
use util::LoggingEvents;
use util::TxErrorCounter;
use util::closest_timeout;

#[cfg(test)]
pub mod socket_tests;

#[cfg(test)]
mod cookie_resolution_tests;

const MIN_VERIFICATION_TAG: u32 = 1;
const MAX_VERIFICATION_TAG: u32 = u32::MAX;
const MIN_INITIAL_TSN: u32 = u32::MIN;
const MAX_INITIAL_TSN: u32 = u32::MAX;

/// An SCTP socket.
///
/// The socket is the main entry point for using the `dcsctp` library. It is used to send and
/// receive messages, and to manage the connection.
///
/// To create a socket, use the [`Socket::new`] method.
pub struct Socket {
    name: String,
    now: Rc<RefCell<SocketTime>>,
    state: State,
    ctx: Context,
}

impl Socket {
    /// Creates a new `Socket`.
    ///
    /// The provided `name` is only used for logging to identify this socket, and `start_time`
    /// is the initial time, used as a basline for all time-based operations.
    pub fn new(name: &str, options: &Options) -> Self {
        let now = Rc::new(RefCell::new(SocketTime::zero()));
        let events: Rc<RefCell<Events>> = Rc::new(RefCell::new(Events::new()));
        let events: Rc<RefCell<dyn EventSink>> =
            Rc::new(RefCell::new(LoggingEvents::new(events, name.into(), Rc::clone(&now))));
        let sqe = Rc::clone(&events);
        let ctx = Context {
            options: options.clone(),
            events,
            send_queue: SendQueue::new(options.mtu, options, sqe),
            limit_forward_tsn_until: SocketTime::zero(),
            heartbeat_interval: Timer::new(
                options.heartbeat_interval,
                BackoffAlgorithm::Fixed,
                None,
                None,
            ),
            heartbeat_timeout: Timer::new(
                options.rto_initial,
                BackoffAlgorithm::Exponential,
                Some(0),
                None,
            ),
            heartbeat_counter: 0,
            heartbeat_sent_time: SocketTime::zero(),
            metrics: SocketMetrics {
                rx_packets_count: 0,
                tx_packets_count: 0,
                tx_messages_count: 0,
                tx_error_counter: TxErrorCounter::new(options.max_retransmissions),
            },
            peer_implementation: SctpImplementation::Unknown,
        };
 
        Socket { name: name.into(), now, state: State::Closed, ctx }
    }

    fn validate_send(&self, message: &Message, send_options: &SendOptions) -> SendStatus {
        let lifecycle_id = &send_options.lifecycle_id;
        let add_error_events = |kind, msg: &str| {
            if let Some(id) = lifecycle_id {
                self.ctx.events.borrow_mut().add(SocketEvent::OnLifecycleEnd(id.clone()));
            }
            self.ctx.events.borrow_mut().add(SocketEvent::OnError(kind, msg.to_string()));
        };

        if message.payload.is_empty() {
            add_error_events(ErrorKind::ProtocolViolation, "Unable to send empty message");
            return SendStatus::ErrorMessageEmpty;
        }
        if message.payload.len() > self.ctx.options.max_message_size {
            add_error_events(ErrorKind::ProtocolViolation, "Unable to send too large message");
            return SendStatus::ErrorMessageTooLarge;
        }
        if matches!(
            self.state,
            State::ShutdownPending(_)
                | State::ShutdownSent(_)
                | State::ShutdownReceived(_)
                | State::ShutdownAckSent(_)
        ) {
            add_error_events(
                ErrorKind::WrongSequence,
                "Unable to send message as the socket is shutting down",
            );
            return SendStatus::ErrorShuttingDown;
        }
        if self.ctx.send_queue.total_buffered_amount() >= self.ctx.options.max_send_buffer_size
            || self.ctx.send_queue.buffered_amount(message.stream_id)
                >= self.ctx.options.per_stream_send_queue_limit
        {
            add_error_events(
                ErrorKind::ResourceExhaustion,
                "Unable to send message as the send queue is full",
            );
            return SendStatus::ErrorResourceExhaustion;
        }
        SendStatus::Success
    }

    pub fn verification_tag(&self) -> u32 {
        self.state.tcb().map_or(0, |tcb| tcb.my_verification_tag)
    }
}

impl DcSctpSocket for Socket {
    fn poll_event(&mut self) -> Option<SocketEvent> {
        self.ctx.events.borrow_mut().next_event()
    }

    fn get_next_message(&mut self) -> Option<Message> {
        self.state.tcb_mut()?.reassembly_queue.get_next_message()
    }

    fn connect(&mut self) {
        let State::Closed = self.state else {
            warn!("Called connect on a socket that is not closed");
            return;
        };
        let now = *self.now.borrow();
        let mut t1_init = Timer::new(
            self.ctx.options.t1_init_timeout,
            BackoffAlgorithm::Exponential,
            self.ctx.options.max_init_retransmits,
            None,
        );
        t1_init.start(now);
        let initial_tsn = Tsn(rand::rng().random_range(MIN_INITIAL_TSN..MAX_INITIAL_TSN));
        let verification_tag = rand::rng().random_range(MIN_VERIFICATION_TAG..MAX_VERIFICATION_TAG);
        self.state = State::CookieWait(CookieWaitState { t1_init, initial_tsn, verification_tag });

        handshake::send_init(&mut self.state, &mut self.ctx);
    }

    fn handle_input(&mut self, packet: &[u8]) {
        self.ctx.metrics.rx_packets_count += 1;
        let now = *self.now.borrow();
        log_packet(&self.name, now.into(), false, packet);

        match SctpPacket::from_bytes(packet, &self.ctx.options) {
            Err(_e) => {
                self.ctx.events.borrow_mut().add(SocketEvent::OnError(
                    ErrorKind::ParseFailed,
                    "Failed to parse SCTP packet".into(),
                ));
            }
            Ok(packet) => {
                shutdown::maybe_send_shutdown_on_packet_received(
                    &mut self.state,
                    &mut self.ctx,
                    now,
                    &packet.chunks,
                );

                for chunk in packet.chunks {
                    match chunk {
                        Chunk::Data(DataChunk { tsn, data })
                        | Chunk::IData(IDataChunk { tsn, data }) => {
                            data::handle_data(&mut self.state, &mut self.ctx, now, tsn, data);
                        }
                        Chunk::Init(c) => handshake::handle_init(&mut self.state, &mut self.ctx, c),
                        Chunk::InitAck(c) => {
                            handshake::handle_init_ack(&mut self.state, &mut self.ctx, now, c)
                        }
                        Chunk::Sack(c) => data::handle_sack(&mut self.state, &mut self.ctx, now, c),
                        Chunk::Abort(c) => {
                            error_handler::handle_abort(&mut self.state, &mut self.ctx, c)
                        }
                        Chunk::Shutdown(_) => {
                            shutdown::handle_shutdown(&mut self.state, &mut self.ctx)
                        }
                        Chunk::ShutdownAck(_) => shutdown::handle_shutdown_ack(
                            &mut self.state,
                            &mut self.ctx,
                            &packet.common_header,
                        ),
                        Chunk::Error(c) => {
                            error_handler::handle_error(&mut self.state, &mut self.ctx, c)
                        }
                        Chunk::CookieEcho(c) => {
                            handshake::handle_cookie_echo(
                                &mut self.state,
                                &mut self.ctx,
                                now,
                                &packet.common_header,
                                c,
                            );
                        }
                        Chunk::CookieAck(_) => {
                            handshake::handle_cookie_ack(&mut self.state, &mut self.ctx, now)
                        }
                        Chunk::HeartbeatRequest(c) => {
                            heartbeat::handle_heartbeat_req(&mut self.state, &mut self.ctx, c)
                        }
                        Chunk::HeartbeatAck(c) => {
                            heartbeat::handle_heartbeat_ack(&mut self.state, &mut self.ctx, now, c)
                        }
                        Chunk::ShutdownComplete(c) => {
                            shutdown::handle_shutdown_complete(&mut self.state, &mut self.ctx, c)
                        }
                        Chunk::ReConfig(c) => {
                            reconfig::handle_reconfig(&mut self.state, &mut self.ctx, now, c)
                        }
                        Chunk::ForwardTsn(ForwardTsnChunk {
                            new_cumulative_tsn,
                            skipped_streams,
                        })
                        | Chunk::IForwardTsn(IForwardTsnChunk {
                            new_cumulative_tsn,
                            skipped_streams,
                        }) => data::handle_forward_tsn(
                            &mut self.state,
                            &mut self.ctx,
                            now,
                            new_cumulative_tsn,
                            skipped_streams,
                        ),
                        Chunk::Unknown(c) => {
                            if !error_handler::handle_unrecognized_chunk(
                                &mut self.state,
                                &mut self.ctx,
                                c,
                            ) {
                                break;
                            }
                        }
                    }
                }
                data::maybe_send_sack(&mut self.state, &mut self.ctx, now);
            }
        }
    }

    fn advance_time(&mut self, now: SocketTime) {
        if now < *self.now.borrow() {
            // Time is not allowed to go backwards.
            return;
        }
        self.now.replace(now);

        if let Some(tcb) = self.state.tcb_mut() {
            tcb.data_tracker.handle_timeout(now);
            if tcb.retransmission_queue.handle_timeout(now) {
                self.ctx.metrics.tx_error_counter.increment();
            }
        }

        if matches!(self.state, State::Closed) {
            // Nothing to do
        } else if matches!(self.state, State::CookieWait(_)) {
            handshake::handle_t1init_timeout(&mut self.state, &mut self.ctx, now);
        } else if let State::CookieEchoed(s) = &self.state {
            // NOTE: Only let the t1-cookie timer drive retransmissions.
            debug_assert!(s.t1_cookie.is_running());
            // Drop borrow
            handshake::handle_t1cookie_timeout(&mut self.state, &mut self.ctx, now);
        } else if matches!(
            self.state,
            State::Established(_)
                | State::ShutdownPending(_)
                | State::ShutdownSent(_)
                | State::ShutdownReceived(_)
                | State::ShutdownAckSent(_)
        ) {
            heartbeat::handle_heartbeat_timeouts(&mut self.state, &mut self.ctx, now);
            reconfig::handle_reconfig_timeout(&mut self.state, &mut self.ctx, now);
            shutdown::handle_t2_shutdown_timeout(&mut self.state, &mut self.ctx, now);
        }
        if let Some(tcb) = self.state.tcb_mut() {
            if self.ctx.metrics.tx_error_counter.is_exhausted() {
                // We need to send ABORT.
                // This logic was in advance_time.
                // I should extract it or handle it here using context.
                use crate::packet::abort_chunk::AbortChunk;
                use crate::packet::error_causes::ErrorCause;
                use crate::packet::user_initiated_abort_error_cause::UserInitiatedAbortErrorCause;

                self.ctx.events.borrow_mut().add(SocketEvent::SendPacket(
                    tcb.new_packet()
                        .add(&Chunk::Abort(AbortChunk {
                            error_causes: vec![ErrorCause::UserInitiatedAbort(
                                UserInitiatedAbortErrorCause {
                                    reason: "Too many retransmissions".into(),
                                },
                            )],
                        }))
                        .build(),
                ));
                self.ctx.metrics.tx_packets_count += 1;
                self.ctx.internal_close(
                    &mut self.state,
                    ErrorKind::TooManyRetries,
                    "Too many retransmissions".into(),
                );
                return;
            }

            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.1-2.3.2>:
            //
            //   [...] until the COOKIE ACK chunk is returned, the sender MUST NOT send any other
            //   packets to the peer.
            if !matches!(self.state, State::CookieEchoed(_)) {
                self.ctx.send_buffered_packets(&mut self.state, now);
            }
        }
    }

    fn poll_timeout(&self) -> SocketTime {
        let timeout = match self.state {
            State::Closed => None,
            State::CookieWait(ref s) => {
                debug_assert!(s.t1_init.is_running());
                s.t1_init.next_expiry()
            }
            State::CookieEchoed(ref s) => {
                debug_assert!(s.t1_cookie.is_running());
                s.t1_cookie.next_expiry()
            }
            State::Established(ref tcb)
            | State::ShutdownPending(ref tcb)
            | State::ShutdownSent(state::ShutdownSentState { ref tcb, .. })
            | State::ShutdownReceived(ref tcb)
            | State::ShutdownAckSent(ref tcb) => {
                let mut timeout = tcb.retransmission_queue.next_timeout();
                timeout = closest_timeout(timeout, tcb.reconfig_timer.next_expiry());
                timeout = closest_timeout(timeout, tcb.data_tracker.next_timeout());
                timeout = closest_timeout(timeout, self.ctx.heartbeat_interval.next_expiry());
                timeout = closest_timeout(timeout, self.ctx.heartbeat_timeout.next_expiry());
                if let State::ShutdownSent(ref s) = self.state {
                    timeout = closest_timeout(timeout, s.t2_shutdown.next_expiry());
                }
                timeout
            }
        };

        // Ensure that already expired timers don't return a socket time in the past.
        let now = *self.now.borrow();
        timeout.map(|t| t.max(now)).unwrap_or(SocketTime::infinite_future())
    }

    fn shutdown(&mut self) {
        let now = *self.now.borrow();

        match self.state {
            State::Closed
            | State::ShutdownPending(_)
            | State::ShutdownSent(_)
            | State::ShutdownAckSent(_)
            | State::ShutdownReceived(_) => {
                // Already closed or shutting down.
            }
            State::CookieWait(_) => {
                // Connection closed during the initial connection phase. There is no outstanding
                // data, so the socket can just be closed (stopping any connection timers, if any),
                // as this is the client's intention, by calling [shutdown()].
                self.ctx.internal_close(&mut self.state, ErrorKind::NoError, "".to_string());
            }
            State::CookieEchoed(_) | State::Established(_) => {
                // We need to transition state.
                // Context doesn't offer `transition_between` directly on arbitrary states easily
                // without macros visible. But we can use
                // `util::transition_between`. However, we need to match first to
                // get `tcb`. Let's modify state directly here, it's fine.

                // We can use the logic from handshake/shutdown handlers if available?
                // `shutdown::handle_shutdown` is for receiving shutdown chunk.
                // This is User initiated shutdown.

                // Logic:
                if let Some(_tcb) = self.state.tcb_mut() {
                    // We need to take TCB out of state.
                    // The macro `transition_between` does `mem::replace`.
                    // We can replicate logic or import macro.
                    // Macro is exported in util.rs as `macro_rules! transition_between`.
                    // Since `util` is pub(crate), we can use it?
                    // Macros are usually `#[macro_use]` or `use crate::transition_between`.
                    // I exported it.
                    // But I didn't add `#[macro_use]` on `extern crate` or `mod`.
                    // In Rust 2018+, macros are imported like items.
                    // I added `use util::transition_between` ? check util.rs
                    // `transition_between!` is a macro.
                    // I need to use `crate::transition_between!` or import it.
                    // If I put `#[macro_export]` in `util.rs`, it is at crate root.
                    // So `use crate::transition_between;`
                }

                // Workaround: manual transition.
                let prev_state = std::mem::replace(&mut self.state, State::Closed);
                let tcb = match prev_state {
                    State::CookieEchoed(state::CookieEchoState { tcb, .. })
                    | State::Established(tcb) => tcb,
                    _ => unreachable!(),
                };
                self.state = State::ShutdownPending(tcb);

                shutdown::maybe_send_shutdown(&mut self.state, &mut self.ctx, now);
            }
        }
    }

    fn close(&mut self) {
        if !matches!(self.state, State::Closed) {
            if let Some(tcb) = self.state.tcb() {
                use crate::packet::abort_chunk::AbortChunk;
                use crate::packet::error_causes::ErrorCause;
                use crate::packet::user_initiated_abort_error_cause::UserInitiatedAbortErrorCause;

                self.ctx.events.borrow_mut().add(SocketEvent::SendPacket(
                    tcb.new_packet()
                        .add(&Chunk::Abort(AbortChunk {
                            error_causes: vec![ErrorCause::UserInitiatedAbort(
                                UserInitiatedAbortErrorCause { reason: "Close called".into() },
                            )],
                        }))
                        .build(),
                ));
                self.ctx.metrics.tx_packets_count += 1;
            }
            self.ctx.internal_close(&mut self.state, ErrorKind::NoError, String::new());
        }
    }

    fn state(&self) -> SocketState {
        match self.state {
            State::Closed => SocketState::Closed,
            State::CookieWait(_) | State::CookieEchoed(_) => SocketState::Connecting,
            State::Established(_) => SocketState::Connected,
            State::ShutdownPending(_)
            | State::ShutdownSent(_)
            | State::ShutdownReceived(_)
            | State::ShutdownAckSent(_) => SocketState::ShuttingDown,
        }
    }

    fn messages_ready_count(&self) -> usize {
        let Some(tcb) = self.state.tcb() else {
            return 0;
        };
        tcb.reassembly_queue.messages_ready_count()
    }

    fn options(&self) -> Options {
        self.ctx.options.clone()
    }

    fn set_max_message_size(&mut self, max_message_size: usize) {
        self.ctx.options.max_message_size = max_message_size;
    }

    fn set_stream_priority(&mut self, stream_id: StreamId, priority: u16) {
        self.ctx.send_queue.set_priority(stream_id, priority);
    }

    fn get_stream_priority(&self, stream_id: StreamId) -> u16 {
        self.ctx.send_queue.get_priority(stream_id)
    }

    fn send(&mut self, message: Message, send_options: &SendOptions) -> SendStatus {
        let status = self.validate_send(&message, send_options);
        if status != SendStatus::Success {
            return status;
        }

        let now = *self.now.borrow();
        self.ctx.metrics.tx_messages_count += 1;
        self.ctx.send_queue.add(now, message, send_options);

        self.ctx.send_buffered_packets(&mut self.state, now);
        SendStatus::Success
    }

    fn send_many(&mut self, messages: Vec<Message>, send_options: &SendOptions) -> Vec<SendStatus> {
        let now = *self.now.borrow();
        let statuses = messages
            .into_iter()
            .map(|message| {
                let status = self.validate_send(&message, send_options);
                if status == SendStatus::Success {
                    self.ctx.metrics.tx_messages_count += 1;
                    self.ctx.send_queue.add(now, message, send_options);
                }
                status
            })
            .collect();

        self.ctx.send_buffered_packets(&mut self.state, now);
        statuses
    }

    fn reset_streams(&mut self, outgoing_streams: &[StreamId]) -> ResetStreamsStatus {
        let Some(tcb) = self.state.tcb_mut() else {
            return ResetStreamsStatus::NotConnected;
        };
        if !tcb.capabilities.reconfig {
            return ResetStreamsStatus::NotSupported;
        }
        let now = *self.now.borrow();
        for stream_id in outgoing_streams {
            self.ctx.send_queue.prepare_reset_stream(*stream_id);
        }

        // This will send the SSN reset request control messagae.
        self.ctx.send_buffered_packets(&mut self.state, now);

        ResetStreamsStatus::Performed
    }

    fn buffered_amount(&self, stream_id: StreamId) -> usize {
        self.ctx.send_queue.buffered_amount(stream_id)
    }

    fn buffered_amount_low_threshold(&self, stream_id: StreamId) -> usize {
        self.ctx.send_queue.buffered_amount_low_threshold(stream_id)
    }

    fn set_buffered_amount_low_threshold(&mut self, stream_id: StreamId, bytes: usize) {
        self.ctx.send_queue.set_buffered_amount_low_threshold(stream_id, bytes);
    }

    fn get_metrics(&self) -> Option<Metrics> {
        let tcb = self.state.tcb()?;

        let packet_payload_size =
            self.ctx.options.mtu - sctp_packet::COMMON_HEADER_SIZE - data_chunk::HEADER_SIZE;
        Some(Metrics {
            tx_packets_count: self.ctx.metrics.tx_packets_count,
            tx_messages_count: self.ctx.metrics.tx_messages_count,
            rtx_packets_count: tcb.retransmission_queue.rtx_packets_count(),
            rtx_bytes_count: tcb.retransmission_queue.rtx_bytes_count(),
            cwnd_bytes: tcb.retransmission_queue.cwnd(),
            srtt: tcb.rto.srtt(),
            unack_data_count: tcb.retransmission_queue.unacked_items()
                + self.ctx.send_queue.total_buffered_amount().div_ceil(packet_payload_size),
            rx_packets_count: self.ctx.metrics.rx_packets_count,
            rx_messages_count: tcb.reassembly_queue.rx_messages_count(),
            peer_rwnd_bytes: tcb.retransmission_queue.rwnd() as u32,
            peer_implementation: self.ctx.peer_implementation,
            uses_message_interleaving: tcb.capabilities.message_interleaving,
            uses_zero_checksum: tcb.capabilities.zero_checksum,
            negotiated_maximum_incoming_streams: tcb
                .capabilities
                .negotiated_maximum_incoming_streams,
            negotiated_maximum_outgoing_streams: tcb
                .capabilities
                .negotiated_maximum_outgoing_streams,
        })
    }

    fn get_handover_readiness(&self) -> HandoverReadiness {
        match &self.state {
            State::Closed => HandoverReadiness::READY,
            State::Established(tcb) => {
                self.ctx.send_queue.get_handover_readiness() | tcb.get_handover_readiness()
            }
            _ => HandoverReadiness::WRONG_CONNECTION_STATE,
        }
    }

    fn restore_from_state(&mut self, state: &SocketHandoverState) {
        if !matches!(self.state, State::Closed) {
            self.ctx.events.borrow_mut().add(SocketEvent::OnError(
                ErrorKind::NotConnected,
                "Only closed socket can be restored from state".into(),
            ));
            return;
        } else if matches!(state.socket_state, HandoverSocketState::Closed) {
            // Nothing to do.
            return;
        }

        self.ctx.send_queue.restore_from_state(state);

        let capabilities = Capabilities {
            partial_reliability: state.capabilities.partial_reliability,
            message_interleaving: state.capabilities.message_interleaving,
            reconfig: state.capabilities.reconfig,
            zero_checksum: state.capabilities.zero_checksum,
            negotiated_maximum_incoming_streams: state
                .capabilities
                .negotiated_maximum_incoming_streams,
            negotiated_maximum_outgoing_streams: state
                .capabilities
                .negotiated_maximum_outgoing_streams,
        };
        let mut tcb = TransmissionControlBlock::new(
            &self.ctx.options,
            state.my_verification_tag,
            Tsn(state.my_initial_tsn),
            state.peer_verification_tag,
            Tsn(state.peer_initial_tsn),
            state.tie_tag,
            /* rwnd */ 0,
            capabilities,
            Rc::clone(&self.ctx.events),
        );
        tcb.restore_from_state(state);

        self.state = State::Established(tcb);
        self.ctx.events.borrow_mut().add(SocketEvent::OnConnected());
    }

    fn get_handover_state_and_close(&mut self) -> Option<SocketHandoverState> {
        if !self.get_handover_readiness().is_ready() {
            return None;
        }

        let mut handover_state = SocketHandoverState::default();

        if let State::Established(tcb) = &self.state {
            handover_state.socket_state = HandoverSocketState::Connected;
            self.ctx.send_queue.add_to_handover_state(&mut handover_state);
            tcb.add_to_handover_state(&mut handover_state);
            self.ctx.events.borrow_mut().add(SocketEvent::OnClosed());
            self.state = State::Closed;
        }
        Some(handover_state)
    }
}
