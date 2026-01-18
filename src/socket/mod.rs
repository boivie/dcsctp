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
#[cfg(test)]
use std::println as warn;
use rand::Rng;
use std::cell::RefCell;
use std::rc::Rc;

pub mod capabilities;
pub mod state_cookie;
pub mod transmission_control_block;

pub(crate) mod context;
pub(crate) mod handlers;
pub(crate) mod state;
pub(crate) mod util;

use context::Context;
use handlers::{data, handshake, heartbeat, reconfig, shutdown, error as error_handler};
use state::{CookieWaitState, State};
use util::{closest_timeout, LoggingEvents, TxErrorCounter};

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
pub struct Socket<'a> {
    name: String,
    now: Rc<RefCell<SocketTime>>,
    options: Options,
    state: State,
    events: Rc<RefCell<dyn EventSink>>,
    send_queue: SendQueue<'a>,

    limit_forward_tsn_until: SocketTime,

    heartbeat_interval: Timer,
    heartbeat_timeout: Timer,
    heartbeat_counter: u32,
    heartbeat_sent_time: SocketTime,

    rx_packets_count: usize,
    tx_packets_count: usize,
    tx_messages_count: usize,
    peer_implementation: SctpImplementation,

    tx_error_counter: TxErrorCounter,
}

impl<'a> Socket<'a> {
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
        Socket {
            name: name.into(),
            now,
            options: options.clone(),
            state: State::Closed,
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
            rx_packets_count: 0,
            tx_packets_count: 0,
            tx_messages_count: 0,
            peer_implementation: SctpImplementation::Unknown,
            tx_error_counter: TxErrorCounter::new(options.max_retransmissions),
        }
    }
    
    fn create_context<'b>(&'b mut self) -> (Context<'b, 'a>, &'b mut State) {
        (
            Context {
                options: &self.options,
                events: &self.events,
                send_queue: &mut self.send_queue,
                limit_forward_tsn_until: &mut self.limit_forward_tsn_until,
                heartbeat_interval: &mut self.heartbeat_interval,
                heartbeat_timeout: &mut self.heartbeat_timeout,
                heartbeat_counter: &mut self.heartbeat_counter,
                heartbeat_sent_time: &mut self.heartbeat_sent_time,
                rx_packets_count: &mut self.rx_packets_count,
                tx_packets_count: &mut self.tx_packets_count,
                tx_messages_count: &mut self.tx_messages_count,
                peer_implementation: &mut self.peer_implementation,
                tx_error_counter: &mut self.tx_error_counter,
            },
            &mut self.state,
        )
    }

    fn validate_send(&self, message: &Message, send_options: &SendOptions) -> SendStatus {
        let lifecycle_id = &send_options.lifecycle_id;
        let add_error_events = |kind, msg: &str| {
            if let Some(id) = lifecycle_id {
                self.events.borrow_mut().add(SocketEvent::OnLifecycleEnd(id.clone()));
            }
            self.events.borrow_mut().add(SocketEvent::OnError(kind, msg.to_string()));
        };

        if message.payload.is_empty() {
            add_error_events(ErrorKind::ProtocolViolation, "Unable to send empty message");
            return SendStatus::ErrorMessageEmpty;
        }
        if message.payload.len() > self.options.max_message_size {
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
        if self.send_queue.total_buffered_amount() >= self.options.max_send_buffer_size
            || self.send_queue.buffered_amount(message.stream_id)
                >= self.options.per_stream_send_queue_limit
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

impl DcSctpSocket for Socket<'_> {
    fn poll_event(&mut self) -> Option<SocketEvent> {
        self.events.borrow_mut().next_event()
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
            self.options.t1_init_timeout,
            BackoffAlgorithm::Exponential,
            self.options.max_init_retransmits,
            None,
        );
        t1_init.start(now);
        let initial_tsn = Tsn(rand::rng().random_range(MIN_INITIAL_TSN..MAX_INITIAL_TSN));
        let verification_tag = rand::rng().random_range(MIN_VERIFICATION_TAG..MAX_VERIFICATION_TAG);
        self.state = State::CookieWait(CookieWaitState { t1_init, initial_tsn, verification_tag });
        
        // Delegate to handler
        let (mut ctx, state) = self.create_context();
        handshake::send_init(state, &mut ctx);
    }

    fn handle_input(&mut self, packet: &[u8]) {
        self.rx_packets_count += 1;
        let now = *self.now.borrow();
        log_packet(&self.name, now.into(), false, packet);

        match SctpPacket::from_bytes(packet, &self.options) {
            Err(_e) => {
                self.events.borrow_mut().add(SocketEvent::OnError(
                    ErrorKind::ParseFailed,
                    "Failed to parse SCTP packet".into(),
                ));
            }
            Ok(packet) => {
                let (mut ctx, state) = self.create_context();
                shutdown::maybe_send_shutdown_on_packet_received(state, &mut ctx, now, &packet.chunks);
                
                for chunk in packet.chunks {
                    match chunk {
                        Chunk::Data(DataChunk { tsn, data })
                        | Chunk::IData(IDataChunk { tsn, data }) => {
                             data::handle_data(state, &mut ctx, now, tsn, data);
                        }
                        Chunk::Init(c) => handshake::handle_init(state, &mut ctx, c),
                        Chunk::InitAck(c) => handshake::handle_init_ack(state, &mut ctx, now, c),
                        Chunk::Sack(c) => data::handle_sack(state, &mut ctx, now, c),
                        Chunk::Abort(c) => error_handler::handle_abort(state, &mut ctx, c),
                        Chunk::Shutdown(_) => shutdown::handle_shutdown(state, &mut ctx),
                        Chunk::ShutdownAck(_) => shutdown::handle_shutdown_ack(state, &mut ctx, &packet.common_header),
                        Chunk::Error(c) => error_handler::handle_error(state, &mut ctx, c),
                        Chunk::CookieEcho(c) => {
                            handshake::handle_cookie_echo(state, &mut ctx, now, &packet.common_header, c);
                        }
                        Chunk::CookieAck(_) => handshake::handle_cookie_ack(state, &mut ctx, now),
                        Chunk::HeartbeatRequest(c) => heartbeat::handle_heartbeat_req(state, &mut ctx, c),
                        Chunk::HeartbeatAck(c) => heartbeat::handle_heartbeat_ack(state, &mut ctx, now, c),
                        Chunk::ShutdownComplete(c) => shutdown::handle_shutdown_complete(state, &mut ctx, c),
                        Chunk::ReConfig(c) => reconfig::handle_reconfig(state, &mut ctx, now, c),
                        Chunk::ForwardTsn(ForwardTsnChunk {
                            new_cumulative_tsn,
                            skipped_streams,
                        })
                        | Chunk::IForwardTsn(IForwardTsnChunk {
                            new_cumulative_tsn,
                            skipped_streams,
                        }) => data::handle_forward_tsn(state, &mut ctx, now, new_cumulative_tsn, skipped_streams),
                        Chunk::Unknown(c) => {
                            if !error_handler::handle_unrecognized_chunk(state, &mut ctx, c) {
                                break;
                            }
                        }
                    }
                }
                data::maybe_send_sack(state, &mut ctx, now);
            }
        }
    }

    fn advance_time(&mut self, now: SocketTime) {
        if now < *self.now.borrow() {
            // Time is not allowed to go backwards.
            return;
        }
        self.now.replace(now);
        
        let (mut ctx, state) = self.create_context();

        if let Some(tcb) = state.tcb_mut() {
            tcb.data_tracker.handle_timeout(now);
            if tcb.retransmission_queue.handle_timeout(now) {
                ctx.tx_error_counter.increment();
            }
        }
        
        match state {
            State::Closed => {}
            State::CookieWait(_) => {
                handshake::handle_t1init_timeout(state, &mut ctx, now);
            }
            State::CookieEchoed(s) => {
                // NOTE: Only let the t1-cookie timer drive retransmissions.
                debug_assert!(s.t1_cookie.is_running());
                handshake::handle_t1cookie_timeout(state, &mut ctx, now);
            }
            State::Established(_)
            | State::ShutdownPending(_)
            | State::ShutdownSent(_)
            | State::ShutdownReceived(_)
            | State::ShutdownAckSent(_) => {
                heartbeat::handle_heartbeat_timeouts(state, &mut ctx, now);
                reconfig::handle_reconfig_timeout(state, &mut ctx, now);
                shutdown::handle_t2_shutdown_timeout(state, &mut ctx, now);
            }
        }
        if let Some(tcb) = state.tcb_mut() {
            if ctx.tx_error_counter.is_exhausted() {
                // We need to send ABORT.
                // This logic was in advance_time.
                // I should extract it or handle it here using context.
                use crate::packet::error_causes::ErrorCause;
                use crate::packet::user_initiated_abort_error_cause::UserInitiatedAbortErrorCause;
                use crate::packet::abort_chunk::AbortChunk;
                
                 ctx.events.borrow_mut().add(SocketEvent::SendPacket(
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
                *ctx.tx_packets_count += 1;
                // internal_close requires context.
                ctx.internal_close(state, ErrorKind::TooManyRetries, "Too many retransmissions".into());
                return;
            }

            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.1-2.3.2>:
            //
            //   [...] until the COOKIE ACK chunk is returned, the sender MUST NOT send any other
            //   packets to the peer.
            if !matches!(state, State::CookieEchoed(_)) {
                ctx.send_buffered_packets(state, now);
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
                timeout = closest_timeout(timeout, self.heartbeat_interval.next_expiry());
                timeout = closest_timeout(timeout, self.heartbeat_timeout.next_expiry());
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
        let (mut ctx, state) = self.create_context();

        match state {
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
                ctx.internal_close(state, ErrorKind::NoError, "".to_string());
            }
            State::CookieEchoed(_) | State::Established(_) => {
                 // We need to transition state. 
                 // Context doesn't offer `transition_between` directly on arbitrary states easily without macros visible.
                 // But we can use `util::transition_between`.
                 // However, we need to match first to get `tcb`.
                 // Let's modify state directly here, it's fine.
                 
                 // We can use the logic from handshake/shutdown handlers if available?
                 // `shutdown::handle_shutdown` is for receiving shutdown chunk.
                 // This is User initiated shutdown.
                 
                 // Logic:
                 if let Some(_tcb) = state.tcb_mut() {
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
                 let prev_state = std::mem::replace(state, State::Closed);
                 let tcb = match prev_state {
                     State::CookieEchoed(state::CookieEchoState { tcb, .. }) 
                     | State::Established(tcb) => tcb,
                     _ => unreachable!(),
                 };
                 *state = State::ShutdownPending(tcb);

                 shutdown::maybe_send_shutdown(state, &mut ctx, now);
            }
        }
    }

    fn close(&mut self) {
        let (mut ctx, state) = self.create_context();
        if !matches!(state, State::Closed) {
            if let Some(tcb) = state.tcb() {
                use crate::packet::error_causes::ErrorCause;
                use crate::packet::user_initiated_abort_error_cause::UserInitiatedAbortErrorCause;
                use crate::packet::abort_chunk::AbortChunk;
                
                ctx.events.borrow_mut().add(SocketEvent::SendPacket(
                    tcb.new_packet()
                        .add(&Chunk::Abort(AbortChunk {
                            error_causes: vec![ErrorCause::UserInitiatedAbort(
                                UserInitiatedAbortErrorCause { reason: "Close called".into() },
                            )],
                        }))
                        .build(),
                ));
                *ctx.tx_packets_count += 1;
            }
            ctx.internal_close(state, ErrorKind::NoError, String::new());
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
        self.options.clone()
    }

    fn set_max_message_size(&mut self, max_message_size: usize) {
        self.options.max_message_size = max_message_size;
    }

    fn set_stream_priority(&mut self, stream_id: StreamId, priority: u16) {
        self.send_queue.set_priority(stream_id, priority);
    }

    fn get_stream_priority(&self, stream_id: StreamId) -> u16 {
        self.send_queue.get_priority(stream_id)
    }

    fn send(&mut self, message: Message, send_options: &SendOptions) -> SendStatus {
        let status = self.validate_send(&message, send_options);
        if status != SendStatus::Success {
            return status;
        }

        let now = *self.now.borrow();
        self.tx_messages_count += 1;
        self.send_queue.add(now, message, send_options);
        
        let (mut ctx, state) = self.create_context();
        ctx.send_buffered_packets(state, now);
        SendStatus::Success
    }

    fn send_many(&mut self, messages: Vec<Message>, send_options: &SendOptions) -> Vec<SendStatus> {
        let now = *self.now.borrow();
        let statuses = messages
            .into_iter()
            .map(|message| {
                let status = self.validate_send(&message, send_options);
                if status == SendStatus::Success {
                    self.tx_messages_count += 1;
                    self.send_queue.add(now, message, send_options);
                }
                status
            })
            .collect();

        let (mut ctx, state) = self.create_context();
        ctx.send_buffered_packets(state, now);
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
            self.send_queue.prepare_reset_stream(*stream_id);
        }

        // This will send the SSN reset request control messagae.
        let (mut ctx, state) = self.create_context();
        ctx.send_buffered_packets(state, now);

        ResetStreamsStatus::Performed
    }

    fn buffered_amount(&self, stream_id: StreamId) -> usize {
        self.send_queue.buffered_amount(stream_id)
    }

    fn buffered_amount_low_threshold(&self, stream_id: StreamId) -> usize {
        self.send_queue.buffered_amount_low_threshold(stream_id)
    }

    fn set_buffered_amount_low_threshold(&mut self, stream_id: StreamId, bytes: usize) {
        self.send_queue.set_buffered_amount_low_threshold(stream_id, bytes);
    }

    fn get_metrics(&self) -> Option<Metrics> {
        let tcb = self.state.tcb()?;

        let packet_payload_size =
            self.options.mtu - sctp_packet::COMMON_HEADER_SIZE - data_chunk::HEADER_SIZE;
        Some(Metrics {
            tx_packets_count: self.tx_packets_count,
            tx_messages_count: self.tx_messages_count,
            rtx_packets_count: tcb.retransmission_queue.rtx_packets_count(),
            rtx_bytes_count: tcb.retransmission_queue.rtx_bytes_count(),
            cwnd_bytes: tcb.retransmission_queue.cwnd(),
            srtt: tcb.rto.srtt(),
            unack_data_count: tcb.retransmission_queue.unacked_items()
                + self.send_queue.total_buffered_amount().div_ceil(packet_payload_size),
            rx_packets_count: self.rx_packets_count,
            rx_messages_count: tcb.reassembly_queue.rx_messages_count(),
            peer_rwnd_bytes: tcb.retransmission_queue.rwnd() as u32,
            peer_implementation: self.peer_implementation,
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
                self.send_queue.get_handover_readiness() | tcb.get_handover_readiness()
            }
            _ => HandoverReadiness::WRONG_CONNECTION_STATE,
        }
    }

    fn restore_from_state(&mut self, state: &SocketHandoverState) {
        if !matches!(self.state, State::Closed) {
            self.events.borrow_mut().add(SocketEvent::OnError(
                ErrorKind::NotConnected,
                "Only closed socket can be restored from state".into(),
            ));
            return;
        } else if matches!(state.socket_state, HandoverSocketState::Closed) {
            // Nothing to do.
            return;
        }

        self.send_queue.restore_from_state(state);

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
            &self.options,
            state.my_verification_tag,
            Tsn(state.my_initial_tsn),
            state.peer_verification_tag,
            Tsn(state.peer_initial_tsn),
            state.tie_tag,
            /* rwnd */ 0,
            capabilities,
            Rc::clone(&self.events),
        );
        tcb.restore_from_state(state);

        self.state = State::Established(tcb);
        self.events.borrow_mut().add(SocketEvent::OnConnected());
    }

    fn get_handover_state_and_close(&mut self) -> Option<SocketHandoverState> {
        if !self.get_handover_readiness().is_ready() {
            return None;
        }

        let mut handover_state = SocketHandoverState::default();

        if let State::Established(tcb) = &self.state {
            handover_state.socket_state = HandoverSocketState::Connected;
            self.send_queue.add_to_handover_state(&mut handover_state);
            tcb.add_to_handover_state(&mut handover_state);
            self.events.borrow_mut().add(SocketEvent::OnClosed());
            self.state = State::Closed;
        }
        Some(handover_state)
    }
}
