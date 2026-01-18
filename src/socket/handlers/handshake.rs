use crate::api::ErrorKind;
use crate::api::SocketEvent;
use crate::api::SocketTime;
use crate::api::ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE;
use crate::math::round_down_to_4;
use crate::packet::abort_chunk::AbortChunk;
use crate::packet::chunk::Chunk;
use crate::packet::cookie_ack_chunk::CookieAckChunk;
use crate::packet::cookie_echo_chunk::CookieEchoChunk;
use crate::packet::cookie_received_while_shutting_down::CookieReceivedWhileShuttingDownErrorCause;
use crate::packet::error_causes::ErrorCause;
use crate::packet::error_chunk::ErrorChunk;
use crate::packet::init_ack_chunk::InitAckChunk;
use crate::packet::init_chunk::InitChunk;
use crate::packet::parameter::Parameter;
use crate::packet::protocol_violation_error_cause::ProtocolViolationErrorCause;
use crate::packet::sctp_packet::CommonHeader;
use crate::packet::sctp_packet::SctpPacketBuilder;
use crate::packet::shutdown_ack_chunk::ShutdownAckChunk;
use crate::packet::state_cookie_parameter::StateCookieParameter;
use crate::socket::context::Context;
use crate::socket::handlers::shutdown::send_shutdown_ack;
use crate::socket::state::CookieEchoState;
use crate::socket::state::CookieResolution;
use crate::socket::state::CookieWaitState;
use crate::socket::state::ShutdownSentState;
use crate::socket::state::State;
use crate::socket::state_cookie::StateCookie;
use crate::socket::transmission_control_block::TransmissionControlBlock;
use crate::socket::util::compute_capabilities;
use crate::socket::util::detemine_sctp_implementation;
use crate::socket::util::make_capability_parameters;
use crate::timer::BackoffAlgorithm;
use crate::timer::Timer;
use crate::transition_between;
use crate::types::Tsn;
#[cfg(not(test))]
use log::info;
#[cfg(not(test))]
use log::warn;
use rand::Rng;
#[cfg(test)]
use std::println as info;
#[cfg(test)]
use std::println as warn;

pub(crate) const MIN_VERIFICATION_TAG: u32 = 1;
pub(crate) const MAX_VERIFICATION_TAG: u32 = u32::MAX;
pub(crate) const MIN_INITIAL_TSN: u32 = u32::MIN;
pub(crate) const MAX_INITIAL_TSN: u32 = u32::MAX;

pub(crate) fn handle_init(state: &mut State, ctx: &mut Context, chunk: InitChunk) {
    let my_verification_tag: u32;
    let my_initial_tsn: Tsn;
    let tie_tag: u64;

    match state {
        State::Closed => {
            my_initial_tsn = Tsn(rand::rng().random_range(MIN_INITIAL_TSN..MAX_INITIAL_TSN));
            my_verification_tag =
                rand::rng().random_range(MIN_VERIFICATION_TAG..MAX_VERIFICATION_TAG);
            tie_tag = 0;
        }
        State::CookieWait(CookieWaitState { verification_tag, initial_tsn, .. })
        | State::CookieEchoed(CookieEchoState { verification_tag, initial_tsn, .. }) => {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.2.1>:
            //
            //   This usually indicates an initialization collision, i.e., each endpoint is
            //   attempting, at about the same time, to establish an association with the other
            //   endpoint.
            info!("Received Init indicating simultaneous connections");
            my_verification_tag = *verification_tag;
            my_initial_tsn = *initial_tsn;
            tie_tag = 0;
        }
        State::ShutdownAckSent(_) => {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-18>:
            //
            //   If an endpoint is in the SHUTDOWN-ACK-SENT state and receives an INIT chunk
            //   (e.g., if the SHUTDOWN COMPLETE chunk was lost) with source and destination
            //   transport addresses (either in the IP addresses or in the INIT chunk) that
            //   belong to this association, it SHOULD discard the INIT chunk and retransmit
            // the   SHUTDOWN ACK chunk.
            send_shutdown_ack(state, ctx);
            return;
        }
        State::Established(tcb)
        | State::ShutdownPending(tcb)
        | State::ShutdownSent(ShutdownSentState { tcb, .. })
        | State::ShutdownReceived(tcb) => {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.2.2>:
            //
            //   The outbound SCTP packet containing this INIT ACK chunk MUST carry a
            //   Verification Tag value equal to the Initiate Tag found in the unexpected INIT
            //   chunk. And the INIT ACK chunk MUST contain a new Initiate Tag (randomly
            //   generated; see Section 5.3.1). Other parameters for the endpoint SHOULD be
            //   copied from the existing parameters of the association (e.g., number of
            //   outbound streams) into the INIT ACK chunk and cookie.
            //
            // Create a new verification tag, different from the previous one.
            my_verification_tag =
                rand::rng().random_range(MIN_VERIFICATION_TAG..MAX_VERIFICATION_TAG);
            my_initial_tsn = tcb.retransmission_queue.next_tsn().add_to(1000000);
            tie_tag = tcb.tie_tag;
        }
    }

    let capabilities = compute_capabilities(
        &ctx.options,
        chunk.nbr_outbound_streams,
        chunk.nbr_inbound_streams,
        &chunk.parameters,
    );
    let write_checksum = !capabilities.zero_checksum;
    let mut parameters = make_capability_parameters(&ctx.options, capabilities.zero_checksum);
    parameters.push(Parameter::StateCookie(StateCookieParameter {
        cookie: StateCookie {
            peer_tag: chunk.initiate_tag,
            my_tag: my_verification_tag,
            peer_initial_tsn: chunk.initial_tsn,
            my_initial_tsn,
            a_rwnd: chunk.a_rwnd,
            tie_tag,
            capabilities,
        }
        .serialize(),
    }));
    let init_ack = InitAckChunk {
        initiate_tag: my_verification_tag,
        a_rwnd: ctx.options.max_receiver_window_buffer_size as u32,
        nbr_outbound_streams: ctx.options.announced_maximum_outgoing_streams,
        nbr_inbound_streams: ctx.options.announced_maximum_incoming_streams,
        initial_tsn: my_initial_tsn,
        parameters,
    };

    ctx.events.borrow_mut().add(SocketEvent::SendPacket(
        SctpPacketBuilder::new(
            chunk.initiate_tag,
            ctx.options.local_port,
            ctx.options.remote_port,
            ctx.options.mtu,
        )
        .write_checksum(write_checksum)
        .add(&Chunk::InitAck(init_ack))
        .build(),
    ));
    ctx.metrics.tx_packets_count += 1;
}

pub(crate) fn handle_init_ack(
    state: &mut State,
    ctx: &mut Context,
    now: SocketTime,
    chunk: InitAckChunk,
) {
    let State::CookieWait(s) = state else {
        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.2.3>:
        //
        //   If an INIT ACK chunk is received by an endpoint in any state other than the
        //   COOKIE-WAIT or CLOSED state, the endpoint SHOULD discard the INIT ACK chunk. An
        //   unexpected INIT ACK chunk usually indicates the processing of an old or duplicated
        //   INIT chunk.
        info!("Received INIT_ACK in unexpected state");
        return;
    };

    let capabilities = compute_capabilities(
        &ctx.options,
        chunk.nbr_outbound_streams,
        chunk.nbr_inbound_streams,
        &chunk.parameters,
    );

    let Some(cookie) = chunk.parameters.into_iter().find_map(|p| match p {
        Parameter::StateCookie(StateCookieParameter { cookie }) => Some(cookie),
        _ => None,
    }) else {
        ctx.events.borrow_mut().add(SocketEvent::SendPacket(
            SctpPacketBuilder::new(
                s.verification_tag,
                ctx.options.local_port,
                ctx.options.remote_port,
                round_down_to_4!(ctx.options.mtu),
            )
            .add(&Chunk::Abort(AbortChunk {
                error_causes: vec![ErrorCause::ProtocolViolation(ProtocolViolationErrorCause {
                    information: "INIT-ACK malformed".into(),
                })],
            }))
            .build(),
        ));
        ctx.metrics.tx_packets_count += 1;
        ctx.internal_close(
            state,
            ErrorKind::ProtocolViolation,
            "InitAck chunk doesn't contain a cookie".into(),
        );
        return;
    };

    ctx.send_queue.enable_message_interleaving(capabilities.message_interleaving);
    let mut t1_cookie = Timer::new(
        ctx.options.t1_cookie_timeout,
        BackoffAlgorithm::Exponential,
        ctx.options.max_init_retransmits,
        None,
    );
    t1_cookie.start(now);
    ctx.peer_implementation = detemine_sctp_implementation(&cookie);
    ctx.send_queue.reset();
    let tie_tag = rand::rng().random::<u64>();
    *state = State::CookieEchoed(CookieEchoState {
        t1_cookie,
        cookie_echo_chunk: CookieEchoChunk { cookie },
        initial_tsn: s.initial_tsn,
        verification_tag: s.verification_tag,
        tcb: TransmissionControlBlock::new(
            &ctx.options,
            s.verification_tag,
            s.initial_tsn,
            chunk.initiate_tag,
            chunk.initial_tsn,
            tie_tag,
            chunk.a_rwnd,
            capabilities,
            ctx.events.clone(),
        ),
    });

    // The connection isn't fully established just yet.
    send_cookie_echo(state, ctx, now);
}

pub(crate) fn send_cookie_echo(state: &mut State, ctx: &mut Context, now: SocketTime) {
    let &mut State::CookieEchoed(ref s) = state else {
        unreachable!();
    };

    // From <https://datatracker.ietf.org/doc/html/rfc9260.html#section-5.1-2.3.2>:
    //
    //   The COOKIE ECHO chunk MAY be bundled with any pending outbound DATA chunks, but it MUST
    //   be the first chunk in the packet [...]
    let mut builder = SctpPacketBuilder::new(
        s.tcb.peer_verification_tag,
        ctx.options.local_port,
        ctx.options.remote_port,
        ctx.options.mtu,
    );

    builder.add(&Chunk::CookieEcho(s.cookie_echo_chunk.clone()));
    ctx.send_buffered_packets_with(state, now, &mut builder);
}

pub(crate) fn handle_cookie_echo(
    state: &mut State,
    ctx: &mut Context,
    now: SocketTime,
    header: &CommonHeader,
    chunk: CookieEchoChunk,
) {
    let cookie = match StateCookie::from_bytes(&chunk.cookie) {
        Ok(c) => c,
        Err(s) => {
            return ctx
                .events
                .borrow_mut()
                .add(SocketEvent::OnError(ErrorKind::ParseFailed, s.into()));
        }
    };

    let resolution = if let Some(tcb) = state.tcb() {
        CookieResolution::from_tcb(header, tcb, &cookie)
    } else if header.verification_tag != cookie.my_tag {
        CookieResolution::InvalidTag
    } else {
        CookieResolution::EstablishNew
    };

    match resolution {
        CookieResolution::Discard => return,
        CookieResolution::InvalidTag => {
            return ctx.events.borrow_mut().add(SocketEvent::OnError(
                ErrorKind::ParseFailed,
                "Received CookieEcho with invalid verification tag".into(),
            ));
        }
        CookieResolution::RestartDetected => {
            // If the socket is shutting down, reject the restart.
            if matches!(state, State::ShutdownAckSent(_)) {
                let tcb = state.tcb().expect("TCB must exist in ShutdownAckSent");

                let packet = tcb
                    .new_packet()
                    .add(&Chunk::ShutdownAck(ShutdownAckChunk {}))
                    .add(&Chunk::Error(ErrorChunk {
                        error_causes: vec![ErrorCause::CookieReceivedWhileShuttingDown(
                            CookieReceivedWhileShuttingDownErrorCause {},
                        )],
                    }))
                    .build();

                ctx.events.borrow_mut().add(SocketEvent::SendPacket(packet));
                ctx.events.borrow_mut().add(SocketEvent::OnError(
                    ErrorKind::WrongSequence,
                    "Received COOKIE-ECHO while shutting down".into(),
                ));
                ctx.metrics.tx_packets_count += 1;
                return;
            }
            ctx.events.borrow_mut().add(SocketEvent::OnConnectionRestarted());
            establish_new_tcb(state, ctx, now, &cookie, true);
        }
        CookieResolution::SimultaneousInit => {
            establish_new_tcb(state, ctx, now, &cookie, true);
        }
        CookieResolution::EstablishNew => {
            establish_new_tcb(state, ctx, now, &cookie, false);
        }
        CookieResolution::MaintainExisting => {
            if matches!(state, State::CookieEchoed(_)) {
                transition_between!(*state,
                    State::CookieEchoed(s) => State::Established(s.tcb)
                );
                ctx.heartbeat_interval.start(now);
                info!("{}: Connection established", "Socket"); // Placeholder name
                ctx.events.borrow_mut().add(SocketEvent::OnConnected());
            }
        }
    }

    let Some(tcb) = state.tcb() else {
        unreachable!();
    };

    let write_checksum = !tcb.capabilities.zero_checksum;
    let mut b = SctpPacketBuilder::new(
        cookie.peer_tag,
        ctx.options.local_port,
        ctx.options.remote_port,
        ctx.options.mtu,
    );
    b.write_checksum(write_checksum);
    b.add(&Chunk::CookieAck(CookieAckChunk {}));
    ctx.send_buffered_packets_with(state, now, &mut b);
}

/// Transitions the socket to Established using the data in the Cookie.
/// If `reset_queue` is true, reset message identifiers (used for restarts).
fn establish_new_tcb(
    state: &mut State,
    ctx: &mut Context,
    now: SocketTime,
    cookie: &StateCookie,
    reset_queue: bool,
) {
    ctx.send_queue.enable_message_interleaving(cookie.capabilities.message_interleaving);

    if reset_queue {
        ctx.send_queue.reset();
    }

    let tie_tag = rand::rng().random::<u64>();
    let new_tcb = TransmissionControlBlock::new(
        &ctx.options,
        cookie.my_tag,
        cookie.my_initial_tsn,
        cookie.peer_tag,
        cookie.peer_initial_tsn,
        tie_tag,
        cookie.a_rwnd,
        cookie.capabilities,
        ctx.events.clone(),
    );

    *state = State::Established(new_tcb);
    ctx.heartbeat_interval.start(now);

    info!("Connection established");
    ctx.events.borrow_mut().add(SocketEvent::OnConnected());
}

pub(crate) fn handle_cookie_ack(state: &mut State, ctx: &mut Context, now: SocketTime) {
    if !matches!(state, State::CookieEchoed(_)) {
        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.2.5>:
        //
        //   At any state other than COOKIE-ECHOED, an endpoint SHOULD silently discard a
        //   received COOKIE ACK chunk.
        warn!("Received COOKIE_ACK not in COOKIE_ECHOED state");
        return;
    }

    transition_between!(*state,
        State::CookieEchoed(s) => State::Established(s.tcb)
    );

    ctx.heartbeat_interval.start(now);
    info!("Socket is connected!");
    ctx.events.borrow_mut().add(SocketEvent::OnConnected());
}

pub(crate) fn send_init(state: &mut State, ctx: &mut Context) {
    let &mut State::CookieWait(ref s) = state else {
        unreachable!();
    };
    let support_zero_checksum = ctx.options.zero_checksum_alternate_error_detection_method
        != ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE;
    ctx.events.borrow_mut().add(SocketEvent::SendPacket(
        SctpPacketBuilder::new(0, ctx.options.local_port, ctx.options.remote_port, ctx.options.mtu)
            .add(&Chunk::Init(InitChunk {
                initiate_tag: s.verification_tag,
                a_rwnd: ctx.options.max_receiver_window_buffer_size as u32,
                nbr_outbound_streams: ctx.options.announced_maximum_outgoing_streams,
                nbr_inbound_streams: ctx.options.announced_maximum_incoming_streams,
                initial_tsn: s.initial_tsn,
                parameters: make_capability_parameters(&ctx.options, support_zero_checksum),
            }))
            .build(),
    ));
    ctx.metrics.tx_packets_count += 1;
}

pub(crate) fn handle_t1init_timeout(state: &mut State, ctx: &mut Context, now: SocketTime) {
    let &mut State::CookieWait(ref mut s) = state else { unreachable!() };
    if s.t1_init.expire(now) {
        if s.t1_init.is_running() {
            send_init(state, ctx);
        } else {
            ctx.internal_close(state, ErrorKind::TooManyRetries, "No INIT_ACK received".into());
        }
    }
}

pub(crate) fn handle_t1cookie_timeout(state: &mut State, ctx: &mut Context, now: SocketTime) {
    let &mut State::CookieEchoed(ref mut s) = state else { unreachable!() };
    if s.t1_cookie.expire(now) {
        if !s.t1_cookie.is_running() {
            ctx.internal_close(state, ErrorKind::TooManyRetries, "No COOKIE_ACK received".into());
        } else {
            send_cookie_echo(state, ctx, now);
        }
    }
}
