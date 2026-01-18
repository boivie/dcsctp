use crate::api::ErrorKind;
use crate::api::SocketEvent;
use crate::api::SocketTime;
use crate::packet::chunk::Chunk;
use crate::packet::data::Data;
use crate::packet::chunk_validators::clean_sack;
use crate::packet::error_causes::ErrorCause;
use crate::packet::error_chunk::ErrorChunk;
use crate::packet::no_user_data_error_cause::NoUserDataErrorCause;
use crate::packet::sack_chunk::SackChunk;
use crate::socket::context::Context;
use crate::socket::state::State;
use crate::tx::retransmission_queue::HandleSackResult;
use crate::types::Tsn;
use crate::packet::SkippedStream;
use crate::packet::iforward_tsn_chunk::IForwardTsnChunk;
use crate::socket::handlers::shutdown::{maybe_send_shutdown, maybe_send_shutdown_ack};

#[cfg(not(test))]
use log::debug;
#[cfg(test)]
use std::println as debug;

pub(crate) fn handle_data(state: &mut State, ctx: &mut Context<'_, '_>, now: SocketTime, tsn: Tsn, data: Data) {
    if data.payload.is_empty() {
        ctx.events.borrow_mut().add(SocketEvent::OnError(
            ErrorKind::ProtocolViolation,
            "Received DATA chunk with no user data".into(),
        ));
        if let Some(tcb) = state.tcb_mut() {
            ctx.events.borrow_mut().add(SocketEvent::SendPacket(
                tcb.new_packet()
                    .add(&Chunk::Error(ErrorChunk {
                        error_causes: vec![ErrorCause::NoUserData(NoUserDataErrorCause {
                            tsn,
                        })],
                    }))
                    .build(),
            ));
            *ctx.tx_packets_count += 1;
        }
        return;
    }
    let Some(tcb) = state.tcb_mut() else {
        ctx.events.borrow_mut().add(SocketEvent::OnError(
            ErrorKind::NotConnected,
            "Received unexpected commands on socket that is not connected".into(),
        ));
        return;
    };
    if tcb.reassembly_queue.is_full() {
        // If the reassembly queue is full, there is nothing that can be done. The specification
        // only allows dropping gap-ack-blocks, and that's not likely to help as the socket has
        // been trying to fill gaps since the watermark was reached.
        return;
    }
    if tcb.reassembly_queue.is_above_watermark() {
        // TODO: Implement
        return;
    }
    if !tcb.data_tracker.is_tsn_valid(tsn) {
        // TODO: Implement
        return;
    }
    if tcb.data_tracker.observe(now, tsn, false) {
        tcb.reassembly_queue.add(tsn, data);
    }
}

pub(crate) fn handle_sack(state: &mut State, ctx: &mut Context<'_, '_>, now: SocketTime, sack: SackChunk) {
    let Some(tcb) = state.tcb_mut() else {
        ctx.events
            .borrow_mut()
            .add(SocketEvent::OnError(ErrorKind::NotConnected, "No TCB".into()));
        return;
    };

    let sack = clean_sack(sack);
    match tcb.retransmission_queue.handle_sack(now, &sack) {
        HandleSackResult::Invalid => {
            debug!("Dropping out-of-order SACK with TSN {}", sack.cumulative_tsn_ack);
            return;
        }
        HandleSackResult::Valid { rtt, reset_error_counter } => {
            if let Some(rtt) = rtt {
                tcb.rto.observe_rto(rtt);
                tcb.retransmission_queue.update_rto(tcb.rto.rto());
                tcb.data_tracker.update_rto(tcb.rto.rto());
            }
            if reset_error_counter {
                ctx.tx_error_counter.reset();
            }
        }
    }

    match state {
        State::ShutdownPending(_) => maybe_send_shutdown(state, ctx, now),
        State::ShutdownReceived(_) => maybe_send_shutdown_ack(state, ctx),
        _ => (),
    }

    // Receiving an ACK may make the socket go into fast recovery mode. From
    // <https://datatracker.ietf.org/doc/html/rfc9260#section-7.2.4>:
    //
    //   If not in Fast Recovery, determine how many of the earliest (i.e., lowest TSN) DATA
    //   chunks marked for retransmission will fit into a single packet, subject to constraint
    //   of the PMTU of the destination transport address to which the packet is being sent.
    //   Call this value K. Retransmit those K DATA chunks in a single packet. When a Fast
    //   Retransmit is being performed, the sender SHOULD ignore the value of cwnd and SHOULD
    //   NOT delay retransmission for this single packet.
    maybe_send_fast_retransmit(state, ctx, now);

    // Receiving an ACK will decrease outstanding bytes (maybe now below cwnd?) or indicate
    // packet loss that may result in sending FORWARD-TSN.
    ctx.send_buffered_packets(state, now);
}

pub(crate) fn maybe_send_fast_retransmit(state: &mut State, ctx: &mut Context<'_, '_>, now: SocketTime) {
    let tcb = state.tcb_mut().unwrap();
    if !tcb.retransmission_queue.has_data_to_be_fast_retransmitted() {
        return;
    }

    let mut builder = tcb.new_packet();

    let chunks =
        tcb.retransmission_queue.get_chunks_for_fast_retransmit(now, builder.bytes_remaining());
    for (tsn, data) in chunks {
        builder.add(&tcb.make_data_chunk(tsn, data));
    }

    debug_assert!(!builder.is_empty());
    ctx.events.borrow_mut().add(SocketEvent::SendPacket(builder.build()));
    *ctx.tx_packets_count += 1;
}

pub(crate) fn handle_forward_tsn(
    state: &mut State,
    _ctx: &mut Context<'_, '_>, // Unused
    now: SocketTime,
    new_cumulative_tsn: Tsn,
    skipped_streams: Vec<SkippedStream>,
) {
    if let Some(tcb) = state.tcb_mut() {
        if tcb.data_tracker.handle_forward_tsn(now, new_cumulative_tsn) {
            tcb.reassembly_queue.handle_forward_tsn(new_cumulative_tsn, skipped_streams);
        }
    }
}

pub(crate) fn handle_iforward_tsn(_state: &mut State, _ctx: &mut Context<'_, '_>, _now: SocketTime, _chunk: IForwardTsnChunk) {}

pub(crate) fn maybe_send_sack(state: &mut State, ctx: &mut Context<'_, '_>, now: SocketTime) {
    if let Some(tcb) = state.tcb_mut() {
        tcb.data_tracker.observe_packet_end(now);
        if tcb.data_tracker.should_send_ack(now, false) {
            let mut b = tcb.new_packet();
            let rwnd = tcb.reassembly_queue.remaining_bytes();
            b.add(&Chunk::Sack(tcb.data_tracker.create_selective_ack(rwnd as u32)));
            ctx.send_buffered_packets_with(state, now, &mut b);
        }
    }
}
