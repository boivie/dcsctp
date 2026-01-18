use crate::api::ErrorKind;
use crate::api::SocketEvent;
use crate::packet::SerializableTlv;
use crate::packet::abort_chunk::AbortChunk;
use crate::packet::chunk::Chunk;
use crate::packet::error_causes::ErrorCause;
use crate::packet::error_chunk::ErrorChunk;
use crate::packet::unknown_chunk::UnknownChunk;
use crate::packet::unrecognized_chunk_error_cause::UnrecognizedChunkErrorCause;
use crate::socket::context::Context;
use crate::socket::state::State;

pub(crate) fn handle_abort(state: &mut State, ctx: &mut Context, chunk: AbortChunk) {
    if state.tcb().is_none() {
        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.7>:
        //
        //   If an endpoint receives an ABORT chunk with a format error or no TCB is found, it
        //   MUST silently discard it.
        return;
    }
    let reason =
        chunk.error_causes.into_iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",");
    ctx.internal_close(state, ErrorKind::PeerReported, reason);
}

pub(crate) fn handle_error(state: &mut State, ctx: &mut Context, chunk: ErrorChunk) {
    if state.tcb().is_none() {
        return;
    }
    let message =
        chunk.error_causes.into_iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",");
    ctx.events.borrow_mut().add(SocketEvent::OnError(ErrorKind::PeerReported, message));
}

pub(crate) fn handle_unrecognized_chunk(
    state: &mut State,
    ctx: &mut Context,
    chunk: UnknownChunk,
) -> bool {
    // From <https://datatracker.ietf.org/doc/html/rfc9260#section-3.2-3.2.5>:
    //
    //   Chunk Types are encoded such that the highest-order 2 bits specify the action that is
    //   taken if the processing endpoint does not recognize the Chunk Type.
    let typ = chunk.typ;
    let report_as_error = (typ & 0x40) != 0;
    let continue_processing = (typ & 0x80) != 0;
    if report_as_error {
        ctx.events
            .borrow_mut()
            .add(SocketEvent::OnError(ErrorKind::ParseFailed, format!("Received {}, ", chunk)));
        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-3.2-3.2.6.1.2.2.1>:
        //
        //   [...] report the unrecognized chunk in an ERROR chunk using the 'Unrecognized Chunk
        //   Type' error cause.
        if let Some(tcb) = state.tcb() {
            let mut serialized = vec![0; chunk.serialized_size()];
            chunk.serialize_to(&mut serialized);
            ctx.events.borrow_mut().add(SocketEvent::SendPacket(
                tcb.new_packet()
                    .add(&Chunk::Error(ErrorChunk {
                        error_causes: vec![ErrorCause::UnrecognizedChunk(
                            UnrecognizedChunkErrorCause { chunk: serialized },
                        )],
                    }))
                    .build(),
            ));
            ctx.metrics.tx_packets_count += 1;
        }
    }
    continue_processing
}
