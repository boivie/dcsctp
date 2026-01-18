use crate::api::ErrorKind;
use crate::packet::parameter::Parameter;
use crate::api::SocketEvent;
use crate::api::SocketTime;
use crate::packet::chunk::Chunk;
use crate::packet::heartbeat_ack_chunk::HeartbeatAckChunk;
use crate::packet::heartbeat_info_parameter::HeartbeatInfoParameter;
use crate::packet::heartbeat_request_chunk::HeartbeatRequestChunk;
use crate::packet::read_u32_be;
use crate::packet::write_u32_be;
use crate::socket::context::Context;
use crate::socket::state::State;

pub(crate) fn handle_heartbeat_req(state: &mut State, ctx: &mut Context<'_, '_>, chunk: HeartbeatRequestChunk) {
    // From <https://datatracker.ietf.org/doc/html/rfc9260#section-8.3-9>:
    //
    //   The receiver of the HEARTBEAT chunk SHOULD immediately respond with a HEARTBEAT ACK
    //   chunk that contains the Heartbeat Information TLV, together with any other received
    //   TLVs, copied unchanged from the received HEARTBEAT chunk.
    if let Some(tcb) = state.tcb_mut() {
        ctx.events.borrow_mut().add(SocketEvent::SendPacket(
            tcb.new_packet()
                .add(&Chunk::HeartbeatAck(HeartbeatAckChunk { parameters: chunk.parameters }))
                .build(),
        ));
        *ctx.tx_packets_count += 1;
    }
}

pub(crate) fn handle_heartbeat_ack(_state: &mut State, ctx: &mut Context<'_, '_>, now: SocketTime, chunk: HeartbeatAckChunk) {
    // state is unused here? No, Socket had this method.
    // It uses `self.heartbeat_timeout`, `self.heartbeat_counter`, `self.heartbeat_sent_time`, `self.tx_error_counter`.
    // These are all in Context.
    // So `state` might not be needed?
    // Socket method didn't use state except indirectly?
    // Ah, logic:
    /*
        self.heartbeat_timeout.stop();
        match ... {
            ...
               if counter == self.heartbeat_counter {
                   self.tx_error_counter.reset();
               }
        }
    */
    // State is not used!
    // But consistent signature?
    // I'll keep `_state: &mut State` for consistency if needed, or remove it.
    // I will keep it to avoid changing pattern if I need it later (e.g. accessing TCB).
    
    ctx.heartbeat_timeout.stop();
    match chunk.parameters.iter().find_map(|p| match p {
        Parameter::HeartbeatInfo(HeartbeatInfoParameter { info }) => Some(info),
        _ => None,
    }) {
        Some(info) if info.len() == 4 => {
            let counter = read_u32_be!(info);
            if counter == *ctx.heartbeat_counter {
                let _rtt = now - *ctx.heartbeat_sent_time;
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-8.1>:
                //
                //   When a HEARTBEAT ACK chunk is received from the peer endpoint, the counter
                //   SHOULD also be reset.
                ctx.tx_error_counter.reset();
            }
        }
        _ => {
            ctx.events.borrow_mut().add(SocketEvent::OnError(
                ErrorKind::ParseFailed,
                "Failed to parse HEARTBEAT-ACK; Invalid info parameter".into(),
            ));
        }
    }
}

pub(crate) fn handle_heartbeat_timeouts(state: &mut State, ctx: &mut Context<'_, '_>, now: SocketTime) {
    if ctx.heartbeat_interval.expire(now) {
        if let Some(tcb) = state.tcb() {
            ctx.heartbeat_timeout.set_duration(ctx.options.rto_initial);
            ctx.heartbeat_timeout.start(now);
            *ctx.heartbeat_counter = ctx.heartbeat_counter.wrapping_add(1);
            *ctx.heartbeat_sent_time = now;
            let mut info = vec![0; 4];
            write_u32_be!(&mut info, *ctx.heartbeat_counter);
            ctx.events.borrow_mut().add(SocketEvent::SendPacket(
                tcb.new_packet()
                    .add(&Chunk::HeartbeatRequest(HeartbeatRequestChunk {
                        parameters: vec![Parameter::HeartbeatInfo(HeartbeatInfoParameter {
                            info,
                        })],
                    }))
                    .build(),
            ));
            *ctx.tx_packets_count += 1;
        }
    }
    if ctx.heartbeat_timeout.expire(now) {
        // Note that the timeout timer is not restarted. It will be started again when the
        // interval timer expires.
        debug_assert!(!ctx.heartbeat_timeout.is_running());
        ctx.tx_error_counter.increment();
    }
}
