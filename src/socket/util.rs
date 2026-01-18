use crate::EventSink;
use crate::api::Options;
use crate::api::SctpImplementation;
use crate::api::SocketEvent;
use crate::api::SocketTime;
use crate::api::ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE;
use crate::logging::log_packet;
use crate::packet::forward_tsn_chunk;
use crate::packet::forward_tsn_supported_parameter::ForwardTsnSupportedParameter;
use crate::packet::idata_chunk;
use crate::packet::iforward_tsn_chunk;
use crate::packet::parameter::Parameter;
use crate::packet::re_config_chunk;
use crate::packet::supported_extensions_parameter::SupportedExtensionsParameter;
use crate::packet::zero_checksum_acceptable_parameter::ZeroChecksumAcceptableParameter;
use crate::socket::capabilities::Capabilities;
#[cfg(not(test))]
use log::info;
use std::cell::RefCell;
use std::cmp::min;
use std::collections::HashSet;
#[cfg(test)]
use std::println as info;
use std::rc::Rc;

pub(crate) struct TxErrorCounter {
    error_counter: u32,
    limit: Option<u32>,
}

impl TxErrorCounter {
    pub(crate) fn new(limit: Option<u32>) -> Self {
        Self { error_counter: 0, limit }
    }

    pub(crate) fn increment(&mut self) {
        match self.limit {
            Some(limit) if self.error_counter <= limit => {
                self.error_counter += 1;
            }
            _ => {}
        }
    }

    pub(crate) fn reset(&mut self) {
        self.error_counter = 0;
    }

    pub(crate) fn is_exhausted(&self) -> bool {
        if let Some(limit) = self.limit { self.error_counter > limit } else { false }
    }
}

pub(crate) struct LoggingEvents {
    parent: Rc<RefCell<dyn EventSink>>,
    name: String,
    now: Rc<RefCell<SocketTime>>,
}

impl LoggingEvents {
    pub fn new(
        parent: Rc<RefCell<dyn EventSink>>,
        name: String,
        now: Rc<RefCell<SocketTime>>,
    ) -> LoggingEvents {
        Self { parent, name, now }
    }
}

impl EventSink for LoggingEvents {
    fn add(&mut self, event: SocketEvent) {
        match event {
            SocketEvent::SendPacket(ref e) => {
                let now = *self.now.borrow();
                log_packet(&self.name, now.into(), true, e);
            }
            SocketEvent::OnConnected() => info!("OnConnected"),
            SocketEvent::OnError(kind, ref e) => info!("OnError: {:?}, {}", kind, e),
            SocketEvent::OnBufferedAmountLow(e) => info!("OnBufferedAmountLow: {}", e),
            SocketEvent::OnTotalBufferedAmountLow() => info!("OnTotalBufferedAmountLow"),
            SocketEvent::OnLifecycleMessageFullySent(ref id) => {
                info!("OnLifecycleMessageFullySent({})", id);
            }
            SocketEvent::OnLifecycleMessageExpired(ref id) => {
                info!("OnLifecycleMessageExpired({})", id);
            }
            SocketEvent::OnLifecycleMessageMaybeExpired(ref id) => {
                info!("OnLifecycleMessageMaybeExpired({})", id);
            }
            SocketEvent::OnLifecycleMessageDelivered(ref id) => {
                info!("OnLifecycleMessageDelivered({})", id);
            }
            SocketEvent::OnLifecycleEnd(ref id) => {
                info!("OnLifecycleEnd({})", id);
            }
            SocketEvent::OnStreamsResetFailed(ref streams) => {
                info!("OnStreamsResetFailed({:?})", streams);
            }
            SocketEvent::OnStreamsResetPerformed(ref streams) => {
                info!("OnStreamsResetPerformed({:?})", streams);
            }
            SocketEvent::OnIncomingStreamReset(ref streams) => {
                info!("OnIncomingStreamReset({:?})", streams);
            }
            SocketEvent::OnClosed() => {
                info!("OnClosed()");
            }
            SocketEvent::OnAborted(ref error, ref reason) => {
                info!("OnAborted({:?}, {})", error, reason);
            }
            SocketEvent::OnConnectionRestarted() => {
                info!("OnConnectionRestarted()");
            }
        }
        self.parent.borrow_mut().add(event);
    }

    fn next_event(&mut self) -> Option<SocketEvent> {
        self.parent.borrow_mut().next_event()
    }
}

pub(crate) fn closest_timeout(a: Option<SocketTime>, b: Option<SocketTime>) -> Option<SocketTime> {
    match (a, b) {
        (None, None) => None,
        (None, Some(_)) => b,
        (Some(_), None) => a,
        (Some(t1), Some(t2)) => Some(min(t1, t2)),
    }
}

pub(crate) fn detemine_sctp_implementation(cookie: &[u8]) -> SctpImplementation {
    if cookie.len() > 8 {
        return match std::str::from_utf8(&cookie[0..8]) {
            Ok("dcSCTP00") => SctpImplementation::DcsctpCc,
            Ok("dcSCTPr0") => SctpImplementation::DcsctpRs,
            Ok("KAME-BSD") => SctpImplementation::UsrSctp,
            _ => SctpImplementation::Unknown,
        };
    }
    SctpImplementation::Unknown
}

pub(crate) fn make_capability_parameters(
    options: &Options,
    support_zero_checksum: bool,
) -> Vec<Parameter> {
    let mut result: Vec<Parameter> = Vec::new();
    let mut chunk_types: Vec<u8> = Vec::new();
    chunk_types.push(re_config_chunk::CHUNK_TYPE);

    if options.enable_partial_reliability {
        result.push(Parameter::ForwardTsnSupported(ForwardTsnSupportedParameter {}));
        chunk_types.push(forward_tsn_chunk::CHUNK_TYPE);
    }
    if options.enable_message_interleaving {
        chunk_types.push(idata_chunk::CHUNK_TYPE);
        chunk_types.push(iforward_tsn_chunk::CHUNK_TYPE);
    }
    if support_zero_checksum {
        result.push(Parameter::ZeroChecksumAcceptable(ZeroChecksumAcceptableParameter {
            method: options.zero_checksum_alternate_error_detection_method,
        }));
    }
    result.push(Parameter::SupportedExtensions(SupportedExtensionsParameter { chunk_types }));

    result
}

pub(crate) fn compute_capabilities(
    options: &Options,
    peer_nbr_outbound_streams: u16,
    peer_nbr_inbound_streams: u16,
    parameters: &[Parameter],
) -> Capabilities {
    let supported: HashSet<u8> = HashSet::from_iter(
        parameters
            .iter()
            .find_map(|e| match e {
                Parameter::SupportedExtensions(SupportedExtensionsParameter { chunk_types }) => {
                    Some(chunk_types)
                }
                _ => None,
            })
            .unwrap_or(&vec![])
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
    );

    let partial_reliability = options.enable_partial_reliability
        && (parameters.iter().any(|e| matches!(e, Parameter::ForwardTsnSupported(_)))
            || supported.contains(&forward_tsn_chunk::CHUNK_TYPE));

    let message_interleaving = options.enable_message_interleaving
        && supported.contains(&idata_chunk::CHUNK_TYPE)
        && supported.contains(&iforward_tsn_chunk::CHUNK_TYPE);

    let peer_zero_checksum = *parameters
        .iter()
        .find_map(|e| match e {
            Parameter::ZeroChecksumAcceptable(ZeroChecksumAcceptableParameter { method }) => {
                Some(method)
            }
            _ => None,
        })
        .unwrap_or(&ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE);
    let zero_checksum = (options.zero_checksum_alternate_error_detection_method
        != ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE)
        && (options.zero_checksum_alternate_error_detection_method == peer_zero_checksum);

    Capabilities {
        partial_reliability,
        message_interleaving,
        reconfig: supported.contains(&re_config_chunk::CHUNK_TYPE),
        zero_checksum,
        negotiated_maximum_incoming_streams: min(
            options.announced_maximum_incoming_streams,
            peer_nbr_outbound_streams,
        ),
        negotiated_maximum_outgoing_streams: min(
            options.announced_maximum_outgoing_streams,
            peer_nbr_inbound_streams,
        ),
    }
}

/// Facilitates state transitions within a `State` enum, allowing the state enum variant arguments
/// to be moved to the new state, improving code readability.
#[macro_export]
macro_rules! transition_between {
    ($state:expr, $($from_pat:pat),+ => $to_expr:expr) => {
        $state = match std::mem::replace(&mut $state, $crate::socket::state::State::Closed) {
            $($from_pat => $to_expr,)+
            _ => unreachable!(),
        };
    };
}
