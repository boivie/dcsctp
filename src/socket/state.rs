use crate::packet::cookie_echo_chunk::CookieEchoChunk;
use crate::packet::sctp_packet::CommonHeader;
use crate::socket::state_cookie::StateCookie;
use crate::socket::transmission_control_block::TransmissionControlBlock;
use crate::timer::Timer;
use crate::types::Tsn;

pub(crate) struct CookieWaitState {
    pub t1_init: Timer,
    pub initial_tsn: Tsn,
    pub verification_tag: u32,
}

pub(crate) struct CookieEchoState {
    pub t1_cookie: Timer,
    pub cookie_echo_chunk: CookieEchoChunk,
    pub initial_tsn: Tsn,
    pub verification_tag: u32,
    pub tcb: TransmissionControlBlock,
}

pub(crate) struct ShutdownSentState {
    pub t2_shutdown: Timer,
    pub tcb: TransmissionControlBlock,
}

pub(crate) enum State {
    Closed,
    CookieWait(CookieWaitState),
    CookieEchoed(CookieEchoState),
    Established(TransmissionControlBlock),
    ShutdownPending(TransmissionControlBlock),
    ShutdownSent(ShutdownSentState),
    ShutdownReceived(TransmissionControlBlock),
    ShutdownAckSent(TransmissionControlBlock),
}

impl State {
    pub(crate) fn tcb_mut(&mut self) -> Option<&mut TransmissionControlBlock> {
        match self {
            State::CookieEchoed(CookieEchoState { tcb, .. })
            | State::Established(tcb)
            | State::ShutdownPending(tcb)
            | State::ShutdownSent(ShutdownSentState { tcb, .. })
            | State::ShutdownReceived(tcb)
            | State::ShutdownAckSent(tcb) => Some(tcb),
            _ => None,
        }
    }

    pub(crate) fn tcb(&self) -> Option<&TransmissionControlBlock> {
        match self {
            State::CookieEchoed(CookieEchoState { tcb, .. })
            | State::Established(tcb)
            | State::ShutdownPending(tcb)
            | State::ShutdownSent(ShutdownSentState { tcb, .. })
            | State::ShutdownReceived(tcb)
            | State::ShutdownAckSent(tcb) => Some(tcb),
            _ => None,
        }
    }
}

/// Represents the action to take after analyzing the Cookie against the current state.
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-5.2.4>.
pub(crate) enum CookieResolution {
    /// Case A: Peer restarted.
    RestartDetected,
    /// Case B: Simultaneous INIT.
    SimultaneousInit,
    /// Case C: Late arrival, silently discard.
    Discard,
    /// Case D: Tags match, proceed with existing TCB.
    MaintainExisting,
    /// No existing TCB, but tags match. Start new.
    EstablishNew,
    /// Tags do not match expected values.
    InvalidTag,
}

impl CookieResolution {
    pub(crate) fn from_tcb(
        header: &CommonHeader,
        tcb: &TransmissionControlBlock,
        cookie: &StateCookie,
    ) -> Self {
        let v_tag_mismatch = header.verification_tag != tcb.my_verification_tag;
        let peer_tag_mismatch = tcb.peer_verification_tag != cookie.peer_tag;

        // https://datatracker.ietf.org/doc/html/rfc9260#section-5.2.4
        if v_tag_mismatch && peer_tag_mismatch && cookie.tie_tag == tcb.tie_tag {
            // Case A
            CookieResolution::RestartDetected
        } else if !v_tag_mismatch && peer_tag_mismatch {
            // Case B
            CookieResolution::SimultaneousInit
        } else if v_tag_mismatch && !peer_tag_mismatch && cookie.tie_tag == 0 {
            // Case C
            CookieResolution::Discard
        } else if !v_tag_mismatch && !peer_tag_mismatch {
            // Case D
            CookieResolution::MaintainExisting
        } else {
            // Fallback for unhandled collisions or mismatching tags
            CookieResolution::InvalidTag
        }
    }
}
