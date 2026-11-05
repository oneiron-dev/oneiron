//! Claim-write decision recording and pending-consent mode.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateWriteMode {
    pub record_decision: bool,
    pub persist_pending_consent: bool,
    pub resolve_pending: bool,
    pub can_resolve_pending_consent: bool,
    pub include_source_in_gate_input: bool,
}
