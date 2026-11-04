//! Claim-write decision recording and pending-consent mode.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateWriteMode {
    pub(crate) record_decision: bool,
    pub(crate) persist_pending_consent: bool,
    pub(crate) resolve_pending: bool,
    pub(crate) can_resolve_pending_consent: bool,
    pub(crate) include_source_in_gate_input: bool,
}
