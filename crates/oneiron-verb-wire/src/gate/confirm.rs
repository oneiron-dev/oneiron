//! Moved from `crates/oneiron/src/gate/confirm.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::critical_confirm_record::CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS;
pub use oneiron_store::critical_confirm_record::GATE_REASON_CRITICAL_CONFIRM_TIMEOUT;
pub(super) use oneiron_store::critical_confirm_record::GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED;
pub(super) use oneiron_store::critical_confirm_record::GATE_REASON_PENDING_CRITICAL_CONFIRM_REOPENED;
pub(super) use oneiron_store::critical_confirm_record::GATE_REASON_PENDING_REPLICATED_CRITICAL_CONFIRM;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum CriticalWriteConfirmResolution {
    Cleared,
    Retracted,
    DemotedToProposed,
    AlreadySettled,
}
