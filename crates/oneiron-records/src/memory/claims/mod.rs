//! Moved from `crates/oneiron/src/memory/claims/mod.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::reference_refusal::RefusalReason;
pub use oneiron_verb_wire::memory::claims::ClaimInput;
pub use oneiron_verb_wire::memory::claims::settle::ClaimChangeVerdict;
pub use oneiron_verb_wire::memory::claims::settle::ClaimProposalReviewRequest;
pub use oneiron_verb_wire::memory::claims::settle::ClaimSettleDecision;
pub use oneiron_verb_wire::memory::claims::settle::ClaimSettleRequest;
pub use oneiron_verb_wire::memory::claims::settle::ClaimSettlementAnswer;
pub use oneiron_verb_wire::memory::claims::settle::ClaimSettlementReason;
pub use oneiron_verb_wire::memory::claims::settle::ClaimSettlementRevert;
pub use oneiron_verb_wire::memory::claims::settle::ClaimSettlementVerdict;
pub use oneiron_verb_wire::memory::claims::settle::SettleWarning;
pub use oneiron_verb_wire::memory::claims::settle::SettleWarningCode;
use serde::Deserialize;
use serde::Serialize;

/// Where one delete request stands (FIX 1465). Neither says the erase is
/// complete: that is its deletion receipt's signed final row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteRequestState {
    /// The local delete rail applied it.
    Applied,
    /// Accepted and recorded, not applied yet: "erase confirmed; completion
    /// pending". It runs once nothing holds the record, or once the shared
    /// vault's veto window has run out.
    CompletionPending,
}

impl DeleteRequestState {
    /// Stable string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::CompletionPending => "completion_pending",
        }
    }
}

/// Receipt for one safe delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteReceipt {
    /// Whether the entity existed before the delete.
    pub existed: bool,
    /// The reason the delete was performed under.
    pub reason: String,
    /// Redaction audit receipt ref (`redaction:<hex>`); `None` for
    /// `user_delete`, which writes no receipt entity by design, and for a
    /// request not applied yet.
    pub receipt_ref: Option<String>,
    /// Whether the local rail applied it or it waits (FIX 1465).
    pub state: DeleteRequestState,
}

/// One pending gated write awaiting consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWrite {
    /// 32-hex id of the parked claim.
    pub claim_ref: String,
    /// Gate decision ref (`gate:<hex>`).
    pub decision_ref: String,
    /// Unix seconds the decision was recorded.
    pub created_at: u64,
    /// Gate reason codes (e.g. `gate.pending.actor_ceiling`).
    pub reason_codes: Vec<String>,
    /// Dreamer run lane, when the write came from a consolidation run.
    pub dreamer_run_id: Option<String>,
}
