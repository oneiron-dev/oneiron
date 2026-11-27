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

/// The [`DeleteReceipt::reason`] of the owner's delete of a live artifact's lone `blob.version`
/// claim, which runs as the release of the version it records: the claim goes with its version
/// and its unheld bytes (ASTRA-R2-002).
pub const DELETE_RECEIPT_VERSION_RELEASE: &str = "blob_version_release";

/// One thing a delete or erase leaves behind that the person is told
/// (FIX HARD-DELETE-ANSWER-SILENT-ON-OWED-SWEEP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemainingNotice {
    /// The remainder's code (`history_sweep`).
    pub code: String,
    /// The remainder's words, as the answer shows them.
    pub text: String,
}

/// [`RemainingNotice::code`] of a history sweep the delete queued.
pub const REMAINING_HISTORY_SWEEP: &str = "history_sweep";

/// [`RemainingNotice::text`] beside [`REMAINING_HISTORY_SWEEP`].
pub const REMAINING_HISTORY_SWEEP_TEXT: &str = "Removed now. Older copies in this vault's sync history are cleared by a background sweep, and the receipt shows when that is done.";

/// The [`DeleteReceipt::remaining`] of a delete that queued `sweep_key`: one
/// history-sweep entry when a sweep was queued, else empty. The receipt
/// writer returns an empty key when no sweep was queued, and callers wrap it
/// in `Some`, so only a non-empty key counts.
#[must_use]
pub fn remaining_after_delete(sweep_key: Option<&[u8]>) -> Vec<RemainingNotice> {
    match sweep_key {
        Some(key) if !key.is_empty() => vec![RemainingNotice {
            code: REMAINING_HISTORY_SWEEP.to_owned(),
            text: REMAINING_HISTORY_SWEEP_TEXT.to_owned(),
        }],
        _ => Vec::new(),
    }
}

/// Receipt for one safe delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteReceipt {
    /// Whether the entity existed before the delete.
    pub existed: bool,
    /// The reason the delete was performed under, or [`DELETE_RECEIPT_VERSION_RELEASE`] when the
    /// delete of a live artifact's lone version claim ran as that version's release.
    pub reason: String,
    /// Redaction audit receipt ref (`redaction:<hex>`); `None` for
    /// `user_delete`, which writes no receipt entity by design, and for a
    /// request not applied yet.
    pub receipt_ref: Option<String>,
    /// Whether the local rail applied it or it waits (FIX 1465).
    pub state: DeleteRequestState,
    /// The check-in decision `vault.delete` ran on (ROLES-CHECKIN 2k5;
    /// P25-SHAPE Q1 = A): the Owner's own proof, or a person's judgment
    /// under their membership role. None for an agent's delete under its
    /// Grant, which PR 3's act gate judges, and for a delete another door
    /// runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<oneiron_verb_wire::check_in::CheckInDecision>,
    /// What the delete leaves behind that the person is told, one entry per
    /// remainder (FIX HARD-DELETE-ANSWER-SILENT-ON-OWED-SWEEP).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remaining: Vec<RemainingNotice>,
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
