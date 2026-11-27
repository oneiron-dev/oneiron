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

/// [`RemainingNotice::code`] of old backups a delete leaves (D, when the delete's reason keeps backups).
pub const REMAINING_BACKUPS_BEFORE_DELETE: &str = "backups_before_delete";

/// [`RemainingNotice::text`] beside [`REMAINING_BACKUPS_BEFORE_DELETE`] (D, when the delete's reason keeps backups).
pub const REMAINING_BACKUPS_BEFORE_DELETE_TEXT: &str =
    "Backups made before this delete still hold it, and restoring one brings it back.";

/// [`RemainingNotice::code`] of old backups an erase leaves (P and R, always).
pub const REMAINING_BACKUPS_BEFORE_ERASE: &str = "backups_before_erase";

/// [`RemainingNotice::text`] beside [`REMAINING_BACKUPS_BEFORE_ERASE`] (P and R, always).
pub const REMAINING_BACKUPS_BEFORE_ERASE_TEXT: &str = "Backups made before this erase may still hold parts of it, and restoring one can bring those parts back.";

/// [`RemainingNotice::code`] of disk space freed, not overwritten (P and R, always; plain or sealed text).
pub const REMAINING_DISK_NOT_OVERWRITTEN: &str = "disk_not_overwritten";

/// [`RemainingNotice::text`] beside [`REMAINING_DISK_NOT_OVERWRITTEN`] (P and R on a plain vault, always).
pub const REMAINING_DISK_NOT_OVERWRITTEN_PLAIN_TEXT: &str = "The disk space and files it used are freed, not overwritten. Someone who copies this vault's files before that space is reused could still read it.";

/// [`RemainingNotice::text`] beside [`REMAINING_DISK_NOT_OVERWRITTEN`] (P and R on a sealed vault, always).
pub const REMAINING_DISK_NOT_OVERWRITTEN_SEALED_TEXT: &str = "The disk space it used is freed, not overwritten, and stays encrypted with this vault's key until it is reused.";

/// [`RemainingNotice::code`] of body files still in use after the collect pass (D and R's first, when files are left).
pub const REMAINING_FILES_STILL_IN_USE: &str = "files_still_in_use";

/// [`RemainingNotice::text`] beside [`REMAINING_FILES_STILL_IN_USE`] for `n` files left (D and R's first, when files are left).
#[must_use]
pub fn files_still_in_use_text(n: usize) -> String {
    format!("{n} of its files are still in use and will be removed later.")
}

/// [`RemainingNotice::code`] of exports an erase does not reach (P and R, always).
pub const REMAINING_EXPORTS_BEFORE_ERASE: &str = "exports_before_erase";

/// [`RemainingNotice::text`] beside [`REMAINING_EXPORTS_BEFORE_ERASE`] (P and R, always).
pub const REMAINING_EXPORTS_BEFORE_ERASE_TEXT: &str =
    "Exports made before this erase still hold it. This erase does not reach them.";

/// [`RemainingNotice::code`] of devices and peers an erase reaches only later (P and R, when the vault syncs or the record was shared).
pub const REMAINING_DEVICES_AND_PEERS: &str = "devices_and_peers";

/// [`RemainingNotice::text`] beside [`REMAINING_DEVICES_AND_PEERS`] (P and R, when the vault syncs or the record was shared).
pub const REMAINING_DEVICES_AND_PEERS_TEXT: &str = "Your other devices remove it when they next sync. A device that stays offline keeps it until then. People it was shared with are asked to delete their copy, and may not.";

/// [`RemainingNotice::code`] of provider copies an erase cannot call back (P and R, when the vault's settings allow a provider model).
pub const REMAINING_MODEL_PROVIDERS: &str = "model_providers";

/// [`RemainingNotice::text`] beside [`REMAINING_MODEL_PROVIDERS`] (P and R, when the vault's settings allow a provider model).
pub const REMAINING_MODEL_PROVIDERS_TEXT: &str = "Anything already sent to an AI model provider stays with that provider under its own retention. Oneiron cannot call it back.";

/// [`RemainingNotice::code`] of a legal hold's sealed copy an erase leaves (P and R, when a hold covers the record).
pub const REMAINING_LEGAL_HOLD_COPY: &str = "legal_hold_copy";

/// [`RemainingNotice::text`] beside [`REMAINING_LEGAL_HOLD_COPY`] (P and R, when a hold covers the record).
pub const REMAINING_LEGAL_HOLD_COPY_TEXT: &str = "A legal hold keeps a sealed copy of this record outside your vault until the hold is lifted. This erase does not remove that copy.";

/// The [`DeleteReceipt::remaining`] of a delete that queued `sweep_key`: the
/// history-sweep entry when a sweep was queued, then the old-backups entry
/// when `backups_hold_it`, then the still-in-use-files entry when `files_left`
/// is nonzero. The receipt writer returns an empty key when no sweep was
/// queued, and callers wrap it in `Some`, so only a non-empty key counts.
#[must_use]
pub fn remaining_after_delete(
    sweep_key: Option<&[u8]>,
    backups_hold_it: bool,
    files_left: usize,
) -> Vec<RemainingNotice> {
    let mut remaining = Vec::new();
    if let Some(key) = sweep_key {
        if !key.is_empty() {
            remaining.push(RemainingNotice {
                code: REMAINING_HISTORY_SWEEP.to_owned(),
                text: REMAINING_HISTORY_SWEEP_TEXT.to_owned(),
            });
        }
    }
    if backups_hold_it {
        remaining.push(RemainingNotice {
            code: REMAINING_BACKUPS_BEFORE_DELETE.to_owned(),
            text: REMAINING_BACKUPS_BEFORE_DELETE_TEXT.to_owned(),
        });
    }
    if files_left > 0 {
        remaining.push(RemainingNotice {
            code: REMAINING_FILES_STILL_IN_USE.to_owned(),
            text: files_still_in_use_text(files_left),
        });
    }
    remaining
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
