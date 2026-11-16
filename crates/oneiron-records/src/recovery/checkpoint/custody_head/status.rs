//! Moved from `crates/oneiron/src/recovery/checkpoint/custody_head/status.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::custody_retirement_status::CUSTODY_RETIREMENT_COMPLETE;
use serde::Serialize;

/// The owner's status read's names for where a vault's custody publication
/// stands.
pub const CUSTODY_NONE: &str = "custody_none";

pub const CUSTODY_PUBLISHED: &str = "custody_published";

pub const CUSTODY_TARGET_PENDING: &str = "custody_target_pending";

pub const CUSTODY_ANCHOR_PENDING: &str = "custody_anchor_pending";

pub const CUSTODY_FENCED: &str = "custody_fenced";

/// Where a vault's key retirements stand against every required target and
/// the anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CustodyRetirement {
    /// [`CUSTODY_RETIREMENT_PENDING`] or [`CUSTODY_RETIREMENT_COMPLETE`].
    pub state: &'static str,
    /// Each step still owed, in order.
    pub pending: Vec<CustodyPendingStep>,
    /// The same steps as the CLI prints them:
    /// `custody_target_pending(<target id>)`.
    pub names: Vec<String>,
    /// Handed-off retirements not complete yet.
    pub outstanding: u64,
    /// The completion watermark: every retirement at or before this log
    /// position is complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_seq: Option<u64>,
    /// The required target set's revision.
    pub set_revision: u64,
    /// Every member of the required set.
    pub targets: Vec<CustodyTargetState>,
    /// "rollback not proven: no custody anchor configured" while no anchor
    /// is configured: a retirement completes on every required target's
    /// acknowledgement alone (CALLS CUSTODY_COMPLETION_NEEDS_ANCHOR,
    /// overruled Engine 10-20).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

/// One step a retirement still owes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CustodyPendingStep {
    /// [`CUSTODY_RETIREMENT_PENDING`] (an intent not handed off yet),
    /// [`CUSTODY_TARGET_PENDING`], [`CUSTODY_ANCHOR_PENDING`] or
    /// [`CUSTODY_REMOTE_RETIREMENT_PENDING`] (its `target_id` the holder
    /// machine).
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    /// The target's last sanitized reason: `offline`, `locked`, `denied`,
    /// `no_adapter`, `moved` or `failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

impl CustodyPendingStep {
    /// `state`, or `state(<target id>)` for a target's step.
    pub fn name(&self) -> String {
        match &self.target_id {
            Some(target) => format!("{}({target})", self.state),
            None => self.state.to_owned(),
        }
    }
}

/// One required target's acknowledgement state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CustodyTargetState {
    pub target_id: String,
    /// `folder`, `residence`, or a hosted kind.
    pub kind: &'static str,
    /// The log position its newest accepted acknowledgement names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acked_seq: Option<u64>,
    /// Why its last attempt did not ack, and when (unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_since: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
