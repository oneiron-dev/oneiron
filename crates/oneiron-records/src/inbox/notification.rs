//! Moved from `crates/oneiron/src/inbox/notification.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_state::AttemptState;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// What happened. A job's kind names its real outcome: a failed, cancelled
/// or abandoned job never reads as completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    JobCompleted,
    JobFailed,
    JobCancelled,
    JobAbandoned,
    Finding,
    EventReceived,
    ImportFinished,
    /// A built digest, including proactivity and weave; `source.result` names its id.
    Digest,
    /// A decision waiting on its recipient; `source.producer` names what
    /// asks, `source.result` the thing to answer and `source.detail`, when
    /// the producer gives it, why it asks.
    Ask,
    /// An agent's tighten of a world's settings applied, under its Grant or
    /// by a holder's yes (FIX 4480): `source.result` names the settings
    /// receipt, and the notice's one tap is its undo, the tapping holder's
    /// own act (`Vault::undo_world_privacy_change`).
    WorldPrivacyChanged,
    /// An agent's proposal of stricter settings for a world waits for a
    /// holder (FIX 4480): `source.result` names the proposal, and the
    /// notice's one tap cancels it (`Vault::answer_world_privacy_request`).
    WorldPrivacyProposed,
    /// The Coach's change to the owner's weave-digest rhythm or section
    /// order applied, under his Grant that names digest settings or by his
    /// accept (FIX 5495): `source.result` names the change, `source.detail`
    /// its reason, and the notice's one tap is its undo, the owner's own act
    /// (`Vault::undo_weave_digest_setting_change`).
    WeaveDigestSettingsChanged,
    /// The vault's Owner or an Admin walked into a private thread, reading
    /// from now on (FIX 6381, 6466): told to the thread's members alone.
    /// `source.result` names the thread's root and `source.detail` the op.
    ThreadWalkIn,
    /// A private thread's full history was opened (FIX 6383, 6466): the
    /// Owner's own, or the Owner's add of someone with full history from
    /// outside the thread. Told to the thread's members alone;
    /// `source.result` names the root and `source.detail` which it was.
    ThreadHistoryOpened,
    /// Someone asked to join a private thread (FIX 6384, 6466): a decision
    /// waiting on each member it is for, who approves or denies it.
    /// `source.result` names the root and `source.detail` the op.
    ThreadJoinRequested,
    /// The model pack the vault follows changed (FIX 5369): an install or
    /// removal, the owner's setting, a retirement's move or a revert.
    /// `source.result` names the change and `source.detail` the packs
    /// before and after with their changelog headlines; the notice's one
    /// tap, while the change is the vault's last and the pack before it can
    /// run, is its revert, the owner's own act
    /// (`Vault::revert_model_pack_change_as_owner`).
    ModelPackChanged,
}

impl NotificationKind {
    /// The kind a queue row's terminal state reports; `None` for a row that
    /// has not settled (queued, scheduled, paused, leased or landing).
    #[must_use]
    pub const fn for_job(state: AttemptState) -> Option<Self> {
        match state {
            AttemptState::Completed => Some(Self::JobCompleted),
            AttemptState::Failed => Some(Self::JobFailed),
            AttemptState::Cancelled => Some(Self::JobCancelled),
            AttemptState::Abandoned => Some(Self::JobAbandoned),
            _ => None,
        }
    }
}

/// Where a notification came from: its producer, the producer's stable event
/// identity, and the persisted job, run and result it reports on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationSource {
    pub producer: String,
    /// The producer's own identity for the event; with `producer` it derives
    /// the row id.
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// The producer's own words on the event, for the inbox to show as they
    /// are: a takeover ask's reason. Never part of the row's identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The stored NOTIFICATION body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationBody {
    pub kind: NotificationKind,
    pub source: NotificationSource,
    /// The records the event is about (the finding, the realized TASK, the
    /// imported conversation), as entity ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_refs: Vec<String>,
    /// The one caller it is for. Absent: every caller whose read admits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// When the event happened. The envelope's `learned_at` is when the row
    /// was last recorded, and moves on every mark; this never does.
    pub created_at: u64,
    /// The conversation whose request started the work, as its admission
    /// boundary stamped it. Never a conversation the work merely read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_conversation: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub seen_by: BTreeMap<String, bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub acked_by: BTreeMap<String, bool>,
}
