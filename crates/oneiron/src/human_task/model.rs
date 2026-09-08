//! Human TASK follow-up shared types, stage machine and timing bounds.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Schema version of the persisted follow-up cursor.
pub const HUMAN_TASK_FOLLOWUP_SCHEMA_VERSION: u8 = 1;

/// Repeatable follow-up stage tokens. The generation rides INSIDE the token
/// (ONE-1699's namespace is `(task_ref, stage)`), so an intentionally repeated
/// escalation gets a fresh idempotency key while a restart-driven replay of the
/// same generation collapses.
pub const HUMAN_FOLLOWUP_STAGE_REMINDER: &str = "human_reminder";

pub const HUMAN_FOLLOWUP_STAGE_DIGEST: &str = "human_digest";

pub const HUMAN_FOLLOWUP_STAGE_ESCALATION: &str = "human_escalation";

/// The one outbound verb follow-up uses. `remind`/`digest`/`escalate` are NOT
/// outbound verbs and are never minted: the connector manifest decides what a
/// channel can do, and follow-up is an ordinary send.
pub(super) const HUMAN_FOLLOWUP_VERB: &str = "send";

/// Quiet interval before the first direct nudge.
pub(super) const REMINDER_AFTER_SECONDS: u64 = 24 * 60 * 60;

/// Interval from the reminder to the open-loop digest entry.
const DIGEST_AFTER_SECONDS: u64 = 3 * 24 * 60 * 60;

/// Interval from the digest to escalation, and between escalations.
pub(super) const ESCALATION_AFTER_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Bound on one wake-pass follow-up drive.
pub(super) const FOLLOWUP_WAKE_LIMIT: usize = 64;

/// Page size for the bounded TASK walk in [`HumanTaskFollowupDriver::rebuild_cursors`].
pub(super) const REBUILD_PAGE: usize = 256;

/// Typed failure surface for native-human routing and response signalling.
///
/// A rejected assignee is refused in its own name — never degraded into a
/// Dreamer fallback, and never routed out through a marketplace pack.
#[derive(Debug, thiserror::Error)]
pub enum HumanTaskError {
    #[error(transparent)]
    Engine(#[from] Error),
    /// The assignee resolves to something that is not a PERSON.
    #[error("task assignee is not a person")]
    NotAPerson,
    /// A known person the vault has no native route to. Deliberately distinct
    /// from `NotAPerson`: the TASK fact stays legible either way, but only this
    /// one says "we know who, we just cannot reach them here".
    #[error("known person is not currently reachable through a native route")]
    NotNativelyReachable,
    /// The response did not come from the bound person, task, or step.
    #[error("human response does not match its wait binding")]
    UnboundResponse,
}

pub type HumanTaskResult<T> = std::result::Result<T, HumanTaskError>;

/// Where one human-assigned TASK's nudging has got to.
///
/// `Tracking` is the resting state; the three `*Due` stages are what the
/// driver has ALREADY done, and `Completed` closes the cursor. There is
/// deliberately no failure stage: a held, degraded or suppressed delivery is an
/// outbound receipt outcome, not a follow-up state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HumanFollowupStage {
    Tracking,
    ReminderDue,
    DigestDue,
    EscalationDue,
    Completed,
}

impl HumanFollowupStage {
    /// Stable storage token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tracking => "tracking",
            Self::ReminderDue => "reminder_due",
            Self::DigestDue => "digest_due",
            Self::EscalationDue => "escalation_due",
            Self::Completed => "completed",
        }
    }

    pub(super) fn from_token(token: &str) -> Result<Self> {
        match token {
            "tracking" => Ok(Self::Tracking),
            "reminder_due" => Ok(Self::ReminderDue),
            "digest_due" => Ok(Self::DigestDue),
            "escalation_due" => Ok(Self::EscalationDue),
            "completed" => Ok(Self::Completed),
            _ => Err(Error::CorruptedIndex("human_task.followup stage")),
        }
    }

    /// What running this stage's due work produces: the stage reached and the
    /// outbound family it notifies through. `Completed` and a not-yet-due
    /// `Tracking` produce nothing.
    pub(super) const fn advance(self) -> Option<(Self, &'static str, u64)> {
        match self {
            Self::Tracking => Some((
                Self::ReminderDue,
                HUMAN_FOLLOWUP_STAGE_REMINDER,
                DIGEST_AFTER_SECONDS,
            )),
            Self::ReminderDue => Some((
                Self::DigestDue,
                HUMAN_FOLLOWUP_STAGE_DIGEST,
                ESCALATION_AFTER_SECONDS,
            )),
            // Escalation repeats: the Dreamer keeps surfacing an unresolved
            // human loop rather than silently giving up on it.
            Self::DigestDue | Self::EscalationDue => Some((
                Self::EscalationDue,
                HUMAN_FOLLOWUP_STAGE_ESCALATION,
                ESCALATION_AFTER_SECONDS,
            )),
            Self::Completed => None,
        }
    }
}

/// The native route one reminder travels: OUR sending identity on a channel the
/// person is known to be reachable on, plus their address on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeHumanRoute {
    pub person_ref: EntityId,
    /// OUR sending identity on this channel — the auditable half of the route.
    pub channel_identity_ref: EntityId,
    pub channel: String,
    /// The person's address on that channel, straight off the contact row.
    pub target: String,
}

/// Durable, rebuildable follow-up cursor for one human-assigned TASK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanTaskFollowupRecord {
    pub schema_version: u8,
    pub task_ref: EntityId,
    pub assignee_ref: EntityId,
    pub stage: HumanFollowupStage,
    pub stage_generation: u32,
    pub next_due_at: Option<u64>,
    pub reminders_sent: u32,
    pub last_receipt_ref: Option<String>,
    pub completed_at: Option<u64>,
}

/// Device-local binding from one human-assigned TASK to the trap parked on the
/// person's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanTaskWaitBinding {
    pub task_ref: EntityId,
    pub responder_ref: EntityId,
    pub trap_claim_id: EntityId,
    pub step_hash: [u8; 32],
    /// The persisted authorization bit. Release writes an inactive tombstone so
    /// an old in-memory handle cannot revive a consumed wait.
    pub is_active: bool,
}

/// One identity-stamped inbound response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanResponseSignal {
    pub task_ref: EntityId,
    pub responder_ref: EntityId,
    pub surface_event_ref: EntityId,
    pub occurred_at: u64,
}

/// What one due follow-up actually scheduled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanFollowupDispatch {
    pub task_ref: EntityId,
    pub stage: HumanFollowupStage,
    /// `(task_ref, stage)` namespace token, generation included.
    pub stage_token: String,
    pub intent_ref: String,
    /// Outbound schedule outcome, verbatim from the OF-327 receipt.
    pub outcome: String,
}
