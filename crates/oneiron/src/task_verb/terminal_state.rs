use crate::consult_ladder::{LadderTerminalDisposition, LadderTerminalState};
use crate::context_board::TaskBoardStatus;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::consult_payload::ConsultPayloadRef;
use super::wire_encode::{canonical_bytes, task_terminal_record_value};

/// Terminal outcomes for ANY executor. `Expired` (deadline passed) and
/// `Abandoned` (lease reclaimed / executor gone) stay distinct causes even
/// though both project onto the failed board lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskTerminalDisposition {
    Completed,
    Rejected,
    Failed,
    Expired,
    Abandoned,
    Cancelled,
}

impl TaskTerminalDisposition {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Abandoned => "abandoned",
            Self::Cancelled => "cancelled",
        }
    }

    pub(super) fn from_token(token: &str) -> Result<Self> {
        match token {
            "completed" => Ok(Self::Completed),
            "rejected" => Ok(Self::Rejected),
            "failed" => Ok(Self::Failed),
            "expired" => Ok(Self::Expired),
            "abandoned" => Ok(Self::Abandoned),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(Error::InvalidTaskBody("tasks.terminal.disposition")),
        }
    }
}

/// Maps a terminal disposition onto the existing five-value board axis.
/// `Expired` and `Abandoned` both read as failed; the exact cause survives
/// BESIDE the status, never folded into it.
#[must_use]
pub const fn board_status_for_disposition(disposition: TaskTerminalDisposition) -> TaskBoardStatus {
    match disposition {
        TaskTerminalDisposition::Completed => TaskBoardStatus::Done,
        TaskTerminalDisposition::Rejected
        | TaskTerminalDisposition::Failed
        | TaskTerminalDisposition::Expired
        | TaskTerminalDisposition::Abandoned
        | TaskTerminalDisposition::Cancelled => TaskBoardStatus::Failed,
    }
}

/// The small typed summary a terminal consult keeps for board projection and
/// resume logic. Evidence and abstention are mutually exclusive BY
/// CONSTRUCTION — there is no runtime field convention to violate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsultResultSummary {
    Answer {
        evidence_refs: Vec<ConsultPayloadRef>,
    },
    Abstained {
        reason_ref: ConsultPayloadRef,
    },
}

/// Board-projected consult outcome: canonical short refs, never result bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsultResultPresence {
    Answer {
        result_ref: String,
        evidence_ref_count: usize,
    },
    Abstained {
        result_ref: String,
        reason_ref: String,
    },
}

/// The ONE terminal register value. Disposition, `result_ref`, summary, and
/// `finished_at` merge atomically as this single value — never as independently
/// mergeable fields, which could otherwise converge to a record no replica ever
/// wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTerminalRecord {
    pub disposition: TaskTerminalDisposition,
    /// Compatibility decoders may read `None` from an old row; every new
    /// terminal transition writes `Some`.
    pub result_ref: Option<EntityId>,
    pub summary: Option<ConsultResultSummary>,
    pub finished_at: u64,
    /// ONE-1888 ladder projection. `Approved` and `Overridden` both persist as
    /// `Completed`, and `Countered` as `Rejected`, so the finer ladder
    /// vocabulary rides HERE — inside the same single register, never as an
    /// independently mergeable field. Absent on every ONE-1699 row.
    pub ladder: Option<LadderTerminalDisposition>,
    /// Set exactly on a `Countered` ladder outcome: the NEW task minted in the
    /// same transaction that terminalized this one.
    pub counter_task_ref: Option<EntityId>,
}

/// CRDT merge for the one terminal register. Later `finished_at` wins; a
/// SUBSTANTIVE terminal (`Completed` or `Rejected` — someone actually decided)
/// dominates an expiry-like one (`Expired`/`Abandoned` — nobody did) on an
/// exact tie; any remaining tie falls to canonical serialized bytes so both
/// replicas pick the same winner in either merge order.
#[must_use]
pub fn merge_task_terminal_register(
    left: Option<&TaskTerminalRecord>,
    right: Option<&TaskTerminalRecord>,
) -> Option<TaskTerminalRecord> {
    match (left, right) {
        (None, None) => None,
        (Some(only), None) | (None, Some(only)) => Some(only.clone()),
        (Some(left), Some(right)) => Some(
            if terminal_register_order(left) >= terminal_register_order(right) {
                left.clone()
            } else {
                right.clone()
            },
        ),
    }
}

/// A decision beats a timeout at the same instant. `Completed` and `Rejected`
/// are both decisions — an owner's "no" that landed exactly on the deadline is
/// no less an answer than a "yes" — so both outrank the expiry sweep, and the
/// two of them fall to canonical bytes against each other.
pub(super) fn terminal_register_order(record: &TaskTerminalRecord) -> (u64, u8, Vec<u8>) {
    let substantive = matches!(
        record.disposition,
        TaskTerminalDisposition::Completed | TaskTerminalDisposition::Rejected
    );
    (
        record.finished_at,
        u8::from(substantive),
        canonical_bytes(&task_terminal_record_value(record)),
    )
}

/// Execution state of one TASK intent on this replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskExecutionState {
    Queued,
    Working {
        started_at: u64,
    },
    /// Reserved for ONE-1888's consent-required ladder state.
    Interrupted {
        /// ONE-1888: the settled LADDER state, when the ladder terminal
        /// deferred to a follow-on assignee instead of settling the TASK
        /// (`LadderTerminalDisposition::defers_to_follow_on`).
        ///
        /// The ONE-1699 axis deliberately stays `interrupted` — the board
        /// keeps the case live and [`Self::terminal`] stays `None` — while the
        /// ladder half of the SAME single register remembers that this ladder
        /// is settled. Without it the deferring projection is not injective:
        /// an escalated terminal and an ordinary interruption persist as the
        /// same value, and a compare-and-set against the second would move the
        /// first. Absent on every ordinary interruption.
        ladder: Option<LadderTerminalState>,
    },
    Terminal(TaskTerminalRecord),
}

impl TaskExecutionState {
    /// The terminal record, if this replica has settled the task.
    #[must_use]
    pub const fn terminal(&self) -> Option<&TaskTerminalRecord> {
        match self {
            Self::Terminal(record) => Some(record),
            Self::Queued | Self::Working { .. } | Self::Interrupted { .. } => None,
        }
    }

    /// The settled LADDER state this row carries, on either axis.
    ///
    /// A ladder is settled both when the TASK settled with it and when the
    /// ladder terminal deferred to a follow-on and left the TASK live. Both
    /// are immutable, so every ladder write door asks this one question rather
    /// than re-deriving the two cases.
    pub(super) fn settled_ladder_disposition(&self) -> Option<LadderTerminalDisposition> {
        match self {
            Self::Terminal(record) => record.ladder,
            Self::Interrupted { ladder } => ladder.map(|state| state.disposition),
            Self::Queued | Self::Working { .. } => None,
        }
    }
}
