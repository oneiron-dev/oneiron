//! Read-only retrieval verbs and their model-facing observations.

use crate::claim::ScopedReadReceipt;
use crate::entity_id::EntityId;
use crate::retrieval_quality::RetrievalQualityReport;
use crate::store::RetrievalState;
use crate::temporal::TimeRange;
use crate::vault::RevisionRef;
use serde::{Deserialize, Serialize};

/// The sandbox grade's action waist. No action can mutate vault content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetrievalLoopAction {
    /// Replace the direct query signals, retaining the host's scope and blend.
    Search {
        query: String,
        #[serde(default)]
        vector: Option<Vec<f32>>,
        #[serde(default)]
        phonetic: Vec<String>,
    },
    /// One graph hop from known handles; an empty list uses the current set.
    Expand {
        anchors: Vec<EntityId>,
    },
    DrillUp {
        anchor: EntityId,
    },
    DrillDown {
        anchor: EntityId,
    },
    /// A superset of the current occurred-time window, never a scope change.
    WidenTemporal {
        start: u64,
        end: u64,
        sigma_secs: u64,
    },
    /// The only action that returns entity bodies, at their ranked frontiers.
    Read {
        handles: Vec<EntityId>,
    },
    /// Release the next loop-owned page of the current admitted ranking.
    Continue,
    Stop,
    Abstain,
}

impl RetrievalLoopAction {
    /// Stable local action tags for the shared pre-decision state bus.
    pub(super) const fn state_tag(&self) -> u8 {
        match self {
            Self::Search { .. } => 1,
            Self::Expand { .. } => 2,
            Self::DrillUp { .. } => 3,
            Self::DrillDown { .. } => 4,
            Self::WidenTemporal { .. } => 5,
            Self::Read { .. } => 6,
            Self::Continue => 9,
            Self::Stop => 7,
            Self::Abstain => 8,
        }
    }
}

/// A scored handle is not authority: every later action checks it again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalHandle {
    pub id: EntityId,
    pub score: f32,
    pub revision: Option<RevisionRef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetrievalEvidence {
    pub handle: RetrievalHandle,
    pub entity_type: u8,
    #[serde(serialize_with = "serialize_time_range")]
    pub occurred: TimeRange,
    pub learned_at: u64,
    /// Served JSON projection, including ordinary secret redaction.
    pub body: serde_json::Value,
}

fn serialize_time_range<S>(range: &TimeRange, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeStruct;

    let mut state = serializer.serialize_struct("TimeRange", 2)?;
    state.serialize_field("start", &range.start)?;
    state.serialize_field("end", &range.end)?;
    state.end()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalLoopStatus {
    Running,
    Stopped,
    Abstained,
    /// The host's turn allowance ended, not a claim of sufficient evidence.
    Yielded,
}

/// One REPL observation. Scores and receipt hints reach the planner every turn.
/// Bodies occur only in a Read observation; callers retain evidence they need.
#[derive(Debug, Clone, Serialize)]
pub struct RetrievalLoopObservation {
    pub status: RetrievalLoopStatus,
    pub iteration: u32,
    pub action: Option<RetrievalLoopAction>,
    pub state: RetrievalState,
    pub handles: Vec<RetrievalHandle>,
    pub evidence: Vec<RetrievalEvidence>,
    pub retrieval_quality: RetrievalQualityReport,
    /// The cumulative intersection, never wider than any preceding turn.
    pub narrowing: ScopedReadReceipt,
    /// The last action's own receipt, so repeated clamp hints remain visible.
    pub last_narrowing: ScopedReadReceipt,
    /// The caller's full requested ranking size, before page sizing.
    pub requested_limit: usize,
    /// The most handles one observation releases.
    pub effective_page_size: usize,
    /// Whether the request was larger than one page.
    pub limit_clamped: bool,
    /// Loop-owned raw offset of the next page; never a bearer credential.
    pub next_cursor: Option<u64>,
    /// Whether the current ranking has no unreleased handles.
    pub end: bool,
}
