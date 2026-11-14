//! Moved from `crates/oneiron/src/receipt/questions.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::receipt::questions::AI_VERDICT_DEADLINE_MS;
pub use oneiron_verb_wire::receipt::questions::GRAPH_ASK_UNIT_DEADLINE_MS;
pub use oneiron_verb_wire::receipt::questions::GraphAdmitRequest;
pub use oneiron_verb_wire::receipt::questions::GraphAskDeclined;
pub use oneiron_verb_wire::receipt::questions::GraphAskSelection;
pub use oneiron_verb_wire::receipt::questions::QuestionAnswersRequest;
pub use oneiron_verb_wire::receipt::questions::QuestionBackfillRequest;
pub use oneiron_verb_wire::receipt::questions::QuestionOutcomeWindowsRequest;
pub use oneiron_verb_wire::receipt::questions::QuestionOutcomes;
pub use oneiron_verb_wire::receipt::questions::QuestionOutcomesProjectRequest;
pub use oneiron_verb_wire::receipt::questions::QuestionOutcomesProjected;
pub use oneiron_verb_wire::receipt::questions::QuestionOutcomesRequest;
pub use oneiron_verb_wire::receipt::questions::QuestionPauseRequest;
pub use oneiron_verb_wire::receipt::questions::QuestionReadRequest;
pub use oneiron_verb_wire::receipt::questions::QuestionRefreshRequest;
pub use oneiron_verb_wire::receipt::questions::QuestionScheduleRequest;
pub use oneiron_verb_wire::receipt::questions::standing_admit::QuestionAdmitRequest;
pub use oneiron_verb_wire::receipt::questions::standing_admit::QuestionPrepareRequest;
pub use oneiron_verb_wire::receipt::questions::standing_admit::QuestionPrepared;
pub use oneiron_verb_wire::receipt::questions::standing_admit::QuestionPreparedSource;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;

/// `vault.questions.pause`'s answer: the question and the state it now has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuestionPaused {
    pub id: EntityId,
    pub paused: bool,
}
