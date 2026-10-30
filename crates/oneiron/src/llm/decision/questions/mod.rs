//! Versioned questions, scoped answer receipts, and bound outcome labels.

mod answer_landing;
mod answer_scope;
mod answers;
mod arrival;
mod artifact_refresh;
mod ask_history;
mod backfill;
mod criteria;
mod graph_ask;
mod health_ask;
mod lifetime;
mod outcomes;
mod reader_authority;
mod recipe;
mod records;
mod refresh;
mod role_asks;
mod saved_reader;
mod standing;
mod store;
mod task_ask;
mod windows;

#[cfg(test)]
mod standing_tests;

pub use answer_scope::{
    answers_in_lane, calibration_pairs_in_lane, closed_outcome_windows_in_lane,
    outcome_labels_in_lane, project_bound_outcomes_in_lane, question_answers_in_lane,
    schedule_backfill_in_lane,
};
pub use answers::question_answers;
pub(crate) use arrival::{project_arrivals_in_txn, unit_watched_in_txn};
pub(crate) use artifact_refresh::artifact_unit_receipts;
pub use artifact_refresh::{
    ArtifactAskRecord, ArtifactAskStanding, ArtifactUnitReceipt, artifact_ask_records,
};
pub use artifact_refresh::{
    ArtifactRefreshBatch, ArtifactRefreshFailure, refresh_artifact_question_now,
    refresh_due_artifact_questions, refresh_due_artifact_questions_while,
};
pub(crate) use ask_history::erase_ask_history_actor_in_txn;
pub(crate) use ask_history::{
    StandingReask, record_failed_standing_reask, record_standing_reask_in_txn,
};
pub use backfill::schedule_backfill;
pub use graph_ask::validate_decision as validate_unit_decision;
pub use graph_ask::{
    GraphAnswerer, GraphAskFailure, GraphAskReceipts, GraphAskResult, GraphContextSource,
    GraphDecision, GraphPrediction, GraphTypeSelection, GraphUnitContext, run_graph_ask,
    run_graph_ask_by_type, run_graph_ask_receipted, select_graph_units_by_type,
};
pub(crate) use graph_ask::{trial_unit_context, trial_unit_context_in_txn};
pub use health_ask::{
    HEALTH_CROSSING_PREDICATE, HEALTH_OUTCOME_PREDICATE, HealthAnswer, HealthBound,
};
pub(crate) use lifetime::erase_question_source_in_txn;
pub(crate) use outcomes::calibration_pairs_in_txn;
pub use outcomes::{
    calibration_pairs, outcome_labels, person_changed_pairs, project_bound_outcomes,
};
pub(crate) use reader_authority::question_lane;
pub(crate) use recipe::run_graph_question_with_proposals;
pub use recipe::{GraphQuestionInput, GraphQuestionRef, run_graph_question};
pub use records::*;
pub(crate) use refresh::answer_records_in_txn;
pub use refresh::{
    RefreshBatch, RefreshFailure, answer_records, refresh_due_questions,
    refresh_due_questions_by_role, refresh_due_questions_by_role_while, refresh_due_questions_with,
    refresh_question, refresh_question_with, refresh_standing_question_with, standing_ask_route,
};
pub(crate) use refresh::{principal_actor, standing_asker_for_question};
pub(crate) use role_asks::keep_artifact_unit_ask;
pub use role_asks::{QuestionUnitAsk, question_unit_correlation};
pub(crate) use saved_reader::{wake_artifact_reads, wake_lane};
pub use standing::{StandingAnswer, backfill_standing_answer, standing_source_frontier};
pub(crate) use store::read_question_in_txn;
pub use store::{
    create_question, create_question_with_lane, edit_question, edit_question_with_lane,
    pause_question, read_question, read_question_schedule,
};
pub(crate) use task_ask::{TaskAnswerBinding, bind_task_answer_in_txn, validate_task_answer_unit};
pub use windows::{
    SILENCE_OUTCOME, close_due_outcome_windows, closed_outcome_windows,
    next_outcome_window_close_at,
};

#[cfg(test)]
mod graph_ask_tests;
