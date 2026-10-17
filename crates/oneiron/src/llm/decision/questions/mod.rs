//! Versioned questions, scoped answer receipts, and bound outcome labels.

mod arrival;
mod graph_ask;
mod health_ask;
mod outcomes;
mod recipe;
mod records;
mod refresh;
mod standing;
mod store;
mod task_ask;

#[cfg(test)]
mod standing_tests;

pub(crate) use arrival::{project_arrivals_in_txn, unit_watched_in_txn};
pub(crate) use graph_ask::validate_decision as validate_unit_decision;
pub use graph_ask::{
    GraphAnswerer, GraphAskFailure, GraphAskReceipts, GraphAskResult, GraphContextSource,
    GraphDecision, GraphPrediction, GraphTypeSelection, GraphUnitContext, run_graph_ask,
    run_graph_ask_by_type, run_graph_ask_receipted, select_graph_units_by_type,
};
pub use health_ask::{
    HEALTH_CROSSING_PREDICATE, HEALTH_OUTCOME_PREDICATE, HealthAnswer, HealthBound,
};
pub use outcomes::{calibration_pairs, person_changed_pairs, project_bound_outcomes};
pub(crate) use recipe::run_graph_question_with_proposals;
pub use recipe::{GraphQuestionInput, GraphQuestionRef, run_graph_question};
pub use records::*;
pub(crate) use refresh::principal_actor;
pub use refresh::{
    RefreshBatch, RefreshFailure, answer_records, refresh_due_questions,
    refresh_due_questions_by_role, refresh_due_questions_with, refresh_question,
    standing_ask_route,
};
pub use standing::{StandingAnswer, backfill_standing_answer, standing_source_frontier};
pub use store::{create_question, edit_question, pause_question, read_question};
pub(crate) use task_ask::{TaskAnswerBinding, bind_task_answer_in_txn, validate_task_answer_unit};

#[cfg(test)]
mod graph_ask_tests;
