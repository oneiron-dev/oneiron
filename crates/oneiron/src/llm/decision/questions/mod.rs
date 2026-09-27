//! Versioned questions, scoped answer receipts, and bound outcome labels.

mod arrival;
mod graph_ask;
mod outcomes;
mod records;
mod store;
mod task_ask;

pub(crate) use arrival::project_arrivals_in_txn;
pub use graph_ask::{
    GraphAnswerer, GraphAskResult, GraphContextSource, GraphPrediction, GraphTypeSelection,
    GraphUnitContext, run_graph_ask, run_graph_ask_by_type, select_graph_units_by_type,
};
pub use outcomes::{calibration_pairs, project_bound_outcomes};
pub use records::*;
pub use store::{create_question, edit_question, pause_question, read_question};
pub(crate) use task_ask::{TaskAnswerBinding, bind_task_answer_in_txn, validate_task_answer_unit};

#[cfg(test)]
mod graph_ask_tests;
