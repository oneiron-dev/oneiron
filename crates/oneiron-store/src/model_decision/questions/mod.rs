//! Graph-question recipe and outcome vocabulary.

mod recipe;
mod records;
mod route;

pub use recipe::{GraphQuestionInput, GraphQuestionRef};
pub use records::*;
pub use route::{DecisionRoute, RoutingPolicy};
