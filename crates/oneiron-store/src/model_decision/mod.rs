//! Model-independent typed decision vocabulary and pure policy values.

mod answer_actor;
pub use answer_actor::AnswerActor;
pub mod catalogue;
pub mod codec;
mod policy;
mod provider;
pub mod questions;
mod roles;
mod slides_policy;
mod state;
mod types;

pub use policy::*;
pub use provider::validate_pin;
pub use provider::{
    MAX_DECISION_STATE_BYTES, MAX_SCORE_LEVEL_BYTES, PairedAnswer, ProviderCapability,
    ProviderDecision, SCORE_LEVELS_FIELD, level_score, score_levels_in,
};
pub use roles::*;
pub use slides_policy::*;
pub use state::{cut_text, fit_reserve_state, fit_state, fit_state_with_budget};
pub use types::*;
pub use types::{invalid, paired_valid};
