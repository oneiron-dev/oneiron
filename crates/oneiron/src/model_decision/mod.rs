//! Model-independent typed decision vocabulary and pure policy values.

mod answer_actor;
pub use answer_actor::AnswerActor;
pub(crate) mod codec;
pub mod catalogue;
pub mod questions;
mod policy;
mod provider;
mod roles;
mod slides_policy;
mod state;
mod types;

pub use policy::*;
pub use provider::{
    MAX_DECISION_STATE_BYTES, MAX_SCORE_LEVEL_BYTES, SCORE_LEVELS_FIELD,
    PairedAnswer, ProviderCapability, ProviderDecision, level_score, score_levels_in,
};
pub(crate) use provider::validate_pin;
pub use roles::*;
pub use slides_policy::*;
pub use state::{cut_text, fit_reserve_state, fit_state};
pub use types::*;
pub(crate) use types::{invalid, paired_valid};
