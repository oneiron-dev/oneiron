//! Training compute choices, authorization provenance and run states.
use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_records::skill_optimize::training_choice::{
    ComputeChoice, TrainingAuthorizationSource, TrainingState,
};

#[doc(hidden)]
pub use oneiron_verb_wire::skill_optimize::training_choice::SwapChoice;
