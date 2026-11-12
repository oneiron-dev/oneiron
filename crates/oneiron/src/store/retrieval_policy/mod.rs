//! Stored retrieval policy actions, trajectories and learned evidence.

mod posterior;
pub use posterior::RetrievalPolicyPosterior;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::RetrievalState;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::store::retrieval_policy::{
    RetrievalPolicyAction, RetrievalPolicyDecision, RetrievalPolicyEnvelope,
    RetrievalPolicyIdentity, RetrievalPolicyTier, RetrievalPolicyTrace,
};
