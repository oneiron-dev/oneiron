//! Moved from `crates/oneiron/src/store/retrieval_policy/posterior.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub(crate) use oneiron_store::retrieval_policy::posterior::*;
use oneiron_verb_wire::store::retrieval_policy::RetrievalPolicyAction;
use oneiron_verb_wire::store::retrieval_policy::RetrievalPolicyIdentity;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyObservation {
    pub identity: RetrievalPolicyIdentity,
    pub context: [f64; 16],
    pub action: RetrievalPolicyAction,
    pub reward: f64,
    pub weight: f64,
}
