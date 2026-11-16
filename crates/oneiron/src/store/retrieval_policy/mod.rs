//! Stored retrieval policy actions, trajectories and learned evidence.

mod posterior;
pub use posterior::RetrievalPolicyPosterior;

#[doc(hidden)]
pub use oneiron_verb_wire::store::retrieval_policy::{
    RetrievalPolicyAction, RetrievalPolicyDecision, RetrievalPolicyEnvelope,
    RetrievalPolicyIdentity, RetrievalPolicyTier, RetrievalPolicyTrace,
};
