//! Deterministic claim clustering is defined in the Dreamer layer.

pub use crate::memory::claim_cluster::{
    CLUSTER_COHESION_THRESHOLD, CLUSTER_ID_DOMAIN, ClaimCohort, ClusterAssignments, ClusterClaim,
    ClusterOptions, ClusterPartitionKey, CohortId, cluster_claims,
};
