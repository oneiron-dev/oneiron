//! Purposes of claim clustering (`oneiron::cluster`, `crates/oneiron/src/memory/claim_cluster.rs`).

purposes! {}

legacy_purposes! {
    /// A claim cohort's id (`memory::claim_cluster::cohort_id`, `CohortId`). Plain BLAKE3,
    /// the tag first; the partition's encoded subject and its predicate root, each a u64
    /// little-endian length and its bytes; the world and the facet, each `1` and the id's 16
    /// bytes, or `0`; the member count as a u64 little-endian; each member id's 16 bytes,
    /// ascending. Sent as `cohort_id` in the clustering door's answer.
    CLAIM_COHORT = (Blake3, HashedFirst, "oneiron:claim-cohort:v1");
}
