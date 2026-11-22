//! Purposes of the bench's retrieval ruler arms (`crates/oneiron-bench/src/scorecard/`).
//!
//! None of these is stored: each names a value of one throwaway bench run or of its card.

purposes! {
    /// The world-scoped arm's partition draw (`scorecard/world_scoped/partition.rs`,
    /// `is_hidden`). Parts: the partition seed as 4 little-endian bytes, then the pack
    /// record id. Its first 8 bytes, read big-endian, modulo 1000, below the hidden share
    /// put the record in the second world.
    WORLD_SCOPED_PARTITION = "oneiron.bench_scorecard.world_scoped_partition.v1";

    /// The id of a world-scoped fixture claim (`scorecard/world_scoped/fixture.rs`,
    /// `derived_id`): its first 16 bytes. Parts: the pack record id.
    WORLD_SCOPED_CLAIM_ID = "oneiron.bench_scorecard.world_scoped_claim_id.v1";

    /// The id of a world-scoped fixture claim's subject (`scorecard/world_scoped/fixture.rs`,
    /// `derived_id`): its first 16 bytes. Parts: the pack record id.
    WORLD_SCOPED_SUBJECT_ID = "oneiron.bench_scorecard.world_scoped_subject_id.v1";

    /// The world-scoped arm's params digest, the card's `params_digest`
    /// (`scorecard/world_scoped/mod.rs`, `Settings::digest`). Parts: the retriever name,
    /// the hidden share per mille as a u64, the partition seed as a u64.
    WORLD_SCOPED_PARAMS = "oneiron.bench_scorecard.world_scoped_params.v1";
}

legacy_purposes! {}
