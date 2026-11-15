//! Purposes of runtime hooks (`crates/oneiron/src/runtime_hooks`).
//!
//! Each legacy purpose here is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {}

legacy_purposes! {
    /// The claim a hook's Propose lands, one per run (`runtime_hooks::apply::proposal_id`).
    /// Parts: the run key.
    PROPOSAL = (Blake3, HashedFirst, "oneiron.hook-proposal.v1");

    /// A hook run's block (`runtime_hooks::runner::block_id`). Parts: the run key.
    BLOCK = (Blake3, HashedFirst, "oneiron.hook-block.v1");
}
