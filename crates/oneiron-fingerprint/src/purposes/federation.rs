//! Purposes of federation (`crates/oneiron/src/federation`).
//!
//! Each legacy purpose here is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {}

legacy_purposes! {
    /// The CODE anchor a served store has in a project (FIX 7608, 9328;
    /// `federation::git_push::anchor`). Parts: the served store's object identity, the project.
    SERVED_REPO_ANCHOR = (Blake3, HashedFirst, "oneiron:served-repo-anchor:v1");

    /// A vault's shared-ruling anchor (`federation::rulings::ruling_anchor_id`). Parts: the vault
    /// id (big-endian).
    SHARED_RULING_ANCHOR = (Blake3, HashedFirst, "oneiron.shared-ruling.anchor.v1");
}
