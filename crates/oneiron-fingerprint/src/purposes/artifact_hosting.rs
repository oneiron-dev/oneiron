//! Purposes of artifact hosting (`crates/oneiron/src/artifact_hosting`).
//!
//! Each legacy purpose here is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {}

legacy_purposes! {
    /// A hosted artifact's publication on one channel
    /// (`artifact_hosting::publication_sync::publication_entity_id`). Parts: the channel's key
    /// byte, the artifact.
    PUBLICATION = (Blake3, HashedFirst, "oneiron.artifact.publication.v1");
}
