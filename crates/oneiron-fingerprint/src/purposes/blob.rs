//! Purposes of blob artifacts (`crates/oneiron/src/blob_artifact`).
//!
//! Each legacy purpose below is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {
    /// The producer an erased artifact names (`blob_artifact::erase`). No parts.
    ERASED_PRODUCER = "oneiron:erased-producer:v1";
}

legacy_purposes! {
    /// The ASSET a blob artifact version's bytes are stored as
    /// (`blob_artifact::versions::blob_artifact_asset_entity_id`). Parts: the content hash.
    ARTIFACT_ASSET = (Blake3, HashedFirst, "oneiron:blob-artifact-asset:v1");
}
