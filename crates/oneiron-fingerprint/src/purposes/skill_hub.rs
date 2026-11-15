//! Purposes of the skill hub (`crates/oneiron/src/skill_hub`) and pack byte maps
//! (`registry::pack_byte_map`).
//!
//! Each legacy purpose below, except `REFINEMENT_RECEIPT_ASSET`, is an id by the legacy
//! material rule (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first,
//! then a u64 little-endian salt, then each part as its u64 little-endian length and its
//! bytes. The id is the first 16 bytes, with no version stamp; a reserved result takes the
//! next salt. Every one of these ids is a key that vaults already hold, so its bytes are
//! kept until the launch reset (PLAN-UC-04 stage 9).

purposes! {
    /// The vault-resident actor a hub's publisher runs hooks as
    /// (`skill_hub::pack_catalog::hooks::author`). Parts: hub, identity.
    PACK_HOOK_FOREIGN_PUBLISHER = "oneiron.pack-hook.foreign-publisher.v1";
}

legacy_purposes! {
    /// A pack's bundled skill (`skill_hub::pack_catalog::builtin` and `bundled_skills`). Parts:
    /// the skill's hash.
    PACK_SKILL = (Blake3, HashedFirst, "oneiron.pack-skill.v1");

    /// A pack hook's CODE entity (`skill_hub::pack_catalog::hooks::bindings`). Parts: the pack,
    /// the hook's name, the hook's body hash.
    PACK_HOOK = (Blake3, HashedFirst, "oneiron.pack-hook.v1");

    /// A pack hook's binding (`skill_hub::pack_catalog::hooks::bindings`). Parts: as
    /// `PACK_HOOK`.
    PACK_HOOK_BINDING = (Blake3, HashedFirst, "oneiron.pack-hook-binding.v1");

    /// The carrier ASSET of a pack byte map
    /// (`registry::pack_byte_map::persistence::carrier_id`). Parts: the map's hash.
    PACK_BYTE_MAP_CARRIER = (Blake3, HashedFirst, "oneiron:pack-byte-map-carrier:v1");

    /// A refinement receipt's ASSET, whose rows replicate to other machines
    /// (`skill_hub::refinement_custody`). Not the material rule: SHA-256 of the tag (with its
    /// final NUL byte), the candidate and the ruling, with no lengths; the id is the first 16
    /// bytes, and a reserved result is refused.
    REFINEMENT_RECEIPT_ASSET = (Sha256, HashedFirst, "oneiron.refinement-receipt.asset.v1\0");
}
