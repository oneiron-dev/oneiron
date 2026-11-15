//! Purposes of model decisions (`crates/oneiron/src/llm`).
//!
//! Each legacy purpose below is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {
    /// A question unit's ask (`llm::decision::questions::role_asks`). Parts: question,
    /// version (little-endian), principal, unit, source.
    QUESTION_UNIT_ASK = "oneiron:question-unit-ask:v1";
}

legacy_purposes! {
    /// A model pack change, from the change before it, so no two changes share one
    /// (`llm::model_pack::change::model_pack_change_ref`). Parts: the prior change, the active
    /// pack, its hash, the change time (big-endian).
    MODEL_PACK_CHANGE = (Blake3, HashedFirst, "oneiron:model-pack-change:v1");
}
