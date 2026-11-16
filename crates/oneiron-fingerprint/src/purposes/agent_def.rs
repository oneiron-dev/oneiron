//! Purposes of agent definitions and the fixed base agents (`oneiron-store`'s `base_agent`
//! and `agent_birth_identity`).
//!
//! Each legacy purpose here is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {}

legacy_purposes! {
    /// The Dreamer's fixed MACHINE principal row, which every replica seeds identically
    /// (`base_agent::dreamer_actor_id`). No parts.
    DREAMER_AUTHORITY = (Blake3, HashedFirst, "oneiron.dreamer.authority.v1");

    /// The Coach's fixed MACHINE principal row, seeded like the Dreamer's
    /// (`base_agent::coach_actor_id`). No parts.
    COACH_AUTHORITY = (Blake3, HashedFirst, "oneiron.coach.authority.v1");

    /// The ASSET that carries a birthed agent's captured source; export and archive
    /// derive it again to find it (`agent_birth_identity::birth_source_id`). Parts: the
    /// child agent.
    BIRTH_SOURCE = (Blake3, HashedFirst, "oneiron.agent-birth-source.v1");
}
