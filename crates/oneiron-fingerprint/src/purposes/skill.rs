//! Purposes of a skill's canonical identity (`oneiron-store` `write_envelope::skill_record`).
//!
//! The canonical skill tree hash is a skill's content identity (ARCH-0053 section 7,
//! ONE-1735). Every skill record stores it (`SkillRecord.content_hash`), a hub index
//! declares it per skill, a fetch compares a Git subtree or a package with the pinned or
//! declared one, an import compares it with a source-tree proof, and the hub cross-check
//! compares it with a hub's declared hash. So it keeps its bytes (K, PLAN-UC-04 6.3).

purposes! {}

legacy_purposes! {
    /// The canonical skill tree hash (`identity::canonical_skill_tree_hash`). SHA-256: the
    /// tag, NUL-terminated and with no length before it; the file count as a u64-BE; then
    /// per file in byte order of its path: the path's length as a u64-BE and its bytes,
    /// the content's length as a u64-BE and its bytes. Written as 64 lowercase hex digits.
    TREE_HASH = (Sha256, HashedFirst, "oneiron.skill.tree.v1\0");
}
