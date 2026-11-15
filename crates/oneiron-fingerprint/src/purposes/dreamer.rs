//! Purposes of the Dreamer (`crates/oneiron/src/dreamer_consolidation`, `dreamer_runner`,
//! `dreamer_wake`).

purposes! {}

legacy_purposes! {
    /// A Coach site-skill candidate's fingerprint, the key of its seen marker
    /// (`dreamer_runner::maintenance::site_skills::distill::digest`): plain BLAKE3, the tag's
    /// bytes, then each part as its u64 big-endian length and its bytes. Parts: the distill
    /// version (u32 big-endian), the site, and the candidate's JSON body. It differs from
    /// `browser_library::PROGRAM_CANDIDATE`, so the two facets never share a seen marker.
    SITE_SKILL_DISTILL = (Blake3, HashedFirst, "oneiron:coach-site-skill-distill:v1");
}
