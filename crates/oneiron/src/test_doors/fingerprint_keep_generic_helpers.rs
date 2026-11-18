//! Door for `tests/fingerprint_keep_generic_helpers.rs` (PLAN-UC-04 stage 6.1a): the generic
//! digest helpers of the Coach's seen markers, the feedback triage work graph and the claim
//! conflict packet, which the engine computes in private code.

use oneiron_contracts::fingerprint::LegacyPurpose;

/// A Coach site-skill candidate's fingerprint over `parts`.
#[must_use]
pub fn site_skill_digest(parts: &[&[u8]]) -> [u8; 32] {
    crate::dreamer_runner::maintenance::site_skills::site_skill_digest_for_test(parts)
}

/// A candidate browser program's input fingerprint over `parts`.
#[must_use]
pub fn program_candidate_digest(parts: &[&[u8]]) -> [u8; 32] {
    crate::dreamer_runner::maintenance::browser_programs::program_candidate_digest_for_test(parts)
}

/// A feedback triage digest (lowercase hex) of `bytes` under `purpose`.
#[must_use]
pub fn triage_digest(purpose: LegacyPurpose, bytes: &[u8]) -> String {
    crate::feedback::triage_digest_for_test(purpose, bytes)
}

/// The content address of a claim conflict packet whose stripped bytes are `stripped`.
#[must_use]
pub fn claim_conflict_packet_digest(stripped: &[u8]) -> [u8; 32] {
    crate::memory::claim_conflict_packet_digest_for_test(stripped)
}
