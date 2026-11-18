//! K-proof door for self-heal digests that existing rows, keys and findings hold.
//! Compiled only under `oneiron_test_support`; never part of the engine API.
#![cfg(oneiron_test_support)]

use crate::EntityId;
use crate::self_heal::tiered::{DetectorPolicy, ProposedTier};
use crate::self_heal::{
    blocked_reports, consent_depth, detector_pass, distillation, healer_host, issue_evidence,
    tier1_source, tiered,
};
use crate::store::{RetrievalRunId, RetrievalRunRecord};

/// A retrieval run id with exactly `bytes`.
#[must_use]
pub fn retrieval_run_id(bytes: [u8; 16]) -> RetrievalRunId {
    RetrievalRunId::from_bytes(bytes)
}

/// A blocked report's replay hash over its receipt's content.
#[must_use]
pub fn blocked_report_content(content: &str) -> [u8; 32] {
    blocked_reports::blocked_content_hash_for_test(content)
}

/// A consent-depth finding's replay hash.
#[must_use]
pub fn consent_depth_digest(
    payload_digests: &[[u8; 32]],
    snapshot_at: u64,
    threshold: u64,
) -> [u8; 32] {
    consent_depth::depth_content_hash_for_test(payload_digests, snapshot_at, threshold)
}

/// A T2 window's key once a T2a corpus with `revision` is in force.
#[must_use]
pub fn centroid_window(key: &[u8; 32], revision: &[u8; 32]) -> [u8; 32] {
    detector_pass::centroid_revision_key_for_test(key, revision)
}

/// The retrieval-window digest a minted T2's example window is compared by.
///
/// # Errors
/// A run record that does not encode.
pub fn replays_digest(runs: &[RetrievalRunRecord]) -> crate::Result<[u8; 32]> {
    distillation::replays_digest_for_test(runs)
}

/// The digest half of a healer run receipt's key.
#[must_use]
pub fn healer_run(run: &str) -> [u8; 32] {
    healer_host::run_digest_for_test(run)
}

/// An observed window: each run's id, replay hash and start, then the coordinate's content
/// hash and run ref.
///
/// # Errors
/// A run record that does not encode.
pub fn observed_window(
    runs: &[RetrievalRunRecord],
) -> crate::Result<(Vec<([u8; 16], [u8; 32], u64)>, [u8; 32], Option<String>)> {
    issue_evidence::observed_window_for_test(runs)
}

/// A tier-1 source row's pin.
///
/// # Errors
/// A value that does not encode.
pub fn tier1_source_digest<T: serde::Serialize>(value: &T) -> crate::Result<[u8; 32]> {
    tier1_source::digest_for_test(value)
}

/// The digest a detector question past the text room is keyed by.
#[must_use]
pub fn detector_wording(prompt: &str, rubric: &str) -> [u8; 32] {
    tiered::wording_digest_for_test(prompt, rubric)
}

/// A finding's recipe revision.
#[must_use]
pub fn finding_recipe(
    policy: &DetectorPolicy,
    tier: ProposedTier,
    positive: &[EntityId],
    negative: &[EntityId],
    corpus: Option<&[u8; 32]>,
) -> [u8; 32] {
    tiered::recipe_revision_for_test(policy, tier, (positive, negative), corpus)
}

/// A model finding's replay hash over `runs` and its sorted run evidence.
///
/// # Errors
/// A run record that does not encode, or a run id that is not an entity id.
pub fn window_evidence(runs: &[RetrievalRunRecord]) -> crate::Result<([u8; 32], Vec<EntityId>)> {
    tiered::window_evidence_for_test(runs)
}

/// A window's context digest over the states asked in order.
#[must_use]
pub fn window_context(states: &[&[u8]]) -> [u8; 32] {
    tiered::window_context_for_test(states)
}
