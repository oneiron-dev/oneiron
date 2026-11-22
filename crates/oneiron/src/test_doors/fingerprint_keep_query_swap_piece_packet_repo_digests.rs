//! Door for `tests/fingerprint_keep_query_swap_piece_packet_repo_digests.rs` (PLAN-UC-04
//! stage 6.4e): the sorted-JSON digests of a verdict memo's params, a saved query judge's
//! rubric, a training swap question, a triage packet and an owner's code request, and a
//! capsule request piece's ref, which the engine computes in private code.

use crate::compaction::output::OutputRef;
use crate::edit_distance::attribution::TriagePacket;
use crate::repo_mutation::RepoBundleFile;
use crate::saved_query::MatcherSpec;
use crate::training_pack::{ExportCheck, SwapExpectation};

/// The params hash a verdict memo's envelope holds for `matcher`, or `None` when the
/// matcher does not encode.
#[must_use]
pub fn derivation_params_hash(matcher: &MatcherSpec) -> Option<String> {
    crate::saved_query::derivation_params_hash_for_test(matcher)
}

/// The rubric hash a saved query judge keys its membership question by, or `None` when
/// the rubric does not encode.
#[must_use]
pub fn rubric_digest(rubric: &serde_json::Value) -> Option<[u8; 32]> {
    crate::saved_query::rubric_digest_for_test(rubric)
}

/// The digest a training swap question freezes for `expected` and `checks`, or `None`
/// when they do not encode.
#[must_use]
pub fn swap_question_digest(expected: &SwapExpectation, checks: &ExportCheck) -> Option<String> {
    crate::task_verb::swap_question_digest_for_test(expected, checks)
}

/// The ref a capsule request piece of `bytes` is published under.
#[must_use]
pub fn piece_ref(bytes: &[u8]) -> OutputRef {
    crate::code_run::piece_ref_for_test(bytes)
}

/// The content hash an issue signature holds for `packet`, or `None` when it does not
/// encode.
#[must_use]
pub fn packet_content_hash(packet: &TriagePacket) -> Option<String> {
    crate::feedback::packet_content_hash_for_test(packet)
}

/// The content hash an owner's native bundle of `files` stages, or `None` when the bundle
/// is refused.
#[must_use]
pub fn bundle_content_hash(files: &[RepoBundleFile]) -> Option<String> {
    crate::repo_mutation::proposal::bundle_content_hash_for_test(files)
}

/// The request hash of an owner request whose hash input is `preimage`, or `None` when it
/// does not encode.
#[must_use]
pub fn owner_request_hash(preimage: &serde_json::Value) -> Option<String> {
    crate::repo_mutation::proposal::owner_request_hash_for_test(preimage)
}
