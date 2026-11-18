//! K-proof door for the Dreamer wake digests that stored rows and deterministic
//! comparisons already use. Only compiled under `oneiron_test_support`; never API.
#![cfg(oneiron_test_support)]

use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimSource;
use crate::dreamer_wake::{self, SievePolicy, SpanKind, SpanOrigin};
use crate::llm::LlmResponse;
use crate::tagging::DerivationEnvelope;

/// The queued follower session identity for an authority under the vault read scope.
#[must_use]
pub fn follower_session(authority: &EntityId) -> [u8; 32] {
    dreamer_wake::follower::session_key_for_test(authority)
}

/// The prepared prefix's stored digest, instruction first.
#[must_use]
pub fn follower_prefix(instruction: &str, parts: &[String]) -> [u8; 32] {
    dreamer_wake::follower::prefix_digest_for_test(instruction, parts)
}

/// The prepared question's stored digest.
#[must_use]
pub fn follower_question(question: &str) -> [u8; 32] {
    dreamer_wake::follower::question_digest_for_test(question)
}

/// The grouping key of folded topic words, absent for whitespace-only words.
#[must_use]
pub fn nightly_topic(words: &str) -> Option<[u8; 32]> {
    dreamer_wake::nightly::topic_of_for_test(words)
}

/// The durable program step's result digest, absent when its response cannot encode.
#[must_use]
pub fn turn_program_response(response: &LlmResponse) -> Option<[u8; 32]> {
    dreamer_wake::response_digest_for_test(response)
}

/// The key a retry's trigger input uses in the read-phase map.
#[must_use]
pub fn read_phase_trigger(input: &str) -> [u8; 32] {
    dreamer_wake::read_phase_trigger_key_for_test(input)
}

/// The exact prefixed hex dedupe key stored with a turn projection's queued work.
#[must_use]
pub fn turn_projection(
    turn_ordinal: u64,
    projection_digest: &[u8; 32],
    dedupe_key: Option<&str>,
) -> String {
    dreamer_wake::turn_projection_key_for_test(turn_ordinal, projection_digest, dedupe_key)
}

/// The rank used by the turn and window audit draws.
#[must_use]
pub fn audit_window_sample(domain: &[u8], seed: AttemptId, id: &[u8]) -> [u8; 32] {
    dreamer_wake::sieve::draw_rank_for_test(domain, seed, id)
}

/// The shared source-text digest stored by spans and compared by evidence reads.
#[must_use]
pub fn sieve_chunk(text: &str) -> [u8; 32] {
    dreamer_wake::sieve::chunk_digest_for_test(text)
}

/// The stored reading cursor digest of source/digest pairs in reading order.
#[must_use]
pub fn sieve_reading(chunks: &[(EntityId, [u8; 32])]) -> [u8; 32] {
    let chunks = chunks
        .iter()
        .map(|(source, digest)| dreamer_wake::sieve::ChunkRefForTest {
            source: *source,
            digest: *digest,
            len: 0,
        })
        .collect::<Vec<_>>();
    dreamer_wake::sieve::reading_digest_for_test(&chunks)
}

/// The canonical-JSON policy digest stored on a queued span.
#[must_use]
pub fn policy_digest(policy: &SievePolicy) -> Option<[u8; 32]> {
    dreamer_wake::sieve::policy_digest_for_test(policy)
}

/// The stored span identity, including the kind and its rule or saved-tag origin.
#[must_use]
pub fn span_id(
    turn: &EntityId,
    source: &EntityId,
    start: u64,
    end: u64,
    chunk_digest: &[u8; 32],
    kind: SpanKind,
    origin: SpanOrigin,
) -> [u8; 32] {
    dreamer_wake::sieve::span_id_for_test(turn, source, start, end, chunk_digest, kind, origin)
}

/// The envelope version compared by saved reading rows.
#[must_use]
pub fn tag_envelope_digest(envelope: &DerivationEnvelope) -> [u8; 32] {
    dreamer_wake::sieve::envelope_digest_for_test(envelope)
}

/// The first 16 digest bytes used as a typing member's AUDIT receipt key.
#[must_use]
pub fn typing_member_key(carrier: AttemptId, span_id: &[u8; 32]) -> [u8; 16] {
    *dreamer_wake::sieve::typing_member_key_for_test(carrier, span_id)
        .expect("a digest prefix has 16 bytes")
        .as_bytes()
}

/// The exact prefixed hex rung key stored with queued work.
#[must_use]
pub fn rung_dedupe_key(input: &str) -> String {
    dreamer_wake::sieve::rung_dedupe_key_for_test(input)
}

/// The deterministic span audit rank used for selection and sorting.
#[must_use]
pub fn audit_sample(seed: AttemptId, span_id: &[u8; 32]) -> [u8; 32] {
    dreamer_wake::sieve::audit_sample_rank_for_test(seed, span_id)
}

/// The Arc success-material digest of a sentence in its evidence class.
#[must_use]
pub fn statement(sentence: &str, class: Option<ClaimSource>) -> Option<[u8; 32]> {
    dreamer_wake::statement_material::statement_for_test(sentence, class)
}
