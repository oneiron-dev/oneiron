//! K-proof for the 17 Dreamer wake legacy recipes at 8dc388b6c4b4: every stored or
//! compared digest keeps main's bytes through the fingerprint K door.
//!
//! Queued follower inputs and persisted sessions use the session key; prepared suffixes
//! store prefix and question digests. Nightly Name-span grouping compares topic keys.
//! Durable program steps store response digests. Retry deferral stamps compare trigger
//! keys, and queued projections and rungs store their prefixed hex dedupe keys. Audit
//! draws compare and sort window and span ranks. Spans store chunk versions and evidence
//! reads compare them; READ cursors store reading and tag-envelope digests. Queued spans
//! store policy digests, and SPANS/QUEUE rows key and compare span ids. AUDIT receipts use
//! typing-member AttemptId bytes. Arc success material stores statement digests and the
//! gate and projector compare them.
//!
//! The base modules hold exact main lines at 8dc388b6c4b4, copied by the lane's
//! gen_keep_oracle.py. Stand-ins contain only fields read by private site arguments.
//! The chunk oracle includes all four production copies and the nightly test-door copy.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_dreamer_wake_digests`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::attempt_queue::AttemptId;
use oneiron::claim::ClaimSource;
use oneiron::dreamer_wake::{RuleClass, SievePolicy, SpanKind, SpanOrigin};
use oneiron::llm::{ContentPart, FinishReason, LlmMessage, LlmMessageRole, LlmResponse, LlmUsage};
use oneiron::tagging::DerivationEnvelope;
use oneiron::test_doors::fingerprint_keep_dreamer_wake_digests as door;
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};
use serde_json::json;

// The public path main's copied envelope function names.
mod tagging {
    pub(crate) use oneiron::tagging::DerivationEnvelope;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_follower {
    use oneiron::{EntityId, Result};
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/follower/mod.rs:65-71
    const SESSION_DOMAIN: &[u8] = b"oneiron:dreamer-follower:session:v1";
    /// The read scope every session reads under at this head: the Dreamer's own
    /// gate over the vault. An off-record or private route never reaches the
    /// sieve, so it never shares a session.
    const READ_SCOPE: &[u8] = b"dreamer-gate:vault";
    const PREFIX_DOMAIN: &[u8] = b"oneiron:dreamer-follower:prefix:v1";
    const QUESTION_DOMAIN: &[u8] = b"oneiron:dreamer-follower:question:v1";

    pub(crate) fn session(authority: &EntityId) -> Result<[u8; 32]> {
        // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/follower/mod.rs:87-92
            Ok(*blake3::Hasher::new()
                .update(SESSION_DOMAIN)
                .update(authority.as_bytes())
                .update(READ_SCOPE)
                .finalize()
                .as_bytes())
    }
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/follower/mod.rs:616-624
    fn prefix_digest(instruction: &str, parts: &[String]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PREFIX_DOMAIN);
        for part in std::iter::once(instruction).chain(parts.iter().map(String::as_str)) {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/follower/mod.rs:626-632
    fn question_digest(question: &str) -> [u8; 32] {
        *blake3::Hasher::new()
            .update(QUESTION_DOMAIN)
            .update(question.as_bytes())
            .finalize()
            .as_bytes()
    }

    pub(crate) fn prefix(instruction: &str, parts: &[String]) -> [u8; 32] {
        prefix_digest(instruction, parts)
    }
    pub(crate) fn question(question: &str) -> [u8; 32] {
        question_digest(question)
    }
    pub(crate) fn tags() -> [&'static [u8]; 3] {
        [SESSION_DOMAIN, PREFIX_DOMAIN, QUESTION_DOMAIN]
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_topic {
    type TopicKey = [u8; 32];
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/nightly/things/topics.rs:20-20
    const TOPIC_DOMAIN: &[u8] = b"oneiron:dreamer-nightly-topic:v1";
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/nightly/things/topics.rs:56-72
    fn topic_of(words: &str) -> Option<TopicKey> {
        let folded = words
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>()
            .join(" ");
        if folded.is_empty() {
            return None;
        }
        Some(
            *blake3::Hasher::new()
                .update(TOPIC_DOMAIN)
                .update(folded.as_bytes())
                .finalize()
                .as_bytes(),
        )
    }

    pub(crate) fn topic(words: &str) -> Option<[u8; 32]> { topic_of(words) }
    pub(crate) fn tag() -> &'static [u8] { TOPIC_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_response {
    use oneiron::llm::LlmResponse;
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/program.rs:75-75
    const RESPONSE_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-response:v1";
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/program.rs:811-820
    fn response_digest(response: &LlmResponse) -> Option<[u8; 32]> {
        let bytes = serde_json::to_vec(response).ok()?;
        Some(
            *blake3::Hasher::new()
                .update(RESPONSE_DOMAIN)
                .update(&bytes)
                .finalize()
                .as_bytes(),
        )
    }

    pub(crate) fn response(response: &LlmResponse) -> Option<[u8; 32]> {
        response_digest(response)
    }
    pub(crate) fn tag() -> &'static [u8] { RESPONSE_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_trigger {
    pub(crate) fn trigger(input: &str) -> [u8; 32] {
        // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/recipe_wake.rs:97-97
            let trigger_key = *blake3::hash(input.as_bytes()).as_bytes();
        trigger_key
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_projection {
    pub(crate) fn projection(turn_ordinal: u64, projection_digest: [u8; 32], dedupe_key: Option<&str>) -> String {
        // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/scheduling.rs:283-291
            let mut key_hash = blake3::Hasher::new();
            key_hash.update(b"dreamer:turn-projection:v1");
            key_hash.update(&turn_ordinal.to_be_bytes());
            key_hash.update(&projection_digest);
            if let Some(key) = dedupe_key {
                key_hash.update(&(key.len() as u64).to_be_bytes());
                key_hash.update(key.as_bytes());
            }
            let image_key = format!("turn-projection:{}", key_hash.finalize().to_hex());
        image_key
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_audit_window {
    use oneiron::attempt_queue::AttemptId;
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/audit_windows.rs:280-288
    fn draw_rank(domain: &[u8], seed: AttemptId, id: &[u8]) -> [u8; 32] {
        *blake3::Hasher::new()
            .update(b"oneiron:sieve:audit-window-sample:v1")
            .update(domain)
            .update(seed.as_bytes())
            .update(id)
            .finalize()
            .as_bytes()
    }

    pub(crate) fn rank(domain: &[u8], seed: AttemptId, id: &[u8]) -> [u8; 32] {
        draw_rank(domain, seed, id)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_chunk {
    use oneiron::test_doors::nightly::{SpentSpan, SpentSpanKind};

    pub(crate) fn chunk_constructor(text: &str) -> [u8; 32] {
        // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/chunks.rs:47-51
                let digest = *blake3::Hasher::new()
                    .update(b"oneiron:dreamer-sieve:chunk:v1")
                    .update(text.as_bytes())
                    .finalize()
                    .as_bytes();
        digest
    }
    pub(crate) fn audit_window(text: &str) -> [u8; 32] {
        // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/audit_windows.rs:423-427
            *blake3::Hasher::new()
                .update(b"oneiron:dreamer-sieve:chunk:v1")
                .update(text.as_bytes())
                .finalize()
                .as_bytes()
    }
    pub(crate) fn follower(text: &str) -> [u8; 32] {
        // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/follower.rs:77-81
            *blake3::Hasher::new()
                .update(b"oneiron:dreamer-sieve:chunk:v1")
                .update(text.as_bytes())
                .finalize()
                .as_bytes()
    }
    pub(crate) fn rung_evidence(text: &str) -> [u8; 32] {
        // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/recipes.rs:335-339
            let digest = *blake3::Hasher::new()
                .update(b"oneiron:dreamer-sieve:chunk:v1")
                .update(text.as_bytes())
                .finalize()
                .as_bytes();
        digest
    }
    pub(crate) fn nightly(text: &str) -> [u8; 32] {
        let spent = SpentSpan {
            turn: super::id(1), message: super::id(2), text, words: "",
            kind: SpentSpanKind::Name, entity: None, score: 0,
        };
        // main 8dc388b6c4b4: crates/oneiron/src/test_doors/nightly.rs:95-99
            let source_digest = *blake3::Hasher::new()
                .update(b"oneiron:dreamer-sieve:chunk:v1")
                .update(spent.text.as_bytes())
                .finalize()
                .as_bytes();
        source_digest
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_reading {
    use oneiron::EntityId;
    // Main reads only these fields of its crate-private ChunkRef.
    pub(crate) struct ChunkRef {
        pub(crate) source: EntityId,
        pub(crate) digest: [u8; 32],
    }
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/chunks.rs:326-335
    pub(super) fn reading_digest(chunks: &[ChunkRef]) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron:dreamer-sieve:reading:v1");
        hash.update(&(chunks.len() as u64).to_be_bytes());
        for chunk in chunks {
            hash.update(chunk.source.as_bytes());
            hash.update(&chunk.digest);
        }
        *hash.finalize().as_bytes()
    }

    pub(crate) fn reading(chunks: &[(EntityId, [u8; 32])]) -> [u8; 32] {
        let chunks = chunks.iter().map(|(source, digest)| ChunkRef { source: *source, digest: *digest }).collect::<Vec<_>>();
        reading_digest(&chunks)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_policy {
    use oneiron::Result;
    use serde::{Deserialize, Serialize};
    use oneiron_verb_wire::dreamer_wake::sieve::policy::invalid;
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/policy.rs:20-49
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub struct SievePolicy {
        /// Turns one pass reads; the rest wait for the next pass.
        pub max_turns_per_pass: u32,
        /// Timeline rows one pass's forward scan steps over looking for turns.
        /// The late sweep of the cursor's own second is not capped by it.
        pub max_scan_per_pass: u32,
        /// Bytes of turn text one pass hashes and reads for spans. A turn with
        /// more is read a segment at a time and keeps its place at a segment's
        /// end; the next pass reads on from there, so nothing past the bound is
        /// dropped. A pass's first segment reads whatever the bound, so every
        /// pass moves a read on.
        pub max_text_bytes_per_pass: u32,
        /// Interest of a date span at full confidence.
        pub date_interest: u32,
        /// Interest of a name span at full confidence.
        pub name_interest: u32,
        pub absolute_date_confidence: u8,
        pub relative_date_confidence: u8,
        pub vague_date_confidence: u8,
        pub name_confidence: u8,
        pub initial_name_confidence: u8,
        pub katakana_name_confidence: u8,
        /// Below this a span is low interest; it is still kept.
        pub uncertain_low: u8,
        /// From `uncertain_low` up to this a span is uncertain and owes the
        /// typing rung; at or above it the span is sure.
        pub uncertain_high: u8,
    }
    impl SievePolicy {
        // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/policy.rs:85-91
            pub(super) fn digest(&self) -> Result<[u8; 32]> {
                let json = serde_json::to_vec(self).map_err(|_| invalid())?;
                let mut hash = blake3::Hasher::new();
                hash.update(b"oneiron:dreamer-sieve:policy:v1");
                hash.update(&json);
                Ok(*hash.finalize().as_bytes())
            }
    }
    pub(crate) fn policy(policy: &oneiron::dreamer_wake::SievePolicy) -> Option<[u8; 32]> {
        SievePolicy {
            max_turns_per_pass: policy.max_turns_per_pass,
            max_scan_per_pass: policy.max_scan_per_pass,
            max_text_bytes_per_pass: policy.max_text_bytes_per_pass,
            date_interest: policy.date_interest,
            name_interest: policy.name_interest,
            absolute_date_confidence: policy.absolute_date_confidence,
            relative_date_confidence: policy.relative_date_confidence,
            vague_date_confidence: policy.vague_date_confidence,
            name_confidence: policy.name_confidence,
            initial_name_confidence: policy.initial_name_confidence,
            katakana_name_confidence: policy.katakana_name_confidence,
            uncertain_low: policy.uncertain_low,
            uncertain_high: policy.uncertain_high,
        }.digest().ok()
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_span {
    use oneiron::EntityId;
    use oneiron::dreamer_wake::{SpanKind, SpanOrigin};
    // The two fields of the private ChunkRef that main's span recipe reads.
    struct ChunkRef { source: EntityId, digest: [u8; 32] }
    pub(crate) fn span(turn: &EntityId, source: &EntityId, start: u64, end: u64, chunk_digest: &[u8; 32], kind: SpanKind, origin: SpanOrigin) -> [u8; 32] {
        let chunk = ChunkRef { source: *source, digest: *chunk_digest };
        // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/read.rs:342-359
                let mut id = blake3::Hasher::new();
                id.update(b"oneiron:dreamer-sieve:span:v2");
                id.update(turn.as_bytes());
                id.update(chunk.source.as_bytes());
                id.update(&start.to_be_bytes());
                id.update(&end.to_be_bytes());
                id.update(&chunk.digest);
                match origin {
                    SpanOrigin::Rule { rules, class } => {
                        id.update(&[0, kind as u8, class as u8]);
                        id.update(&rules.to_be_bytes());
                    }
                    SpanOrigin::SavedTag { envelope, index } => {
                        id.update(&[1, kind as u8]);
                        id.update(&envelope);
                        id.update(&index.to_be_bytes());
                    }
                }
        *id.finalize().as_bytes()
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_envelope {
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/read.rs:441-464
    pub(super) fn envelope_digest(envelope: &crate::tagging::DerivationEnvelope) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron:dreamer-sieve:tag-envelope:v1");
        for field in [
            &envelope.content_hash,
            &envelope.model_id,
            &envelope.version,
            &envelope.params_hash,
        ] {
            hash.update(&(field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        match &envelope.stack {
            Some(stack) => {
                hash.update(&[1]);
                hash.update(&(stack.len() as u64).to_be_bytes());
                hash.update(stack.as_bytes());
            }
            None => {
                hash.update(&[0]);
            }
        }
        *hash.finalize().as_bytes()
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_member {
    use oneiron::attempt_queue::AttemptId;
    use oneiron::Result;
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/recipes/typing_batch.rs:28-28
    const MEMBER_DOMAIN: &[u8] = b"oneiron:dreamer-sieve:typing-member:v1";
    pub(crate) fn member(carrier: AttemptId, span_id: &[u8; 32]) -> Result<AttemptId> {
        let span = super::span_row(*span_id);
        // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/recipes/typing_batch.rs:147-152
            let hash = blake3::Hasher::new()
                .update(MEMBER_DOMAIN)
                .update(carrier.as_bytes())
                .update(&span.id)
                .finalize();
            Ok(AttemptId::from_bytes(&hash.as_bytes()[..16])?)
    }
    pub(crate) fn tag() -> &'static [u8] { MEMBER_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_rung {
    pub(crate) fn rung(input: &str) -> String {
        // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/recipes.rs:229-229
                format!("sieve:rungs:{}", blake3::hash(input.as_bytes()).to_hex())
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_audit {
    use oneiron::attempt_queue::AttemptId;
    pub(crate) fn rank(seed: AttemptId, span_id: &[u8; 32]) -> [u8; 32] {
        let span = super::span_row(*span_id);
        // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/sieve/recipes.rs:258-262
                let mut hash = blake3::Hasher::new();
                hash.update(b"oneiron:sieve:audit-sample:v1");
                hash.update(seed.as_bytes());
                hash.update(&span.id);
                let rank = *hash.finalize().as_bytes();
        rank
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_statement {
    use oneiron::claim::ClaimSource;
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/statement_material.rs:20-25
    const FORMATTING: &[char] = &[
        '"', '\'', '“', '”', '‘', '’', '«', '»', '「', '」', '『', '』', '.', ',', '!', '?', ':', ';',
        '(', ')', '[', ']', '*', '_', '`', '…', '、', '。', '！', '？',
    ];
    /// Tokens that only mark a list item or a quote where a sentence starts.
    const BULLETS: &[&str] = &["-", "–", "—", "•", "·", ">", "+"];
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/statement_material.rs:50-67
    fn statement(sentence: &str, class: Option<ClaimSource>) -> Option<[u8; 32]> {
        let tokens: Vec<String> = sentence
            .split_whitespace()
            .skip_while(|token| BULLETS.contains(token))
            .map(|token| trim_token(token).to_lowercase())
            .filter(|token| !token.is_empty())
            .collect();
        if tokens.is_empty() {
            return None;
        }
        let class = class.map_or("", ClaimSource::as_str);
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron:dreamer-projector:statement:v3");
        hash.update(&(class.len() as u64).to_be_bytes());
        hash.update(class.as_bytes());
        hash.update(tokens.join(" ").as_bytes());
        Some(*hash.finalize().as_bytes())
    }
    // main 8dc388b6c4b4: crates/oneiron/src/dreamer_wake/statement_material.rs:71-87
    fn trim_token(token: &str) -> &str {
        let token = token.trim_end_matches(FORMATTING);
        if !token.chars().any(|ch| ch.is_ascii_digit()) {
            return token.trim_start_matches(FORMATTING);
        }
        let mut rest = token;
        while let Some(first) = rest.chars().next() {
            let after = &rest[first.len_utf8()..];
            let opens_number =
                matches!(first, '.' | ',') && after.starts_with(|ch: char| ch.is_ascii_digit());
            if !FORMATTING.contains(&first) || opens_number {
                break;
            }
            rest = after;
        }
        rest
    }

    pub(crate) fn material(sentence: &str, class: Option<ClaimSource>) -> Option<[u8; 32]> {
        statement(sentence, class)
    }
}

fn id(n: u8) -> EntityId {
    let mut bytes = [0x5a; 16];
    bytes[0] = n;
    EntityId::from_bytes(bytes).expect("an unreserved entity id")
}

fn attempt(n: u8) -> AttemptId {
    AttemptId::from_bytes(&[n; 16]).expect("16 bytes")
}

/// Six byte-distinct strings, including a >1024-byte transcript and embedded NUL.
fn texts() -> Vec<String> {
    vec![
        String::new(),
        " \t\n".into(),
        "ordinary words".into(),
        "é 日本 α".into(),
        "a\0b".into(),
        "長x".repeat(600),
    ]
}

/// A public span row for main's inline recipes, which read only its id.
fn span_row(span_id: [u8; 32]) -> oneiron::dreamer_wake::SieveSpan {
    oneiron::dreamer_wake::SieveSpan {
        id: span_id,
        turn: id(1),
        source: id(2),
        start: 0,
        end: 0,
        kind: SpanKind::Name,
        entity: None,
        novel: None,
        origin: SpanOrigin::Rule {
            rules: 0,
            class: RuleClass::Name,
        },
        source_digest: [0; 32],
        policy_digest: [0; 32],
        confidence: 0,
        score: 0,
        band: oneiron::dreamer_wake::SpanBand::Low,
        owed: Vec::new(),
        queued_at: 0,
    }
}

fn prefixes() -> Vec<(String, Vec<String>)> {
    let long = "長x".repeat(600);
    vec![
        (String::new(), vec![]),
        (String::new(), vec![String::new()]),
        ("instruction".into(), vec![]),
        ("instruction".into(), vec!["a".into(), "bc".into()]),
        ("instruction".into(), vec!["ab".into(), "c".into()]),
        ("é".into(), vec!["日本".into(), "α\0β".into()]),
        (long.clone(), vec![]),
        (String::new(), vec![long]),
    ]
}

fn policy_zero() -> SievePolicy {
    SievePolicy {
        max_turns_per_pass: 0,
        max_scan_per_pass: 0,
        max_text_bytes_per_pass: 0,
        date_interest: 0,
        name_interest: 0,
        absolute_date_confidence: 0,
        relative_date_confidence: 0,
        vague_date_confidence: 0,
        name_confidence: 0,
        initial_name_confidence: 0,
        katakana_name_confidence: 0,
        uncertain_low: 0,
        uncertain_high: 0,
    }
}

/// Sixteen policies: zeros, one change per serialized field, all maxima and a mixed row.
/// Digesting a row does not validate its scheduling dials.
fn policies() -> Vec<SievePolicy> {
    let zero = policy_zero();
    let mut rows = vec![zero];
    rows.push(SievePolicy {
        max_turns_per_pass: u32::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        max_scan_per_pass: u32::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        max_text_bytes_per_pass: u32::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        date_interest: u32::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        name_interest: u32::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        absolute_date_confidence: u8::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        relative_date_confidence: u8::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        vague_date_confidence: u8::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        name_confidence: u8::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        initial_name_confidence: u8::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        katakana_name_confidence: u8::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        uncertain_low: u8::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        uncertain_high: u8::MAX,
        ..zero
    });
    rows.push(SievePolicy {
        max_turns_per_pass: u32::MAX,
        max_scan_per_pass: u32::MAX,
        max_text_bytes_per_pass: u32::MAX,
        date_interest: u32::MAX,
        name_interest: u32::MAX,
        absolute_date_confidence: u8::MAX,
        relative_date_confidence: u8::MAX,
        vague_date_confidence: u8::MAX,
        name_confidence: u8::MAX,
        initial_name_confidence: u8::MAX,
        katakana_name_confidence: u8::MAX,
        uncertain_low: u8::MAX,
        uncertain_high: u8::MAX,
    });
    rows.push(SievePolicy {
        max_turns_per_pass: 1,
        max_scan_per_pass: 3,
        max_text_bytes_per_pass: 1025,
        date_interest: 50,
        name_interest: 25,
        absolute_date_confidence: 95,
        relative_date_confidence: 80,
        vague_date_confidence: 40,
        name_confidence: 90,
        initial_name_confidence: 60,
        katakana_name_confidence: 70,
        uncertain_low: 30,
        uncertain_high: 85,
    });
    rows
}

/// Rule versions at both u32 extremes, all classes, and saved-tag envelopes/indices
/// at both byte/u64 extremes. Each is crossed with both span kinds.
fn origins() -> Vec<SpanOrigin> {
    let mut rows = Vec::new();
    for class in [
        RuleClass::AbsoluteDate,
        RuleClass::RelativeDate,
        RuleClass::VagueDate,
        RuleClass::Name,
        RuleClass::InitialName,
        RuleClass::KatakanaName,
    ] {
        for rules in [0, u32::MAX] {
            rows.push(SpanOrigin::Rule { rules, class });
        }
    }
    for envelope in [[0; 32], [255; 32]] {
        for index in [0, u64::MAX] {
            rows.push(SpanOrigin::SavedTag { envelope, index });
        }
    }
    rows
}

fn empty_envelope() -> DerivationEnvelope {
    DerivationEnvelope {
        content_hash: String::new(),
        model_id: String::new(),
        version: String::new(),
        params_hash: String::new(),
        stack: None,
        text_hash: None,
    }
}

/// Eleven rows; text_hash deliberately has no effect on main's recipe.
fn envelopes() -> Vec<DerivationEnvelope> {
    let empty = empty_envelope();
    vec![
        empty.clone(),
        DerivationEnvelope {
            stack: Some(String::new()),
            ..empty.clone()
        },
        DerivationEnvelope {
            content_hash: "a".into(),
            ..empty.clone()
        },
        DerivationEnvelope {
            model_id: "a".into(),
            ..empty.clone()
        },
        DerivationEnvelope {
            version: "a".into(),
            ..empty.clone()
        },
        DerivationEnvelope {
            params_hash: "a".into(),
            ..empty.clone()
        },
        DerivationEnvelope {
            stack: Some("é 日本\0".into()),
            ..empty.clone()
        },
        DerivationEnvelope {
            content_hash: "長x".repeat(600),
            ..empty.clone()
        },
        DerivationEnvelope {
            text_hash: Some("ignored".into()),
            ..empty.clone()
        },
        DerivationEnvelope {
            content_hash: "ab".into(),
            model_id: "c".into(),
            ..empty.clone()
        },
        DerivationEnvelope {
            content_hash: "a".into(),
            model_id: "bc".into(),
            ..empty
        },
    ]
}

/// Six text cases, empty content, and a structured tool response with optional JSON.
fn responses() -> Vec<LlmResponse> {
    let make = |content| LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content,
        },
        usage: LlmUsage::zero(),
        finish_reason: FinishReason::Stop,
        reply_assertions: Default::default(),
        token_scores: None,
    };
    let mut rows = texts()
        .into_iter()
        .map(|text| {
            make(vec![ContentPart::Text {
                text,
                signature: None,
            }])
        })
        .collect::<Vec<_>>();
    rows.push(make(Vec::new()));
    let mut tools = make(vec![
        ContentPart::ToolCall {
            call_id: "call-é".into(),
            name: "read".into(),
            input: json!({"b": [0, null], "a": true}),
            signature: Some("sig".into()),
        },
        ContentPart::ToolResult {
            call_id: "call-é".into(),
            output: json!({"text": "日本"}),
            is_error: false,
        },
    ]);
    tools.finish_reason = FinishReason::ToolCalls;
    tools.usage.input.total = u64::MAX;
    tools.usage.output.total = u64::MAX;
    tools.usage.raw_provider = json!({"nested": [1, "é"]});
    tools.token_scores = Some(json!({"content": []}));
    rows.push(tools);
    rows
}

fn classes() -> [Option<ClaimSource>; 7] {
    [
        None,
        Some(ClaimSource::UserStated),
        Some(ClaimSource::Observed),
        Some(ClaimSource::Inferred),
        Some(ClaimSource::Imported),
        Some(ClaimSource::ToolOutput),
        Some(ClaimSource::Generated),
    ]
}

fn sentences() -> Vec<String> {
    vec![
        String::new(),
        " \t\n".into(),
        "!!!".into(),
        "- >".into(),
        "Hello world".into(),
        "hello WORLD!".into(),
        "「東京」 α".into(),
        "$-1.5 50% +2 .5".into(),
        "5".into(),
        ".5".into(),
        "Long ".repeat(300),
    ]
}

#[test]
fn the_purposes_keep_main_s_recipes() {
    let recipes: [(LegacyPurpose, TagMode, &[u8]); 17] = [
        (
            purposes::dreamer_wake::AUDIT_SAMPLE,
            TagMode::HashedFirst,
            b"oneiron:sieve:audit-sample:v1",
        ),
        (
            purposes::dreamer_wake::AUDIT_WINDOW_SAMPLE,
            TagMode::HashedFirst,
            b"oneiron:sieve:audit-window-sample:v1",
        ),
        (
            purposes::dreamer_wake::FOLLOWER_PREFIX,
            TagMode::HashedFirst,
            base_follower::tags()[1],
        ),
        (
            purposes::dreamer_wake::FOLLOWER_QUESTION,
            TagMode::HashedFirst,
            base_follower::tags()[2],
        ),
        (
            purposes::dreamer_wake::FOLLOWER_SESSION,
            TagMode::HashedFirst,
            base_follower::tags()[0],
        ),
        (
            purposes::dreamer_wake::NIGHTLY_TOPIC,
            TagMode::HashedFirst,
            base_topic::tag(),
        ),
        (
            purposes::dreamer_wake::POLICY_DIGEST,
            TagMode::HashedFirst,
            b"oneiron:dreamer-sieve:policy:v1",
        ),
        (
            purposes::dreamer_wake::READ_PHASE_TRIGGER,
            TagMode::NotHashed,
            b"oneiron.dreamer_wake.read_phase_trigger.v1",
        ),
        (
            purposes::dreamer_wake::RUNG_DEDUPE_KEY,
            TagMode::NotHashed,
            b"oneiron.dreamer_wake.rung_dedupe_key.v1",
        ),
        (
            purposes::dreamer_wake::SIEVE_CHUNK,
            TagMode::HashedFirst,
            b"oneiron:dreamer-sieve:chunk:v1",
        ),
        (
            purposes::dreamer_wake::SIEVE_READING,
            TagMode::HashedFirst,
            b"oneiron:dreamer-sieve:reading:v1",
        ),
        (
            purposes::dreamer_wake::SPAN_ID,
            TagMode::HashedFirst,
            b"oneiron:dreamer-sieve:span:v2",
        ),
        (
            purposes::dreamer_wake::STATEMENT,
            TagMode::HashedFirst,
            b"oneiron:dreamer-projector:statement:v3",
        ),
        (
            purposes::dreamer_wake::TAG_ENVELOPE_DIGEST,
            TagMode::HashedFirst,
            b"oneiron:dreamer-sieve:tag-envelope:v1",
        ),
        (
            purposes::dreamer_wake::TURN_PROGRAM_RESPONSE,
            TagMode::HashedFirst,
            base_response::tag(),
        ),
        (
            purposes::dreamer_wake::TURN_PROJECTION,
            TagMode::HashedFirst,
            b"dreamer:turn-projection:v1",
        ),
        (
            purposes::dreamer_wake::TYPING_MEMBER_KEY,
            TagMode::HashedFirst,
            base_member::tag(),
        ),
    ];
    for (purpose, mode, tag) in recipes {
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), mode);
        assert_eq!(purpose.tag().as_bytes(), tag);
    }
}

#[test]
fn follower_session_keeps_main_s_bytes() {
    let rows = [id(0), id(1), id(127), id(255)];
    let mut hashes = BTreeSet::new();
    for authority in &rows {
        let head = door::follower_session(authority);
        assert_eq!(
            head,
            base_follower::session(authority).expect("main session")
        );
        hashes.insert(head);
    }
    assert_eq!(hashes.len(), rows.len());
}

#[test]
fn follower_prefix_keeps_main_s_bytes() {
    let rows = prefixes();
    let mut hashes = BTreeSet::new();
    for (instruction, parts) in &rows {
        let head = door::follower_prefix(instruction, parts);
        assert_eq!(head, base_follower::prefix(instruction, parts));
        hashes.insert(head);
    }
    assert_eq!((rows.len(), hashes.len()), (8, 8));
}

#[test]
fn follower_question_keeps_main_s_bytes() {
    let rows = texts();
    let mut hashes = BTreeSet::new();
    for text in &rows {
        let head = door::follower_question(text);
        assert_eq!(head, base_follower::question(text));
        hashes.insert(head);
    }
    assert_eq!((rows.len(), hashes.len()), (6, 6));
}

#[test]
fn read_phase_trigger_keeps_main_s_bytes() {
    let rows = texts();
    let mut hashes = BTreeSet::new();
    for text in &rows {
        let head = door::read_phase_trigger(text);
        assert_eq!(head, base_trigger::trigger(text));
        hashes.insert(head);
    }
    assert_eq!((rows.len(), hashes.len()), (6, 6));
}

#[test]
fn rung_dedupe_key_keeps_main_s_bytes() {
    let rows = texts();
    let mut hashes = BTreeSet::new();
    for text in &rows {
        let head = door::rung_dedupe_key(text);
        assert_eq!(head, base_rung::rung(text));
        hashes.insert(head);
    }
    assert_eq!((rows.len(), hashes.len()), (6, 6));
}

#[test]
fn nightly_topic_keeps_main_s_bytes() {
    let mut rows = texts();
    rows.extend([
        "HELLO  world".into(),
        "hello world".into(),
        "  É\t日本 ".into(),
    ]);
    let mut hashes = BTreeSet::new();
    for words in &rows {
        let head = door::nightly_topic(words);
        assert_eq!(head, base_topic::topic(words));
        hashes.insert(head);
    }
    assert_eq!((rows.len(), hashes.len()), (9, 7));
    assert_eq!(
        door::nightly_topic("HELLO  world"),
        door::nightly_topic("hello world")
    );
    assert_ne!(door::nightly_topic("hello"), door::nightly_topic("world"));
}

#[test]
fn turn_program_response_keeps_main_s_bytes() {
    let rows = responses();
    let mut hashes = BTreeSet::new();
    for response in &rows {
        let head = door::turn_program_response(response);
        assert_eq!(head, base_response::response(response));
        assert!(head.is_some());
        hashes.insert(head);
    }
    assert_eq!((rows.len(), hashes.len()), (8, 8));
}

#[test]
fn turn_projection_keeps_main_s_bytes() {
    let long = "長x".repeat(600);
    let keys = [
        None,
        Some(""),
        Some("key"),
        Some("é 日本"),
        Some(long.as_str()),
    ];
    let mut hashes = BTreeSet::new();
    let mut rows = 0;
    for ordinal in [0, 1, u64::MAX] {
        for projection in [[0; 32], [255; 32]] {
            for key in keys {
                let head = door::turn_projection(ordinal, &projection, key);
                assert_eq!(head, base_projection::projection(ordinal, projection, key));
                assert!(head.starts_with("turn-projection:"));
                hashes.insert(head);
                rows += 1;
            }
        }
    }
    assert_eq!((rows, hashes.len()), (30, 30));
}

#[test]
fn audit_window_sample_keeps_main_s_bytes() {
    let ids = [
        Vec::new(),
        vec![0; 16],
        vec![255; 32],
        "é日本".repeat(300).into_bytes(),
    ];
    let domains: [&[u8]; 3] = [b"", b"turn", b"window"];
    let mut hashes = BTreeSet::new();
    let mut rows = 0;
    for domain in domains {
        for seed in [attempt(0), attempt(255)] {
            for id in &ids {
                let head = door::audit_window_sample(domain, seed, id);
                assert_eq!(head, base_audit_window::rank(domain, seed, id));
                hashes.insert(head);
                rows += 1;
            }
        }
    }
    assert_eq!((rows, hashes.len()), (24, 24));
}

#[test]
fn sieve_chunk_keeps_each_main_copy_s_bytes() {
    let rows = texts();
    let mut hashes = BTreeSet::new();
    for text in &rows {
        let head = door::sieve_chunk(text);
        assert_eq!(head, base_chunk::chunk_constructor(text));
        assert_eq!(head, base_chunk::audit_window(text));
        assert_eq!(head, base_chunk::follower(text));
        assert_eq!(head, base_chunk::rung_evidence(text));
        assert_eq!(head, base_chunk::nightly(text));
        hashes.insert(head);
    }
    assert_eq!((rows.len(), hashes.len()), (6, 6));
}

#[test]
fn sieve_reading_keeps_main_s_bytes() {
    let a = (id(1), [0; 32]);
    let b = (id(2), [255; 32]);
    let rows = [
        vec![],
        vec![a],
        vec![(id(2), [0; 32])],
        vec![(id(1), [255; 32])],
        vec![a, b],
        vec![b, a],
        vec![a, a],
        vec![a; 33],
    ];
    let mut hashes = BTreeSet::new();
    for chunks in &rows {
        let head = door::sieve_reading(chunks);
        assert_eq!(head, base_reading::reading(chunks));
        hashes.insert(head);
    }
    assert_eq!((rows.len(), hashes.len()), (8, 8));
}

#[test]
fn policy_digest_keeps_main_s_bytes() {
    let rows = policies();
    let mut hashes = BTreeSet::new();
    for policy in &rows {
        let head = door::policy_digest(policy);
        assert_eq!(head, base_policy::policy(policy));
        assert!(head.is_some());
        hashes.insert(head);
    }
    assert_eq!((rows.len(), hashes.len()), (16, 16));
}

#[test]
fn span_id_keeps_main_s_bytes() {
    let fields = [
        (id(1), id(2), 0, 0, [0; 32]),
        (id(1), id(2), 0, u64::MAX, [255; 32]),
        (id(2), id(1), u64::MAX, u64::MAX, [0; 32]),
    ];
    let mut hashes = BTreeSet::new();
    let mut rows = 0;
    for kind in [SpanKind::Date, SpanKind::Name] {
        for origin in origins() {
            for (turn, source, start, end, digest) in fields {
                let head = door::span_id(&turn, &source, start, end, &digest, kind, origin);
                assert_eq!(
                    head,
                    base_span::span(&turn, &source, start, end, &digest, kind, origin)
                );
                hashes.insert(head);
                rows += 1;
            }
        }
    }
    assert_eq!((rows, hashes.len()), (96, 96));
}

#[test]
fn tag_envelope_digest_keeps_main_s_bytes() {
    let rows = envelopes();
    let mut hashes = BTreeSet::new();
    for envelope in &rows {
        let head = door::tag_envelope_digest(envelope);
        assert_eq!(head, base_envelope::envelope_digest(envelope));
        hashes.insert(head);
    }
    assert_eq!((rows.len(), hashes.len()), (11, 10));
    assert_ne!(
        door::tag_envelope_digest(&rows[0]),
        door::tag_envelope_digest(&rows[1])
    );
    assert_eq!(
        door::tag_envelope_digest(&rows[0]),
        door::tag_envelope_digest(&rows[8])
    );
}

#[test]
fn typing_member_key_keeps_main_s_bytes() {
    let mut hashes = BTreeSet::new();
    let mut rows = 0;
    for carrier in [attempt(0), attempt(255)] {
        for span in [[0; 32], [255; 32], [0x5a; 32]] {
            let head = door::typing_member_key(carrier, &span);
            assert_eq!(
                head,
                *base_member::member(carrier, &span)
                    .expect("main member")
                    .as_bytes()
            );
            hashes.insert(head);
            rows += 1;
        }
    }
    assert_eq!((rows, hashes.len()), (6, 6));
}

#[test]
fn audit_sample_keeps_main_s_bytes() {
    let mut hashes = BTreeSet::new();
    let mut rows = 0;
    for seed in [attempt(0), attempt(255)] {
        for span in [[0; 32], [255; 32], [0x5a; 32]] {
            let head = door::audit_sample(seed, &span);
            assert_eq!(head, base_audit::rank(seed, &span));
            hashes.insert(head);
            rows += 1;
        }
    }
    assert_eq!((rows, hashes.len()), (6, 6));
}

#[test]
fn statement_keeps_main_s_bytes() {
    let mut hashes = BTreeSet::new();
    let mut rows = 0;
    for sentence in sentences() {
        for class in classes() {
            let head = door::statement(&sentence, class);
            assert_eq!(head, base_statement::material(&sentence, class));
            hashes.insert(head);
            rows += 1;
        }
    }
    assert_eq!(rows, 77);
    assert!(hashes.len() > 7);
    assert_ne!(door::statement(".5", None), door::statement("5", None));
    assert_ne!(
        door::statement("words", None),
        door::statement("words", Some(ClaimSource::UserStated))
    );
    assert_eq!(
        door::statement("Hello world", None),
        door::statement("hello WORLD!", None)
    );
}
