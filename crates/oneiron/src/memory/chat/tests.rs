//! `.chat` acceptance tests: depth→effort mapping, composer call counts, the
//! zero-model minimal tier, and the typed refusals.
//!
//! The composer is a counting stub, so "exactly once" and "never" are
//! assertions rather than commentary, and every call runs against a real
//! seeded vault so `chat` is proven to ride the real `recall` body.

use super::*;

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::entity_id::EntityId;
use crate::memory::tests::{facade_for, open_vault, put_person, witness_message};

/// One recorded composer invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComposerCall {
    question: String,
    depth: ChatDepth,
    items: usize,
    deep_pending: Option<bool>,
    lease: Option<String>,
}

/// A provider-neutral composer that records what it was handed. It holds no
/// vault handle because the seam gives it none.
#[derive(Default)]
struct CountingComposer {
    calls: AtomicUsize,
    seen: Mutex<Vec<ComposerCall>>,
}

impl CountingComposer {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn seen(&self) -> Vec<ComposerCall> {
        self.seen.lock().expect("composer log").clone()
    }
}

impl ChatComposer for CountingComposer {
    fn compose(
        &self,
        request: &ChatComposeRequest<'_>,
        lease: Option<&BudgetLease>,
    ) -> MemoryResult<ComposedChatDraft> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let call = ComposerCall {
            question: request.question.to_owned(),
            depth: request.depth,
            items: request.pack.items.len(),
            deep_pending: request.pack.retrieval_meta.deep_pending,
            lease: lease.map(|lease| lease.id().to_owned()),
        };
        self.seen.lock().expect("composer log").push(call);
        Ok(ComposedChatDraft {
            answer: format!("composed {} answer", request.depth.as_str()),
            tokens_used: 42,
        })
    }
}

/// Opens a vault holding one witnessed message and returns the actor bound to
/// it, so tests recall real items instead of a stubbed pack.
fn seeded_vault(seed: u8, content: &str) -> (tempfile::TempDir, crate::Vault, EntityId) {
    let (dir, vault) = open_vault();
    let actor = put_person(&vault, seed);
    let conversation = EntityId::from_bytes([seed ^ 0xFF; 16]).expect("conversation id");
    facade_for(&vault, actor)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, content)],
            occurred_at: 2100,
        })
        .expect("witness");
    (dir, vault, actor)
}

// ── the depth dial ──────────────────────────────────────────────────────

#[test]
fn chat_depth_parses_canonical_values_and_low_med_high_aliases() {
    for (token, depth) in [
        ("minimal", ChatDepth::Minimal),
        ("low", ChatDepth::Minimal),
        ("standard", ChatDepth::Standard),
        ("med", ChatDepth::Standard),
        ("deep", ChatDepth::Deep),
        ("high", ChatDepth::Deep),
    ] {
        assert_eq!(ChatDepth::parse(token), Some(depth), "parses {token:?}");
    }

    // Aliases are input only: the canonical form is what comes back out, and
    // it is exactly the one effort enum's own string.
    for depth in [ChatDepth::Minimal, ChatDepth::Standard, ChatDepth::Deep] {
        assert_eq!(depth.as_str(), depth.effort().as_str());
        assert_eq!(ChatDepth::parse(depth.as_str()), Some(depth));
    }

    // The mapping is onto the ONE effort enum, not a second tier ladder.
    assert_eq!(ChatDepth::Minimal.effort(), Effort::Minimal);
    assert_eq!(ChatDepth::Standard.effort(), Effort::Standard);
    assert_eq!(ChatDepth::Deep.effort(), Effort::Deep);

    // Exact match: no trimming, no case folding, no invented synonyms.
    for token in [
        "", " ", "Minimal", "MINIMAL", " low", "low ", "medium", "Med", "HIGH", "deeper", "none",
    ] {
        assert_eq!(ChatDepth::parse(token), None, "rejects {token:?}");
    }
}

#[test]
fn chat_depth_serializes_canonically_and_rejects_aliases_on_the_wire() {
    for (depth, json) in [
        (ChatDepth::Minimal, "\"minimal\""),
        (ChatDepth::Standard, "\"standard\""),
        (ChatDepth::Deep, "\"deep\""),
    ] {
        assert_eq!(serde_json::to_string(&depth).expect("serialize"), json);
        assert_eq!(
            serde_json::from_str::<ChatDepth>(json).expect("deserialize"),
            depth
        );
    }

    // The aliases never become a second wire vocabulary.
    for json in ["\"low\"", "\"med\"", "\"high\""] {
        assert!(
            serde_json::from_str::<ChatDepth>(json).is_err(),
            "{json} is a parse alias, not a wire value"
        );
    }
}

// ── minimal: zero-model, extractive ─────────────────────────────────────

#[test]
fn chat_minimal_is_zero_model_extractive_and_never_calls_the_composer() {
    let (_dir, vault, actor) = seeded_vault(0x41, "the kiln reached cone six overnight");
    let memory = facade_for(&vault, actor);
    let scope = RecallScope::default();
    let composer = CountingComposer::default();

    // A composer supplied at minimal is structurally out of reach.
    let draft = memory
        .chat(
            "kiln",
            ChatDepth::Minimal,
            ChatOptions {
                scope: &scope,
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("minimal chat");

    assert_eq!(composer.calls(), 0, "minimal is zero-model");
    assert_eq!(draft.tokens_used, 0);
    assert_eq!(draft.depth, ChatDepth::Minimal);
    assert!(
        draft.retrieval.rendered.is_none(),
        "no format was requested"
    );
    let first = draft.retrieval.items.first().expect("the message");
    assert_eq!(draft.answer, first.value_text);
    assert!(!draft.answer.is_empty());

    // With a format the rendered pack IS the answer.
    let rendered = memory
        .chat(
            "kiln",
            ChatDepth::Minimal,
            ChatOptions {
                scope: &scope,
                limit: 10,
                format: Some("md"),
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("minimal chat with a format");
    assert_eq!(composer.calls(), 0);
    assert_eq!(rendered.tokens_used, 0);
    assert_eq!(
        rendered.answer,
        rendered.retrieval.rendered.as_deref().expect("md")
    );
    assert!(!rendered.answer.is_empty());
}

#[test]
fn chat_minimal_on_an_empty_pack_is_an_ok_empty_answer() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x42);
    let memory = facade_for(&vault, actor);
    let scope = RecallScope::default();

    let draft = memory
        .chat(
            "nothing in this vault matches",
            ChatDepth::Minimal,
            ChatOptions {
                scope: &scope,
                limit: 5,
                format: None,
                lease: None,
                composer: None,
            },
        )
        .expect("an empty pack is a successful empty answer");

    assert!(draft.retrieval.items.is_empty());
    assert_eq!(draft.answer, "");
    assert_eq!(draft.tokens_used, 0);
    assert_eq!(draft.retrieval.pack_version, MEMORY_PACK_VERSION);
}

// ── standard/deep: the composer runs exactly once, after retrieval ──────

#[test]
fn chat_standard_invokes_the_composer_exactly_once_after_retrieval() {
    let (_dir, vault, actor) = seeded_vault(0x43, "the fjord aurora peaked just after midnight");
    let memory = facade_for(&vault, actor);
    let scope = RecallScope::default();
    let composer = CountingComposer::default();

    let draft = memory
        .chat(
            "aurora",
            ChatDepth::Standard,
            ChatOptions {
                scope: &scope,
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("standard chat");

    assert_eq!(composer.calls(), 1);
    assert_eq!(draft.answer, "composed standard answer");
    assert_eq!(draft.tokens_used, 42);
    assert_eq!(draft.depth, ChatDepth::Standard);
    assert!(draft.retrieval.retrieval_meta.deep_pending.is_none());

    let seen = composer.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].question, "aurora");
    assert_eq!(seen[0].depth, ChatDepth::Standard);
    assert_eq!(seen[0].lease, None);
    // The composer saw the retrieval, so it ran after it.
    assert_eq!(seen[0].items, draft.retrieval.items.len());
    assert!(seen[0].items > 0);
}

#[test]
fn chat_deep_requires_the_lease_and_propagates_deep_pending() {
    let (_dir, vault, actor) = seeded_vault(0x44, "the ridge trail washed out in the spring melt");
    let memory = facade_for(&vault, actor);
    let scope = RecallScope::default();
    let composer = CountingComposer::default();

    // The lease rule stays recall's: chat forwards and lets the typed gate
    // refuse, and the composer never runs behind a refused retrieval.
    let err = memory
        .chat(
            "ridge trail",
            ChatDepth::Deep,
            ChatOptions {
                scope: &scope,
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect_err("deep without a lease");
    assert_eq!(err.code, MEMORY_CODE_LEASE_REQUIRED);
    assert!(err.suggestions.iter().any(|s| s.contains("lease")));
    assert_eq!(composer.calls(), 0);

    let lease = BudgetLease::for_test("chat-deep");
    let draft = memory
        .chat(
            "ridge trail",
            ChatDepth::Deep,
            ChatOptions {
                scope: &scope,
                limit: 10,
                format: None,
                lease: Some(&lease),
                composer: Some(&composer),
            },
        )
        .expect("leased deep chat");

    assert_eq!(composer.calls(), 1);
    assert_eq!(draft.depth, ChatDepth::Deep);
    assert_eq!(draft.answer, "composed deep answer");
    assert_eq!(draft.tokens_used, 42);
    // Honest propagation: the core still executed the standard body.
    assert_eq!(draft.retrieval.retrieval_meta.deep_pending, Some(true));

    let seen = composer.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].depth, ChatDepth::Deep);
    assert_eq!(seen[0].deep_pending, Some(true));
    assert_eq!(seen[0].lease.as_deref(), Some("chat-deep"));
}

// ── typed refusals ──────────────────────────────────────────────────────

#[test]
fn chat_requires_a_composer_before_any_retrieval_at_standard_and_deep() {
    let (_dir, vault, actor) = seeded_vault(0x45, "the harbour bell rang twice at dusk");
    let memory = facade_for(&vault, actor);
    let scope = RecallScope::default();

    let err = memory
        .chat(
            "harbour bell",
            ChatDepth::Standard,
            ChatOptions {
                scope: &scope,
                limit: 10,
                format: None,
                lease: None,
                composer: None,
            },
        )
        .expect_err("standard without a composer");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
    assert!(err.message.contains("standard"));
    assert!(err.suggestions.iter().any(|s| s.contains("ChatComposer")));

    // Deep without EITHER a composer or a lease refuses on the composer: the
    // composer check runs before recall, so no retrieval was paid for.
    let err = memory
        .chat(
            "harbour bell",
            ChatDepth::Deep,
            ChatOptions {
                scope: &scope,
                limit: 10,
                format: None,
                lease: None,
                composer: None,
            },
        )
        .expect_err("deep without a composer");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
    assert!(err.message.contains("deep"));
}

#[test]
fn chat_rejects_a_blank_question_and_a_zero_limit() {
    let (_dir, vault, actor) = seeded_vault(0x46, "the orchard was pruned before the frost");
    let memory = facade_for(&vault, actor);
    let scope = RecallScope::default();

    // A blank question is refused ahead of every other check.
    for question in ["", "   ", "\t\n"] {
        let err = memory
            .chat(
                question,
                ChatDepth::Deep,
                ChatOptions {
                    scope: &scope,
                    limit: 0,
                    format: None,
                    lease: None,
                    composer: None,
                },
            )
            .expect_err("blank question");
        assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
        assert!(err.message.contains("blank"));
        assert!(!err.suggestions.is_empty());
    }

    // Then the limit, ahead of the composer requirement.
    let err = memory
        .chat(
            "orchard",
            ChatDepth::Standard,
            ChatOptions {
                scope: &scope,
                limit: 0,
                format: None,
                lease: None,
                composer: None,
            },
        )
        .expect_err("zero limit");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
    assert!(err.message.contains("at least 1"));
}

// ── the draft contract ONE-1487 stacks on ───────────────────────────────

#[test]
fn chat_draft_carries_the_whole_memory_pack() {
    let (_dir, vault, actor) = seeded_vault(0x47, "the lighthouse keeper logged a supply run");
    let memory = facade_for(&vault, actor);
    let scope = RecallScope::default();

    let draft = memory
        .chat(
            "lighthouse",
            ChatDepth::Minimal,
            ChatOptions {
                scope: &scope,
                limit: 10,
                format: None,
                lease: None,
                composer: None,
            },
        )
        .expect("minimal chat");

    // Provenance is default-on and travels with the answer: the draft carries
    // the typed pack, never an opaque content string.
    let item = draft.retrieval.items.first().expect("an item");
    assert!(!item.provenance.source.is_empty());
    assert!(!item.provenance.source_revision_ids.is_empty());

    let json = serde_json::to_value(&draft).expect("serialize draft");
    assert_eq!(json["depth"], "minimal");
    assert_eq!(json["tokens_used"], 0_u32);
    assert_eq!(json["retrieval"]["pack_version"], MEMORY_PACK_VERSION);
    assert!(json["retrieval"]["items"][0]["provenance"].is_object());
    assert!(json["retrieval"]["scope_honesty"].is_object());
    assert!(json["retrieval"]["retrieval_meta"].is_object());

    let round_tripped: ChatDraft = serde_json::from_value(json).expect("deserialize draft");
    assert_eq!(round_tripped, draft);
}
