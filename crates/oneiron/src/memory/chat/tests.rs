//! `.chat` acceptance tests: depth→effort mapping, composer call counts, the
//! zero-model minimal tier, the typed refusals, and the answered-or-abstained
//! outcome with the citation gate that decides between them.
//!
//! The composer is a counting stub, so "exactly once" and "never" are
//! assertions rather than commentary, and every call runs against a real
//! seeded vault so `chat` is proven to ride the real `recall` body and the
//! real hydration surface.

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

/// A provider-neutral composer that records what it was handed and answers
/// exactly as the test told it to. It holds no vault handle because the seam
/// gives it none.
struct CountingComposer {
    calls: AtomicUsize,
    seen: Mutex<Vec<ComposerCall>>,
    /// Answer text; `None` composes the default sentence.
    answer: Option<String>,
    /// Citations to propose; `None` cites every item in the pack it was given.
    sources: Option<Vec<String>>,
    gaps: Vec<String>,
    declined: bool,
    tokens_used: u32,
}

impl Default for CountingComposer {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            answer: None,
            sources: None,
            gaps: Vec::new(),
            declined: false,
            tokens_used: 42,
        }
    }
}

impl CountingComposer {
    /// A composer proposing exactly these citations.
    fn citing(sources: &[&str]) -> Self {
        let mut proposed = Vec::new();
        for source in sources {
            proposed.push((*source).to_owned());
        }
        Self {
            sources: Some(proposed),
            ..Self::default()
        }
    }

    /// A composer returning exactly this answer text.
    fn answering(answer: &str) -> Self {
        Self {
            answer: Some(answer.to_owned()),
            ..Self::default()
        }
    }

    /// A composer that refuses, having already spent tokens deciding to.
    fn declining() -> Self {
        Self {
            declined: true,
            gaps: vec!["the host would not answer".to_owned()],
            ..Self::default()
        }
    }

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
    ) -> MemoryResult<ComposedChatAnswer> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let call = ComposerCall {
            question: request.question.to_owned(),
            depth: request.depth,
            items: request.pack.items.len(),
            deep_pending: request.pack.retrieval_meta.deep_pending,
            lease: lease.map(|lease| lease.id().to_owned()),
        };
        self.seen.lock().expect("composer log").push(call);
        let answer = match &self.answer {
            Some(answer) => answer.clone(),
            None => format!("composed {} answer", request.depth.as_str()),
        };
        let source_short_ids = match &self.sources {
            Some(sources) => sources.clone(),
            None => pack_short_ids(request.pack),
        };
        Ok(ComposedChatAnswer {
            answer,
            source_short_ids,
            gaps: self.gaps.clone(),
            tokens_used: self.tokens_used,
            declined: self.declined,
        })
    }
}

/// The parts of an answered outcome, so assertions read as prose.
struct Answered {
    answer: String,
    source_short_ids: Vec<String>,
    gaps: Vec<String>,
    tokens_used: u32,
    depth: ChatDepth,
    retrieval: MemoryPack,
}

/// The parts of an abstained outcome.
struct Abstained {
    reason: ChatAbstentionReason,
    gaps: Vec<String>,
    tokens_used: u32,
}

/// Unwraps an answered outcome; an abstention fails the test instead.
fn expect_answered(response: ChatResponse) -> Answered {
    match response {
        ChatResponse::Answered {
            answer,
            source_short_ids,
            gaps,
            tokens_used,
            depth,
            retrieval,
        } => Answered {
            answer,
            source_short_ids,
            gaps,
            tokens_used,
            depth,
            retrieval,
        },
        other => panic!("expected an answered response, got {other:?}"),
    }
}

/// Unwraps an abstained outcome; an answer fails the test instead.
fn expect_abstained(response: ChatResponse) -> Abstained {
    match response {
        ChatResponse::Abstained { reason, gaps, tokens_used } => Abstained {
            reason,
            gaps,
            tokens_used,
        },
        other => panic!("expected an abstained response, got {other:?}"),
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

/// The same, with two separately citable messages in the turn.
fn seeded_pair(seed: u8, one: &str, two: &str) -> (tempfile::TempDir, crate::Vault, EntityId) {
    let (dir, vault) = open_vault();
    let actor = put_person(&vault, seed);
    let conversation = EntityId::from_bytes([seed ^ 0xFF; 16]).expect("conversation id");
    facade_for(&vault, actor)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![
                witness_message(0, WitnessAuthor::User, one),
                witness_message(1, WitnessAuthor::User, two),
            ],
            occurred_at: 2100,
        })
        .expect("witness");
    (dir, vault, actor)
}

/// The short ids a plain minimal recall sees for `query`, in pack order.
fn recalled_short_ids(memory: &Memory<'_>, query: &str) -> Vec<String> {
    let scope = RecallScope::default();
    let pack = memory
        .recall(query, Effort::Minimal, &scope, 10, None, None)
        .expect("recall");
    pack_short_ids(&pack)
}

/// Recall scope over the whole vault: the ordinary shape most tests use.
fn whole_vault() -> ChatScope {
    ChatScope::Recall(RecallScope::default())
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

// ── minimal: zero-model, extractive, still sourced ──────────────────────

#[test]
fn chat_minimal_is_zero_model_extractive_and_never_calls_the_composer() {
    let (_dir, vault, actor) = seeded_vault(0x41, "the kiln reached cone six overnight");
    let memory = facade_for(&vault, actor);
    let composer = CountingComposer::default();

    // A composer supplied at minimal is structurally out of reach.
    let response = memory
        .chat(
            "kiln",
            ChatDepth::Minimal,
            ChatOptions {
                scope: whole_vault(),
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("minimal chat");

    assert_eq!(composer.calls(), 0, "minimal is zero-model");
    let answered = expect_answered(response);
    assert_eq!(answered.tokens_used, 0);
    assert_eq!(answered.depth, ChatDepth::Minimal);
    assert!(answered.gaps.is_empty());
    // No format was requested, so the pack is typed only.
    assert!(answered.retrieval.rendered.is_none());
    let first = answered.retrieval.items.first().expect("the message");
    assert_eq!(answered.answer, first.value_text);
    assert!(!answered.answer.is_empty());

    // A zero-model answer still shows its sources, and each one is an item of
    // the pack the answer was read out of.
    assert!(!answered.source_short_ids.is_empty());
    let items = &answered.retrieval.items;
    for source in &answered.source_short_ids {
        let in_pack = items.iter().any(|item| item.short_id == *source);
        assert!(in_pack, "{source} is in the pack");
    }

    // With a format the rendered pack IS the answer.
    let response = memory
        .chat(
            "kiln",
            ChatDepth::Minimal,
            ChatOptions {
                scope: whole_vault(),
                limit: 10,
                format: Some("md"),
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("minimal chat with a format");
    let rendered = expect_answered(response);
    assert_eq!(rendered.tokens_used, 0);
    let markdown = rendered.retrieval.rendered.as_deref().expect("md");
    assert_eq!(rendered.answer, markdown);
    assert!(!rendered.answer.is_empty());
    assert!(!rendered.source_short_ids.is_empty());
    assert_eq!(composer.calls(), 0);
}

#[test]
fn chat_minimal_on_an_empty_pack_abstains_with_insufficient_evidence() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x42);
    let memory = facade_for(&vault, actor);

    let response = memory
        .chat(
            "nothing in this vault matches",
            ChatDepth::Minimal,
            ChatOptions {
                scope: whole_vault(),
                limit: 5,
                format: None,
                lease: None,
                composer: None,
            },
        )
        .expect("an empty pack abstains, it does not error");

    // An empty answer string would leave the caller unable to tell "the vault
    // does not know" apart from "the answer is nothing".
    assert_eq!(
        response,
        ChatResponse::Abstained {
            reason: ChatAbstentionReason::InsufficientEvidence,
            gaps: Vec::new(),
            tokens_used: 0,
        }
    );
}

// ── standard/deep: the composer runs exactly once, after retrieval ──────

#[test]
fn chat_standard_invokes_the_composer_exactly_once_after_retrieval() {
    let (_dir, vault, actor) = seeded_vault(0x43, "the fjord aurora peaked just after midnight");
    let memory = facade_for(&vault, actor);
    let composer = CountingComposer::default();

    let response = memory
        .chat(
            "aurora",
            ChatDepth::Standard,
            ChatOptions {
                scope: whole_vault(),
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("standard chat");

    assert_eq!(composer.calls(), 1);
    let answered = expect_answered(response);
    assert_eq!(answered.answer, "composed standard answer");
    assert_eq!(answered.tokens_used, 42);
    assert_eq!(answered.depth, ChatDepth::Standard);
    assert!(answered.retrieval.retrieval_meta.deep_pending.is_none());
    assert!(!answered.source_short_ids.is_empty());

    let seen = composer.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].question, "aurora");
    assert_eq!(seen[0].depth, ChatDepth::Standard);
    assert_eq!(seen[0].lease, None);
    // The composer saw the retrieval, so it ran after it.
    assert_eq!(seen[0].items, answered.retrieval.items.len());
    assert!(seen[0].items > 0);
}

#[test]
fn chat_deep_requires_the_lease_and_propagates_deep_pending() {
    let (_dir, vault, actor) = seeded_vault(0x44, "the ridge trail washed out in the spring melt");
    let memory = facade_for(&vault, actor);
    let composer = CountingComposer::default();

    // The lease rule stays recall's: chat forwards and lets the typed gate
    // refuse, and the composer never runs behind a refused retrieval.
    let err = memory
        .chat(
            "ridge trail",
            ChatDepth::Deep,
            ChatOptions {
                scope: whole_vault(),
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
    let response = memory
        .chat(
            "ridge trail",
            ChatDepth::Deep,
            ChatOptions {
                scope: whole_vault(),
                limit: 10,
                format: None,
                lease: Some(&lease),
                composer: Some(&composer),
            },
        )
        .expect("leased deep chat");

    assert_eq!(composer.calls(), 1);
    let answered = expect_answered(response);
    assert_eq!(answered.depth, ChatDepth::Deep);
    assert_eq!(answered.answer, "composed deep answer");
    assert_eq!(answered.tokens_used, 42);
    // Honest propagation: the core still executed the standard body.
    let meta = &answered.retrieval.retrieval_meta;
    assert_eq!(meta.deep_pending, Some(true));

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

    let err = memory
        .chat(
            "harbour bell",
            ChatDepth::Standard,
            ChatOptions {
                scope: whole_vault(),
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
                scope: whole_vault(),
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

    // A blank question is refused ahead of every other check.
    for question in ["", "   ", "\t\n"] {
        let err = memory
            .chat(
                question,
                ChatDepth::Deep,
                ChatOptions {
                    scope: whole_vault(),
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
                scope: whole_vault(),
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

// ── the answer carries its evidence ─────────────────────────────────────

#[test]
fn chat_answer_carries_the_whole_memory_pack() {
    let (_dir, vault, actor) = seeded_vault(0x47, "the lighthouse keeper logged a supply run");
    let memory = facade_for(&vault, actor);

    let response = memory
        .chat(
            "lighthouse",
            ChatDepth::Minimal,
            ChatOptions {
                scope: whole_vault(),
                limit: 10,
                format: None,
                lease: None,
                composer: None,
            },
        )
        .expect("minimal chat");

    let json = serde_json::to_value(&response).expect("serialize");
    assert_eq!(json["outcome"], "answered");
    assert_eq!(json["depth"], "minimal");
    assert_eq!(json["tokensUsed"], 0_u32);
    assert!(json["sourceShortIds"].is_array());
    assert!(json["gaps"].is_array());
    assert_eq!(json["retrieval"]["pack_version"], MEMORY_PACK_VERSION);
    assert!(json["retrieval"]["items"][0]["provenance"].is_object());
    assert!(json["retrieval"]["scope_honesty"].is_object());
    assert!(json["retrieval"]["retrieval_meta"].is_object());

    let round_tripped: ChatResponse = serde_json::from_value(json).expect("deserialize");
    assert_eq!(round_tripped, response);

    // Provenance is default-on and travels with the answer: the response
    // carries the typed pack, never an opaque content string.
    let answered = expect_answered(response);
    let item = answered.retrieval.items.first().expect("an item");
    assert!(!item.provenance.source.is_empty());
    assert!(!item.provenance.source_revision_ids.is_empty());
}

#[test]
fn chat_answers_cite_short_ids_that_hydrate_back_out_of_the_pack() {
    let (_dir, vault, actor) = seeded_vault(0x48, "the ferry schedule changed for the winter");
    let memory = facade_for(&vault, actor);
    let composer = CountingComposer::default();

    let response = memory
        .chat(
            "ferry",
            ChatDepth::Standard,
            ChatOptions {
                scope: whole_vault(),
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("standard chat");

    let answered = expect_answered(response);
    assert!(!answered.source_short_ids.is_empty());
    let items = &answered.retrieval.items;
    for source in &answered.source_short_ids {
        let in_pack = items.iter().any(|item| item.short_id == *source);
        assert!(in_pack, "{source} is in the pack handed over");
    }

    // OF-096 round trip: a cited source is one the caller can open.
    let sources = &answered.source_short_ids;
    let views = memory.hydrate(sources).expect("hydrate sources");
    assert_eq!(views.len(), sources.len());
}

#[test]
fn chat_abstains_without_fabrication_when_the_citations_do_not_hold() {
    let (_dir, vault, actor) = seeded_vault(0x49, "the printing press jammed on the third run");
    let memory = facade_for(&vault, actor);

    // No citation, one the pack never carried, a blank one, and blank text:
    // each sinks the answer rather than quietly dropping the citation.
    for composer in [
        CountingComposer::citing(&[]),
        CountingComposer::citing(&["ms97:a1"]),
        CountingComposer::citing(&["   "]),
        CountingComposer::answering("   "),
    ] {
        let response = memory
            .chat(
                "printing press",
                ChatDepth::Standard,
                ChatOptions {
                    scope: whole_vault(),
                    limit: 10,
                    format: None,
                    lease: None,
                    composer: Some(&composer),
                },
            )
            .expect("standard chat");

        assert_eq!(composer.calls(), 1, "the composer did run");
        // No composed text escapes, and the tokens it already spent are still
        // reported: the caller is told what the attempt cost.
        assert_eq!(
            response,
            ChatResponse::Abstained {
                reason: ChatAbstentionReason::InsufficientEvidence,
                gaps: Vec::new(),
                tokens_used: 42,
            }
        );
    }
}

#[test]
fn chat_citations_dedupe_preserving_first_appearance() {
    let (_dir, vault, actor) = seeded_pair(
        0x4A,
        "the tide tables were reprinted",
        "the tide gauge was recalibrated",
    );
    let memory = facade_for(&vault, actor);
    let documents = recalled_short_ids(&memory, "tide");
    assert!(documents.len() >= 2, "two citable messages");
    let (first, second) = (documents[0].clone(), documents[1].clone());

    let composer = CountingComposer::citing(&[
        second.as_str(),
        first.as_str(),
        second.as_str(),
        first.as_str(),
    ]);
    let response = memory
        .chat(
            "tide",
            ChatDepth::Standard,
            ChatOptions {
                scope: ChatScope::Documents {
                    source_short_ids: vec![first.clone(), second.clone()],
                },
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("document chat");

    let answered = expect_answered(response);
    assert_eq!(answered.source_short_ids, vec![second, first]);
}

#[test]
fn chat_a_declining_composer_is_a_typed_abstention_not_an_error() {
    let (_dir, vault, actor) = seeded_vault(0x4B, "the archive index was rebuilt overnight");
    let memory = facade_for(&vault, actor);
    let composer = CountingComposer::declining();

    let response = memory
        .chat(
            "archive",
            ChatDepth::Standard,
            ChatOptions {
                scope: whole_vault(),
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("a decline is a value, not an error");

    assert_eq!(composer.calls(), 1);
    assert_eq!(
        response,
        ChatResponse::Abstained {
            reason: ChatAbstentionReason::BackendDeclined,
            gaps: vec!["the host would not answer".to_owned()],
            tokens_used: 42,
        }
    );
}

// ── document scope: an allowlist, never a wider search ──────────────────

#[test]
fn chat_document_scope_reads_only_the_named_ids_and_cannot_leak() {
    let (_dir, vault, actor) = seeded_pair(
        0x4C,
        "the observatory dome was resealed",
        "the seed inventory was audited",
    );
    let memory = facade_for(&vault, actor);
    let document = recalled_short_ids(&memory, "observatory")
        .first()
        .expect("the observatory message")
        .clone();
    let outsider = recalled_short_ids(&memory, "inventory")
        .into_iter()
        .find(|short_id| *short_id != document)
        .expect("the inventory message");

    let composer = CountingComposer::default();
    let response = memory
        .chat(
            "what happened at the observatory?",
            ChatDepth::Standard,
            ChatOptions {
                scope: ChatScope::Documents {
                    source_short_ids: vec![document.clone(), document.clone()],
                },
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("document chat");

    assert_eq!(composer.calls(), 1);
    let seen = composer.seen();
    assert_eq!(seen[0].items, 1, "the duplicate id was read once");
    let answered = expect_answered(response);
    assert_eq!(answered.source_short_ids, vec![document.clone()]);
    assert!(answered.gaps.is_empty());
    // Only the named document was read: the rest of the vault is not evidence
    // here, however well it matches the question.
    assert_eq!(answered.retrieval.items.len(), 1);
    assert_eq!(answered.retrieval.items[0].short_id, document);
    assert!(!answered.retrieval.items[0].value_text.is_empty());
    assert!(answered.retrieval.rendered.is_none());

    // A composer reaching for a document outside the allowlist gets nothing:
    // the pack it was handed never carried that id.
    let leaking = CountingComposer::citing(&[outsider.as_str()]);
    let response = memory
        .chat(
            "what happened at the observatory?",
            ChatDepth::Standard,
            ChatOptions {
                scope: ChatScope::Documents {
                    source_short_ids: vec![document],
                },
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&leaking),
            },
        )
        .expect("document chat");
    assert_eq!(
        response,
        ChatResponse::Abstained {
            reason: ChatAbstentionReason::InsufficientEvidence,
            gaps: Vec::new(),
            tokens_used: 42,
        }
    );
}

#[test]
fn chat_document_scope_without_a_resolving_document_abstains() {
    let (_dir, vault, actor) = seeded_vault(0x4D, "the cellar humidity log was updated");
    let memory = facade_for(&vault, actor);
    let composer = CountingComposer::default();

    let response = memory
        .chat(
            "cellar",
            ChatDepth::Standard,
            ChatOptions {
                scope: ChatScope::Documents {
                    source_short_ids: vec!["ms97:a1".to_owned(), "ms97:a1".to_owned()],
                },
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("an unresolved document is not an error");

    assert_eq!(composer.calls(), 0, "nothing in scope");
    let abstained = expect_abstained(response);
    assert_eq!(abstained.reason, ChatAbstentionReason::NoInScopeDocuments);
    assert_eq!(abstained.tokens_used, 0);
    // Deduped on first appearance: one ref asked for, one gap named.
    assert_eq!(abstained.gaps.len(), 1);
    assert!(abstained.gaps[0].contains("ms97:a1"));

    // An empty allowlist is not "everything": it never falls back to recall,
    // although the vault plainly holds a cellar message.
    let response = memory
        .chat(
            "cellar",
            ChatDepth::Standard,
            ChatOptions {
                scope: ChatScope::Documents {
                    source_short_ids: Vec::new(),
                },
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("an empty allowlist abstains");
    assert_eq!(
        response,
        ChatResponse::Abstained {
            reason: ChatAbstentionReason::NoInScopeDocuments,
            gaps: Vec::new(),
            tokens_used: 0,
        }
    );
    assert_eq!(composer.calls(), 0);

    // A ref that is no OF-096 ref at all stays the caller's typed refusal.
    let err = memory
        .chat(
            "cellar",
            ChatDepth::Standard,
            ChatOptions {
                scope: ChatScope::Documents {
                    source_short_ids: vec!["not a ref".to_owned()],
                },
                limit: 10,
                format: None,
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect_err("a malformed ref");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
}

#[test]
fn chat_document_scope_bounds_the_read_and_refuses_an_unknown_format() {
    let (_dir, vault, actor) = seeded_pair(
        0x4E,
        "the aqueduct survey was filed",
        "the aqueduct valve was replaced",
    );
    let memory = facade_for(&vault, actor);
    let documents = recalled_short_ids(&memory, "aqueduct");
    assert!(documents.len() >= 2, "two citable messages");

    // The limit bounds the read, and what it left out is said out loud.
    let response = memory
        .chat(
            "aqueduct",
            ChatDepth::Minimal,
            ChatOptions {
                scope: ChatScope::Documents {
                    source_short_ids: documents.clone(),
                },
                limit: 1,
                format: None,
                lease: None,
                composer: None,
            },
        )
        .expect("bounded document chat");
    let answered = expect_answered(response);
    assert_eq!(answered.source_short_ids, vec![documents[0].clone()]);
    assert_eq!(answered.retrieval.items.len(), 1);
    assert_eq!(answered.gaps.len(), documents.len() - 1);
    assert!(answered.gaps[0].contains("limit"));
    assert!(answered.gaps[0].contains(&documents[1]));

    // A format the engine does not know is refused before a single document
    // is read, exactly as recall refuses it.
    let err = memory
        .chat(
            "aqueduct",
            ChatDepth::Minimal,
            ChatOptions {
                scope: ChatScope::Documents {
                    source_short_ids: documents,
                },
                limit: 10,
                format: Some("docx"),
                lease: None,
                composer: None,
            },
        )
        .expect_err("unknown format");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
    assert!(err.message.contains("docx"));
}

#[test]
fn chat_document_scope_renders_the_requested_format_over_only_the_named_ids() {
    let (_dir, vault, actor) = seeded_pair(
        0x4F,
        "the telescope mirror was recoated",
        "the greenhouse boiler was serviced",
    );
    let memory = facade_for(&vault, actor);
    let document = recalled_short_ids(&memory, "telescope")
        .first()
        .expect("the telescope message")
        .clone();
    let outsider = recalled_short_ids(&memory, "greenhouse")
        .into_iter()
        .find(|short_id| *short_id != document)
        .expect("the greenhouse message");

    // Every OF-096 format the engine knows renders, through the serializer
    // recall renders through: the pack carries the document's own short ref
    // and its text, and at minimal depth that rendering IS the answer.
    for format in ["toon", "md", "json", "yaml", "txt"] {
        let response = memory
            .chat(
                "what happened to the telescope?",
                ChatDepth::Minimal,
                ChatOptions {
                    scope: ChatScope::Documents {
                        source_short_ids: vec![document.clone()],
                    },
                    limit: 10,
                    format: Some(format),
                    lease: None,
                    composer: None,
                },
            )
            .expect("rendered document chat");

        let answered = expect_answered(response);
        let Some(rendered) = answered.retrieval.rendered.as_deref() else {
            panic!("{format} renders a pack");
        };
        assert!(rendered.contains(&document), "{format} shows the ref");
        assert!(
            rendered.contains("telescope mirror was recoated"),
            "{format} shows the document text"
        );
        assert_eq!(answered.answer, rendered, "{format} answers");
        assert_eq!(answered.tokens_used, 0, "{format} stays zero-model");

        // The allowlist bounds the rendering too: what the caller did not name
        // is not in it, however well the rest of the vault fits the question.
        assert!(!rendered.contains(&outsider), "{format} leaks no ref");
        assert!(
            !rendered.contains("greenhouse boiler"),
            "{format} leaks no out-of-scope text"
        );
        // And a rendered answer still stands on the in-scope ids alone.
        assert_eq!(answered.source_short_ids, vec![document.clone()]);
    }

    // Optionality is preserved: no format asked for, nothing rendered, and
    // the answer falls back to the document's own text.
    let response = memory
        .chat(
            "what happened to the telescope?",
            ChatDepth::Minimal,
            ChatOptions {
                scope: ChatScope::Documents {
                    source_short_ids: vec![document],
                },
                limit: 10,
                format: None,
                lease: None,
                composer: None,
            },
        )
        .expect("document chat without a format");
    let plain = expect_answered(response);
    assert!(plain.retrieval.rendered.is_none());
    assert_eq!(plain.answer, plain.retrieval.items[0].value_text);
}

#[test]
fn chat_document_scope_cites_the_named_ids_with_the_rendered_pack_present() {
    let (_dir, vault, actor) = seeded_pair(
        0x50,
        "the weather station anemometer was replaced",
        "the pantry inventory was counted",
    );
    let memory = facade_for(&vault, actor);
    let document = recalled_short_ids(&memory, "anemometer")
        .first()
        .expect("the weather station message")
        .clone();
    let composer = CountingComposer::default();

    let response = memory
        .chat(
            "what was replaced at the weather station?",
            ChatDepth::Standard,
            ChatOptions {
                scope: ChatScope::Documents {
                    source_short_ids: vec![document.clone()],
                },
                limit: 10,
                format: Some("json"),
                lease: None,
                composer: Some(&composer),
            },
        )
        .expect("rendered document chat");

    assert_eq!(composer.calls(), 1);
    let answered = expect_answered(response);
    // With a composer in play the rendering is evidence, not the answer, and
    // the citations are checked against that same rendered pack.
    assert_eq!(answered.answer, "composed standard answer");
    assert_eq!(answered.source_short_ids, vec![document.clone()]);
    assert!(answered.gaps.is_empty());
    let rendered = answered.retrieval.rendered.as_deref().expect("json");
    assert!(rendered.contains(&document));
    assert!(rendered.contains("anemometer was replaced"));
}

// ── the wire contract ───────────────────────────────────────────────────

#[test]
fn chat_abstention_wire_tags_and_reasons_are_exact() {
    for (reason, tag) in [
        (
            ChatAbstentionReason::InsufficientEvidence,
            "insufficient_evidence",
        ),
        (
            ChatAbstentionReason::NoInScopeDocuments,
            "no_in_scope_documents",
        ),
        (ChatAbstentionReason::BackendDeclined, "backend_declined"),
    ] {
        let response = ChatResponse::Abstained {
            reason,
            gaps: vec!["missing timeframe".to_owned()],
            tokens_used: 7,
        };
        let json = serde_json::to_value(&response).expect("serialize");
        assert_eq!(json["outcome"], "abstained");
        assert_eq!(json["reason"], tag);
        assert_eq!(json["tokensUsed"], 7_u32);
        assert_eq!(json["gaps"][0], "missing timeframe");
        // No answer text rides along on an abstention.
        assert!(json.get("answer").is_none());

        let round_tripped: ChatResponse = serde_json::from_value(json).expect("deserialize");
        assert_eq!(round_tripped, response);
    }
}
