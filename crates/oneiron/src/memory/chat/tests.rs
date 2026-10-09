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

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
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
            retrieval: *retrieval,
        },
        other => panic!("expected an answered response, got {other:?}"),
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
        .recall(query, Effort::Light, &scope, 10, None, None)
        .expect("recall");
    pack.items
        .iter()
        .filter(|item| item.value_text.contains(query))
        .map(MemoryItem::reference)
        .collect()
}

/// Recall scope over the whole vault: the ordinary shape most tests use.
fn whole_vault() -> ChatScope {
    ChatScope::Recall(RecallScope::default())
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
            ChatDepth::Light,
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
    assert_eq!(answered.depth, ChatDepth::Light);
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
        let in_pack = items.iter().any(|item| item.reference() == *source);
        assert!(in_pack, "{source} is in the pack");
    }

    // With a format the rendered pack IS the answer.
    let response = memory
        .chat(
            "kiln",
            ChatDepth::Light,
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

// ── the answer carries its evidence ─────────────────────────────────────

#[test]
fn chat_answers_cite_short_ids_that_hydrate_back_out_of_the_pack() {
    let (_dir, vault, actor) = seeded_vault(0x48, "the ferry schedule changed for the winter");
    let memory = facade_for(&vault, actor);
    let composer = CountingComposer::default();

    let response = memory
        .chat(
            "ferry",
            ChatDepth::Medium,
            ChatOptions {
                // The TURN below comes back because the scope names it.
                scope: ChatScope::Recall(RecallScope {
                    kinds: Some(vec!["MESSAGE".to_owned(), "TURN".to_owned()]),
                    ..RecallScope::default()
                }),
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
        let in_pack = items.iter().any(|item| item.reference() == *source);
        assert!(in_pack, "{source} is in the pack handed over");
    }

    // OF-096 round trip: a cited source is one the caller can open.
    let sources = &answered.source_short_ids;
    let views = memory.hydrate(sources).expect("hydrate sources");
    assert_eq!(views.len(), sources.len());

    // A structural TURN has no editable text leaves. Its implicit pack pin
    // must still survive a later metadata write, without an explicit pin call.
    let turn = views.iter().find(|view| view.kind == "TURN").unwrap();
    let id = EntityId::from_hex(&turn.id_hex).unwrap();
    let raw = vault
        .get_raw_with_mode(&id, crate::vault::ReadMode::Live)
        .unwrap()
        .unwrap();
    let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
    let learned_at = header.learned_at.checked_add(1).unwrap();
    vault
        .batch()
        .put(
            &id,
            header.entity_type,
            crate::TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at,
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )
        .commit()
        .unwrap();
    assert_eq!(
        memory
            .get_entity(&turn.id_hex)
            .unwrap()
            .value
            .unwrap()
            .learned_at,
        learned_at
    );
    assert_eq!(memory.hydrate(sources).unwrap(), views);
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
                ChatDepth::Medium,
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

// ── document scope: an allowlist, never a wider search ──────────────────

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
                ChatDepth::Light,
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
            ChatDepth::Light,
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
