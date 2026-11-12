//! L9-11 (ARCH-0004 #rerank-door-open): a MESSAGE whose words live in its
//! entity document is reranked at those words. A new MESSAGE keeps its words
//! inline in its row; its document is born at its first later edit (FIX
//! 4840): a nonempty continuation of its stream, or the owner moving its text
//! to the document plane. The revision the ledger then indexes it at is that
//! document's birth frontier, which pins the words. The paid recall's
//! reranker is sent the message with them, and its scores bind to them.
//! Before, every MESSAGE with a document head was set aside unscored
//! (`pipeline/execution/channels/rerank.rs`, `BoundWords::UNSCORED`): the
//! reranker never saw it, and it kept its fusion rank. Each test asserts the
//! message owns a document head before it recalls, so a message that keeps
//! its words inline cannot pass it.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test rerank_document_message`
#![cfg(all(feature = "sync", feature = "test-support"))]

use std::sync::Mutex;
use std::time::Instant;

use oneiron::entity_doc::{DocAuthorization, TextField};
use oneiron::llm::WorkCancel;
use oneiron::memory::{
    Memory, MemoryResult, MessageWriteMode, RecallEffort, RecallRequest, RecallRerank,
    RecallRerankHost, RerankDocument, RerankEgress, RerankReport, RerankScores, WitnessAssertions,
    WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{RecallDoor, recall_at_door};
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, EdgeActorClass, EntityId, Vault, VaultConfig,
    WriteActor,
};

/// The streamed message's words: the best lexical match for the query.
const STREAMED: &str = "lantern lantern: the lantern wick is trimmed";

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    bind_host_owner(&vault, &test_host_issuer(), owner).expect("owner host binding");
    (directory, vault)
}

fn owner_memory(vault: &Vault) -> Memory<'_> {
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    vault.memory(owner, EdgeActorClass::Human)
}

/// One turn of one user message holding `content`.
fn one_message_turn(vault: &Vault, content: &str) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: Some(EntityId::now().to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(EntityId::now().to_hex()),
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: content.to_owned(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: vault.now_recorded_at(),
        assertions: WitnessAssertions::default(),
    }
}

/// A host reranker that records each document it is sent, with its words,
/// and scores the streamed words highest.
struct RecordingReranker {
    lease: BudgetLease,
    sent: Mutex<Vec<(EntityId, String)>>,
}

impl RecallRerankHost for RecordingReranker {
    fn lease(&self) -> &BudgetLease {
        &self.lease
    }

    fn score(
        &self,
        _query: &str,
        documents: &[RerankDocument<'_>],
        _egress: &RerankEgress<'_>,
        _answer_at: Option<Instant>,
        _cancel: Option<WorkCancel>,
    ) -> MemoryResult<RerankScores> {
        self.sent.lock().expect("sent documents").extend(
            documents
                .iter()
                .map(|document| (document.id, document.text.to_owned())),
        );
        Ok(RerankScores {
            scores: documents
                .iter()
                .map(|document| match document.text {
                    text if text.contains("wick is trimmed") => 30.0,
                    text if text.contains("shop") => 10.0,
                    text if text.contains("repair kit") => 7.0,
                    _ => 1.0,
                })
                .collect(),
            model: "test/reranker@v1".to_owned(),
            served_model: None,
        })
    }
}

/// Two witnessed turns and an atomically streamed MESSAGE holding
/// [`STREAMED`], which it keeps inline in its row (FIX 4840).
fn streamed_message(vault: &Vault) -> EntityId {
    let memory = owner_memory(vault);
    memory
        .witness(&one_message_turn(vault, "a lantern shop that sells wicks"))
        .expect("witness the shop turn");
    memory
        .witness(&one_message_turn(
            vault,
            "the lantern repair kit is on the shelf",
        ))
        .expect("witness the repair kit turn");
    let stream = memory
        .begin_message_stream(&one_message_turn(vault, ""), Some(MessageWriteMode::Atomic))
        .expect("open a MESSAGE stream");
    memory
        .append_to_stream(stream, STREAMED)
        .expect("the stream takes the words");
    memory.finalize_stream(stream).expect("finalize the stream");
    stream.message_id()
}

/// The precondition: `message`'s words are in its entity document.
fn assert_document_headed(vault: &Vault, message: &EntityId) {
    let head = vault
        .entity_document_head(message)
        .expect("the message owns an entity document head");
    assert_eq!(head.field, TextField::MapField("content".to_owned()));
    let text = vault.entity_text(message).expect("the document's text");
    assert!(
        text.contains("wick is trimmed"),
        "the document holds the streamed words: {text:?}",
    );
}

/// A paid recall for lanterns: the reranker is sent `message` at its
/// document words, and those words, scored highest, lead the pack.
fn assert_reranked_at_document_words(vault: &Vault, message: EntityId) {
    let memory = owner_memory(vault);
    let host = RecordingReranker {
        lease: BudgetGuard::new(
            "rerank-document-message",
            100_000,
            BudgetExhaustionPolicy::Suspend,
        )
        .admit()
        .expect("a lease")
        .lease,
        sent: Mutex::default(),
    };
    let pack = recall_at_door(
        &memory,
        RecallRequest {
            query: "lantern".to_owned(),
            effort: Some(RecallEffort::High),
            limit: Some(10),
            ..RecallRequest::default()
        },
        |_| None,
        &RecallDoor {
            hyde: None,
            arrived: Instant::now(),
            on_cut: None,
            rerank: RecallRerank::Host(&host),
        },
    )
    .expect("recall");

    let sent = host.sent.lock().expect("sent documents");
    let items: Vec<(&str, &str)> = pack
        .items
        .iter()
        .map(|item| (item.kind.as_str(), item.value_text.as_str()))
        .collect();
    assert!(
        sent.iter()
            .any(|(id, text)| *id == message && text.contains("wick is trimmed")),
        "the reranker is sent the message {} at its document words; it was sent {sent:?}; the pack holds {items:?}",
        message.to_hex(),
    );
    assert!(
        matches!(
            pack.retrieval_meta.rerank,
            Some(RerankReport::Applied { .. })
        ),
        "{:?}",
        pack.retrieval_meta.rerank,
    );
    assert!(
        items
            .first()
            .is_some_and(|(_, text)| text.contains("wick is trimmed")),
        "the document words, scored highest, lead the pack: {items:?}",
    );
}

/// The owner moves the message's text to the document plane: the birth
/// rewrites its row to a pointer with no words.
#[test]
fn a_migrated_message_is_reranked_at_its_document_words() {
    let (_directory, vault) = fresh_vault();
    let message = streamed_message(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    vault
        .migrate_entity_text(
            &message,
            &TextField::MapField("content".to_owned()),
            WriteActor::new(owner, EdgeActorClass::Human),
            &DocAuthorization::Owner(&proof),
        )
        .expect("the owner moves the message's words into its document");
    assert_document_headed(&vault, &message);
    assert_reranked_at_document_words(&vault, message);
}

/// A nonempty continuation of the message's stream births its document
/// (FIX 4840), the path a model continuing its reply takes.
#[test]
fn a_continued_message_is_reranked_at_its_document_words() {
    let (_directory, vault) = fresh_vault();
    let message = streamed_message(&vault);
    let memory = owner_memory(&vault);
    let continuation = memory
        .begin_message_continuation(&message, Some(MessageWriteMode::Atomic))
        .expect("open a continuation of the message");
    memory
        .append_to_stream(continuation, " and the glass is clean")
        .expect("the continuation takes more words");
    memory
        .finalize_stream(continuation)
        .expect("finalize the continuation");
    assert_document_headed(&vault, &message);
    assert_reranked_at_document_words(&vault, message);
}
