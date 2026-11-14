//! L2-08 (ARCH-0026 #sieve-open): words a TURN's edges, a deleted MESSAGE or
//! a document edit change reach the turn's listeners. A witnessed TURN's words
//! are its MESSAGE children by `PartOf`, each read with its `BelongsTo` and its
//! speaker's `AuthoredBy`. An edge write that links a MESSAGE into the turn,
//! or binds another speaker to one of its MESSAGEs, changes what the turn says
//! with no write to the turn or to any MESSAGE's text. Before, no door told the
//! Dreamer, the sieve, the projector, the tagger or the embedder: a turn a
//! round had already read stayed read at its old words. Now the edge's own
//! commit admits the turn as a TURN whose words changed: a turn a round may
//! have read (a scope's watermark passed it) takes a re-dirty carrier, pending
//! for every consolidation scope, as a TURN put behind a watermark does; the
//! sieve and the projector owe it a read; and the tagger and the embedder mark
//! it at its new words.
//!
//! A witnessed MESSAGE's own bindings are fixed (`memory/witness/validation.rs`:
//! a new parent or actor is a refusal), so no edge door takes one out of its
//! turn; its author deleting it does. The erase hook already owed the sieve a
//! read of the words the turn keeps; now a turn a round read is pending again
//! for every scope too. A document edit of a MESSAGE inside a turn a round
//! read ("an edit after consolidation") re-dirtied nothing for consolidation
//! either; it is admitted the same way now.
//!
//! The carrier and the embedding marker have no public read, and a round's
//! watermark is settled without a model; all three go through the test door
//! `oneiron::test_doors::turn_words`.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test turn_words_edge_rewire`
#![cfg(all(oneiron_test_support, feature = "test-support"))]
#![allow(clippy::expect_used)]

use oneiron::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, TextField};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::turn_words::{
    embedding_marker, redirty_pending, settle_every_scope_on_turn,
};
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::{
    DeleteReason, EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
}

/// A fresh vault and its embedded owner; `embedder` configures an embedding
/// model, so a turn owes a vector of its words.
fn fixture(embedder: bool) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    if embedder {
        config.embedding_model = Some("test/model@v1".to_owned());
    }
    let vault = Vault::open(dir.path(), config).expect("fresh vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    Fixture {
        _dir: dir,
        vault,
        owner,
    }
}

/// [`fixture`] with no embedder, its owner bound to the host, so the owner
/// can authenticate an act on a document.
fn bound_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    bind_host_owner(&vault, &test_host_issuer(), owner).expect("owner host binding");
    Fixture {
        _dir: dir,
        vault,
        owner,
    }
}

/// [`fixture`] with no embedder, opened as the process that owns the vault
/// (the writer lease the owner's doors ask for) and with its install's key
/// store loaded: a delete signs its receipt with the install's key.
fn deleting_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh owned vault");
    vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    Fixture {
        _dir: dir,
        vault,
        owner,
    }
}

impl Fixture {
    /// A turn the owner said, one MESSAGE per entry of `words`, in its own
    /// conversation: the turn's id and its MESSAGEs' ids in order. A new turn
    /// is new work on its own key, so it holds no re-dirty carrier.
    fn witness_turn(&self, words: &[&str]) -> (EntityId, Vec<EntityId>) {
        self.witness_turn_in(EntityId::now(), words)
    }

    /// [`Self::witness_turn`] in the conversation `room`.
    fn witness_turn_in(&self, room: EntityId, words: &[&str]) -> (EntityId, Vec<EntityId>) {
        let turn = EntityId::now();
        let ids: Vec<EntityId> = words.iter().map(|_| EntityId::now()).collect();
        let messages = words
            .iter()
            .zip(&ids)
            .zip(0_u32..)
            .map(|((content, id), order)| WitnessMessage {
                id: Some(id.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: (*content).to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order,
                quote: None,
            })
            .collect();
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .witness(&WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: None,
                messages,
                occurred_at: self.vault.now_recorded_at(),
                assertions: WitnessAssertions::default(),
            })
            .expect("witness the turn");
        assert!(
            !self.redirty_pending(&turn),
            "a newly witnessed turn holds no re-dirty carrier"
        );
        (turn, ids)
    }

    /// Every scope's watermark settled on `turn`, as rounds that read it
    /// leave it. Settling moves no carrier.
    fn read_by_every_scope(&self, turn: &EntityId) {
        settle_every_scope_on_turn(&self.vault, turn).expect("settle the watermarks");
        assert!(
            !self.redirty_pending(turn),
            "a settled watermark puts no carrier"
        );
    }

    fn redirty_pending(&self, turn: &EntityId) -> bool {
        redirty_pending(&self.vault, turn).expect("read the re-dirty carrier")
    }

    fn person(&self, name: &str) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
            )
            .expect("a person");
        id
    }
}

/// The author deletes a MESSAGE of a turn every scope has read with
/// `reason`: the turn keeps its row and its other words, and is pending again
/// for every consolidation scope.
fn a_message_deleted_from_a_read_turn_re_dirties_the_turn(reason: DeleteReason) {
    let fixture = deleting_fixture();
    let room = EntityId::now();
    let (turn, messages) =
        fixture.witness_turn_in(room, &["the ferry leaves at nine", "bring the map"]);
    fixture.read_by_every_scope(&turn);

    fixture
        .vault
        .delete_room_record(
            room,
            messages[1],
            WriteActor::new(fixture.owner, EdgeActorClass::Human),
            reason,
        )
        .expect("the author deletes the second message");

    assert!(
        fixture.redirty_pending(&turn),
        "the read turn whose words lost a message is pending again ({reason:?})"
    );
}

/// A soft delete scrubs the MESSAGE's words and keeps its shell.
#[test]
fn a_message_deleted_from_a_read_turn_re_dirties_the_turn_on_a_soft_delete() {
    a_message_deleted_from_a_read_turn_re_dirties_the_turn(DeleteReason::UserDelete);
}

/// A hard delete takes the MESSAGE's row and its edges, its `PartOf` included.
#[test]
fn a_message_deleted_from_a_read_turn_re_dirties_the_turn_on_a_hard_delete() {
    a_message_deleted_from_a_read_turn_re_dirties_the_turn(DeleteReason::UserHardDelete);
}

/// A MESSAGE linked into another read turn adds its words there, and its
/// binding in its own read turn changes too: both turns are pending again.
#[test]
fn a_message_linked_into_a_second_read_turn_re_dirties_both_turns() {
    let fixture = fixture(false);
    let (turn, _) = fixture.witness_turn(&["the ferry leaves at nine"]);
    let (other, other_messages) = fixture.witness_turn(&["the harbour office opens at eight"]);
    // A watermark is a cursor: settled on the later turn, it has passed both.
    fixture.read_by_every_scope(&other);

    fixture
        .vault
        .put_edge(&other_messages[0], EdgeKind::PartOf, &turn, 1.0)
        .expect("link the other turn's message into the first turn");

    assert!(
        fixture.redirty_pending(&turn),
        "the read turn that gained a message is pending again"
    );
    assert!(
        fixture.redirty_pending(&other),
        "the read turn whose message is now part of a second turn is pending again"
    );
}

/// Another speaker bound to a member MESSAGE of a read turn changes who said
/// the turn's words: the turn is pending again.
#[test]
fn a_speaker_bound_to_a_member_message_re_dirties_the_read_turn() {
    let fixture = fixture(false);
    let (turn, messages) = fixture.witness_turn(&["the ferry leaves at nine"]);
    fixture.read_by_every_scope(&turn);
    let yuki = fixture.person("yuki");

    fixture
        .vault
        .put_edge(&messages[0], EdgeKind::AuthoredBy, &yuki, 1.0)
        .expect("bind another speaker to the message");

    assert!(
        fixture.redirty_pending(&turn),
        "the read turn whose speakers changed is pending again"
    );
}

/// The owner's document edit of a MESSAGE inside a read turn changes the
/// turn's words: the turn is pending again for every scope ("an edit after
/// consolidation").
#[test]
fn a_document_edit_of_a_read_turns_message_re_dirties_the_turn() {
    let fixture = bound_fixture();
    let (turn, messages) = fixture.witness_turn(&["the ferry leaves at nine"]);
    let proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let owner = WriteActor::new(fixture.owner, EdgeActorClass::Human);
    fixture
        .vault
        .migrate_entity_text(
            &messages[0],
            &TextField::MapField("content".to_owned()),
            owner,
            &DocAuthorization::Owner(&proof),
        )
        .expect("the owner moves the message's words into its document");
    fixture.read_by_every_scope(&turn);
    let end = fixture
        .vault
        .entity_text(&messages[0])
        .expect("the message's words")
        .chars()
        .count();

    fixture
        .vault
        .edit_entity_text(
            &messages[0],
            &[AnchoredEdit {
                actor: Some(owner),
                verb: EditVerb::ReplaceQuotedSpan {
                    span: fixture
                        .vault
                        .entity_text_anchor(&messages[0], 0, end)
                        .expect("the whole text"),
                    text: "the ferry leaves at ten".to_owned(),
                },
            }],
            &DocAuthorization::Owner(&proof),
            fixture.vault.now_recorded_at(),
        )
        .expect("the owner edits the message's words");

    assert!(
        fixture.redirty_pending(&turn),
        "the read turn whose message the owner edited is pending again"
    );
}

/// With an embedder configured, a turn that gains a MESSAGE owes a vector of
/// its new words, read or not: its embedding marker is written again at them.
/// A turn no round has passed takes no carrier: its own key is still ahead of
/// every round, which reads its new words there.
#[test]
fn a_turn_that_gains_a_message_is_marked_for_its_vector_at_its_new_words() {
    let fixture = fixture(true);
    let (turn, _) = fixture.witness_turn(&["the ferry leaves at nine"]);
    let witnessed = embedding_marker(&fixture.vault, &turn)
        .expect("read the marker")
        .expect("the witness marks the turn for its vector");
    let (_, other_messages) = fixture.witness_turn(&["bring the map"]);

    fixture
        .vault
        .put_edge(&other_messages[0], EdgeKind::PartOf, &turn, 1.0)
        .expect("link the other turn's message into the turn");

    let linked = embedding_marker(&fixture.vault, &turn)
        .expect("read the marker")
        .expect("the turn still owes a vector");
    assert_ne!(
        linked, witnessed,
        "the marker is written again at the turn's new words"
    );
    assert!(
        !fixture.redirty_pending(&turn),
        "a turn no round has passed takes no carrier"
    );
}

/// Control: an edge of a kind that binds no words, out of a member MESSAGE
/// of a read turn, leaves the turn as it was.
#[test]
fn an_edge_of_another_kind_leaves_the_read_turn_as_it_was() {
    let fixture = fixture(true);
    let (turn, messages) = fixture.witness_turn(&["the ferry leaves at nine"]);
    fixture.read_by_every_scope(&turn);
    let witnessed = embedding_marker(&fixture.vault, &turn).expect("read the marker");
    let owen = fixture.person("owen");

    fixture
        .vault
        .put_edge(&messages[0], EdgeKind::Mentions, &owen, 1.0)
        .expect("an edge of another kind");

    assert!(
        !fixture.redirty_pending(&turn),
        "an edge that binds no words re-dirties nothing"
    );
    assert_eq!(
        embedding_marker(&fixture.vault, &turn).expect("read the marker"),
        witnessed,
        "and marks nothing again"
    );
}
