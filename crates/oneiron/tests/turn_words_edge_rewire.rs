//! L2-08 (ARCH-0026 #sieve-open): words a TURN's edges change reach the
//! turn's listeners. A witnessed TURN's words are its MESSAGE children by
//! `PartOf`, each read with its `BelongsTo` and its speaker's `AuthoredBy`.
//! An edge write that unlinks a MESSAGE from the turn, links one into it, or
//! rebinds a MESSAGE's speaker changes what the turn says with no write to
//! the turn or to any MESSAGE's text. Before, no door told the Dreamer, the
//! sieve, the projector, the tagger or the embedder: a turn a round had
//! already read stayed read at its old words. Now the edge's own commit
//! admits the turn as a TURN whose words changed: a turn a round may have
//! read (a scope's watermark passed it) takes a re-dirty carrier, pending for
//! every consolidation scope, as a TURN put behind a watermark does; the
//! sieve and the projector owe it a read; and the tagger and the embedder
//! mark it at its new words.
//!
//! The carrier and the embedding marker have no public read, and a round's
//! watermark is settled without a model; all three go through the test door
//! `oneiron::test_doors::turn_words`.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test turn_words_edge_rewire`
#![cfg(oneiron_test_support)]
#![allow(clippy::expect_used)]

use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::turn_words::{
    embedding_marker, redirty_pending, settle_every_scope_on_turn,
};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig};

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

impl Fixture {
    /// A turn the owner said, one MESSAGE per entry of `words`, in its own
    /// conversation: the turn's id and its MESSAGEs' ids in order. A new turn
    /// is new work on its own key, so it holds no re-dirty carrier.
    fn witness_turn(&self, words: &[&str]) -> (EntityId, Vec<EntityId>) {
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
                conversation_ref: EntityId::now().to_hex(),
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

/// A MESSAGE unlinked from a turn every scope has read takes its words out
/// of the turn: the turn is pending again for every consolidation scope.
#[test]
fn a_message_unlinked_from_a_read_turn_re_dirties_the_turn() {
    let fixture = fixture(false);
    let (turn, messages) = fixture.witness_turn(&["the ferry leaves at nine", "bring the map"]);
    fixture.read_by_every_scope(&turn);

    let removed = fixture
        .vault
        .delete_edge(&messages[1], EdgeKind::PartOf, &turn)
        .expect("unlink the second message");

    assert!(removed, "the message was part of the turn");
    assert!(
        fixture.redirty_pending(&turn),
        "the read turn whose words lost a message is pending again"
    );
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

/// A member MESSAGE's speaker rebound in one batch, the old `AuthoredBy`
/// removed and a new one written, changes who said a read turn's words: the
/// turn is pending again.
#[test]
fn a_rebound_speaker_on_a_member_message_re_dirties_the_read_turn() {
    let fixture = fixture(false);
    let (turn, messages) = fixture.witness_turn(&["the ferry leaves at nine"]);
    fixture.read_by_every_scope(&turn);
    let yuki = fixture.person("yuki");

    fixture
        .vault
        .batch()
        .delete_edge(&messages[0], EdgeKind::AuthoredBy, &fixture.owner)
        .edge(&messages[0], EdgeKind::AuthoredBy, &yuki, 1.0)
        .commit()
        .expect("rebind the message's speaker");

    assert!(
        fixture.redirty_pending(&turn),
        "the read turn whose speaker changed is pending again"
    );
}

/// With an embedder configured, an unlinked turn owes a vector of its new
/// words, read or not: its embedding marker is written again at them. A turn
/// no round has passed takes no carrier: its own key is still ahead of every
/// round, which reads its new words there.
#[test]
fn a_rewired_turn_is_marked_for_its_vector_at_its_new_words() {
    let fixture = fixture(true);
    let (turn, messages) = fixture.witness_turn(&["the ferry leaves at nine", "bring the map"]);
    let witnessed = embedding_marker(&fixture.vault, &turn)
        .expect("read the marker")
        .expect("the witness marks the turn for its vector");

    fixture
        .vault
        .delete_edge(&messages[1], EdgeKind::PartOf, &turn)
        .expect("unlink the second message");

    let rewired = embedding_marker(&fixture.vault, &turn)
        .expect("read the marker")
        .expect("the turn still owes a vector");
    assert_ne!(
        rewired, witnessed,
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
