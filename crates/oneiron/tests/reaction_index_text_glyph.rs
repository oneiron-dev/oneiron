//! A reaction's index text is its glyph alone on every path that indexes or
//! embeds a claim, not only at its own write (FIX
//! REACTION-GENERIC-INDEX-TEXT-REACTOR-ID; Engine ANSWERs
//! REACTION-REACTOR-ID-SURFACES = A, 17 Nov 03:15, and
//! REACTION-TEXT-REACTOR-NAME-INDEX = A, 20 Nov 17:12). The generic claim text
//! renders a non-string value whole, so a reaction published by the idle
//! publication pass, a room restage, a value redaction or an approval, or sent
//! to the embedder, carried its reactor's id (`by`, 16 bytes as decimal
//! tokens) and, for a mirrored one, its provider id. A reaction's echo is
//! connector metadata, never a second reaction, and is born with no text: it
//! indexes and embeds nothing.
//!
//! Bob reacts 👍 first-party and Carla's 🎉 arrives through the Slack mirror,
//! in a mirror room of the owner's; then the provider echoes Bob's 👍.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test reaction_index_text_glyph`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::claim::ClaimBody;
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::embed::{PendingEmbeddingPayload, payload_text};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::reaction::{
    PREDICATE_CONVERSATION_REACTION, PREDICATE_CONVERSATION_REACTION_ECHO, ReactionExternalId,
    ReactionIngress, ReactionInput, ReactionState,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::claim_publication_text::published_claim_text;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use rmpv::Value;

/// The mirror room's provider id: the Slack connector's room.
const MIRROR_ROOM: &str = "slack:room-1";
const CONNECTOR: &str = "slack";
const ROOM_WORDS: &str = "The zebras quilt at noon.";

struct Fixture {
    vault: Vault,
    bob: EntityId,
    carla: EntityId,
    /// Bob's first-party 👍.
    first_party: EntityId,
    /// Carla's 🎉, attested by the conversation mirror.
    mirrored: EntityId,
    /// The provider's echo of Bob's 👍.
    echo: EntityId,
    _dir: tempfile::TempDir,
}

fn person(vault: &Vault, id: EntityId, name: &str) {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("a PERSON body");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .expect("a PERSON");
}

fn human(person: EntityId) -> WriteActor {
    WriteActor::new(person, EdgeActorClass::Human)
}

fn generation(id: &str) -> ReactionExternalId {
    ReactionExternalId {
        connector: CONNECTOR.to_owned(),
        id: id.to_owned(),
    }
}

/// The owner's Slack mirror room with Bob and Carla, one MESSAGE of the
/// owner's, Bob's 👍 on it, Carla's mirrored 🎉, and the provider's echo of
/// Bob's 👍.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("a vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let bob = EntityId::now();
    let carla = EntityId::now();
    person(&vault, bob, "Bob");
    person(&vault, carla, "Carla");
    let room = EntityId::now();
    let body = ConversationBody {
        kind: ConversationKind::Mirror,
        external_id: Some(MIRROR_ROOM.to_owned()),
        ..Default::default()
    };
    vault
        .create_conversation(room, &body, human(owner), 1)
        .expect("the owner's mirror room");
    for (at, member) in [(2, owner), (3, bob), (4, carla)] {
        vault
            .join_member(room, member, human(owner), at, HistoryChoice::Share)
            .expect("a member joins the room");
    }
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            thread_audience: None,
            project: None,
            occurred_at: 10,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: ROOM_WORDS.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            assertions: WitnessAssertions::default(),
        })
        .expect("the owner's room MESSAGE");
    let first_party = vault
        .react(ReactionInput {
            message,
            by: bob,
            glyph: "👍".to_owned(),
            // A first-party reaction happens now: one more than five minutes
            // off the vault clock is refused.
            occurred_at: vault.now_recorded_at(),
            actor: human(bob),
        })
        .expect("Bob's 👍")
        .id;
    let mirrored = vault
        .ingest_reaction(ReactionIngress::ProviderAdd {
            message,
            by: carla,
            glyph: "🎉".to_owned(),
            occurred_at: 21,
            generation: generation("g-1"),
        })
        .expect("Carla's mirrored 🎉")
        .id;
    let echoed = vault
        .ingest_reaction(ReactionIngress::Echo {
            original: first_party,
            message,
            by: bob,
            glyph: "👍".to_owned(),
            generation: generation("echo-1"),
        })
        .expect("the provider's echo of Bob's 👍");
    assert_eq!(
        (echoed.id, echoed.state),
        (first_party, ReactionState::Replayed),
        "FIXTURE: the echo binds to Bob's 👍"
    );
    let echoes: Vec<EntityId> = vault
        .claims_for_subject(&first_party)
        .expect("the claims about Bob's 👍")
        .into_iter()
        .filter(|id| {
            vault
                .get_claim(id)
                .expect("a claim read")
                .is_some_and(|claim| claim.predicate == PREDICATE_CONVERSATION_REACTION_ECHO)
        })
        .collect();
    let [echo] = echoes[..] else {
        panic!("FIXTURE: one echo claim binds Bob's 👍: {echoes:?}");
    };
    Fixture {
        vault,
        bob,
        carla,
        first_party,
        mirrored,
        echo,
        _dir: dir,
    }
}

impl Fixture {
    fn claim(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("a claim read")
            .expect("the stored claim")
    }

    /// What the idle publication pass indexes for `id`.
    fn published(&self, id: EntityId) -> Vec<(String, String)> {
        published_claim_text(&self.vault, id)
            .expect("the published text of a stored claim")
            .expect("FIXTURE: the claim is surfaceable and publishes")
    }

    /// The text the embedder is sent for `id`.
    fn embedded(&self, id: EntityId) -> String {
        let raw = self
            .vault
            .get_raw(&id)
            .expect("a raw read")
            .expect("the stored claim row");
        let payload =
            PendingEmbeddingPayload::ClaimBody(raw[ENTITY_METADATA_HEADER_LEN..].to_vec());
        payload_text(&payload)
            .expect("the claim's embedding text")
            .into_owned()
    }
}

fn val(text: &str) -> Vec<(String, String)> {
    vec![("val".to_owned(), text.to_owned())]
}

/// The binary a value map holds under `key`.
fn binary_at<'a>(value: &'a Value, key: &str) -> Option<&'a [u8]> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries.iter().find_map(|(candidate, value)| match value {
        Value::Binary(bytes) if candidate.as_str() == Some(key) => Some(bytes.as_slice()),
        _ => None,
    })
}

/// The reaction rows themselves keep their reactor: only what is indexed and
/// embedded changes, never the stored claim (stored change: keep).
#[test]
fn the_stored_reactions_still_name_their_reactors() {
    let fixture = fixture();
    for (reaction, reactor) in [
        (fixture.first_party, fixture.bob),
        (fixture.mirrored, fixture.carla),
    ] {
        let claim = fixture.claim(reaction);
        assert_eq!(claim.predicate, PREDICATE_CONVERSATION_REACTION);
        assert_eq!(
            binary_at(&claim.value, "by"),
            Some(&reactor.as_bytes()[..]),
            "the stored reaction names its reactor under `by`"
        );
    }
}

/// The idle publication pass, which publishes a reaction's later revision that
/// staged no text, indexes Bob's 👍 by its glyph alone.
#[test]
fn a_first_party_reaction_publishes_its_glyph_alone() {
    let fixture = fixture();
    assert_eq!(
        fixture.published(fixture.first_party),
        val("👍"),
        "the published text holds no `by` and no time, only the glyph"
    );
}

/// The same for the mirrored 🎉, whose value also carries its provider id.
#[test]
fn a_mirrored_reaction_publishes_its_glyph_alone() {
    let fixture = fixture();
    assert_eq!(
        fixture.published(fixture.mirrored),
        val("🎉"),
        "the published text holds no `by` and no provider id, only the glyph"
    );
}

/// The embedder is sent each reaction's glyph alone.
#[test]
fn a_reactions_embedding_text_is_its_glyph_alone() {
    let fixture = fixture();
    assert_eq!(fixture.embedded(fixture.first_party), "👍");
    assert_eq!(fixture.embedded(fixture.mirrored), "🎉");
}

/// An echo, born with no text, publishes none and sends the embedder nothing.
#[test]
fn a_reaction_echo_publishes_and_embeds_no_text() {
    let fixture = fixture();
    assert_eq!(
        fixture.published(fixture.echo),
        Vec::<(String, String)>::new(),
        "the echo publishes no field"
    );
    assert_eq!(
        fixture.embedded(fixture.echo),
        "",
        "the echo embeds nothing"
    );
}
