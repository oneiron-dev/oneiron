//! A reactor's id is gated like their name (FIX REACTION-REACTOR-ID-SURFACES;
//! Engine ANSWER REACTION-REACTOR-ID-SURFACES = A, 17 Nov 03:15). A pill
//! entry whose reactor's PERSON row the reader may not read carries no id:
//! the reaction still counts, and clients render `+1`. Mirela is confirmed
//! from the words of a relationship R, then reacts 👍 to an open MESSAGE in a
//! room the outsider (outside R) and a member of R both sit in. The outsider
//! reads the room MESSAGE and the reaction claim, but not Mirela's PERSON row;
//! the member of R reads all three.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test reaction_reactor_id_admission`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::access_grant::AccessGrantStatus;
use oneiron::access_grant::{AccessGrant, AccessGrantCapability, AccessGrantScope};
use oneiron::claim::ScopedReadActorKey;
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::embed::EmbedderLocality;
use oneiron::memory::extraction::{EncoderAttempt, EncoderInput, EncoderOutput, ExtractionEncoder};
use oneiron::memory::extraction::{ExtractionWork, NerSpan};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::reaction::{ReactionInput, ReactionPill, ReactionSignal};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::tagging::{MentionLink, TaggingMarkerConfig, TaggingMode, TaggingReconciler};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::{EdgeActorClass, EntityId, ModelId, Vault, VaultConfig, WriteActor};
use oneiron_authority::federation::scope_codec::read_preset;

const CHECKPOINT: &str = "0123456789abcdef";
/// The R MESSAGE: only R’s members read it. Mirela is named nowhere else.
const HIDDEN_WORDS: &str = "Mirela told Ada about the move.";
/// The open room MESSAGE the reactor reacts to.
const ROOM_WORDS: &str = "The zebras quilt at noon.";

/// A tagger that tags each name it knows as a `PERSON`, in every MESSAGE it is given.
struct Names {
    model: ModelId,
    known: &'static [&'static str],
}

impl ExtractionEncoder for Names {
    fn model_id(&self) -> &ModelId {
        &self.model
    }
    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }
    fn infer(&self, input: &EncoderInput, _work: ExtractionWork) -> EncoderAttempt {
        let mut spans = Vec::new();
        for (message, each) in input.messages.iter().enumerate() {
            for name in self.known {
                if let Some(start) = each.text.as_str().find(name) {
                    let span = NerSpan {
                        message,
                        start,
                        end: start + name.len(),
                        label: "PERSON".into(),
                        confidence: 0.9,
                    };
                    spans.push(span);
                }
            }
        }
        spans.sort_by_key(|span| (span.message, span.start));
        let output = EncoderOutput {
            spans,
            links: Vec::new(),
            vad: None,
            context_links: Vec::new(),
            speaker_links: Vec::new(),
            mood_parts: Vec::new(),
            stack_sha16: None,
        };
        EncoderAttempt {
            execution: None,
            panicked: false,
            result: Ok(output),
        }
    }
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// The member’s own read key: the key its Memory lane reads under.
fn key(reader: EntityId) -> ScopedReadActorKey {
    ScopedReadActorKey::with_actor_class(reader.to_hex(), "human")
        .expect("a member key")
        .require_access_grants(Some(reader))
}

struct Fixture {
    vault: Arc<Vault>,
    /// A member outside R.
    outsider: EntityId,
    /// A member of R, who reads R’s MESSAGEs on a live grant.
    insider: EntityId,
    /// The author of both MESSAGEs, whose signal feed hears of the reaction.
    speaker: EntityId,
    hidden_message: EntityId,
    room_message: EntityId,
    /// The PERSON confirmed from the name only the R MESSAGE holds.
    reactor: EntityId,
    /// Her 👍 claim on the room MESSAGE.
    reaction: EntityId,
    _dir: tempfile::TempDir,
}

/// Mirela confirmed from R’s words, then seated with the outsider and the member
/// of R in an open room, where Mirela reacts 👍 to the room’s open MESSAGE.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let outsider = EntityId::now();
    let insider = EntityId::now();
    let mut config = VaultConfig::device();
    config.tagging = Some(
        TaggingMarkerConfig::new(CHECKPOINT)
            .expect("checkpoint")
            .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
            .with_mode(TaggingMode::Save),
    );
    let members = [outsider.to_hex(), insider.to_hex()];
    let vault = Arc::new(open_member_vault(dir.path(), config, &members).expect("fixture vault"));
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            at(1),
            1,
            b"relationship",
        )
        .expect("a relationship");
    vault
        .put_entity(&outsider, ENTITY_TYPE_PERSON, at(1), 1, b"outsider")
        .expect("a member outside the relationship");
    vault
        .put_entity(&insider, ENTITY_TYPE_PERSON, at(1), 1, b"insider")
        .expect("a member of R");
    let grant = AccessGrant {
        principal_ref: insider,
        scope: AccessGrantScope::Messages {
            space_ref: relationship,
        },
        capability: AccessGrantCapability::MessagesRead,
        status: AccessGrantStatus::Active,
        created_at: 1,
        revoked_at: None,
        expires_at: None,
        authority_scope: read_preset(),
        companion_bounds: None,
    };
    vault
        .create_access_grant(&EntityId::now(), &grant)
        .expect("the member’s grant on its relationship");
    let speaker = EntityId::now();
    vault
        .put_entity(&speaker, ENTITY_TYPE_PERSON, at(1), 1, b"speaker")
        .expect("a speaker");
    let message = |id: EntityId, words: &str, metadata: Option<serde_json::Value>| WitnessMessage {
        id: Some(id.to_hex()),
        author: WitnessAuthor::User,
        message_type: "dialogue".into(),
        content: words.into(),
        parts: None,
        metadata,
        is_visible: true,
        order: 0,
        quote: None,
    };

    let turn = EntityId::now();
    let hidden_message = EntityId::now();
    let rel = serde_json::json!({"rel": relationship.to_hex()});
    let hidden = message(hidden_message, HIDDEN_WORDS, Some(rel));
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            project: None,
            messages: vec![hidden],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })
        .expect("witness");
    let model = "fixture/names@v1".parse().expect("model id");
    let tagger = Arc::new(Names {
        model,
        known: &["Mirela"],
    });
    TaggingReconciler::new(Arc::clone(&vault), tagger)
        .expect("reconciler")
        .drain_once()
        .expect("one tagging pass");
    let tags = vault
        .turn_tags(&turn)
        .expect("tags read")
        .expect("FIXTURE: the turn’s tags are saved");
    let reactor = tags
        .mentions
        .iter()
        .find_map(|mention| match &mention.link {
            MentionLink::Minted { entity, .. } if mention.message == hidden_message => {
                Some(*entity)
            }
            _ => None,
        })
        .expect("FIXTURE: the R MESSAGE’s name minted a provisional entity");
    vault
        .memory(speaker, EdgeActorClass::Human)
        .confirm_provisional_entity(&reactor)
        .expect("the speaker confirms the entity");

    let room = EntityId::now();
    let acting = WriteActor::new(speaker, EdgeActorClass::Human);
    let body = ConversationBody {
        kind: ConversationKind::Group,
        ..Default::default()
    };
    vault
        .create_conversation(room, &body, acting, 11)
        .expect("an open room");
    for (at, member) in [(12, speaker), (13, reactor), (14, outsider), (15, insider)] {
        vault
            .join_member(room, member, acting, at, HistoryChoice::Share)
            .expect("a member joins the room");
    }
    let room_message = EntityId::now();
    let open = message(room_message, ROOM_WORDS, None);
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            thread_audience: None,
            project: None,
            messages: vec![open],
            occurred_at: 20,
            assertions: WitnessAssertions::default(),
        })
        .expect("the room MESSAGE");
    let as_reactor = WriteActor::new(reactor, EdgeActorClass::Human);
    let input = ReactionInput {
        message: room_message,
        by: reactor,
        glyph: "👍".into(),
        occurred_at: vault.now_recorded_at(),
        actor: as_reactor,
    };
    let reaction = vault.react(input).expect("the reactor’s 👍").id;

    let fixture = Fixture {
        vault,
        outsider,
        insider,
        speaker,
        hidden_message,
        room_message,
        reactor,
        reaction,
        _dir: dir,
    };
    fixture.check_setup();
    fixture
}

impl Fixture {
    fn reads(&self, reader: EntityId, id: &EntityId) -> bool {
        self.vault
            .scoped_read(key(reader))
            .is_entity_readable(id)
            .expect("a member’s read")
    }

    /// The outsider reads the reaction claim but neither the R MESSAGE nor the PERSON
    /// named only in it; the member of R reads all three.
    fn check_setup(&self) {
        assert!(
            !self.reads(self.outsider, &self.hidden_message),
            "FIXTURE: the outsider does not read the R MESSAGE"
        );
        assert!(
            !self.reads(self.outsider, &self.reactor),
            "FIXTURE: the outsider does not read the PERSON named only in the R MESSAGE"
        );
        assert!(
            self.reads(self.outsider, &self.reaction),
            "FIXTURE: the outsider reads the reaction claim"
        );
        assert!(
            self.reads(self.insider, &self.hidden_message),
            "FIXTURE: the member of R reads the R MESSAGE"
        );
        assert!(
            self.reads(self.insider, &self.reactor),
            "FIXTURE: the member of R reads the PERSON named in R’s MESSAGE"
        );
        assert!(
            self.reads(self.insider, &self.reaction),
            "FIXTURE: the member of R reads the reaction claim"
        );
    }
}

impl Fixture {
    /// The 👍 pill `reader` gets on the room MESSAGE, as `reader` views it.
    fn pill(&self, reader: EntityId) -> ReactionPill {
        let pills = self
            .vault
            .scoped_read(key(reader))
            .reaction_pills(&[self.room_message], reader)
            .expect("a member reads the room MESSAGE’s pills")
            .value;
        pills
            .get(&self.room_message)
            .and_then(|pills| pills.iter().find(|pill| pill.glyph == "👍"))
            .cloned()
            .expect("the member gets a 👍 pill on the room MESSAGE")
    }
}

/// A pill counts a reactor outside the reader’s relationship but carries no id of theirs.
#[test]
fn a_pill_counts_a_reactor_the_reader_may_not_read_without_their_id() {
    let fixture = fixture();
    let pill = fixture.pill(fixture.outsider);
    assert_eq!(pill.count, 1, "the reaction still counts for the outsider");
    assert!(
        !pill.by.contains(&fixture.reactor),
        "the outsider’s pill carries no id of the reactor it may not read"
    );
    assert!(
        pill.by.is_empty(),
        "the outsider’s pill lists no reactor: clients render +1 from the count"
    );
}

/// A member of R reads the reactor, and the same pill lists their id.
#[test]
fn a_relationship_member_sees_the_reactors_id_in_the_pill() {
    let fixture = fixture();
    let pill = fixture.pill(fixture.insider);
    assert_eq!(pill.count, 1, "the reaction counts for the member of R");
    assert_eq!(
        pill.by,
        vec![fixture.reactor],
        "the member of R is shown the id of the reactor it reads"
    );
}

impl Fixture {
    /// The put signal of the reactor’s 👍 in the room MESSAGE author’s feed.
    fn signal(&self) -> ReactionSignal {
        self.vault
            .reactions_since(self.speaker, 0)
            .expect("the author’s signal feed")
            .into_iter()
            .find(|signal| signal.reaction == self.reaction && !signal.revoked)
            .expect("FIXTURE: the author’s feed carries the reactor’s 👍")
    }
}

/// The outsider hears of the reaction, but its signal carries no id of the reactor it may
/// not read.
#[test]
fn a_signal_carries_no_id_of_a_reactor_the_reader_may_not_read() {
    let fixture = fixture();
    let signal = fixture.signal();
    let read = fixture.vault.scoped_read(key(fixture.outsider));
    assert!(
        read.is_reaction_signal_readable(&signal)
            .expect("the outsider judges the signal"),
        "FIXTURE: the outsider hears of the reaction"
    );
    assert_eq!(
        read.reaction_signal_reactor_under(&signal, None)
            .expect("the outsider judges the reactor"),
        None,
        "the outsider’s signal carries no id of the reactor it may not read"
    );
}

/// A member of R hears of the same reaction with the reactor’s id.
#[test]
fn a_relationship_member_hears_the_reactors_id_in_the_signal() {
    let fixture = fixture();
    let signal = fixture.signal();
    let read = fixture.vault.scoped_read(key(fixture.insider));
    assert!(
        read.is_reaction_signal_readable(&signal)
            .expect("the member of R judges the signal"),
        "FIXTURE: the member of R hears of the reaction"
    );
    assert_eq!(
        read.reaction_signal_reactor_under(&signal, None)
            .expect("the member of R judges the reactor"),
        Some(fixture.reactor),
        "the member of R is told the id of the reactor it reads"
    );
}

/// The outsider gets no history of the reactor’s 👍: the chain is keyed by a person it may
/// not read.
#[test]
fn the_history_of_a_reactor_the_reader_may_not_read_is_withheld() {
    let fixture = fixture();
    let history = fixture
        .vault
        .scoped_read(key(fixture.outsider))
        .reaction_history(fixture.room_message, fixture.reactor, "👍")
        .expect("the outsider reads the history")
        .value;
    assert!(
        history.is_empty(),
        "the outsider reads no chain of the reactor it may not read"
    );
}

/// A member of R reads the reactor’s chain: their one 👍, by their id.
#[test]
fn a_relationship_member_reads_the_reactors_history() {
    let fixture = fixture();
    let history = fixture
        .vault
        .scoped_read(key(fixture.insider))
        .reaction_history(fixture.room_message, fixture.reactor, "👍")
        .expect("the member of R reads the history")
        .value;
    let ids: Vec<(EntityId, EntityId)> = history.iter().map(|entry| (entry.id, entry.by)).collect();
    assert_eq!(
        ids,
        vec![(fixture.reaction, fixture.reactor)],
        "the member of R reads the reactor’s 👍 by their id"
    );
}
