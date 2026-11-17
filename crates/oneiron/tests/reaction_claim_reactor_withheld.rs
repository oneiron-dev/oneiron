//! A reaction claim names its reactor twice: `by` in its value and the writer
//! stamp (`actor_entity_ref`) in its evidence. A reader who may not read the
//! reactor's PERSON row reads the claim with both as nil, and the reaction still
//! counts, in its pill and in the reader's context pack; a reader who reads the PERSON row reads the claim whole (FIX
//! REACTION-CLAIM-VALUE-REACTOR-ID; Engine ANSWER = A, 17 Nov 07:32). Mirela is
//! confirmed from the words of a relationship R, then reacts 👍 to an open
//! MESSAGE in a room the outsider (outside R) and a member of R both sit in.
//! The outsider reads the room MESSAGE and the reaction claim, but not Mirela's
//! PERSON row; the member of R reads all three.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test reaction_claim_reactor_withheld`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::access_grant::AccessGrantStatus;
use oneiron::access_grant::{AccessGrant, AccessGrantCapability, AccessGrantScope};
use oneiron::claim::{ClaimBody, ScopedReadActorKey, decode_claim_body};
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::deletion::{MemoryTimelineRecord, MemoryTimelineRecordState};
use oneiron::embed::EmbedderLocality;
use oneiron::memory::extraction::{EncoderAttempt, EncoderInput, EncoderOutput, ExtractionEncoder};
use oneiron::memory::extraction::{ExtractionWork, NerSpan};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::reaction::ReactionInput;
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::tagging::{MentionLink, TaggingMarkerConfig, TaggingMode, TaggingReconciler};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::{EdgeActorClass, EntityId, ModelId, Vault, VaultConfig, WriteActor};
use oneiron_authority::federation::scope_codec::read_preset;
use rmpv::Value;

const CHECKPOINT: &str = "0123456789abcdef";
/// The R MESSAGE: only R’s members read it. Mirela is named nowhere else.
const HIDDEN_WORDS: &str = "Mirela told Ada about the move.";
/// The open room MESSAGE the reactor reacts to.
const ROOM_WORDS: &str = "The zebras quilt at noon.";
/// The reaction value's reactor key.
const KEY_BY: &str = "by";
/// The writer stamp a write envelope puts in a claim's evidence.
const KEY_WRITER: &str = "actor_entity_ref";

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
            relations: None,
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

    /// The reaction claim's body bytes `reader` gets from a point read.
    fn point_body(&self, reader: EntityId) -> Vec<u8> {
        let (kind, _, body) = self
            .vault
            .scoped_read(key(reader))
            .get_entity_parts_with_receipt(&self.reaction, None)
            .expect("a member’s point read")
            .value
            .expect("the member reads the reaction claim");
        assert_eq!(kind, ENTITY_TYPE_CLAIM, "FIXTURE: the reaction is a CLAIM");
        body
    }

    /// The reaction claim's body bytes `reader` gets from its timeline parts.
    fn timeline_body(&self, reader: EntityId) -> Vec<u8> {
        let record = MemoryTimelineRecord {
            id: self.reaction,
            state: MemoryTimelineRecordState::Live,
            entity_type: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body_bytes: None,
            deletion: None,
            supersedes: Vec::new(),
            superseded_by: Vec::new(),
        };
        let (kind, _, body) = self
            .vault
            .scoped_read(key(reader))
            .memory_timeline_parts_with_receipt(&[record], None)
            .expect("a member’s timeline read")
            .value
            .into_iter()
            .next()
            .flatten()
            .expect("the member reads the reaction claim’s timeline parts");
        assert_eq!(kind, ENTITY_TYPE_CLAIM, "FIXTURE: the reaction is a CLAIM");
        body
    }

    /// Whether `bytes` hold the reactor's 16 id bytes anywhere.
    fn names_reactor(&self, bytes: &[u8]) -> bool {
        bytes
            .windows(16)
            .any(|window| window == self.reactor.as_bytes())
    }
}

/// The value `key` holds in the map `value`, if it is one.
fn entry<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// The id a binary map entry holds.
fn id_at(value: &Value, key: &str) -> Option<EntityId> {
    let Some(Value::Binary(bytes)) = entry(value, key) else {
        return None;
    };
    EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()
}

fn decoded(body: &[u8]) -> ClaimBody {
    decode_claim_body(body, true).expect("the served reaction claim decodes")
}

/// The claim a reader who may not read the reactor gets: still the 👍 reaction on the
/// room MESSAGE, with `by` and the writer stamp absent or nil.
fn assert_reactor_withheld(fixture: &Fixture, body: &[u8], door: &str) {
    let claim = decoded(body);
    assert_eq!(
        claim.predicate, "conversation.reaction",
        "{door}: the outsider still reads a reaction claim"
    );
    assert_eq!(
        entry(&claim.value, "glyph").and_then(Value::as_str),
        Some("👍"),
        "{door}: the outsider still reads the reaction’s glyph"
    );
    assert!(
        entry(&claim.value, KEY_BY).is_none_or(Value::is_nil),
        "{door}: the outsider reads no `by` of a reactor it may not read"
    );
    assert!(
        claim
            .evidence
            .as_ref()
            .and_then(|evidence| entry(evidence, KEY_WRITER))
            .is_none_or(Value::is_nil),
        "{door}: the outsider reads no writer stamp of a reactor it may not read"
    );
    assert!(
        !fixture.names_reactor(body),
        "{door}: no byte run of the served claim is the reactor’s id"
    );
}

/// The claim a reader who reads the reactor gets: `by` and the writer stamp name them.
fn assert_whole(fixture: &Fixture, body: &[u8], door: &str) {
    let claim = decoded(body);
    assert_eq!(
        id_at(&claim.value, KEY_BY),
        Some(fixture.reactor),
        "{door}: the member of R reads the reactor’s `by`"
    );
    assert_eq!(
        claim
            .evidence
            .as_ref()
            .and_then(|evidence| id_at(evidence, KEY_WRITER)),
        Some(fixture.reactor),
        "{door}: the member of R reads the writer stamp naming the reactor"
    );
}

/// A point read of the reaction claim by a reader who may not read the reactor carries
/// no id of theirs.
#[test]
fn a_point_read_of_the_reaction_claim_withholds_a_reactor_the_reader_may_not_read() {
    let fixture = fixture();
    let body = fixture.point_body(fixture.outsider);
    assert_reactor_withheld(&fixture, &body, "point read");
}

/// The reaction claim's timeline parts, read by a reader who may not read the reactor,
/// carry no id of theirs.
#[test]
fn the_timeline_parts_of_the_reaction_claim_withhold_a_reactor_the_reader_may_not_read() {
    let fixture = fixture();
    let body = fixture.timeline_body(fixture.outsider);
    assert_reactor_withheld(&fixture, &body, "timeline parts");
}

/// A member of R reads the reactor, and both doors serve the reaction claim whole.
#[test]
fn a_relationship_member_reads_the_reaction_claim_whole() {
    let fixture = fixture();
    let body = fixture.point_body(fixture.insider);
    assert_whole(&fixture, &body, "point read");
    let body = fixture.timeline_body(fixture.insider);
    assert_whole(&fixture, &body, "timeline parts");
}

/// The reaction still counts in the outsider's pill on the room MESSAGE.
#[test]
fn the_reaction_still_counts_for_a_reader_who_may_not_read_the_reactor() {
    let fixture = fixture();
    let pills = fixture
        .vault
        .scoped_read(key(fixture.outsider))
        .reaction_pills(&[fixture.room_message], fixture.outsider)
        .expect("the outsider reads the room MESSAGE’s pills")
        .value;
    let count = pills
        .get(&fixture.room_message)
        .and_then(|pills| pills.iter().find(|pill| pill.glyph == "👍"))
        .map(|pill| pill.count);
    assert_eq!(count, Some(1), "the reaction still counts for the outsider");
}

/// The reaction claim stays in the context pack of a reader who may not read the reactor.
/// The pack's scoped filter holds each hydrated claim against the row the lane serves now,
/// so the served claim must still match the fields hydration projected, where `by` and
/// the writer stamp already read as null. The search reaches the claim through its
/// indexed text, the glyph and the reactor's stored name (`reaction/write.rs`
/// `indexed_text`).
#[test]
fn the_outsiders_context_pack_keeps_the_reaction_claim() {
    let fixture = fixture();
    let read = fixture.vault.scoped_read(key(fixture.outsider));
    let plan = read.context_pack_plan().expect("the outsider’s pack plan");
    let mut pack = plan
        .admit(fixture.vault.context_pack())
        .search_text("Mirela", 10)
        .filter_types(&[ENTITY_TYPE_CLAIM])
        .run()
        .expect("the outsider’s pack");
    let holds = |pack: &oneiron::ContextPack| {
        pack.results
            .iter()
            .any(|entity| entity.id == fixture.reaction)
    };
    assert!(
        holds(&pack),
        "FIXTURE: the outsider’s search hydrates the reaction claim before the filter: {:?}",
        pack.results
            .iter()
            .map(|entity| entity.id)
            .collect::<Vec<_>>()
    );
    read.filter_context_pack(&mut pack)
        .expect("the outsider’s pack filter");
    assert!(
        holds(&pack),
        "the outsider’s context pack keeps the reaction claim whose reactor it may not read"
    );
}

impl Fixture {
    /// The reaction claim's typed view `reader` gets from its Memory read.
    fn view(&self, reader: EntityId) -> oneiron::EntityView {
        self.vault
            .memory(reader, EdgeActorClass::Human)
            .get_entity(&self.reaction.to_hex())
            .expect("a member’s Memory read")
            .value
            .expect("the member reads the reaction claim’s view")
    }
}

/// The outsider's Memory view of the reaction claim names its reactor nowhere: not in its
/// body, and not as the writer of its birth.
#[test]
fn a_memory_view_of_the_reaction_claim_withholds_a_reactor_the_reader_may_not_read() {
    let fixture = fixture();
    let view = fixture.view(fixture.outsider);
    assert!(
        view.made_by.is_none(),
        "the outsider reads no birth naming the writer of a reactor it may not read"
    );
    let served = serde_json::to_string(&view).expect("the view serializes");
    assert!(
        !served.contains(&fixture.reactor.to_hex()),
        "no field of the outsider’s view spells the reactor’s id"
    );
}

/// A member of R reads the reactor, and the same view names them as the writer of its birth.
#[test]
fn a_relationship_member_reads_the_reaction_claims_birth_whole() {
    let fixture = fixture();
    let view = fixture.view(fixture.insider);
    assert_eq!(
        view.made_by.map(|made_by| made_by.process.actor),
        Some(fixture.reactor),
        "the member of R reads the birth naming the reactor as its writer"
    );
}
