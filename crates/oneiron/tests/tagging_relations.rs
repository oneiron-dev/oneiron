//! A tagger's relations are saved with the turn's tag set and read through
//! `vault.tagging.tags` (L2-03, JointIE as a relation head on the Oneironer;
//! ARCH-0026 "Inside the child JointIE extracts claims", ARCH-0036 "A model
//! declares what it returns").
//!
//! The tagger contract carries relation links between the answer's spans.
//! The answer check refuses a relation that names a missing span, the save
//! keeps the relations beside the mentions they index, and the tag view
//! shows them, leaving out any relation that names a mention the reader
//! does not read. The host's relation table maps a relation label to a claim
//! predicate, and a table naming a predicate no claim write takes refuses
//! the open. The tagger authors no claim; the Dreamer's child does.
//!
//! On main the file does not compile: `EncoderOutput` has no `relations`
//! and `TaggingMarkerConfig` has no `with_relations`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test tagging_relations`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::edge::EdgeActorClass;
use oneiron::embed::EmbedderLocality;
use oneiron::memory::extraction::{
    EncoderAttempt, EncoderInput, EncoderOutput, ExtractionEncoder, ExtractionWork, NerSpan,
    RelationLink, SpeakerLink, SpeakerTarget,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::tagging::{
    HeldTagsOutcome, TaggedRelationView, TaggingMarkerConfig, TaggingMode, TaggingOutcomeView,
    TaggingReconciler, TaggingTurnRequest, TurnTagsView,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::{EntityId, ModelId, Vault, VaultConfig};
use oneiron_authority::federation::scope_codec::read_preset;

const CHECKPOINT: &str = "0123456789abcdef";
const WORDS: &str = "I work at Acme";
const RELATION: &str = "works_at";
const PREDICATE: &str = "work.employer";

/// The tags a relation-capable tagger returns for [`WORDS`]: `I` as the
/// turn's speaker, `Acme` as an organisation, and `relations`.
fn works_at(relations: Option<Vec<RelationLink>>) -> EncoderOutput {
    let span = |start: usize, end: usize, label: &str| NerSpan {
        message: 0,
        start,
        end,
        label: label.to_owned(),
        confidence: 0.9,
    };
    EncoderOutput {
        spans: vec![span(0, 1, "PRONOUN"), span(10, 14, "ORG")],
        links: Vec::new(),
        vad: None,
        context_links: Vec::new(),
        speaker_links: vec![SpeakerLink {
            span: 0,
            target: SpeakerTarget::Speaker,
            confidence: 0.9,
        }],
        mood_parts: Vec::new(),
        relations,
        stack_sha16: None,
    }
}

fn relation(head: usize, tail: usize, label: &str) -> RelationLink {
    RelationLink {
        head,
        tail,
        label: label.to_owned(),
        confidence: 0.9,
    }
}

/// A tagger that answers every call with one scripted answer.
struct Scripted {
    model: ModelId,
    answer: fn(&EncoderInput) -> EncoderOutput,
}

impl Scripted {
    fn new(answer: fn(&EncoderInput) -> EncoderOutput) -> Self {
        Self {
            model: "fixture/relations@v1".parse().expect("model id"),
            answer,
        }
    }
}

impl ExtractionEncoder for Scripted {
    fn model_id(&self) -> &ModelId {
        &self.model
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn infer(&self, input: &EncoderInput, _work: ExtractionWork) -> EncoderAttempt {
        EncoderAttempt {
            execution: None,
            panicked: false,
            result: Ok((self.answer)(input)),
        }
    }
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn person(vault: &Vault, id: EntityId, name: &str) -> EntityId {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            at(1),
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
        )
        .expect("a person");
    id
}

/// A device tagging config that saves its tags, maps `PERSON` and maps
/// `relations`.
fn tagging(relations: BTreeMap<String, String>) -> VaultConfig {
    let mut config = VaultConfig::device();
    config.tagging = Some(
        TaggingMarkerConfig::new(CHECKPOINT)
            .expect("checkpoint")
            .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
            .with_relations(relations)
            .with_mode(TaggingMode::Save),
    );
    config
}

fn works_at_table() -> BTreeMap<String, String> {
    BTreeMap::from([(RELATION.to_owned(), PREDICATE.to_owned())])
}

fn message(id: Option<EntityId>, order: u32, words: &str, rel: Option<EntityId>) -> WitnessMessage {
    WitnessMessage {
        id: id.map(|id| id.to_hex()),
        author: WitnessAuthor::User,
        message_type: "dialogue".to_owned(),
        content: words.to_owned(),
        parts: None,
        metadata: rel.map(|rel| serde_json::json!({ "rel": rel.to_hex() })),
        is_visible: true,
        order,
        quote: None,
    }
}

fn turn_of(turn: EntityId, messages: Vec<WitnessMessage>) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: Some(turn.to_hex()),
        thread_audience: None,
        messages,
        occurred_at: 10,
        assertions: WitnessAssertions::default(),
    }
}

/// A vault armed with `relations`, its speaker, a relationship room, and a
/// reader: a member of the vault who reads the room's MESSAGEs on its own
/// live grant, as `tag_views_source_label.rs`'s outsider reads S's.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    speaker: EntityId,
    reader: EntityId,
    room: EntityId,
}

fn fixture_with(relations: BTreeMap<String, String>) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let reader = EntityId::now();
    let vault = Arc::new(
        open_member_vault(dir.path(), tagging(relations), &[reader.to_hex()])
            .expect("fixture vault"),
    );
    let room = EntityId::now();
    vault
        .put_entity(&room, ENTITY_TYPE_RELATIONSHIP, at(1), 1, b"relationship S")
        .expect("a relationship");
    person(&vault, reader, "reader");
    vault
        .create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                principal_ref: reader,
                scope: AccessGrantScope::Messages { space_ref: room },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: 1,
                revoked_at: None,
                expires_at: None,
                authority_scope: read_preset(),
                companion_bounds: None,
            },
        )
        .expect("the reader's grant on the room");
    let speaker = person(&vault, EntityId::now(), "speaker");
    Fixture {
        _dir: dir,
        vault,
        speaker,
        reader,
        room,
    }
}

fn fixture() -> Fixture {
    fixture_with(works_at_table())
}

impl Fixture {
    /// [`WORDS`] as one turn's one MESSAGE, in the room.
    fn words(&self, turn: EntityId) -> WitnessTurn {
        turn_of(turn, vec![message(None, 0, WORDS, Some(self.room))])
    }

    /// Witnesses [`WORDS`] as one turn, untagged; returns the turn.
    fn witness(&self) -> EntityId {
        let turn = EntityId::now();
        self.vault
            .memory(self.speaker, EdgeActorClass::Human)
            .witness(&self.words(turn))
            .expect("witness");
        turn
    }

    /// One worker pass with a tagger that answers `answer`.
    fn tag(&self, answer: fn(&EncoderInput) -> EncoderOutput) {
        TaggingReconciler::new(Arc::clone(&self.vault), Arc::new(Scripted::new(answer)))
            .expect("reconciler")
            .drain_once()
            .expect("one tagging pass");
    }

    /// `vault.tagging.tags` for `turn`, read as the reader.
    fn tags(&self, turn: &EntityId) -> Option<TurnTagsView> {
        self.vault
            .memory(self.reader, EdgeActorClass::Human)
            .tagging_tags(&TaggingTurnRequest {
                turn_ref: turn.to_hex(),
            })
            .expect("FIXTURE: the reader reads the turn's tags")
            .value
            .tags
    }
}

fn view(head: usize, tail: usize, label: &str) -> TaggedRelationView {
    TaggedRelationView {
        head,
        tail,
        label: label.to_owned(),
        confidence: 0.9,
    }
}

/// The worker's answer carries a relation; the saved set keeps it, and the
/// tag view shows it beside the two mentions it joins.
#[test]
fn a_taggers_relations_are_saved_with_the_turns_tags() {
    let fixture = fixture();
    let turn = fixture.witness();
    fixture.tag(|_| works_at(Some(vec![relation(0, 1, RELATION)])));

    let tags = fixture
        .tags(&turn)
        .expect("the turn's tags are saved and read");
    assert_eq!(tags.mentions.len(), 2, "FIXTURE: one mention per span");
    assert_eq!(tags.relations, Some(vec![view(0, 1, RELATION)]));
}

/// An importer's held tags carry their relations into the set the witness
/// write saves, as a worker's answer does.
#[test]
fn held_tags_carry_their_relations_into_the_saved_set() {
    let fixture = fixture();
    let turn = EntityId::now();
    let (_, outcome) = fixture
        .vault
        .memory(fixture.speaker, EdgeActorClass::Human)
        .witness_with_held_tags(
            &fixture.words(turn),
            &works_at(Some(vec![relation(0, 1, RELATION)])),
        )
        .expect("witness with held tags");
    assert!(
        matches!(outcome, HeldTagsOutcome::Completed(_)),
        "the held tags are saved in the witness write: {outcome:?}"
    );

    let tags = fixture
        .tags(&turn)
        .expect("the held tags are saved and read");
    assert_eq!(tags.relations, Some(vec![view(0, 1, RELATION)]));
}

/// A relation whose tail names no span of the answer breaks the contract:
/// no set is saved, and the turn's history shows the try refused as
/// `bad_relation`.
#[test]
fn a_relation_naming_a_missing_span_is_refused() {
    let fixture = fixture();
    let turn = fixture.witness();
    fixture.tag(|_| works_at(Some(vec![relation(0, 5, RELATION)])));

    assert!(
        fixture.tags(&turn).is_none(),
        "no tag set is saved from a refused answer"
    );
    let history = fixture
        .vault
        .memory(fixture.reader, EdgeActorClass::Human)
        .tagging_history(&TaggingTurnRequest {
            turn_ref: turn.to_hex(),
        })
        .expect("the turn's tagging history")
        .value;
    let refusals: Vec<_> = history
        .traces
        .iter()
        .filter_map(|trace| match &trace.outcome {
            TaggingOutcomeView::Failed { failure, .. } => failure.refusal.clone(),
            _ => None,
        })
        .collect();
    assert_eq!(refusals, vec!["bad_relation".to_owned()]);
}

/// A tagger with no relation head returns no relations: the saved set holds
/// none, and the view says none were read rather than none were found.
#[test]
fn a_tagger_that_returns_no_relations_saves_none() {
    let fixture = fixture();
    let turn = fixture.witness();
    fixture.tag(|_| works_at(None));

    let tags = fixture
        .tags(&turn)
        .expect("the turn's tags are saved and read");
    assert_eq!(tags.mentions.len(), 2, "FIXTURE: one mention per span");
    assert_eq!(tags.relations, None);
}

/// The relation table maps a label to a claim predicate; a predicate no
/// public claim write takes (one segment, or the reserved `edge.*`) refuses
/// the open, so the child never files under it.
#[test]
fn a_relation_table_naming_a_bad_predicate_refuses_the_open() {
    for predicate in ["Employer", "edge.parent"] {
        let dir = tempfile::tempdir().expect("tempdir");
        let table = BTreeMap::from([(RELATION.to_owned(), predicate.to_owned())]);
        let opened = Vault::open(dir.path(), tagging(table));
        assert!(
            matches!(opened, Err(oneiron::Error::InvalidConfig(_))),
            "{predicate}: the open is refused as an invalid config: {:?}",
            opened.err().map(|error| error.to_string())
        );
    }
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(
        Vault::open(dir.path(), tagging(works_at_table())).is_ok(),
        "FIXTURE: a dotted predicate opens"
    );
}

/// A relation is shown only while the reader reads both mentions it joins:
/// the reader, a member outside relationship R, reads the S MESSAGE, never
/// the R one, so a relation into the R MESSAGE is left out of its view
/// (OPUS-LEAKS).
#[test]
fn a_relation_naming_a_mention_the_reader_does_not_read_is_left_out() {
    const SHARED_WORDS: &str = "Ada met Bo.";
    const HIDDEN_WORDS: &str = "Mirela left.";
    let fixture = fixture_with(BTreeMap::from([(
        "met".to_owned(),
        "social.met".to_owned(),
    )]));
    let vault = &fixture.vault;
    let hidden_room = EntityId::now();
    vault
        .put_entity(
            &hidden_room,
            ENTITY_TYPE_RELATIONSHIP,
            at(1),
            1,
            b"relationship R",
        )
        .expect("relationship R");
    let turn = EntityId::now();
    let (shared_message, hidden_message) = (EntityId::now(), EntityId::now());
    vault
        .memory(fixture.speaker, EdgeActorClass::Human)
        .witness(&turn_of(
            turn,
            vec![
                message(Some(shared_message), 0, SHARED_WORDS, Some(fixture.room)),
                message(Some(hidden_message), 1, HIDDEN_WORDS, Some(hidden_room)),
            ],
        ))
        .expect("witness");
    // Ada and Bo in the S MESSAGE, Mirela in the R one; Ada met each.
    let names = |input: &EncoderInput| {
        let mut spans = Vec::new();
        for (index, each) in input.messages.iter().enumerate() {
            for name in ["Ada", "Bo", "Mirela"] {
                if let Some(start) = each.text.find(name) {
                    spans.push(NerSpan {
                        message: index,
                        start,
                        end: start + name.len(),
                        label: "PERSON".to_owned(),
                        confidence: 0.9,
                    });
                }
            }
        }
        spans.sort_by_key(|span| (span.message, span.start));
        let relations = (1..spans.len())
            .map(|tail| relation(0, tail, "met"))
            .collect();
        EncoderOutput {
            spans,
            links: Vec::new(),
            vad: None,
            context_links: Vec::new(),
            speaker_links: Vec::new(),
            mood_parts: Vec::new(),
            relations: Some(relations),
            stack_sha16: None,
        }
    };
    fixture.tag(names);

    let saved = vault
        .turn_tags(&turn)
        .expect("tags read")
        .expect("FIXTURE: the turn's tags are saved");
    let places: Vec<_> = saved
        .mentions
        .iter()
        .map(|mention| (mention.message, mention.start))
        .collect();
    assert_eq!(
        places,
        vec![
            (shared_message, 0),
            (shared_message, 8),
            (hidden_message, 0)
        ],
        "FIXTURE: Ada and Bo in the S MESSAGE, then Mirela in the R one"
    );
    assert_eq!(
        saved.relations.as_ref().map(Vec::len),
        Some(2),
        "FIXTURE: both relations are saved"
    );

    let shown = fixture.tags(&turn).expect("FIXTURE: the TURN has tags");
    assert!(
        shown
            .mentions
            .iter()
            .all(|mention| mention.message_ref == shared_message.to_hex()),
        "FIXTURE: the reader sees only the S MESSAGE's mentions"
    );
    assert_eq!(
        shown.relations,
        Some(vec![view(0, 1, "met")]),
        "LEAK: the view shows a relation into the R MESSAGE to a reader outside R"
    );
}
