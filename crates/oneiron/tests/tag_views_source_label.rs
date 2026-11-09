//! The tag views serve nothing derived from a relationship-scoped MESSAGE
//! outside that relationship (OPUS-LEAKS, lead call G "leaks today").
//!
//! One TURN holds two MESSAGEs: an open one, and one scoped to a
//! relationship R. The tagger reads both, as it does today. A member outside
//! R reads the TURN and the open MESSAGE, never the R MESSAGE. Each test then
//! asserts that one identity writer's output, derived from the R MESSAGE,
//! stays out of that member's reads:
//! - the tag views (`vault.tagging.tags`, `vault.tagging.mentions`);
//! - a provisional entity named only in the R MESSAGE, once confirmed.
//!
//! Each `FIXTURE:` assertion checks the setup, never the leak. The last
//! assertion of each test is the leak check.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test tag_views_source_label`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::edge::EdgeActorClass;
use oneiron::embed::EmbedderLocality;
use oneiron::memory::extraction::{
    EncoderAttempt, EncoderInput, EncoderOutput, ExtractionEncoder, ExtractionWork, NerSpan,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::tagging::{
    TaggingMarkerConfig, TaggingMentionsRequest, TaggingMode, TaggingReconciler,
    TaggingTurnRequest,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::{EntityId, ModelId, Vault, VaultConfig};

const CHECKPOINT: &str = "0123456789abcdef";
/// The open MESSAGE: every member reads it.
const OPEN_WORDS: &str = "Ada waved hello.";
/// The R MESSAGE: only R's members read it. Mirela is named nowhere else.
const HIDDEN_WORDS: &str = "Mirela told Ada about the move.";

/// A tagger that tags each name it knows as a `PERSON`, in every MESSAGE it
/// is given.
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
            let text = each.text.as_str();
            for name in self.known {
                if let Some(start) = text.find(name) {
                    spans.push(NerSpan {
                        message,
                        start,
                        end: start + name.len(),
                        label: "PERSON".to_owned(),
                        confidence: 0.9,
                    });
                }
            }
        }
        spans.sort_by_key(|span| (span.message, span.start));
        EncoderAttempt {
            execution: None,
            panicked: false,
            result: Ok(EncoderOutput {
                spans,
                links: Vec::new(),
                vad: None,
                context_links: Vec::new(),
                speaker_links: Vec::new(),
                mood_parts: Vec::new(),
                stack_sha16: None,
            }),
        }
    }
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
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

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    /// A member outside R.
    outsider: EntityId,
    ada: EntityId,
    turn: EntityId,
    open_message: EntityId,
    hidden_message: EntityId,
}

/// A vault whose tagger saves its tags, a TURN with an open MESSAGE and an
/// R MESSAGE, tagged once.
fn tagged_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let outsider = EntityId::now();
    let mut config = VaultConfig::device();
    config.tagging = Some(
        TaggingMarkerConfig::new(CHECKPOINT)
            .expect("checkpoint")
            .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
            .with_mode(TaggingMode::Save),
    );
    let vault = Arc::new(
        open_member_vault(dir.path(), config, &[outsider.to_hex()]).expect("fixture vault"),
    );
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
    let speaker = person(&vault, "speaker");
    let ada = person(&vault, "Ada");

    let turn = EntityId::now();
    let open_message = EntityId::now();
    let hidden_message = EntityId::now();
    let message = |id: EntityId, order: u32, words: &str, metadata| WitnessMessage {
        id: Some(id.to_hex()),
        author: WitnessAuthor::User,
        message_type: "dialogue".to_owned(),
        content: words.to_owned(),
        parts: None,
        metadata,
        is_visible: true,
        order,
        quote: None,
    };
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![
                message(open_message, 0, OPEN_WORDS, None),
                message(
                    hidden_message,
                    1,
                    HIDDEN_WORDS,
                    Some(serde_json::json!({"rel": relationship.to_hex()})),
                ),
            ],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })
        .expect("witness");

    TaggingReconciler::new(
        Arc::clone(&vault),
        Arc::new(Names {
            model: "fixture/names@v1".parse().expect("model id"),
            known: &["Ada", "Mirela"],
        }),
    )
    .expect("reconciler")
    .drain_once()
    .expect("one tagging pass");

    let fixture = Fixture {
        _dir: dir,
        vault,
        outsider,
        ada,
        turn,
        open_message,
        hidden_message,
    };
    fixture.check_setup();
    fixture
}

impl Fixture {
    fn outsider_reads(&self, id: &EntityId) -> bool {
        self.vault
            .memory(self.outsider, EdgeActorClass::Human)
            .get_entity(&id.to_hex())
            .expect("outsider read")
            .value
            .is_some()
    }

    /// The tags name Ada and Mirela in the R MESSAGE; the outsider reads the
    /// TURN, the open MESSAGE and Ada, never the R MESSAGE.
    fn check_setup(&self) {
        let tags = self
            .vault
            .turn_tags(&self.turn)
            .expect("tags read")
            .expect("FIXTURE: the turn's tags are saved");
        assert!(
            tags.mentions
                .iter()
                .any(|mention| mention.message == self.hidden_message),
            "FIXTURE: the tagger read the R MESSAGE"
        );
        assert!(
            self.outsider_reads(&self.turn),
            "FIXTURE: the outsider reads the TURN"
        );
        assert!(
            self.outsider_reads(&self.open_message),
            "FIXTURE: the outsider reads the open MESSAGE"
        );
        assert!(
            self.outsider_reads(&self.ada),
            "FIXTURE: the outsider reads a PERSON"
        );
        assert!(
            !self.outsider_reads(&self.hidden_message),
            "FIXTURE: the outsider does not read the R MESSAGE"
        );
    }
}

/// `vault.tagging.tags` and `vault.tagging.mentions` serve the outsider no
/// mention from the R MESSAGE: not its id, its span, its label or the
/// entity it names.
#[test]
fn tag_views_serve_no_mention_from_a_message_outside_the_readers_relationship() {
    let fixture = tagged_fixture();
    let outsider = fixture.vault.memory(fixture.outsider, EdgeActorClass::Human);
    let hidden = fixture.hidden_message.to_hex();

    let tags = outsider
        .tagging_tags(&TaggingTurnRequest {
            turn_ref: fixture.turn.to_hex(),
        })
        .expect("FIXTURE: the outsider reads the TURN's tags")
        .value
        .tags
        .expect("FIXTURE: the TURN has tags");
    assert!(
        tags.mentions
            .iter()
            .any(|mention| mention.message_ref == fixture.open_message.to_hex()),
        "FIXTURE: the outsider sees the open MESSAGE's mention"
    );
    let mentions = outsider
        .tagging_mentions(&TaggingMentionsRequest {
            entity_ref: fixture.ada.to_hex(),
            limit: 16,
        })
        .expect("the outsider's mentions of Ada")
        .value
        .mentions;
    assert!(
        mentions
            .iter()
            .any(|hit| hit.mention.message_ref == fixture.open_message.to_hex()),
        "FIXTURE: the outsider sees Ada's mention in the open MESSAGE"
    );

    let leaked_tags: Vec<_> = tags
        .mentions
        .iter()
        .filter(|mention| mention.message_ref == hidden)
        .map(|mention| (mention.start, mention.end, mention.label.clone()))
        .collect();
    let leaked_hits: Vec<_> = mentions
        .iter()
        .filter(|hit| hit.mention.message_ref == hidden)
        .map(|hit| (hit.mention.start, hit.mention.end))
        .collect();
    assert_eq!(
        (
            tags.message_refs.contains(&hidden),
            leaked_tags,
            leaked_hits
        ),
        (false, Vec::new(), Vec::new()),
        "LEAK: the tag views serve the R MESSAGE's id and mentions to a member outside R"
    );
}
