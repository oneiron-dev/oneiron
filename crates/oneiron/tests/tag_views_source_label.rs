//! The tag views serve nothing derived from a relationship-scoped MESSAGE
//! outside that relationship (OPUS-LEAKS, lead call G "leaks today").
//!
//! One TURN holds two MESSAGEs: one scoped to a relationship S, one scoped
//! to a relationship R. The tagger reads both, as it does today. The outsider
//! is a member of S, outside R: it reads the TURN and the S MESSAGE on its
//! own grant, never the R MESSAGE. The test asserts that the tag views
//! (`vault.tagging.tags`, `vault.tagging.mentions`) serve that member no
//! mention from the R MESSAGE.
//!
//! Each `FIXTURE:` assertion checks the setup, never the leak. The last
//! assertion is the leak check.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test tag_views_source_label`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::edge::EdgeActorClass;
use oneiron::embed::EmbedderLocality;
use oneiron::memory::extraction::{
    CorefLink, EncoderAttempt, EncoderInput, EncoderOutput, ExtractionEncoder, ExtractionWork, NerSpan,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::tagging::{
    MentionLink, TaggingMarkerConfig, TaggingMentionsRequest, TaggingMode, TaggingReconciler,
    TaggingTurnRequest,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::{EntityId, ModelId, Vault, VaultConfig};
use oneiron_authority::federation::scope_codec::read_preset;

const CHECKPOINT: &str = "0123456789abcdef";
/// The S MESSAGE: the outsider reads it.
const SHARED_WORDS: &str = "Ada waved hello.";
/// The R MESSAGE: only R's members read it. Mirela is named nowhere else.
const HIDDEN_WORDS: &str = "Mirela told Ada about the move.";

/// A tagger that tags each name it knows as a `PERSON`, in every MESSAGE it
/// is given; with `pronouns`, also each "She" as a `PRONOUN` coreferent with
/// the nearest name before it, in any MESSAGE of the turn.
struct Names {
    model: ModelId,
    known: &'static [&'static str],
    pronouns: bool,
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
            if self.pronouns
                && let Some(start) = text.find("She")
            {
                spans.push(NerSpan {
                    message,
                    start,
                    end: start + 3,
                    label: "PRONOUN".to_owned(),
                    confidence: 0.9,
                });
            }
        }
        spans.sort_by_key(|span| (span.message, span.start));
        let mut links = Vec::new();
        let mut last_name = None;
        for (index, span) in spans.iter().enumerate() {
            if span.label == "PERSON" {
                last_name = Some(index);
            } else if let Some(antecedent) = last_name {
                links.push(CorefLink {
                    span: index,
                    antecedent,
                    confidence: None,
                });
            }
        }
        EncoderAttempt {
            execution: None,
            panicked: false,
            result: Ok(EncoderOutput {
                spans,
                links,
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
    /// The speaker of the MESSAGEs.
    speaker: EntityId,
    /// R and S.
    relationship: EntityId,
    shared: EntityId,
    ada: EntityId,
    turn: EntityId,
    shared_message: EntityId,
    hidden_message: EntityId,
}

/// A vault whose tagger saves its tags, a TURN with an S MESSAGE and an
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
    // The outsider is a member of another relationship, S: it reads S's
    // MESSAGEs on its own live grant, never R's.
    let shared = EntityId::now();
    vault
        .put_entity(&shared, ENTITY_TYPE_RELATIONSHIP, at(1), 1, b"relationship S")
        .expect("relationship S");
    vault
        .create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                principal_ref: outsider,
                scope: AccessGrantScope::Messages { space_ref: shared },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: 1,
                revoked_at: None,
                expires_at: None,
                authority_scope: read_preset(),
                companion_bounds: None,
            },
        )
        .expect("the outsider's grant on S");
    let speaker = person(&vault, "speaker");
    let ada = person(&vault, "Ada");

    let turn = EntityId::now();
    let shared_message = EntityId::now();
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
                message(
                    shared_message,
                    0,
                    SHARED_WORDS,
                    Some(serde_json::json!({"rel": shared.to_hex()})),
                ),
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
            pronouns: false,
        }),
    )
    .expect("reconciler")
    .drain_once()
    .expect("one tagging pass");

    let fixture = Fixture {
        _dir: dir,
        vault,
        outsider,
        speaker,
        relationship,
        shared,
        ada,
        turn,
        shared_message,
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
    /// TURN, the S MESSAGE and Ada, never the R MESSAGE.
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
            self.outsider_reads(&self.shared_message),
            "FIXTURE: the outsider reads the S MESSAGE"
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
            .any(|mention| mention.message_ref == fixture.shared_message.to_hex()),
        "FIXTURE: the outsider sees the S MESSAGE's mention"
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
            .any(|hit| hit.mention.message_ref == fixture.shared_message.to_hex()),
        "FIXTURE: the outsider sees Ada's mention in the S MESSAGE"
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

/// `vault.tagging.mentions` answers a provisional entity (it has no row, so
/// each hit is judged by its own TURN and MESSAGE), and a hit the outsider
/// sees does not point at a mention in the R MESSAGE: a pronoun in the S
/// MESSAGE that corefers with "Mirela" in the R MESSAGE shows with no
/// antecedent (review round 1 of #6970).
#[test]
fn a_mentions_hit_never_points_at_a_mention_outside_the_readers_relationship() {
    let fixture = tagged_fixture();
    let tags = fixture
        .vault
        .turn_tags(&fixture.turn)
        .expect("tags read")
        .expect("FIXTURE: the turn's tags are saved");
    let mirela = tags
        .mentions
        .iter()
        .find_map(|mention| match &mention.link {
            MentionLink::Minted { entity, .. } if mention.message == fixture.hidden_message => {
                Some(*entity)
            }
            _ => None,
        })
        .expect("FIXTURE: Mirela minted a provisional entity");

    // A second turn: "Mirela called." in R, then "She is fine." in S.
    let turn = EntityId::now();
    let (r_message, s_message) = (EntityId::now(), EntityId::now());
    let message = |id: EntityId, order: u32, words: &str, space: EntityId| WitnessMessage {
        id: Some(id.to_hex()),
        author: WitnessAuthor::User,
        message_type: "dialogue".to_owned(),
        content: words.to_owned(),
        parts: None,
        metadata: Some(serde_json::json!({"rel": space.to_hex()})),
        is_visible: true,
        order,
        quote: None,
    };
    fixture
        .vault
        .memory(fixture.speaker, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![
                message(r_message, 0, "Mirela called.", fixture.relationship),
                message(s_message, 1, "She is fine.", fixture.shared),
            ],
            occurred_at: 20,
            assertions: WitnessAssertions::default(),
        })
        .expect("the second turn");
    TaggingReconciler::new(
        Arc::clone(&fixture.vault),
        Arc::new(Names {
            model: "fixture/names@v1".parse().expect("model id"),
            known: &["Ada", "Mirela"],
            pronouns: true,
        }),
    )
    .expect("reconciler")
    .drain_once()
    .expect("the second tagging pass");
    let second = fixture
        .vault
        .turn_tags(&turn)
        .expect("tags read")
        .expect("FIXTURE: the second turn's tags are saved");
    let she = second
        .mentions
        .iter()
        .find(|mention| mention.message == s_message)
        .expect("FIXTURE: the S MESSAGE's pronoun is saved");
    assert_eq!(
        she.antecedent
            .and_then(|antecedent| second.mentions.get(antecedent))
            .map(|antecedent| antecedent.message),
        Some(r_message),
        "FIXTURE: the pronoun corefers with the R MESSAGE's Mirela"
    );
    assert!(
        she.link.entities().contains(&mirela),
        "FIXTURE: the pronoun names Mirela"
    );

    let hits = fixture
        .vault
        .memory(fixture.outsider, EdgeActorClass::Human)
        .tagging_mentions(&TaggingMentionsRequest {
            entity_ref: mirela.to_hex(),
            limit: 16,
        })
        .expect("the outsider's mentions of a provisional entity")
        .value
        .mentions;
    let hidden = [r_message.to_hex(), fixture.hidden_message.to_hex()];
    let shown: Vec<_> = hits
        .iter()
        .map(|hit| {
            (
                hit.mention.message_ref.clone(),
                hidden.contains(&hit.mention.message_ref),
                hit.mention.antecedent,
            )
        })
        .collect();
    assert_eq!(
        shown,
        vec![(s_message.to_hex(), false, None)],
        "LEAK: a mentions hit points at a mention in the R MESSAGE"
    );
}
