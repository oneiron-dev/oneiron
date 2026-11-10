//! A provisional entity named only in a relationship-scoped MESSAGE, once
//! confirmed, stays inside that relationship (OPUS-LEAKS, lead call G "leaks
//! today").
//!
//! One TURN holds three MESSAGEs: one scoped to a relationship S, one scoped
//! to a relationship R, and an open one. The tagger reads all three, as it
//! does today, and mints a provisional entity for "Mirela", named only in the
//! R MESSAGE, and one for "Zora", named only in the open MESSAGE.
//! - The outsider is a member of S, outside R: it reads the TURN and the S
//!   MESSAGE on its own grant, never the R MESSAGE. Once Mirela is confirmed
//!   (`self.provisional.confirm`), it does not read the PERSON she becomes:
//!   her name is the R MESSAGE's words (the leak).
//! - A member of R, and the owner, still read her.
//! - Zora, confirmed from the open MESSAGE, is read by every member, as every
//!   confirmed person was: nothing that was open narrows.
//!
//! Each `FIXTURE:` assertion checks the setup, never the leak. The last
//! assertion is the leak check.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test provisional_confirm_source_label`.
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
use oneiron::tagging::{MentionLink, TaggingMarkerConfig, TaggingMode, TaggingReconciler};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::{EntityId, ModelId, Vault, VaultConfig};
use oneiron_authority::federation::scope_codec::read_preset;

const CHECKPOINT: &str = "0123456789abcdef";
/// The S MESSAGE: the outsider reads it.
const SHARED_WORDS: &str = "Ada waved hello.";
/// The R MESSAGE: only R's members read it. Mirela is named nowhere else.
const HIDDEN_WORDS: &str = "Mirela told Ada about the move.";
/// The open MESSAGE. Zora is named nowhere else.
const OPEN_WORDS: &str = "Zora arrived.";

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
    /// The speaker of the MESSAGEs.
    speaker: EntityId,
    /// A member outside R.
    outsider: EntityId,
    /// A member of R, who reads R's MESSAGEs on a live grant.
    insider: EntityId,
    /// The vault's owner.
    owner: EntityId,
    /// R.
    relationship: EntityId,
    ada: EntityId,
    turn: EntityId,
    shared_message: EntityId,
    hidden_message: EntityId,
    open_message: EntityId,
}

/// A vault whose tagger saves its tags, a TURN with an S MESSAGE and an
/// R MESSAGE, tagged once.
fn tagged_fixture() -> Fixture {
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
    let vault = Arc::new(
        open_member_vault(dir.path(), config, &[outsider.to_hex(), insider.to_hex()])
            .expect("fixture vault"),
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
        .put_entity(&insider, ENTITY_TYPE_PERSON, at(1), 1, b"insider")
        .expect("a member of R");
    for (member, space) in [(outsider, shared), (insider, relationship)] {
        vault
            .create_access_grant(
                &EntityId::now(),
                &AccessGrant {
                    principal_ref: member,
                    scope: AccessGrantScope::Messages { space_ref: space },
                    capability: AccessGrantCapability::MessagesRead,
                    status: AccessGrantStatus::Active,
                    created_at: 1,
                    revoked_at: None,
                    expires_at: None,
                    authority_scope: read_preset(),
                    companion_bounds: None,
                },
            )
            .expect("a member's grant on its relationship");
    }
    let (owner, _proof) = embedded_owner(&vault).expect("the owner");
    let speaker = person(&vault, "speaker");
    let ada = person(&vault, "Ada");

    let turn = EntityId::now();
    let shared_message = EntityId::now();
    let hidden_message = EntityId::now();
    let open_message = EntityId::now();
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
                message(open_message, 2, OPEN_WORDS, None),
            ],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })
        .expect("witness");

    TaggingReconciler::new(
        Arc::clone(&vault),
        Arc::new(Names {
            model: "fixture/names@v1".parse().expect("model id"),
            known: &["Ada", "Mirela", "Zora"],
            pronouns: false,
        }),
    )
    .expect("reconciler")
    .drain_once()
    .expect("one tagging pass");

    let fixture = Fixture {
        _dir: dir,
        vault,
        speaker,
        outsider,
        insider,
        owner,
        relationship,
        ada,
        turn,
        shared_message,
        hidden_message,
        open_message,
    };
    fixture.check_setup();
    fixture
}

impl Fixture {
    fn reads(&self, reader: EntityId, id: &EntityId) -> bool {
        self.vault
            .memory(reader, EdgeActorClass::Human)
            .get_entity(&id.to_hex())
            .expect("a member's read")
            .value
            .is_some()
    }

    fn outsider_reads(&self, id: &EntityId) -> bool {
        self.reads(self.outsider, id)
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
        assert!(
            self.reads(self.insider, &self.hidden_message),
            "FIXTURE: the member of R reads the R MESSAGE"
        );
    }

    /// The provisional entity `message` minted for its only name.
    fn minted_in(&self, message: EntityId) -> EntityId {
        let tags = self
            .vault
            .turn_tags(&self.turn)
            .expect("tags read")
            .expect("FIXTURE: the turn's tags are saved");
        tags.mentions
            .iter()
            .find_map(|mention| match &mention.link {
                MentionLink::Minted { entity, .. } if mention.message == message => Some(*entity),
                _ => None,
            })
            .expect("FIXTURE: the MESSAGE's name minted a provisional entity")
    }

    /// Confirms the provisional entity `id`, as its speaker does.
    fn confirm(&self, id: &EntityId) {
        self.vault
            .memory(self.speaker, EdgeActorClass::Human)
            .confirm_provisional_entity(id)
            .expect("the speaker confirms the entity");
        assert!(
            self.vault.get(id).expect("read").is_some(),
            "FIXTURE: the confirmed entity is a stored row"
        );
    }
}

/// A provisional entity named only in the R MESSAGE, once confirmed, is a
/// PERSON the outsider does not read: its name is the R MESSAGE's words.
#[test]
fn a_confirmed_provisional_named_only_in_a_relationship_message_stays_inside_it() {
    let fixture = tagged_fixture();
    let mirela = fixture.minted_in(fixture.hidden_message);
    fixture.confirm(&mirela);

    assert!(
        !fixture.outsider_reads(&mirela),
        "LEAK: a member outside R reads the PERSON named only in the R MESSAGE"
    );
}

/// A member of R reads the PERSON confirmed from R's words, on the grant it
/// reads R's MESSAGEs by, and the owner reads it.
#[test]
fn a_confirmed_provisional_is_read_by_the_relationships_members_and_the_owner() {
    let fixture = tagged_fixture();
    let mirela = fixture.minted_in(fixture.hidden_message);
    fixture.confirm(&mirela);

    assert!(
        fixture.reads(fixture.insider, &mirela),
        "a member of R reads the PERSON named in R's MESSAGE"
    );
    assert!(
        fixture.reads(fixture.owner, &mirela),
        "the owner reads the PERSON named in R's MESSAGE"
    );
}

/// A provisional entity named in an open MESSAGE, once confirmed, is read by
/// every member, as every confirmed entity was.
#[test]
fn a_provisional_confirmed_from_an_open_message_is_read_by_every_member() {
    let fixture = tagged_fixture();
    let zora = fixture.minted_in(fixture.open_message);
    fixture.confirm(&zora);

    assert!(
        fixture.outsider_reads(&zora) && fixture.reads(fixture.insider, &zora),
        "every member reads the PERSON named in an open MESSAGE"
    );
}

/// A pronoun in an open MESSAGE that corefers with a name read only in the R
/// MESSAGE does not open the name: its words do not say it (review of the
/// fix). Confirmed, the PERSON is still not read outside R.
#[test]
fn a_pronoun_in_an_open_message_does_not_open_a_name_read_only_in_a_relationship() {
    let fixture = tagged_fixture();
    let mirela = fixture.minted_in(fixture.hidden_message);

    // A second turn: "Mirela called." in R, then "She is fine." open.
    let turn = EntityId::now();
    let (r_message, open_message) = (EntityId::now(), EntityId::now());
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
    fixture
        .vault
        .memory(fixture.speaker, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![
                message(
                    r_message,
                    0,
                    "Mirela called.",
                    Some(serde_json::json!({"rel": fixture.relationship.to_hex()})),
                ),
                message(open_message, 1, "She is fine.", None),
            ],
            occurred_at: 20,
            assertions: WitnessAssertions::default(),
        })
        .expect("the second turn");
    TaggingReconciler::new(
        Arc::clone(&fixture.vault),
        Arc::new(Names {
            model: "fixture/names@v1".parse().expect("model id"),
            known: &["Ada", "Mirela", "Zora"],
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
    assert!(
        second
            .mentions
            .iter()
            .any(|mention| mention.message == open_message
                && mention.link.entities().contains(&mirela)),
        "FIXTURE: the open MESSAGE's pronoun names Mirela"
    );

    fixture.confirm(&mirela);
    assert!(
        !fixture.outsider_reads(&mirela),
        "LEAK: an open pronoun opened a name read only in R's MESSAGEs"
    );
}
