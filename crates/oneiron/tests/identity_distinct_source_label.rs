//! The distinct fact an identity answer derives from a relationship-scoped
//! MESSAGE stays inside that relationship (OPUS-LEAKS, lead call G "leaks
//! today").
//!
//! Two people named Ada are in the vault. The owner's TURN holds an open
//! MESSAGE and one scoped to a relationship R that says "Ada"; the tagger
//! links that mention to both Adas. An agent about to act on "Ada"
//! (`self.identity.settle`) opens an identity ask, and the owner answers
//! "someone new" (`self.identity.answer`). The engine then confirms a new
//! person for the span and asserts it distinct from both Adas
//! (`entity.distinct_from`). A member outside R reads both Adas and an
//! `entity.distinct_from` between them, never the R MESSAGE; the test asserts
//! it reads no distinct fact born of the R MESSAGE. The second test says
//! "Ada" in a MESSAGE that names no relationship and is not private, which a
//! member reads only through a grant on its conversation (review round 2 of
//! #6971); the outsider holds none, so it reads no fact born of it either.
//!
//! Each `FIXTURE:` assertion checks the setup, never the leak. The last
//! assertion is the leak check.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test identity_distinct_source_label`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::dreamer_runner::maintenance::identity::{
    IdentityActNow, IdentityActNowRequest, IdentityAnswerRequest, IdentityEffect,
};
use oneiron::edge::EdgeActorClass;
use oneiron::embed::EmbedderLocality;
use oneiron::identity_topology::{AssertDistinctOp, IdentityOpWrite, IdentityTopologyOp};
use oneiron::memory::extraction::{
    EncoderAttempt, EncoderInput, EncoderOutput, ExtractionEncoder, ExtractionWork, NerSpan,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::tagging::{MentionLink, TaggingMarkerConfig, TaggingMode, TaggingReconciler};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::{ClaimSource, EntityId, ModelId, Vault, VaultConfig};

const CHECKPOINT: &str = "0123456789abcdef";

/// A tagger that tags every "Ada" as a `PERSON`, in every MESSAGE it is
/// given.
struct Adas(ModelId);

impl ExtractionEncoder for Adas {
    fn model_id(&self) -> &ModelId {
        &self.0
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn infer(&self, input: &EncoderInput, _work: ExtractionWork) -> EncoderAttempt {
        let spans = input
            .messages
            .iter()
            .enumerate()
            .filter_map(|(message, each)| {
                each.text.find("Ada").map(|start| NerSpan {
                    message,
                    start,
                    end: start + 3,
                    label: "PERSON".to_owned(),
                    confidence: 0.9,
                })
            })
            .collect();
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

/// Runs the fixture with the "Ada" MESSAGE's metadata from `metadata`
/// (given R), and returns how many of the distinct facts the someone-new
/// answer asserts the member outside R reads.
fn distinct_facts_the_outsider_reads(
    metadata: impl FnOnce(EntityId) -> Option<serde_json::Value>,
) -> usize {
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
    let (owner, _proof) = embedded_owner(&vault).expect("the owner");
    // The install's machine keys come from its device keystore, as a host's,
    // so the identity answer's signed topology event has a carrier.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .ensure_serving_install_profile(
            &oneiron::test_support::test_host_issuer(),
            oneiron::authority::MachineRole::Unanswered,
        )
        .expect("this install's machine profile");
    let ada_one = person(&vault, "Ada");
    let ada_two = person(&vault, "Ada");

    let turn = EntityId::now();
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
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![
                message(EntityId::now(), 0, "Good morning.", None),
                message(
                    hidden_message,
                    1,
                    "Ada told me about the move.",
                    metadata(relationship),
                ),
            ],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })
        .expect("the owner's turn");
    TaggingReconciler::new(
        Arc::clone(&vault),
        Arc::new(Adas("fixture/adas@v1".parse().expect("model id"))),
    )
    .expect("reconciler")
    .drain_once()
    .expect("one tagging pass");
    let tags = vault
        .turn_tags(&turn)
        .expect("tags read")
        .expect("FIXTURE: the turn's tags are saved");
    let [mention] = tags.mentions.as_slice() else {
        panic!("FIXTURE: one mention, found {:?}", tags.mentions);
    };
    let mut both = vec![ada_one, ada_two];
    both.sort();
    assert_eq!(
        (mention.message, &mention.link),
        (
            hidden_message,
            &MentionLink::Candidates {
                kind: ENTITY_TYPE_PERSON,
                entities: both,
            }
        ),
        "FIXTURE: the R MESSAGE's Ada names both Adas"
    );

    // An agent about to act on "Ada" opens the ask; the owner says someone new.
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let opened = owner_memory
        .identity_act_now(&IdentityActNowRequest {
            name: "Ada".to_owned(),
            conversation: None,
            effect: IdentityEffect::Send,
            prompt: "Which Ada?".to_owned(),
            someone_new: "Someone new".to_owned(),
            provisional: None,
        })
        .expect("the act-now ask");
    let IdentityActNow::Deciding { ask } = opened else {
        panic!("FIXTURE: an uncertain Ada opens an ask, got {opened:?}");
    };
    let settled = owner_memory
        .identity_answer(&IdentityAnswerRequest {
            ask,
            choice: "someone_new".to_owned(),
        })
        .expect("the owner answers someone new");
    let fresh = EntityId::from_hex(&settled.entity).expect("entity id");
    let born: Vec<EntityId> = [ada_one, ada_two]
        .iter()
        .flat_map(|ada| {
            vault
                .distinct_claims_for_pair(&fresh, ada)
                .expect("pair read")
        })
        .collect();
    assert_eq!(
        born.len(),
        2,
        "FIXTURE: the new person is asserted distinct from both Adas"
    );

    // The same fact between the two Adas, from open sources: the outsider
    // reads it, so a withheld fact is withheld for its source.
    vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::AssertDistinct(AssertDistinctOp {
                a: ada_one,
                b: ada_two,
                reason: "two people".to_owned(),
            }),
            &IdentityOpWrite::auto(ClaimSource::UserStated),
            vault.now_recorded_at(),
        )
        .expect("the Adas are distinct");
    let open = vault
        .distinct_claims_for_pair(&ada_one, &ada_two)
        .expect("pair read");
    let reads = |id: &EntityId| {
        vault
            .memory(outsider, EdgeActorClass::Human)
            .get_entity(&id.to_hex())
            .expect("outsider read")
            .value
            .is_some()
    };
    assert!(reads(&ada_one), "FIXTURE: the outsider reads a PERSON");
    assert!(
        !open.is_empty() && open.iter().all(reads),
        "FIXTURE: the outsider reads the distinct fact between the two Adas"
    );
    assert!(
        !reads(&hidden_message),
        "FIXTURE: the outsider does not read the \"Ada\" MESSAGE"
    );

    born.iter().filter(|id| reads(*id)).count()
}

#[test]
fn a_someone_new_answer_on_a_relationship_message_asserts_no_distinct_fact_outside_it() {
    let leaked = distinct_facts_the_outsider_reads(|relationship| {
        Some(serde_json::json!({"rel": relationship.to_hex()}))
    });
    assert_eq!(
        leaked, 0,
        "LEAK: a member outside R reads {leaked} distinct fact(s) born of the R MESSAGE"
    );
}

/// Review round 2 of #6971: a MESSAGE that names no relationship and is not
/// private reads to a member only through a grant on its conversation. The
/// outsider holds none, so it reads no distinct fact born of it.
#[test]
fn a_someone_new_answer_on_an_unscoped_message_asserts_no_distinct_fact_a_member_reads() {
    let leaked = distinct_facts_the_outsider_reads(|_| None);
    assert_eq!(
        leaked, 0,
        "LEAK: a member with no grant on the conversation reads {leaked} distinct fact(s) born of an unscoped MESSAGE"
    );
}
