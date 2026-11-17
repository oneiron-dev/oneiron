//! The distinct fact an identity answer derives from a MESSAGE stands where
//! that MESSAGE stands: in its project (FIX INTENT-DISTINCT-PROJECT-WORLD;
//! ONE-1592 P3, ARCH-0022 #task-facet-not-built).
//!
//! Two people named Ada are in the vault. The owner's TURN holds a MESSAGE
//! that says "Ada"; the tagger links that mention to both Adas, and the TURN
//! is then settled into a project P, as the leader-chat door settles a
//! project's turn. An agent about to act on "Ada" (`self.identity.settle`)
//! opens an identity ask, and the owner answers "someone new"
//! (`self.identity.answer`). The engine confirms a new person for the span
//! and asserts it distinct from both Adas (`entity.distinct_from`). Those
//! facts must be born in P, so a door that reads only the default project
//! does not read them. Before the fix they landed in the default project.
//!
//! Each `FIXTURE:` assertion checks the setup, never the fix. The last
//! assertion is the check.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test identity_distinct_source_position`.
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
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::tagging::{MentionLink, TaggingMarkerConfig, TaggingMode, TaggingReconciler};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::derivation_position::settle_into_project;
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
                relations: None,
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

/// The project each claim of `claims` is stamped with.
fn projects(vault: &Vault, claims: &[EntityId]) -> Vec<EntityId> {
    claims
        .iter()
        .map(|claim| {
            vault
                .get_claim(claim)
                .expect("claim read")
                .expect("FIXTURE: the claim is stored")
                .scope_project
        })
        .collect()
}

#[test]
fn a_distinct_fact_from_a_project_message_stands_in_that_project() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.tagging = Some(
        TaggingMarkerConfig::new(CHECKPOINT)
            .expect("checkpoint")
            .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
            .with_mode(TaggingMode::Save),
    );
    let vault = Arc::new(open_member_vault(dir.path(), config, &[]).expect("fixture vault"));
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
    let default_project = oneiron::claim::default_project_id();

    let turn = EntityId::now();
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "Ada told me about the move.".to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
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
            message,
            &MentionLink::Candidates {
                kind: ENTITY_TYPE_PERSON,
                entities: both,
            }
        ),
        "FIXTURE: the MESSAGE's Ada names both Adas"
    );
    let project = EntityId::now();
    settle_into_project(&vault, &[turn, message], project).expect("the turn settles into P");

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

    // The same fact between the two Adas, asserted from no MESSAGE: it stands
    // in the default project, so a fact elsewhere is placed for its source.
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
    assert!(
        !open.is_empty()
            && projects(&vault, &open)
                .iter()
                .all(|stamped| *stamped == default_project),
        "FIXTURE: the distinct fact between the two Adas stands in the default project"
    );

    let stamped = projects(&vault, &born);
    assert!(
        stamped.iter().all(|stamped| *stamped == project),
        "LEAK: the distinct facts born of a MESSAGE of project P stand in {stamped:?}, not P"
    );
}
