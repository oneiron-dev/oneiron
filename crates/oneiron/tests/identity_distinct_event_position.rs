//! The ledger event of a distinct fact an identity answer derives from a
//! MESSAGE stands where that fact stands: in the MESSAGE's project (FIX
//! DISTINCT-EVENT-DEFAULT-PROJECT-STAMP; ARCH-0022 :139, a derivation is born
//! under its source's position).
//!
//! The fixture is `identity_distinct_source_position`'s: two people named Ada,
//! the owner's TURN that says "Ada" settled into a project P, an agent's
//! identity ask on "Ada" and the owner's "someone new" answer. The engine
//! asserts the new person distinct from both Adas, and #9165 places those
//! `entity.distinct_from` CLAIMs in P. Each assertion is also a type-74
//! AssertDistinct ledger event that names the pair and its CLAIM, signed by an
//! admission disposition. A door that judges a row by its own stamp
//! (`Vault::records_in_scope`) must read those events where it reads the
//! CLAIMs: in P, never in the default project. Before the fix both rows were
//! stamped in the default project, so a default-project read served the pair
//! and the claim id of P's fact.
//!
//! Each `FIXTURE:` assertion checks the setup, never the fix. The `LEAK:`
//! assertions are the check.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test identity_distinct_event_position`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::dreamer_runner::maintenance::identity::{
    IdentityActNow, IdentityActNowRequest, IdentityAnswerRequest, IdentityEffect,
};
use oneiron::edge::EdgeActorClass;
use oneiron::embed::EmbedderLocality;
use oneiron::federation::record_scope::{ScopeView, ScopedRecord};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::identity_topology::{
    AssertDistinctOp, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp,
    StoredIdentityOpAction,
};
use oneiron::memory::extraction::{
    EncoderAttempt, EncoderInput, EncoderOutput, ExtractionEncoder, ExtractionWork, NerSpan,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_PERSON};
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

/// A selector that reads every record of `project` only.
fn project_selector(project: EntityId) -> Scope {
    let mut selector = Scope::top();
    selector.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(project)]));
    selector
}

/// The records a slip with no limit reads at `selector`.
fn rows_at(vault: &Vault, selector: &Scope) -> Vec<ScopedRecord> {
    let top = Scope::top();
    vault
        .records_in_scope(selector, &top, &top, ScopeView::Normal)
        .expect("scoped read")
}

/// The type-74 identity topology events among `rows`, with their actions.
fn topology_events(
    vault: &Vault,
    rows: &[ScopedRecord],
) -> Vec<(EntityId, StoredIdentityOpAction)> {
    let band = ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT]));
    rows.iter()
        .filter(|row| row.scope.as_ref().is_some_and(|scope| scope.bands == band))
        .map(|row| {
            let event = vault
                .identity_topology_event(&row.id)
                .expect("event read")
                .expect("FIXTURE: a stamped topology event is stored");
            (row.id, event.action)
        })
        .collect()
}

fn held(rows: &[ScopedRecord], ids: &[EntityId]) -> Vec<EntityId> {
    ids.iter()
        .copied()
        .filter(|id| rows.iter().any(|row| row.id == *id))
        .collect()
}

#[test]
fn a_distinct_event_from_a_project_message_stands_in_that_project() {
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
            project: None,
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

    // The same fact between the two Adas, asserted from no MESSAGE: its
    // CLAIM and its event stand in the default project.
    let outcome = vault
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
    let IdentityOpOutcome::Applied {
        event: open_event, ..
    } = outcome
    else {
        panic!("FIXTURE: an Auto assertion applies, got {outcome:?}");
    };

    let everything = topology_events(&vault, &rows_at(&vault, &Scope::top()));
    let events: Vec<EntityId> = everything
        .iter()
        .filter_map(|(id, action)| match action {
            StoredIdentityOpAction::AssertDistinct { claim, .. } if born.contains(claim) => {
                Some(*id)
            }
            _ => None,
        })
        .collect();
    let signed: Vec<EntityId> = everything
        .iter()
        .filter_map(|(id, action)| match action {
            StoredIdentityOpAction::AdmissionDisposition(disposition)
                if events.contains(&disposition.target) =>
            {
                Some(*id)
            }
            _ => None,
        })
        .collect();
    assert!(
        !events.is_empty() && !signed.is_empty(),
        "FIXTURE: the answer's distinct facts are asserted by signed ledger events \
         (events {events:?}, dispositions {signed:?})"
    );
    let placed: Vec<EntityId> = events.iter().chain(&signed).copied().collect();

    let default_rows = rows_at(&vault, &project_selector(default_project));
    assert!(
        held(&default_rows, &[open_event]) == [open_event] && held(&default_rows, &born).is_empty(),
        "FIXTURE: a default-project read holds the default-project event and none of P's CLAIMs"
    );
    let project_rows = rows_at(&vault, &project_selector(project));
    assert_eq!(
        held(&project_rows, &born),
        born,
        "FIXTURE: a read of P holds P's distinct CLAIMs"
    );

    assert_eq!(
        held(&default_rows, &placed),
        Vec::<EntityId>::new(),
        "LEAK: a default-project read serves the ledger events of P's distinct facts"
    );
    assert_eq!(
        held(&project_rows, &placed),
        placed,
        "LEAK: the ledger events of P's distinct facts do not stand in P"
    );
}
