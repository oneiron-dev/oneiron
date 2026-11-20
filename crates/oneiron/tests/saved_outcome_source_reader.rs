//! A saved question's outcome derivation reads through the lane its source
//! reader rebuilds (FIX ARRIVAL-SAVED-LANE-VERDICT-ADOPTS-SHARED-REBUILD).
//!
//! The refresh, artifact asks and withdrawal wakes rebuild a saved lane over
//! the principal's key with `saved_source_key_in_txn`: the key reads as the
//! class the lane was saved under (FIX
//! SAVED-LANE-REBUILD-SUBSTITUTES-ACTOR-CLASS), and with the owner's
//! exemption while the principal is the vault's live owner, kept only where
//! the lane's live key held an owner standing (FIX
//! SAVED-SOURCE-DROPS-OWNER-EXEMPTION). The outcome derivation (a fact's
//! labels, the window closes and the calibration pairs) rebuilt the same lane
//! by hand: the principal's key from its row under the access gate, narrowed
//! as a caller's key. So a lane the owner saved through an agent-class
//! credential on their own PERSON had no meet with that human-class key and
//! read nothing, and its question took no label from a fact its lane, its
//! refresh and its source reader all read. A lane saved through the owner's
//! attenuated device credential lost the owner's exemption, and its question
//! took no label from a fact in a relationship the owner holds no grant in,
//! which the same three read. The derivation now rebuilds the lane through
//! the source reader.
//!
//! Red at c8e2f038f58 (main) plus this file, by reading the rebuild (not
//! run): the agent-class question takes no label at a manual projection,
//! closes its window unknown with no calibration pair, and the device
//! question takes no label from the relationship fact. Guard: the
//! agent-class question, whose live key held no owner standing, still takes
//! no label from the relationship fact.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test saved_outcome_source_reader`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, SlipCaveat, VerifiedSlip,
};
use oneiron::claim::{
    CallerLocality, FrozenReadLane, ScopedReadActorKey, base_world_id, default_project_id,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::llm::decision::questions::{
    AnswerRecord, GraphAnswerer, GraphPrediction, GraphUnitContext, OutcomeBinding, OutcomeLabel,
    OutcomeSource, QuestionActivation, QuestionDefinitionInput, RefreshPolicy, WindowOutcome,
    calibration_pairs, close_due_outcome_windows, closed_outcome_windows, create_question,
    create_question_with_lane, outcome_labels, project_bound_outcomes,
    refresh_standing_question_with,
};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionQuestionInput, DecisionRung, ProviderPin,
};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput, StructuralPutInput,
};
use oneiron::registry::ENTITY_TYPE_RELATIONSHIP;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::question_saved_lane::{question_read, saved_source_reader};
use oneiron::{EdgeActorClass, EntityId, Result, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

const OUTCOME_PREDICATE: &str = "profile.saved_outcome_source.outcome";
const HORIZON: u64 = 60;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:saved-outcome-source-reader";
/// The binding key seed of the owner's agent-class credential.
const AGENT_BINDING_SEED: u8 = 0x5A;
/// The binding key seed of the owner's own human-class device.
const DEVICE_BINDING_SEED: u8 = 0x5B;
/// The caveat that narrows only the device credential's lifetime.
const CAVEAT_TTL_SECS: u64 = 1_800;

/// A device vault under the shipped policy whose embedded owner wrote one
/// PERSON unit, keeps a relationship the owner holds no grant in and is no
/// member of, and paired an agent-class credential and a human-class device
/// on their own PERSON.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    proof: AuthenticatedOwner,
    owner_key: ScopedReadActorKey,
    unit: EntityId,
    relationship: EntityId,
    agent_slip: CapabilitySlip,
    device_slip: CapabilitySlip,
    now: u64,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's pairing link is an owner act this install's live machine
    // profile carries (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let now = vault.now_recorded_at();
    let unit = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(&proof)
        .put_structural(&StructuralPutInput {
            id: Some(unit.to_hex()),
            kind: "PERSON".to_owned(),
            body: json!({"name": "Saved outcome source fixture unit"}),
            text_fields: None,
            edges: None,
            occurred_at: now,
            learned_at: None,
        })
        .expect("precondition: the owner writes the unit");
    let owner_key = vault
        .memory(owner, EdgeActorClass::Human)
        .read_key()
        .expect("the owner's read key");
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"relationship",
        )
        .expect("precondition: a relationship the owner holds no grant in");
    let agent_slip = paired_slip(&vault, &issuer, &proof, owner, "agent", AGENT_BINDING_SEED);
    let device_slip = paired_slip(&vault, &issuer, &proof, owner, "human", DEVICE_BINDING_SEED);
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner,
        proof,
        owner_key,
        unit,
        relationship,
        agent_slip,
        device_slip,
        now,
    }
}

/// A credential on the owner's own PERSON, naming `class`, paired on a link
/// the owner issues and redeemed by the key whose seed is `seed`.
fn paired_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner_proof: &AuthenticatedOwner,
    owner: EntityId,
    class: &str,
    seed: u8,
) -> CapabilitySlip {
    let holder = owner.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            issuer,
            owner_proof,
            Scope::top(),
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some(class.to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("the owner issues a pairing link on their own PERSON");
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("the pairing transcript");
    vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("the credential's key redeems the link")
}

/// `slip`, proved by the key whose seed is `seed`.
fn verified(fixture: &Fixture, slip: &CapabilitySlip, seed: u8) -> VerifiedSlip {
    let signature = SigningKey::from_bytes(&[seed; 32])
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("the holder's request transcript"),
        )
        .to_bytes();
    fixture
        .vault
        .verify_capability_slip(
            &fixture.issuer.public_key(),
            slip,
            REQUEST_CHALLENGE,
            &signature,
        )
        .expect("the holder proves possession of the credential")
}

fn credential_key(fixture: &Fixture, proof: &VerifiedSlip) -> ScopedReadActorKey {
    fixture
        .vault
        .credential_read_key(proof)
        .expect("the credential's read key")
        .expect("the credential grants read")
}

/// The owner's agent-class credential's live key: an agent below the
/// owner's floor, with no owner standing.
fn agent_key(fixture: &Fixture) -> ScopedReadActorKey {
    let key = credential_key(
        fixture,
        &verified(fixture, &fixture.agent_slip, AGENT_BINDING_SEED),
    );
    assert!(
        key.actor_class() == Some("agent") && !key.reads_as_vault_owner(),
        "precondition: the owner's agent-class credential reads as an agent, below the owner's floor; seen class {:?}",
        key.actor_class()
    );
    key
}

/// The owner's device credential narrowed by the device itself, kept on its
/// key: a human-class key below the owner's floor, holding the owner's
/// exemption (`credential_read_key`).
fn attenuated_device_key(fixture: &Fixture) -> ScopedReadActorKey {
    let mut slip = fixture.device_slip.clone();
    slip.attenuate(
        SlipCaveat {
            ttl_secs: Some(CAVEAT_TTL_SECS),
            ..Default::default()
        },
        &SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32]),
    )
    .expect("the device narrows its own credential");
    let key = credential_key(fixture, &verified(fixture, &slip, DEVICE_BINDING_SEED));
    assert!(
        key.actor_class() == Some("human") && !key.reads_as_vault_owner(),
        "precondition: the device's attenuated credential reads as a human, below the owner's floor; seen class {:?}",
        key.actor_class()
    );
    key
}

/// Whether the live lane over `key` point-reads `row`; the text names the
/// answer.
fn reads(vault: &Vault, key: &ScopedReadActorKey, row: EntityId) -> (bool, String) {
    let read = vault
        .scoped_read(key.clone())
        .get_entity_parts_with_receipt(&row, None)
        .map(|read| read.value.is_some());
    (matches!(read, Ok(true)), format!("point={read:?}"))
}

/// What the owner's question saved under `lane` source-reads of `row` (its
/// refresh, artifact and wake reads).
fn source_reads(fixture: &Fixture, lane: &FrozenReadLane, row: EntityId) -> (bool, String) {
    match saved_source_reader(&fixture.vault, fixture.owner, lane) {
        Ok(key) => {
            let read = question_read(&fixture.vault, key)
                .get_entity_parts_with_receipt(&row, None)
                .map(|read| read.value.is_some());
            (matches!(read, Ok(true)), format!("point={read:?}"))
        }
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

struct UnitAnswerer;

impl GraphAnswerer for UnitAnswerer {
    fn answer(
        &mut self,
        _question: &DecisionQuestion,
        _context: &GraphUnitContext,
    ) -> Result<Option<GraphPrediction>> {
        Ok(Some(GraphPrediction {
            answer: DecisionAnswer::Noul(true),
            probability: 0.9,
            provider: ProviderPin {
                rung: DecisionRung::Local,
                model: "local/fixture".into(),
                version: "r1".into(),
            },
            cost_per_thousand: 0.0,
            paired: None,
            rule: None,
        }))
    }
}

/// A learning standing question over `unit`, labelled by the owner's
/// outcome claim about it.
fn definition(unit: EntityId) -> QuestionDefinitionInput {
    QuestionDefinitionInput {
        question: DecisionQuestionInput {
            text: "Does this unit reach a positive outcome?".into(),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        adapter: "graph".into(),
        units: vec![unit],
        recipe: "unit_only".into(),
        profile: "default".into(),
        dial: DecisionDial {
            first: DecisionRung::Local,
            ceiling: DecisionRung::Local,
            band: DecisionBand::default(),
        },
        activation: QuestionActivation::Standing,
        refresh: RefreshPolicy {
            on_arrival: false,
            every_seconds: None,
        },
        delivery: "now".into(),
        learning: true,
        binding: Some(OutcomeBinding {
            source: OutcomeSource::Claim {
                predicate: OUTCOME_PREDICATE.to_owned(),
            },
            horizon: HORIZON,
            mapping: BTreeMap::from([("yes".to_owned(), true)]),
            noise_weight: 1.0,
            linked_by: None,
        }),
        criteria: Default::default(),
        audience: Default::default(),
        posture: None,
        media: Default::default(),
        deadline_ms: None,
        artifacts: Vec::new(),
    }
}

/// The owner's one answer to their own `question`, at the fixture's `now`.
fn owner_answer(fixture: &Fixture, question: EntityId) -> AnswerRecord {
    let actor = WriteActor::new(fixture.owner, EdgeActorClass::Human);
    let mut answers = refresh_standing_question_with(
        &fixture.vault,
        actor,
        fixture.owner,
        question,
        fixture.now,
        |_, _| Ok(UnitAnswerer),
    )
    .expect("precondition: the owner's question answers its unit");
    assert_eq!(
        answers.len(),
        1,
        "precondition: one answer for question {question:?}; seen {answers:?}"
    );
    answers.remove(0)
}

/// The owner's question over the unit saved through a credential's live
/// lane, beside the owner's own question over the same unit.
struct Saved {
    fixture: Fixture,
    /// Which credential the question was saved through, for the messages.
    through: &'static str,
    lane: FrozenReadLane,
    question: EntityId,
    answer: AnswerRecord,
    control: EntityId,
    control_answer: AnswerRecord,
}

/// The owner saves a question through `key`'s live lane, and the same
/// question under their own lane; each answers the unit.
fn saved_through(fixture: Fixture, key: ScopedReadActorKey, through: &'static str) -> Saved {
    let actor = WriteActor::new(fixture.owner, EdgeActorClass::Human);
    let (live, seen) = reads(&fixture.vault, &key, fixture.unit);
    assert!(
        live,
        "precondition: the {through}'s live lane reads the unit; seen {seen}"
    );
    let record = create_question_with_lane(
        &fixture.vault,
        actor,
        &fixture.vault.scoped_read(key),
        definition(fixture.unit),
        fixture.now,
    )
    .expect("precondition: the owner saves a question through the credential's live lane");
    let lane = record.read_lane.clone();
    assert!(
        !lane.is_principal() && !lane.reads_as_principal(),
        "precondition: the {through}'s saved lane keeps its Scope and basis, not its holder's principal lane; seen {lane:?}"
    );
    let (source, seen) = source_reads(&fixture, &lane, fixture.unit);
    assert!(
        source,
        "precondition: the {through}'s saved question source-reads the unit; seen {seen}"
    );
    let control_record =
        create_question(&fixture.vault, actor, definition(fixture.unit), fixture.now)
            .expect("precondition: the owner saves the same question under its own lane");
    assert!(
        control_record.read_lane.is_principal(),
        "precondition: the control is saved under the owner's own lane"
    );
    let question = record.definition.question.id;
    let control = control_record.definition.question.id;
    let answer = owner_answer(&fixture, question);
    let control_answer = owner_answer(&fixture, control);
    for (id, answer) in [(question, &answer), (control, &control_answer)] {
        assert_eq!(
            answer.unit, fixture.unit,
            "precondition: question {id:?} answers the unit"
        );
    }
    let saved = Saved {
        fixture,
        through,
        lane,
        question,
        answer,
        control,
        control_answer,
    };
    for id in [question, control] {
        assert!(
            saved.labels(id).is_empty(),
            "precondition: question {id:?} holds no label before any fact"
        );
    }
    saved
}

impl Saved {
    fn vault(&self) -> &Vault {
        &self.fixture.vault
    }

    fn labels(&self, question: EntityId) -> Vec<OutcomeLabel> {
        outcome_labels(
            self.vault(),
            self.fixture.owner,
            question,
            CallerLocality::OnDevice,
        )
        .expect("stored outcome labels of the owner's question")
    }

    /// The fact time inside both answers' windows.
    fn fact_at(&self) -> u64 {
        self.answer.answered_at.max(self.control_answer.answered_at)
    }

    /// The instant both answers' windows have closed by.
    fn close_at(&self) -> u64 {
        self.fact_at() + HORIZON + 1
    }

    /// The owner states the outcome about the unit in the base world, scoped
    /// to `relationships`, and the control labels it at its arrival.
    fn write_fact(&self, relationships: ClaimRelationships) -> EntityId {
        let fixture = &self.fixture;
        let fact = EntityId::now();
        fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .with_owner_authorship(&fixture.proof)
            .claim_upsert_scoped(&ScopedClaimInput {
                id: Some(fact.to_hex()),
                predicate: OUTCOME_PREDICATE.to_owned(),
                subject_ref: fixture.unit.to_hex(),
                value: json!("yes"),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                scope: ClaimScope {
                    world_id: base_world_id().to_hex(),
                    scope_facet_id: fixture
                        .vault
                        .default_facet()
                        .expect("owner default facet")
                        .to_hex(),
                    scope_relationship_id: relationships,
                    scope_project_id: default_project_id().to_hex(),
                }
                .into(),
                sensitivity: None,
                evidence_turn_refs: Vec::new(),
                valid_from: None,
                valid_to: None,
                occurred_at: Some(self.fact_at()),
                learned_at: Some(self.fact_at()),
                salience: None,
            })
            .expect("precondition: the owner's outcome claim commits");
        let (owner_reads, seen) = reads(&fixture.vault, &fixture.owner_key, fact);
        assert!(
            owner_reads,
            "precondition: the owner reads their own outcome claim; seen {seen}"
        );
        let labels = self.labels(self.control);
        assert!(
            labels.len() == 1
                && labels[0].fact == fact
                && labels[0].answer == self.control_answer.claim,
            "precondition: the owner's own question labels fact {fact:?} at arrival; seen {labels:?}"
        );
        fact
    }

    /// The owner's outcome claim scoped to every relationship.
    fn write_open_fact(&self) -> EntityId {
        self.write_fact(ClaimRelationships::All(AllRelationships::All))
    }

    /// The owner's outcome claim scoped to the relationship the owner holds
    /// no grant in.
    fn write_relationship_fact(&self) -> EntityId {
        self.write_fact(ClaimRelationships::Relationships(vec![
            self.fixture.relationship.to_hex(),
        ]))
    }

    /// Whether the saved question's source reader reads `fact`, as the live
    /// lane over `key` it was saved through does: `expected`.
    fn assert_source_reads(&self, key: &ScopedReadActorKey, fact: EntityId, expected: bool) {
        let through = self.through;
        let (live, seen) = reads(self.vault(), key, fact);
        assert!(
            live == expected,
            "precondition: the {through}'s live lane {} fact {fact:?}; seen {seen}",
            if expected { "reads" } else { "refuses" }
        );
        let (source, seen) = source_reads(&self.fixture, &self.lane, fact);
        assert!(
            source == expected,
            "precondition: the {through}'s saved question source-{} fact {fact:?}, as its refresh reads; seen {seen}",
            if expected { "reads" } else { "refuses" }
        );
    }

    fn assert_labelled_once(&self, fact: EntityId, when: &str) {
        let labels = self.labels(self.question);
        assert!(
            labels.len() == 1 && labels[0].fact == fact && labels[0].answer == self.answer.claim,
            "actor=the owner's question saved through the {}; expected fact {fact:?}, which its \
             lane, its live key and its source reader read, to label its answer {when}; seen \
             {labels:?}",
            self.through
        );
    }

    fn project(&self) {
        project_bound_outcomes(self.vault(), self.fixture.owner, self.question)
            .expect("manual projection of the saved question");
    }

    fn close_windows(&self) {
        let closed = close_due_outcome_windows(self.vault(), self.close_at())
            .expect("close the lapsed windows");
        assert_eq!(closed, 2, "precondition: both answers' windows close");
    }
}

#[test]
fn an_agent_class_credentials_saved_question_labels_a_fact_its_lane_reads_at_a_manual_projection() {
    let fixture = fixture();
    let key = agent_key(&fixture);
    let saved = saved_through(fixture, key.clone(), "owner's agent-class credential");
    let fact = saved.write_open_fact();
    saved.assert_source_reads(&key, fact, true);
    saved.project();
    saved.assert_labelled_once(fact, "once a manual projection has run");
}

#[test]
fn an_agent_class_credentials_saved_question_closes_its_window_observed_with_one_calibration_pair()
{
    let fixture = fixture();
    let key = agent_key(&fixture);
    let saved = saved_through(fixture, key.clone(), "owner's agent-class credential");
    let fact = saved.write_open_fact();
    saved.assert_source_reads(&key, fact, true);
    saved.close_windows();
    saved.assert_labelled_once(fact, "by its window's close");
    let windows = closed_outcome_windows(saved.vault(), saved.fixture.owner, saved.question)
        .expect("the saved question's windows");
    assert!(
        windows.len() == 1 && matches!(windows[0].outcome, WindowOutcome::Observed),
        "actor=the owner's question saved through the owner's agent-class credential; expected \
         its window to close observed on fact {fact:?}; seen {windows:?}"
    );
    let pairs = calibration_pairs(
        saved.vault(),
        saved.fixture.owner,
        saved.question,
        CallerLocality::OnDevice,
    )
    .expect("the saved question's calibration pairs");
    assert_eq!(
        pairs.len(),
        1,
        "actor=the owner's question saved through the owner's agent-class credential; expected \
         one calibration pair from fact {fact:?}; seen {pairs:?}"
    );
}

#[test]
fn an_owner_device_saved_question_labels_a_fact_in_a_relationship_the_owner_holds_no_grant_in() {
    let fixture = fixture();
    let key = attenuated_device_key(&fixture);
    let saved = saved_through(
        fixture,
        key.clone(),
        "owner's device under an attenuated credential",
    );
    let fact = saved.write_relationship_fact();
    saved.assert_source_reads(&key, fact, true);
    saved.project();
    saved.assert_labelled_once(fact, "once a manual projection has run");
}

/// Guard: a lane whose live key held no owner standing gains no exemption
/// from the source reader.
#[test]
fn an_agent_class_credentials_saved_question_takes_no_label_from_a_fact_in_a_relationship_the_owner_holds_no_grant_in()
 {
    let fixture = fixture();
    let key = agent_key(&fixture);
    let saved = saved_through(fixture, key.clone(), "owner's agent-class credential");
    let fact = saved.write_relationship_fact();
    saved.assert_source_reads(&key, fact, false);
    saved.project();
    let labels = saved.labels(saved.question);
    assert!(
        labels.is_empty(),
        "actor=the owner's question saved through the owner's agent-class credential; expected \
         no outcome label after a manual projection from fact {fact:?} in a relationship its \
         live key never read; seen {labels:?}"
    );
    saved.close_windows();
    let labels = saved.labels(saved.question);
    assert!(
        labels.is_empty(),
        "actor=the owner's question saved through the owner's agent-class credential; expected \
         no outcome label after its window's close from fact {fact:?}; seen {labels:?}"
    );
    let windows = closed_outcome_windows(saved.vault(), saved.fixture.owner, saved.question)
        .expect("the saved question's windows");
    assert!(
        windows.len() == 1 && matches!(windows[0].outcome, WindowOutcome::Unknown),
        "actor=the owner's question saved through the owner's agent-class credential; expected \
         its window to close unknown, the only fact lying outside its lane; seen {windows:?}"
    );
    let pairs = calibration_pairs(
        saved.vault(),
        saved.fixture.owner,
        saved.question,
        CallerLocality::OnDevice,
    )
    .expect("the saved question's calibration pairs");
    assert!(
        pairs.is_empty(),
        "actor=the owner's question saved through the owner's agent-class credential; expected \
         no calibration pair from fact {fact:?}; seen {pairs:?}"
    );
}
