//! SAVED-QUESTION-OUTCOME-IGNORES-READ-LANE: a learning question saved under
//! a world-bound read lane takes an outcome label only from a fact that lane
//! reads. A fact outside its worlds labels the owner's own question over the
//! same unit, and never the bound one: not at arrival, not at a manual
//! projection, not at its window's close, and no calibration pair. A fact
//! inside its worlds labels the bound question by its window's close, or by
//! a manual projection before it.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::world_access::WorldAuthoritySet;
use oneiron::claim::{CallerLocality, ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
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
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Result, Vault, VaultConfig, WriteActor};
use serde_json::json;

const OUTCOME_PREDICATE: &str = "profile.saved_lane.outcome";
const HORIZON: u64 = 60;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    proof: AuthenticatedOwner,
    owner_key: ScopedReadActorKey,
    unit: EntityId,
    other_world: EntityId,
    /// The owner's question saved under a lane bound to the base world.
    bound: EntityId,
    bound_answer: AnswerRecord,
    /// The owner's question over the same unit, saved under the owner's own
    /// lane: the control that the fact matches.
    control: EntityId,
    control_answer: AnswerRecord,
}

impl Fixture {
    /// The base-world lane the bound question was saved through, rebuilt
    /// live over the owner's key.
    fn bound_lane(&self) -> oneiron::claim::ScopedRead<'_> {
        self.vault
            .scoped_read(self.owner_key.clone())
            .within_worlds(base_world_only())
    }

    fn labels(&self, question: EntityId) -> Vec<OutcomeLabel> {
        outcome_labels(&self.vault, self.owner, question, CallerLocality::OnDevice)
            .expect("stored outcome labels of the owner's question")
    }

    /// The instant every window of the fixture's answers has closed by.
    fn close_at(&self) -> u64 {
        self.bound_answer
            .answered_at
            .max(self.control_answer.answered_at)
            + HORIZON
            + 1
    }

    /// The fact time inside both answers' windows.
    fn fact_at(&self) -> u64 {
        self.bound_answer
            .answered_at
            .max(self.control_answer.answered_at)
    }

    /// The owner states the outcome about the unit in `world`.
    fn write_fact(&self, world: EntityId) -> EntityId {
        let id = EntityId::now();
        let at = self.fact_at();
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.proof)
            .claim_upsert_scoped(&ScopedClaimInput {
                id: Some(id.to_hex()),
                predicate: OUTCOME_PREDICATE.to_owned(),
                subject_ref: self.unit.to_hex(),
                value: json!("yes"),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                scope: ClaimScope {
                    world_id: world.to_hex(),
                    scope_facet_id: self
                        .vault
                        .default_facet()
                        .expect("owner default facet")
                        .to_hex(),
                    scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                    scope_project_id: default_project_id().to_hex(),
                },
                sensitivity: None,
                evidence_turn_refs: Vec::new(),
                valid_from: None,
                valid_to: None,
                occurred_at: Some(at),
                learned_at: Some(at),
                salience: None,
            })
            .expect("precondition: the owner's outcome fact commits");
        id
    }

    fn owner_reads(&self, id: &EntityId) -> bool {
        self.vault
            .scoped_read(self.owner_key.clone())
            .get_entity_parts_with_receipt(id, None)
            .expect("owner point read")
            .value
            .is_some()
    }

    fn bound_lane_reads(&self, id: &EntityId) -> bool {
        self.bound_lane()
            .get_entity_parts_with_receipt(id, None)
            .expect("base-world lane point read")
            .value
            .is_some()
    }
}

fn base_world_only() -> WorldAuthoritySet {
    WorldAuthoritySet::new(true, Vec::<EntityId>::new()).expect("the base-world set")
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

/// The owner's one answer to `question`, at `now`.
fn answer(vault: &Vault, actor: WriteActor, question: EntityId, now: u64) -> AnswerRecord {
    let mut answers =
        refresh_standing_question_with(vault, actor, actor.entity_ref(), question, now, |_, _| {
            Ok(UnitAnswerer)
        })
        .expect("precondition: the owner's question answers its unit");
    assert_eq!(
        answers.len(),
        1,
        "precondition: one answer for question {question:?}; seen {answers:?}"
    );
    answers.remove(0)
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let now = vault.now_recorded_at();
    let other_world = vault
        .create_world(&proof, "Saved lane excluded world", now)
        .expect("precondition: the owner creates a second world");
    assert_ne!(
        other_world,
        base_world_id(),
        "precondition: the second world is not the base world"
    );
    let unit = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(&proof)
        .put_structural(&StructuralPutInput {
            id: Some(unit.to_hex()),
            kind: "PERSON".to_owned(),
            body: json!({"name": "Saved lane fixture unit"}),
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
    let bound_lane = vault
        .scoped_read(owner_key.clone())
        .within_worlds(base_world_only());
    assert!(
        bound_lane
            .get_entity_parts_with_receipt(&unit, None)
            .expect("base-world lane point read")
            .value
            .is_some(),
        "precondition: the base-world lane reads the unit"
    );
    let bound_record = create_question_with_lane(&vault, actor, &bound_lane, definition(unit), now)
        .expect("precondition: the owner saves a question through the base-world lane");
    assert!(
        !bound_record.read_lane.is_principal(),
        "precondition: the base-world bound survives the save; seen {:?}",
        bound_record.read_lane
    );
    let control_record = create_question(&vault, actor, definition(unit), now)
        .expect("precondition: the owner saves the same question under its own lane");
    assert!(
        control_record.read_lane.is_principal(),
        "precondition: the control is saved under the owner's own lane"
    );
    let bound = bound_record.definition.question.id;
    let control = control_record.definition.question.id;
    let bound_answer = answer(&vault, actor, bound, now);
    let control_answer = answer(&vault, actor, control, now);
    for (question, answer) in [(bound, &bound_answer), (control, &control_answer)] {
        assert_eq!(
            answer.unit, unit,
            "precondition: question {question:?} answers the unit"
        );
    }
    let fixture = Fixture {
        vault,
        _dir: dir,
        owner,
        proof,
        owner_key,
        unit,
        other_world,
        bound,
        bound_answer,
        control,
        control_answer,
    };
    for question in [bound, control] {
        assert!(
            fixture.labels(question).is_empty(),
            "precondition: question {question:?} holds no label before any fact"
        );
    }
    fixture
}

/// The control labels `fact` once, naming its own answer.
fn assert_control_labelled(fixture: &Fixture, fact: EntityId, when: &str) {
    let labels = fixture.labels(fixture.control);
    assert!(
        labels.len() == 1
            && labels[0].fact == fact
            && labels[0].answer == fixture.control_answer.claim,
        "precondition: the owner's own question labels fact {fact:?} {when}; seen {labels:?}"
    );
}

#[test]
fn a_world_bound_saved_question_takes_no_label_from_a_fact_outside_its_worlds() {
    let fixture = fixture();
    let fact = fixture.write_fact(fixture.other_world);
    assert!(
        fixture.owner_reads(&fact),
        "precondition: the owner reads the fact in the second world"
    );
    assert!(
        !fixture.bound_lane_reads(&fact),
        "precondition: the base-world lane does not read the fact in the second world"
    );
    assert_control_labelled(&fixture, fact, "at arrival");
    let labels = fixture.labels(fixture.bound);
    assert!(
        labels.is_empty(),
        "actor=owner's question saved under the base-world lane; expected no outcome label at \
         arrival from fact {fact:?} in world {:?}; seen {labels:?}",
        fixture.other_world
    );
    project_bound_outcomes(&fixture.vault, fixture.owner, fixture.bound)
        .expect("manual projection of the bound question");
    let labels = fixture.labels(fixture.bound);
    assert!(
        labels.is_empty(),
        "actor=owner's question saved under the base-world lane; expected no outcome label after \
         a manual projection from fact {fact:?}; seen {labels:?}"
    );
    let closed = close_due_outcome_windows(&fixture.vault, fixture.close_at())
        .expect("close the lapsed windows");
    assert_eq!(closed, 2, "precondition: both answers' windows close");
    let labels = fixture.labels(fixture.bound);
    assert!(
        labels.is_empty(),
        "actor=owner's question saved under the base-world lane; expected no outcome label after \
         its window's close from fact {fact:?}; seen {labels:?}"
    );
    let control_windows = closed_outcome_windows(&fixture.vault, fixture.owner, fixture.control)
        .expect("control windows");
    assert!(
        control_windows.len() == 1 && matches!(control_windows[0].outcome, WindowOutcome::Observed),
        "precondition: the control's window closes observed; seen {control_windows:?}"
    );
    let windows = closed_outcome_windows(&fixture.vault, fixture.owner, fixture.bound)
        .expect("bound question windows");
    assert!(
        windows.len() == 1 && matches!(windows[0].outcome, WindowOutcome::Unknown),
        "actor=owner's question saved under the base-world lane; expected its window to close \
         unknown, the only fact lying outside its worlds; seen {windows:?}"
    );
    let control_pairs = calibration_pairs(
        &fixture.vault,
        fixture.owner,
        fixture.control,
        CallerLocality::OnDevice,
    )
    .expect("control calibration pairs");
    assert_eq!(
        control_pairs.len(),
        1,
        "precondition: the control pairs its answer with the fact; seen {control_pairs:?}"
    );
    let pairs = calibration_pairs(
        &fixture.vault,
        fixture.owner,
        fixture.bound,
        CallerLocality::OnDevice,
    )
    .expect("bound question calibration pairs");
    assert!(
        pairs.is_empty(),
        "actor=owner's question saved under the base-world lane; expected no calibration pair \
         from fact {fact:?}; seen {pairs:?}"
    );
}

#[test]
fn a_world_bound_saved_question_labels_a_fact_inside_its_worlds_at_its_window_close() {
    let fixture = fixture();
    let fact = fixture.write_fact(base_world_id());
    assert!(
        fixture.bound_lane_reads(&fact),
        "precondition: the base-world lane reads the fact in the base world"
    );
    assert_control_labelled(&fixture, fact, "at arrival");
    let closed = close_due_outcome_windows(&fixture.vault, fixture.close_at())
        .expect("close the lapsed windows");
    assert_eq!(closed, 2, "precondition: both answers' windows close");
    let labels = fixture.labels(fixture.bound);
    assert!(
        labels.len() == 1
            && labels[0].fact == fact
            && labels[0].answer == fixture.bound_answer.claim,
        "actor=owner's question saved under the base-world lane; expected fact {fact:?} inside \
         its worlds to label its answer by its window's close; seen {labels:?}"
    );
    let windows = closed_outcome_windows(&fixture.vault, fixture.owner, fixture.bound)
        .expect("bound question windows");
    assert!(
        windows.len() == 1 && matches!(windows[0].outcome, WindowOutcome::Observed),
        "actor=owner's question saved under the base-world lane; expected its window to close \
         observed; seen {windows:?}"
    );
    let pairs = calibration_pairs(
        &fixture.vault,
        fixture.owner,
        fixture.bound,
        CallerLocality::OnDevice,
    )
    .expect("bound question calibration pairs");
    assert_eq!(
        pairs.len(),
        1,
        "actor=owner's question saved under the base-world lane; expected one calibration pair \
         from fact {fact:?}; seen {pairs:?}"
    );
}

#[test]
fn a_world_bound_saved_question_labels_a_fact_inside_its_worlds_at_a_manual_projection() {
    let fixture = fixture();
    let fact = fixture.write_fact(base_world_id());
    assert_control_labelled(&fixture, fact, "at arrival");
    project_bound_outcomes(&fixture.vault, fixture.owner, fixture.bound)
        .expect("manual projection of the bound question");
    let labels = fixture.labels(fixture.bound);
    assert!(
        labels.len() == 1
            && labels[0].fact == fact
            && labels[0].answer == fixture.bound_answer.claim,
        "actor=owner's question saved under the base-world lane; expected fact {fact:?} inside \
         its worlds to label its answer once a manual projection has run; seen {labels:?}"
    );
}
