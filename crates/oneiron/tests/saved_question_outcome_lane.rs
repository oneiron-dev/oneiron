//! SAVED-QUESTION-OUTCOME-IGNORES-READ-LANE: a learning question saved under
//! a world-bound read lane takes an outcome label only from a fact that lane
//! reads. A fact outside its worlds labels the owner's own question over the
//! same unit, and never the bound one: not at arrival, not at a manual
//! projection, not at its window's close, and no calibration pair. A fact
//! inside its worlds labels the bound question by its window's close, or by
//! a manual projection before it. An arrival defers that judgment to the
//! question pump, whose next pass labels the fact with the window still open,
//! and also a fact recorded after the window closed with an event time
//! inside it.
//!
//! OUTCOME-READER-SKIPS-RELATIONSHIP-ACCESS-GATE: a question whose principal
//! is not a live owner of the vault (here an agent) takes outcome labels only
//! from a fact its own lane reads, the relationship access gate included,
//! even when it was saved under the principal's own lane. The owner's fact
//! scoped to a relationship the agent is not in labels the owner's question
//! over the same unit, and never the agent's: not its standing question and
//! not its task ask, at arrival, at a manual projection or at its window's
//! close. A fact the agent's lane reads labels its question by its window's
//! close, or by a manual projection before it.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::world_access::WorldAuthoritySet;
use oneiron::claim::{CallerLocality, ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::questions::{
    AnswerRecord, GraphAnswerer, GraphPrediction, GraphUnitContext, OutcomeBinding, OutcomeLabel,
    OutcomeSource, OutcomeWindowClose, QuestionActivation, QuestionDefinitionInput, RefreshPolicy,
    WindowOutcome, calibration_pairs, close_due_outcome_windows, closed_outcome_windows,
    create_question, create_question_with_lane, outcome_labels, project_bound_outcomes,
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
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskQuestion, TaskAskSpec, TaskAskStatus, TaskAskTarget,
    TaskAskWord,
};
use oneiron::test_doors::derive::{define_auto_agent, grant_derive_rows};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Result, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

const OUTCOME_PREDICATE: &str = "profile.saved_lane.outcome";
/// The predicate of the claim an agent's task ask is about: never an outcome.
const REFERENCE_PREDICATE: &str = "profile.saved_lane.topic";
const HORIZON: u64 = 60;

/// A device vault whose embedded owner has written one PERSON unit.
struct OwnerVault {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    proof: AuthenticatedOwner,
    owner_key: ScopedReadActorKey,
    unit: EntityId,
    now: u64,
}

fn owner_vault() -> OwnerVault {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
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
    OwnerVault {
        vault,
        _dir: dir,
        owner,
        proof,
        owner_key,
        unit,
        now,
    }
}

/// The owner states `value` under `predicate` about `unit` at `at`, in
/// `world`, scoped to `relationships`.
#[allow(clippy::too_many_arguments)]
fn write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    proof: &AuthenticatedOwner,
    unit: EntityId,
    predicate: &str,
    at: u64,
    world: EntityId,
    relationships: ClaimRelationships,
) -> EntityId {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: predicate.to_owned(),
            subject_ref: unit.to_hex(),
            value: json!("yes"),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: world.to_hex(),
                scope_facet_id: vault.default_facet().expect("owner default facet").to_hex(),
                scope_relationship_id: relationships,
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
        .expect("precondition: the owner's claim commits");
    id
}

/// Whether the live lane over `key` reads `id`.
fn reads(vault: &Vault, key: &ScopedReadActorKey, id: &EntityId) -> bool {
    vault
        .scoped_read(key.clone())
        .get_entity_parts_with_receipt(id, None)
        .expect("live lane point read")
        .value
        .is_some()
}

fn all_relationships() -> ClaimRelationships {
    ClaimRelationships::All(AllRelationships::All)
}

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
        write_owner_claim(
            &self.vault,
            self.owner,
            &self.proof,
            self.unit,
            OUTCOME_PREDICATE,
            self.fact_at(),
            world,
            all_relationships(),
        )
    }

    fn owner_reads(&self, id: &EntityId) -> bool {
        reads(&self.vault, &self.owner_key, id)
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
        binding: Some(binding()),
        criteria: Default::default(),
        audience: Default::default(),
        posture: None,
        media: Default::default(),
        deadline_ms: None,
        artifacts: Vec::new(),
    }
}

/// The outcome binding every question of this file learns by.
fn binding() -> OutcomeBinding {
    OutcomeBinding {
        source: OutcomeSource::Claim {
            predicate: OUTCOME_PREDICATE.to_owned(),
        },
        horizon: HORIZON,
        mapping: BTreeMap::from([("yes".to_owned(), true)]),
        noise_weight: 1.0,
        linked_by: None,
    }
}

/// `actor`'s one answer to its own `question`, at `now`.
fn answer(vault: &Vault, actor: WriteActor, question: EntityId, now: u64) -> AnswerRecord {
    let mut answers =
        refresh_standing_question_with(vault, actor, actor.entity_ref(), question, now, |_, _| {
            Ok(UnitAnswerer)
        })
        .expect("precondition: the asker's question answers its unit");
    assert_eq!(
        answers.len(),
        1,
        "precondition: one answer for question {question:?}; seen {answers:?}"
    );
    answers.remove(0)
}

fn fixture() -> Fixture {
    let OwnerVault {
        vault,
        _dir: dir,
        owner,
        proof,
        owner_key,
        unit,
        now,
    } = owner_vault();
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let other_world = vault
        .create_world(&proof, "Saved lane excluded world", now)
        .expect("precondition: the owner creates a second world");
    assert_ne!(
        other_world,
        base_world_id(),
        "precondition: the second world is not the base world"
    );
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

/// An owner's vault with an owner-defined Auto agent that reads the vault's
/// records under its own `core:read` row and the relationship access gate,
/// and a relationship the agent is not in and holds no grant over.
struct AgentVault {
    base: OwnerVault,
    agent: EntityId,
    /// The agent's own live read key.
    agent_key: ScopedReadActorKey,
    relationship: EntityId,
}

impl AgentVault {
    /// The owner states the outcome about the unit at `at`, scoped to
    /// `relationships`.
    fn write_fact(&self, at: u64, relationships: ClaimRelationships) -> EntityId {
        write_owner_claim(
            &self.base.vault,
            self.base.owner,
            &self.base.proof,
            self.base.unit,
            OUTCOME_PREDICATE,
            at,
            base_world_id(),
            relationships,
        )
    }

    /// The owner's fact scoped to the relationship the agent is not in.
    fn write_fact_outside_the_agents_reach(&self, at: u64) -> EntityId {
        let fact = self.write_fact(
            at,
            ClaimRelationships::Relationships(vec![self.relationship.to_hex()]),
        );
        assert!(
            reads(&self.base.vault, &self.base.owner_key, &fact),
            "precondition: the owner reads its fact scoped to relationship {:?}",
            self.relationship
        );
        assert!(
            !reads(&self.base.vault, &self.agent_key, &fact),
            "precondition: the agent's live lane does not read the owner's fact scoped to \
             relationship {:?}, which it is not in",
            self.relationship
        );
        fact
    }

    /// The owner's fact the agent's live lane reads.
    fn write_fact_inside_the_agents_reach(&self, at: u64) -> EntityId {
        let fact = self.write_fact(at, all_relationships());
        assert!(
            reads(&self.base.vault, &self.agent_key, &fact),
            "precondition: the agent's live lane reads the owner's fact scoped to all \
             relationships"
        );
        fact
    }
}

fn agent_vault() -> AgentVault {
    let base = owner_vault();
    let vault = &base.vault;
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            TimeRange {
                start: base.now,
                end: base.now,
            },
            base.now,
            b"relationship",
        )
        .expect("precondition: a relationship the agent is not in");
    let agent = define_auto_agent(vault).expect("precondition: the owner defines an Auto agent");
    grant_derive_rows(vault, &[agent])
        .expect("precondition: the agent's core:read row and Auto ceiling");
    let agent_key = vault
        .memory(agent, EdgeActorClass::Agent)
        .read_key()
        .expect("the agent's live read key");
    assert!(
        reads(vault, &agent_key, &base.unit),
        "precondition: the agent's live lane reads the owner's unit"
    );
    AgentVault {
        base,
        agent,
        agent_key,
        relationship,
    }
}

/// The agent's standing question over the owner's unit, saved under the
/// agent's own lane, beside the owner's own question over the same unit.
struct AgentFixture {
    reach: AgentVault,
    question: EntityId,
    answer: AnswerRecord,
    control: EntityId,
    control_answer: AnswerRecord,
}

impl AgentFixture {
    fn vault(&self) -> &Vault {
        &self.reach.base.vault
    }

    fn labels(&self) -> Vec<OutcomeLabel> {
        outcome_labels(
            self.vault(),
            self.reach.agent,
            self.question,
            CallerLocality::OnDevice,
        )
        .expect("stored outcome labels of the agent's question")
    }

    fn assert_control_labelled(&self, fact: EntityId, when: &str) {
        let labels = outcome_labels(
            self.vault(),
            self.reach.base.owner,
            self.control,
            CallerLocality::OnDevice,
        )
        .expect("stored outcome labels of the owner's question");
        assert!(
            labels.len() == 1
                && labels[0].fact == fact
                && labels[0].answer == self.control_answer.claim,
            "precondition: the owner's own question labels fact {fact:?} {when}; seen {labels:?}"
        );
    }

    /// The fact time inside both answers' windows.
    fn fact_at(&self) -> u64 {
        self.answer.answered_at.max(self.control_answer.answered_at)
    }

    /// The instant both answers' windows have closed by.
    fn close_at(&self) -> u64 {
        self.fact_at() + HORIZON + 1
    }

    fn close_windows(&self) {
        let closed = close_due_outcome_windows(self.vault(), self.close_at())
            .expect("close the lapsed windows");
        assert_eq!(closed, 2, "precondition: both answers' windows close");
    }

    fn windows(&self) -> Vec<OutcomeWindowClose> {
        closed_outcome_windows(self.vault(), self.reach.agent, self.question)
            .expect("the agent's question windows")
    }
}

fn agent_fixture() -> AgentFixture {
    let reach = agent_vault();
    let base = &reach.base;
    let agent_actor = WriteActor::new(reach.agent, EdgeActorClass::Agent);
    let owner_actor = WriteActor::new(base.owner, EdgeActorClass::Human);
    let record = create_question(&base.vault, agent_actor, definition(base.unit), base.now)
        .expect("precondition: the agent saves a question over the owner's unit");
    assert!(
        record.principal == reach.agent && record.read_lane.is_principal(),
        "precondition: the agent's question is saved under the agent's own lane; seen principal \
         {:?}, lane {:?}",
        record.principal,
        record.read_lane
    );
    let control_record = create_question(&base.vault, owner_actor, definition(base.unit), base.now)
        .expect("precondition: the owner saves the same question under its own lane");
    let question = record.definition.question.id;
    let control = control_record.definition.question.id;
    let agent_answer = answer(&base.vault, agent_actor, question, base.now);
    let control_answer = answer(&base.vault, owner_actor, control, base.now);
    for (question, answer) in [(question, &agent_answer), (control, &control_answer)] {
        assert_eq!(
            answer.unit, base.unit,
            "precondition: question {question:?} answers the unit"
        );
    }
    let fixture = AgentFixture {
        reach,
        question,
        answer: agent_answer,
        control,
        control_answer,
    };
    assert!(
        fixture.labels().is_empty(),
        "precondition: the agent's question holds no label before any fact"
    );
    fixture
}

#[test]
fn an_agents_saved_question_takes_no_label_from_an_owner_fact_in_a_relationship_it_is_not_in() {
    let fixture = agent_fixture();
    let fact = fixture
        .reach
        .write_fact_outside_the_agents_reach(fixture.fact_at());
    fixture.assert_control_labelled(fact, "at arrival");
    let labels = fixture.labels();
    assert!(
        labels.is_empty(),
        "actor=agent's question saved under its own lane; expected no outcome label at arrival \
         from the owner's fact {fact:?} scoped to relationship {:?}, which it is not in; seen \
         {labels:?}",
        fixture.reach.relationship
    );
    project_bound_outcomes(fixture.vault(), fixture.reach.agent, fixture.question)
        .expect("manual projection of the agent's question");
    let labels = fixture.labels();
    assert!(
        labels.is_empty(),
        "actor=agent's question saved under its own lane; expected no outcome label after a \
         manual projection from the owner's fact {fact:?}; seen {labels:?}"
    );
    fixture.close_windows();
    let labels = fixture.labels();
    assert!(
        labels.is_empty(),
        "actor=agent's question saved under its own lane; expected no outcome label after its \
         window's close from the owner's fact {fact:?}; seen {labels:?}"
    );
    let windows = fixture.windows();
    assert!(
        windows.len() == 1 && matches!(windows[0].outcome, WindowOutcome::Unknown),
        "actor=agent's question saved under its own lane; expected its window to close unknown, \
         the only fact lying outside its relationships; seen {windows:?}"
    );
    let pairs = calibration_pairs(
        fixture.vault(),
        fixture.reach.agent,
        fixture.question,
        CallerLocality::OnDevice,
    )
    .expect("the agent's calibration pairs");
    assert!(
        pairs.is_empty(),
        "actor=agent's question saved under its own lane; expected no calibration pair from the \
         owner's fact {fact:?}; seen {pairs:?}"
    );
}

#[test]
fn an_agents_saved_question_labels_an_owner_fact_it_reads_at_its_window_close() {
    let fixture = agent_fixture();
    let fact = fixture
        .reach
        .write_fact_inside_the_agents_reach(fixture.fact_at());
    fixture.assert_control_labelled(fact, "at arrival");
    fixture.close_windows();
    let labels = fixture.labels();
    assert!(
        labels.len() == 1 && labels[0].fact == fact && labels[0].answer == fixture.answer.claim,
        "actor=agent's question saved under its own lane; expected the owner's fact {fact:?}, \
         which its lane reads, to label its answer by its window's close; seen {labels:?}"
    );
    let windows = fixture.windows();
    assert!(
        windows.len() == 1 && matches!(windows[0].outcome, WindowOutcome::Observed),
        "actor=agent's question saved under its own lane; expected its window to close observed; \
         seen {windows:?}"
    );
    let pairs = calibration_pairs(
        fixture.vault(),
        fixture.reach.agent,
        fixture.question,
        CallerLocality::OnDevice,
    )
    .expect("the agent's calibration pairs");
    assert_eq!(
        pairs.len(),
        1,
        "actor=agent's question saved under its own lane; expected one calibration pair from \
         the owner's fact {fact:?}; seen {pairs:?}"
    );
}

#[test]
fn an_agents_saved_question_labels_an_owner_fact_it_reads_at_a_manual_projection() {
    let fixture = agent_fixture();
    let fact = fixture
        .reach
        .write_fact_inside_the_agents_reach(fixture.fact_at());
    fixture.assert_control_labelled(fact, "at arrival");
    project_bound_outcomes(fixture.vault(), fixture.reach.agent, fixture.question)
        .expect("manual projection of the agent's question");
    let labels = fixture.labels();
    assert!(
        labels.len() == 1 && labels[0].fact == fact && labels[0].answer == fixture.answer.claim,
        "actor=agent's question saved under its own lane; expected the owner's fact {fact:?}, \
         which its lane reads, to label its answer once a manual projection has run; seen \
         {labels:?}"
    );
}

#[test]
fn an_agents_task_ask_hands_it_no_outcome_pair_from_an_owner_fact_in_a_relationship_it_is_not_in() {
    let reach = agent_vault();
    let base = &reach.base;
    let topic = write_owner_claim(
        &base.vault,
        base.owner,
        &base.proof,
        base.unit,
        REFERENCE_PREDICATE,
        base.now,
        base_world_id(),
        all_relationships(),
    );
    assert!(
        reads(&base.vault, &reach.agent_key, &topic),
        "precondition: the agent's live lane reads the claim it asks about"
    );
    let agent = base.vault.memory(reach.agent, EdgeActorClass::Agent);
    let mut question = TaskAskQuestion::new(ConsultPayloadRef::Claim(topic));
    question.outcome_binding = Some(binding());
    let spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People(BTreeSet::from([base.owner]))),
        question,
        None,
        TaskAskDefault::AskMe,
    );
    let handle = agent
        .tasks_ask(&spec)
        .expect("precondition: the agent asks the owner about the claim")
        .handle;
    base.vault
        .memory(base.owner, EdgeActorClass::Human)
        .tasks_answer(&handle, &TaskAskWord::new(base.unit))
        .expect("precondition: the owner answers the agent's ask about the unit");
    let TaskAskStatus::Settled(result) = agent
        .tasks_ask_status(handle)
        .expect("the agent's ask status")
    else {
        panic!("precondition: the owner's answer settles the agent's ask");
    };
    assert!(
        result.settlement.outcome_answer_ref.is_some(),
        "precondition: the settled answer is bound as a claim"
    );
    let fact = reach.write_fact_outside_the_agents_reach(base.vault.now_recorded_at());
    let pairs = agent
        .tasks_ask_outcomes(&handle)
        .expect("the agent's ask outcomes");
    assert!(
        pairs.is_empty(),
        "actor=agent's task ask; expected no outcome pair at arrival from the owner's fact \
         {fact:?} scoped to relationship {:?}, which it is not in; seen {pairs:?}",
        reach.relationship
    );
    project_bound_outcomes(&base.vault, reach.agent, handle.group_ref)
        .expect("manual projection of the agent's ask");
    let pairs = agent
        .tasks_ask_outcomes(&handle)
        .expect("the agent's ask outcomes");
    assert!(
        pairs.is_empty(),
        "actor=agent's task ask; expected no outcome pair after a manual projection from the \
         owner's fact {fact:?}; seen {pairs:?}"
    );
}

/// One pass of the question pump's outcome step at `now`, which closes no
/// window when none is due.
fn pump_outcome_pass(fixture: &Fixture, now: u64, closes: usize) {
    let closed =
        close_due_outcome_windows(&fixture.vault, now).expect("the pump's outcome window pass");
    assert_eq!(
        closed, closes,
        "precondition: the pump pass at {now} closes {closes} windows"
    );
}

/// The bound question holds one label, naming `fact` and its own answer.
fn assert_bound_labelled_once(fixture: &Fixture, fact: EntityId, when: &str) {
    let labels = fixture.labels(fixture.bound);
    assert!(
        labels.len() == 1
            && labels[0].fact == fact
            && labels[0].answer == fixture.bound_answer.claim,
        "actor=owner's question saved under the base-world lane; expected fact {fact:?} inside \
         its worlds to label its answer {when}; seen {labels:?}"
    );
}

#[test]
fn a_world_bound_saved_question_labels_a_fact_inside_its_worlds_at_the_next_pump_pass_before_its_window_closes()
 {
    let fixture = fixture();
    let fact = fixture.write_fact(base_world_id());
    assert!(
        fixture.bound_lane_reads(&fact),
        "precondition: the base-world lane reads the fact in the base world"
    );
    assert_control_labelled(&fixture, fact, "at arrival");
    pump_outcome_pass(&fixture, fixture.fact_at(), 0);
    assert_bound_labelled_once(
        &fixture,
        fact,
        "at the pump's next pass, its window still open",
    );
    let windows = closed_outcome_windows(&fixture.vault, fixture.owner, fixture.bound)
        .expect("bound question windows");
    assert!(
        windows.is_empty(),
        "precondition: the bound question's window is still open; seen {windows:?}"
    );
    let pairs = calibration_pairs(
        &fixture.vault,
        fixture.owner,
        fixture.bound,
        CallerLocality::OnDevice,
    )
    .expect("bound question calibration pairs");
    assert!(
        pairs.len() == 1 && pairs[0].outcome.fact == fact,
        "actor=owner's question saved under the base-world lane; expected one calibration pair \
         from fact {fact:?} before its window closes; seen {pairs:?}"
    );
    pump_outcome_pass(&fixture, fixture.fact_at(), 0);
    assert_bound_labelled_once(&fixture, fact, "once, after a second pump pass");
}

#[test]
fn a_world_bound_saved_question_labels_a_fact_recorded_after_its_window_closed_at_the_next_pump_pass()
 {
    let fixture = fixture();
    pump_outcome_pass(&fixture, fixture.close_at(), 2);
    let windows = closed_outcome_windows(&fixture.vault, fixture.owner, fixture.bound)
        .expect("bound question windows");
    assert!(
        windows.len() == 1 && matches!(windows[0].outcome, WindowOutcome::Unknown),
        "precondition: the bound question's window closes unknown, no fact yet; seen {windows:?}"
    );
    // Recorded after the close, with an event time inside the window.
    let fact = fixture.write_fact(base_world_id());
    assert!(
        fixture.bound_lane_reads(&fact),
        "precondition: the base-world lane reads the fact in the base world"
    );
    assert_control_labelled(&fixture, fact, "at arrival after its window closed");
    pump_outcome_pass(&fixture, fixture.close_at() + 1, 0);
    assert_bound_labelled_once(
        &fixture,
        fact,
        "at the pump's next pass after its window closed",
    );
    let pairs = calibration_pairs(
        &fixture.vault,
        fixture.owner,
        fixture.bound,
        CallerLocality::OnDevice,
    )
    .expect("bound question calibration pairs");
    assert!(
        pairs.len() == 1 && pairs[0].outcome.fact == fact,
        "actor=owner's question saved under the base-world lane; expected one calibration pair \
         from fact {fact:?} recorded after its window closed; seen {pairs:?}"
    );
}
