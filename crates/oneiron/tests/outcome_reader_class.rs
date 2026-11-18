//! ARRIVAL-READER-KEY-CLASSLESS: an outcome label and a silence window read
//! a question's principal with the actor class of its live row, as its ask
//! was admitted. An agent whose only `core:read` row names it with the class
//! `agent` saves a question over the owner's unit and answers it through that
//! row; the owner's fact the row reads then labels the agent's answer at a
//! manual projection and at its window's close, and a silence window closes
//! in silence. A row that names the agent under the class `human` reads none
//! of it, so the same fact labels nothing.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::{CallerLocality, ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::questions::{
    AnswerRecord, GraphAnswerer, GraphPrediction, GraphUnitContext, OutcomeBinding, OutcomeLabel,
    OutcomeSource, OutcomeWindowClose, QuestionActivation, QuestionDefinitionInput, RefreshPolicy,
    SILENCE_OUTCOME, WindowOutcome, close_due_outcome_windows, closed_outcome_windows,
    create_question, outcome_labels, project_bound_outcomes, refresh_standing_question_with,
};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionQuestionInput, DecisionRung, ProviderPin,
};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput, StructuralPutInput,
};
use oneiron::test_doors::derive::{define_auto_agent, grant_derive_rows_with_read_class};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Result, Vault, VaultConfig, WriteActor};
use serde_json::json;

const OUTCOME_PREDICATE: &str = "profile.reader_class.outcome";
const HORIZON: u64 = 60;

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

/// [`definition`], its binding labelling a window that closes with no fact
/// `false`, by the silence outcome.
fn definition_with_silence(unit: EntityId) -> QuestionDefinitionInput {
    let mut silence = binding();
    silence.mapping.insert(SILENCE_OUTCOME.to_owned(), false);
    QuestionDefinitionInput {
        binding: Some(silence),
        ..definition(unit)
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

/// Whether the live lane over `key` reads `id`.
fn reads(vault: &Vault, key: &ScopedReadActorKey, id: &EntityId) -> bool {
    vault
        .scoped_read(key.clone())
        .get_entity_parts_with_receipt(id, None)
        .expect("live lane point read")
        .value
        .is_some()
}

/// A device vault whose owner wrote one PERSON unit, and an Auto agent whose
/// only `core:read` row names it with the class `agent`. The agent's question
/// over the unit is saved under its own lane, beside the owner's own question
/// over the same unit.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    proof: AuthenticatedOwner,
    unit: EntityId,
    agent: EntityId,
    agent_key: ScopedReadActorKey,
    question: EntityId,
    answer: AnswerRecord,
    control: EntityId,
    control_answer: AnswerRecord,
}

impl Fixture {
    fn labels(&self) -> Vec<OutcomeLabel> {
        outcome_labels(
            &self.vault,
            self.agent,
            self.question,
            CallerLocality::OnDevice,
        )
        .expect("stored outcome labels of the agent's question")
    }

    fn control_labels(&self) -> Vec<OutcomeLabel> {
        outcome_labels(
            &self.vault,
            self.owner,
            self.control,
            CallerLocality::OnDevice,
        )
        .expect("stored outcome labels of the owner's question")
    }

    fn windows(&self) -> Vec<OutcomeWindowClose> {
        closed_outcome_windows(&self.vault, self.agent, self.question)
            .expect("the agent's question windows")
    }

    fn control_windows(&self) -> Vec<OutcomeWindowClose> {
        closed_outcome_windows(&self.vault, self.owner, self.control)
            .expect("the owner's question windows")
    }

    /// The fact time inside both answers' windows.
    fn fact_at(&self) -> u64 {
        self.answer.answered_at.max(self.control_answer.answered_at)
    }

    fn close_windows(&self) {
        let closed = close_due_outcome_windows(&self.vault, self.fact_at() + HORIZON + 1)
            .expect("close the lapsed windows");
        assert_eq!(closed, 2, "precondition: both answers' windows close");
    }

    /// The owner states the outcome about the unit in the base world, scoped
    /// to every relationship, and its own question takes it as a label.
    fn write_fact(&self) -> EntityId {
        let fact = EntityId::now();
        let at = self.fact_at();
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.proof)
            .claim_upsert_scoped(&ScopedClaimInput {
                id: Some(fact.to_hex()),
                predicate: OUTCOME_PREDICATE.to_owned(),
                subject_ref: self.unit.to_hex(),
                value: json!("yes"),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                scope: ClaimScope {
                    world_id: base_world_id().to_hex(),
                    scope_facet_id: self
                        .vault
                        .default_facet()
                        .expect("owner default facet")
                        .to_hex(),
                    scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                    scope_project_id: default_project_id().to_hex(),
                }
                .into(),
                sensitivity: None,
                evidence_turn_refs: Vec::new(),
                valid_from: None,
                valid_to: None,
                occurred_at: Some(at),
                learned_at: Some(at),
                salience: None,
            })
            .expect("precondition: the owner's fact commits");
        let labels = self.control_labels();
        assert!(
            labels.len() == 1
                && labels[0].fact == fact
                && labels[0].answer == self.control_answer.claim,
            "precondition: the owner's own question labels fact {fact:?} at arrival; seen {labels:?}"
        );
        fact
    }

    /// The owner writes the policy back with the agent's `core:read` row
    /// naming the class `human`: the agent's live lane reads none of `rows`.
    fn rename_the_agents_read_row_to_the_human_class(&self, rows: &[EntityId]) {
        grant_derive_rows_with_read_class(&self.vault, &[self.agent], "human")
            .expect("precondition: the owner writes the agent's read row under the class human");
        for row in rows {
            assert!(
                !reads(&self.vault, &self.agent_key, row),
                "precondition: the agent's live lane does not read {row:?} through a row that \
                 names it under the class human"
            );
        }
    }
}

fn fixture(define: fn(EntityId) -> QuestionDefinitionInput) -> Fixture {
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
            body: json!({"name": "Reader class fixture unit"}),
            text_fields: None,
            edges: None,
            occurred_at: now,
            learned_at: None,
        })
        .expect("precondition: the owner writes the unit");
    let agent = define_auto_agent(&vault).expect("precondition: the owner defines an Auto agent");
    grant_derive_rows_with_read_class(&vault, &[agent], "agent")
        .expect("precondition: the agent's class-named core:read row and Auto ceiling");
    let agent_key = vault
        .memory(agent, EdgeActorClass::Agent)
        .read_key()
        .expect("the agent's live read key");
    assert!(
        reads(&vault, &agent_key, &unit),
        "precondition: the agent's live lane reads the owner's unit through its class-named row"
    );
    let agent_actor = WriteActor::new(agent, EdgeActorClass::Agent);
    let owner_actor = WriteActor::new(owner, EdgeActorClass::Human);
    let record = create_question(&vault, agent_actor, define(unit), now)
        .expect("precondition: the agent saves a question over the owner's unit");
    assert!(
        record.principal == agent && record.read_lane.is_principal(),
        "precondition: the agent's question is saved under the agent's own lane; seen principal \
         {:?}, lane {:?}",
        record.principal,
        record.read_lane
    );
    let control_record = create_question(&vault, owner_actor, define(unit), now)
        .expect("precondition: the owner saves the same question under its own lane");
    let question = record.definition.question.id;
    let control = control_record.definition.question.id;
    let agent_answer = answer(&vault, agent_actor, question, now);
    let control_answer = answer(&vault, owner_actor, control, now);
    let fixture = Fixture {
        vault,
        _dir: dir,
        owner,
        proof,
        unit,
        agent,
        agent_key,
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
fn an_agents_class_named_read_row_labels_its_question_at_a_manual_projection() {
    let fixture = fixture(definition);
    let fact = fixture.write_fact();
    assert!(
        reads(&fixture.vault, &fixture.agent_key, &fact),
        "precondition: the agent's live lane reads the owner's fact through its class-named row"
    );
    project_bound_outcomes(&fixture.vault, fixture.agent, fixture.question)
        .expect("manual projection of the agent's question");
    let labels = fixture.labels();
    assert!(
        labels.len() == 1 && labels[0].fact == fact && labels[0].answer == fixture.answer.claim,
        "actor=agent whose only read row names the class agent; expected the owner's fact \
         {fact:?}, which that row reads, to label its answer at a manual projection; seen \
         {labels:?}"
    );
}

#[test]
fn an_agents_class_named_read_row_labels_its_question_at_its_window_close() {
    let fixture = fixture(definition);
    let fact = fixture.write_fact();
    fixture.close_windows();
    let labels = fixture.labels();
    assert!(
        labels.len() == 1 && labels[0].fact == fact && labels[0].answer == fixture.answer.claim,
        "actor=agent whose only read row names the class agent; expected the owner's fact \
         {fact:?} to label its answer by its window's close; seen {labels:?}"
    );
    let windows = fixture.windows();
    assert!(
        windows.len() == 1 && matches!(windows[0].outcome, WindowOutcome::Observed),
        "actor=agent whose only read row names the class agent; expected its window to close \
         observed; seen {windows:?}"
    );
}

#[test]
fn an_agents_class_named_read_row_closes_its_window_in_silence() {
    let fixture = fixture(definition_with_silence);
    fixture.close_windows();
    let control_windows = fixture.control_windows();
    assert!(
        control_windows.len() == 1 && control_windows[0].outcome == WindowOutcome::Silence(false),
        "precondition: the owner's own window closes in silence, no fact in it; seen \
         {control_windows:?}"
    );
    let windows = fixture.windows();
    assert!(
        windows.len() == 1 && windows[0].outcome == WindowOutcome::Silence(false),
        "actor=agent whose only read row names the class agent; expected its window to close \
         in silence over unit {:?}, which that row reads; seen {windows:?}",
        fixture.unit
    );
}

#[test]
fn an_agents_read_row_naming_the_human_class_labels_nothing() {
    let fixture = fixture(definition);
    fixture.rename_the_agents_read_row_to_the_human_class(&[fixture.unit]);
    let fact = fixture.write_fact();
    assert!(
        !reads(&fixture.vault, &fixture.agent_key, &fact),
        "precondition: the agent's live lane does not read the owner's fact through a row that \
         names it under the class human"
    );
    project_bound_outcomes(&fixture.vault, fixture.agent, fixture.question)
        .expect("manual projection of the agent's question");
    let labels = fixture.labels();
    assert!(
        labels.is_empty(),
        "actor=agent whose read row names it under the class human; expected no outcome label \
         from the owner's fact {fact:?}, which no row of its class reads; seen {labels:?}"
    );
}
