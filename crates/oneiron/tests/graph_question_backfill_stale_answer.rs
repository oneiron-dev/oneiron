//! A scheduled backfill answers, once, each unit of its question that has no
//! standing answer at the question's version (FIX
//! STANDING-ANSWER-SCHEDULED-BACKFILL-COUNTS-STALE, review round 1 on
//! #9604). An answer the owner marked stale (`vault.claims.demote`) or
//! retracted no longer stands: the backfill answers its unit again, and the
//! new answer stands. A unit whose answer still stands is left alone.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test graph_question_backfill_stale_answer`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::questions::{
    AnswerProposal, GraphAnswerer, GraphPrediction, GraphQuestionInput, GraphQuestionRef,
    GraphUnitContext, QuestionActivation, QuestionDefinitionInput, RefreshBatch, RefreshPolicy,
    create_question, refresh_due_questions, run_graph_question, schedule_backfill,
};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionQuestionInput, DecisionRung, ProviderPin,
};
use oneiron::memory::{
    ClaimDemoteActionInput, ClaimDemoteRequest, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimBody, ClaimLifecycleStatus, EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor,
};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A rooted vault with its embedded owner bound to the host and the owner's
/// proof; the root project carries the owner's signature. The vault closes
/// before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.sign_owner_project(
        &owner_proof,
        &vault.owner_project_signer(&issuer)?,
        vault.root_project()?,
    )?;
    Ok(Fixture {
        vault,
        owner,
        owner_proof,
        _dir: dir,
    })
}

impl Fixture {
    fn actor(&self) -> WriteActor {
        WriteActor::new(self.owner, EdgeActorClass::Human)
    }

    /// The owner's MESSAGE in a fresh ordinary conversation.
    fn message(&self, text: &str) -> TestResult<EntityId> {
        let message = EntityId::now();
        let turn = WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            project: None,
            occurred_at: self.vault.now_recorded_at(),
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: text.to_owned(),
                parts: None,
                metadata: Some(json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            assertions: Default::default(),
        };
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .witness(&turn)?;
        Ok(message)
    }

    /// The owner's saved graph question over `units`.
    fn question(&self, units: Vec<EntityId>) -> TestResult<GraphQuestionRef> {
        let record = create_question(&self.vault, self.actor(), definition(units), 2)?;
        Ok(GraphQuestionRef {
            id: record.definition.question.id,
            version: record.definition.question.version,
        })
    }

    /// The owner's answer on `unit`; returns its CLAIM.
    fn ask(&self, question: GraphQuestionRef, unit: EntityId) -> TestResult<EntityId> {
        let result = run_graph_question(
            &self.vault,
            self.owner,
            self.actor(),
            question,
            &[GraphQuestionInput {
                unit,
                evidence: Vec::new(),
            }],
            &mut ScriptedAnswerer,
            3,
        )
        .map_err(|failure| format!("the owner's answer lands; it refused: {}", failure.error))?;
        assert_eq!(result.answers.len(), 1, "one answer is written");
        Ok(result.answers[0].claim)
    }

    /// One pass of the question pump over the work due now.
    fn refresh_due(&self) -> TestResult<RefreshBatch> {
        Ok(refresh_due_questions(
            &self.vault,
            self.actor(),
            self.vault.now_recorded_at(),
            |_, _, _| {
                Ok(AnswerProposal {
                    answer: DecisionAnswer::Choice("yes".into()),
                    probability: Some(0.8),
                    providers: vec![ProviderPin {
                        rung: DecisionRung::Local,
                        model: "local/fixture".into(),
                        version: "r1".into(),
                    }],
                    paired: Vec::new(),
                    rule: None,
                    cost_per_thousand: None,
                })
            },
        )?)
    }

    /// The owner schedules `question`'s backfill, due now, over every unit,
    /// and the pump runs one pass.
    fn backfill(&self, question: GraphQuestionRef) -> TestResult<RefreshBatch> {
        schedule_backfill(
            &self.vault,
            self.owner,
            question.id,
            question.version,
            self.vault.now_recorded_at(),
            Vec::new(),
        )?;
        self.refresh_due()
    }

    fn claim(&self, claim: EntityId) -> TestResult<ClaimBody> {
        Ok(self
            .vault
            .get_claim(&claim)?
            .ok_or("the answer CLAIM reads back")?)
    }

    /// `batch` wrote one answer, on `unit`, and that answer stands; a second
    /// pass finds the backfill consumed.
    fn assert_answered_again_only(&self, batch: &RefreshBatch, unit: EntityId) -> TestResult {
        let failures: Vec<String> = batch
            .failures
            .iter()
            .map(|failure| failure.error.to_string())
            .collect();
        assert!(failures.is_empty(), "the backfill runs: {failures:?}");
        let units: Vec<EntityId> = batch.answers.iter().map(|answer| answer.unit).collect();
        assert_eq!(
            units,
            vec![unit],
            "the backfill answers again the unit whose answer no longer stands, and only it"
        );
        let answer = self.claim(batch.answers[0].claim)?;
        assert!(!answer.stale, "the new answer is not stale");
        assert_eq!(
            answer.lifecycle,
            ClaimLifecycleStatus::Active,
            "the new answer stands"
        );
        assert!(
            self.refresh_due()?.answers.is_empty(),
            "the backfill runs once"
        );
        Ok(())
    }
}

struct ScriptedAnswerer;

impl GraphAnswerer for ScriptedAnswerer {
    fn answer(
        &mut self,
        _question: &DecisionQuestion,
        _context: &GraphUnitContext,
    ) -> oneiron::Result<Option<GraphPrediction>> {
        Ok(Some(GraphPrediction {
            answer: DecisionAnswer::Choice("yes".into()),
            probability: 0.8,
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

fn definition(units: Vec<EntityId>) -> QuestionDefinitionInput {
    QuestionDefinitionInput {
        question: DecisionQuestionInput {
            text: "Does the evidence settle the unit?".into(),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Choice {
                options: vec!["yes".into(), "no".into()],
            },
            accept_type: false,
        },
        adapter: "graph".into(),
        units,
        recipe: "unit".into(),
        profile: "fixture".into(),
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
        learning: false,
        binding: None,
        criteria: Default::default(),
        audience: Default::default(),
        posture: None,
        media: Default::default(),
        deadline_ms: None,
        artifacts: Vec::new(),
    }
}

/// Two units answered at the question's version; returns the question, the
/// unit whose answer the caller takes out, that answer's CLAIM, and the unit
/// whose answer stands.
fn two_answered_units(fixture: &Fixture) -> TestResult<(GraphQuestionRef, EntityId, EntityId)> {
    let unit = fixture.message("The ward closes for repairs in May.")?;
    let standing = fixture.message("The clinic opens on Saturdays.")?;
    let question = fixture.question(vec![unit, standing])?;
    let answer = fixture.ask(question, unit)?;
    fixture.ask(question, standing)?;
    // Whatever the question's creation queued runs first.
    fixture.refresh_due()?;
    Ok((question, unit, answer))
}

#[test]
fn a_scheduled_backfill_answers_again_a_unit_whose_answer_is_stale() -> TestResult {
    let fixture = open()?;
    let (question, unit, answer) = two_answered_units(&fixture)?;
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .claim_demote(&ClaimDemoteRequest {
            claim_ref: answer.to_hex(),
            action: ClaimDemoteActionInput::Stale,
        })
        .map_err(|error| format!("the owner marks the answer stale; it refused: {error:?}"))?;
    assert!(
        fixture.claim(answer)?.stale,
        "precondition: the answer is marked stale"
    );

    let batch = fixture.backfill(question)?;
    fixture.assert_answered_again_only(&batch, unit)
}

#[test]
fn a_scheduled_backfill_answers_again_a_unit_whose_answer_is_retracted() -> TestResult {
    let fixture = open()?;
    let (question, unit, answer) = two_answered_units(&fixture)?;
    fixture
        .vault
        .retract_claim_as_owner(
            &fixture.owner_proof,
            &answer,
            fixture.vault.now_recorded_at(),
        )
        .map_err(|error| format!("the owner retracts the answer; it refused: {error}"))?;
    assert_eq!(
        fixture.claim(answer)?.lifecycle,
        ClaimLifecycleStatus::Retracted,
        "precondition: the answer is retracted"
    );

    let batch = fixture.backfill(question)?;
    fixture.assert_answered_again_only(&batch, unit)
}

#[test]
fn a_scheduled_backfill_leaves_units_whose_answers_stand() -> TestResult {
    let fixture = open()?;
    let (question, _, _) = two_answered_units(&fixture)?;

    let batch = fixture.backfill(question)?;
    assert!(
        batch.failures.is_empty() && batch.answers.is_empty(),
        "a backfill writes nothing over answers that stand: {} answers, {} failures",
        batch.answers.len(),
        batch.failures.len()
    );
    Ok(())
}
