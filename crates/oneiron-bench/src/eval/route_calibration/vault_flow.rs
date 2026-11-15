//! The run's vault: fresh, its embedded owner the one principal and writer,
//! and every write through a public door the served host uses: a NOTE per
//! case, the standing question, each prepared and admitted answer, and each
//! gold claim through the gated claim writer.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oneiron::claim::{CallerLocality, ScopedRead};
use oneiron::llm::decision::questions::{
    AnswerRecord, CalibrationPair, GraphQuestionInput, GraphQuestionRef, GraphUnitContext,
    QuestionDefinitionInput, QuestionRecord, RouteCalibrationReport, admit_standing_answer,
    calibration_pairs, create_question, outcome_labels, prepare_standing_answer,
    project_bound_outcomes, route_calibration_report,
};
use oneiron::llm::decision::{DecisionAnswer, EvidenceVersion, TypedDecision};
use oneiron::memory::ClaimInput;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

use super::cases::{Case, GOLD_FALSE, GOLD_TRUE, TRUTH_PREDICATE};
use super::house_read::HouseReadRung;
use super::report::{CaseRow, CaseStatus};
use super::{failure, failure_from, unix_now};
use crate::eval::EvalResult;

/// Every case's unit: a NOTE of this shipped kind holding the case's body.
/// Research notes are readable vault-wide and extract only once sealed, so a
/// seeded unit starts no extraction of its own.
const CASE_NOTE_KIND: &str = "research";
/// The gold claim's source: the vault owner, the run's evaluator, states the
/// known answer, as the owner's own outcome door states an outcome.
const GOLD_CLAIM_SOURCE: &str = "user_stated";
/// A gold label is certain.
const GOLD_CONFIDENCE: f32 = 1.0;

/// The run's fresh vault and its embedded owner.
pub(super) struct BenchVault {
    /// Shared with the Big rung, which routes and admits each of its calls
    /// against the vault's live model policy.
    vault: Arc<Vault>,
    owner: EntityId,
    path: PathBuf,
}

/// The gold claim one case's answer is labelled by.
pub(super) struct GoldFact {
    pub(super) id: EntityId,
    /// The approval the gate stored it at (`auto` or `proposed`).
    pub(super) approval: String,
}

impl BenchVault {
    /// Opens a new vault at `path`, which must be absent or an empty
    /// directory, and binds its embedded owner.
    pub(super) fn create(path: &Path) -> EvalResult<Self> {
        refuse_occupied(path)?;
        let vault = Arc::new(Vault::open_owned(path, VaultConfig::device())?);
        let owner = vault.ensure_embedded_owner_actor().map_err(failure_from)?;
        Ok(Self {
            vault,
            owner,
            path: path.to_path_buf(),
        })
    }

    pub(super) fn vault(&self) -> &Arc<Vault> {
        &self.vault
    }

    pub(super) fn owner(&self) -> EntityId {
        self.owner
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    fn actor(&self) -> WriteActor {
        WriteActor::new(self.owner, EdgeActorClass::Human)
    }

    /// The owner's own read lane on this device: the key the owner's memory
    /// handle reads under, its actor and owner binding checked. A bare actor
    /// key holds no read grant, so every prepare would read no unit.
    fn lane(&self) -> EvalResult<ScopedRead<'_>> {
        let key = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .read_key()
            .map_err(failure_from)?;
        Ok(self.vault.scoped_read(key))
    }

    /// One owner NOTE per case, its body the case's own, in case order.
    pub(super) fn seed_units(&self, cases: &[Case]) -> EvalResult<Vec<EntityId>> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        cases
            .iter()
            .map(|case| -> EvalResult<EntityId> {
                let receipt = memory
                    .create_note(CASE_NOTE_KIND, &case.body)
                    .map_err(failure_from)?;
                Ok(EntityId::from_hex(&receipt.id_hex)?)
            })
            .collect()
    }

    /// Stores `definition` over `units` as the owner's standing question.
    pub(super) fn store_question(
        &self,
        mut definition: QuestionDefinitionInput,
        units: Vec<EntityId>,
    ) -> EvalResult<QuestionRecord> {
        definition.units = units;
        Ok(create_question(
            &self.vault,
            self.actor(),
            definition,
            unix_now(),
        )?)
    }

    /// Writes `gold` on `answer`'s unit as the truth claim, through the gated
    /// claim writer, occurring after the answer.
    fn write_gold(&self, answer: &AnswerRecord, gold: bool) -> Result<GoldFact, String> {
        let input = ClaimInput {
            id: None,
            predicate: TRUTH_PREDICATE.to_owned(),
            subject_ref: answer.unit.to_hex(),
            value: serde_json::Value::from(if gold { GOLD_TRUE } else { GOLD_FALSE }),
            confidence: GOLD_CONFIDENCE,
            source: GOLD_CLAIM_SOURCE.to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            // An outcome counts only at or after the answer it labels.
            occurred_at: Some(unix_now().max(answer.answered_at)),
            learned_at: None,
            salience: None,
            confidence_details: None,
        };
        let receipt = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_upsert(&input)
            .map_err(|error| error.to_string())?;
        let landed = receipt
            .claim
            .as_ref()
            .ok_or_else(|| "the gold write named no landed claim".to_owned())?;
        Ok(GoldFact {
            id: EntityId::from_hex(&landed.id).map_err(|error| error.to_string())?,
            approval: receipt.approval,
        })
    }

    /// Projects every existing fact onto the question's answers; the count of
    /// labels that arrival had not bound already.
    pub(super) fn project(&self, question: EntityId) -> EvalResult<usize> {
        Ok(project_bound_outcomes(&self.vault, self.owner, question)?)
    }

    /// The question's calibration pairs, as the existing pair reader returns
    /// them on this device.
    pub(super) fn pairs(&self, question: EntityId) -> EvalResult<Vec<CalibrationPair>> {
        Ok(calibration_pairs(
            &self.vault,
            self.owner,
            question,
            CallerLocality::OnDevice,
        )?)
    }

    pub(super) fn label_count(&self, question: EntityId) -> EvalResult<usize> {
        Ok(outcome_labels(&self.vault, self.owner, question, CallerLocality::OnDevice)?.len())
    }

    pub(super) fn report(&self, question: EntityId) -> EvalResult<RouteCalibrationReport> {
        Ok(route_calibration_report(
            &self.vault,
            self.owner,
            question,
            CallerLocality::OnDevice,
        )?)
    }
}

/// One case's walk through the standing doors and the ladder, at one question
/// version, on one clock budget per decision.
pub(super) struct CaseRun<'r> {
    bench: &'r BenchVault,
    rung: &'r HouseReadRung,
    reference: GraphQuestionRef,
    budget: Duration,
}

impl<'r> CaseRun<'r> {
    pub(super) fn new(
        bench: &'r BenchVault,
        rung: &'r HouseReadRung,
        question: &QuestionRecord,
        budget: Duration,
    ) -> Self {
        Self {
            bench,
            rung,
            reference: GraphQuestionRef {
                id: question.definition.question.id,
                version: question.definition.question.version,
            },
            budget,
        }
    }
}

impl CaseRun<'_> {
    /// The case's row: answered and labelled, or the step it stopped at and why.
    pub(super) fn answer(&self, case: &Case, unit: EntityId) -> CaseRow {
        let mut row = CaseRow::new(case, unit);
        let status = match self.answer_into(case, unit, &mut row) {
            Ok(status) => status,
            Err((status, error)) => {
                row.error = Some(error);
                status
            }
        };
        row.status = status;
        row
    }

    /// Prepares the unit, decides it on the ladder, admits the full decision,
    /// then writes the gold. Every step's failure is the case's own status.
    fn answer_into(
        &self,
        case: &Case,
        unit: EntityId,
        row: &mut CaseRow,
    ) -> Result<CaseStatus, (CaseStatus, String)> {
        let lane = self
            .bench
            .lane()
            .map_err(|error| (CaseStatus::PrepareFailed, error.to_string()))?;
        let actor = self.bench.actor();
        let input = GraphQuestionInput {
            unit,
            evidence: Vec::new(),
        };
        let (record, context, frontier) =
            prepare_standing_answer(&lane, self.reference, actor, &input)
                .map_err(|error| (CaseStatus::PrepareFailed, error.to_string()))?;
        let state = context.state_under(&[], &[], &record.definition.criteria);
        let evidence: Vec<EntityId> = context.sources.iter().map(|source| source.id).collect();
        let decision = self
            .rung
            .decide(
                &record.definition.question,
                record.principal,
                &evidence,
                &state,
                record.definition.dial,
                self.budget,
            )
            .map_err(|error| (CaseStatus::LadderFailed, error.to_string()))?;
        row.clock = decision.receipt.time;
        row.human_ask = decision.human_ask;
        row.prediction = Some(decision.answer.clone());
        if decision.answer == DecisionAnswer::Abstain {
            return Ok(CaseStatus::Abstained);
        }
        let decision = bound_to_prepared(decision, &context);
        let answer = admit_standing_answer(
            &lane,
            self.reference,
            actor,
            input,
            frontier,
            decision,
            unix_now(),
        )
        .map_err(|error| (CaseStatus::AdmitFailed, error.to_string()))?;
        row.answer = Some(answer.claim.to_hex());
        row.probability = answer.decision.probability;
        let fact = self
            .bench
            .write_gold(&answer, case.gold)
            .map_err(|error| (CaseStatus::GoldWriteFailed, error))?;
        row.fact = Some(fact.id.to_hex());
        row.fact_approval = Some(fact.approval);
        // Paired once the pair reader returns this answer's pair.
        Ok(CaseStatus::PairMissing)
    }
}

/// `decision` bound to the prepared sources the way the admit door checks
/// them: its evidence the sources after the unit, and its receipt's evidence
/// versions every source at the body hash the preparation read. The ladder
/// names only the call's ids; no answer, probability, reading or clock moves.
fn bound_to_prepared(mut decision: TypedDecision, context: &GraphUnitContext) -> TypedDecision {
    decision.evidence = context
        .sources
        .iter()
        .skip(1)
        .map(|source| source.id)
        .collect();
    decision.receipt.evidence_versions = context
        .sources
        .iter()
        .map(|source| EvidenceVersion {
            id: source.id,
            body_hash: source.hash,
        })
        .collect();
    decision
}

/// Refuses a `--vault` that already holds anything: each run is one fresh
/// vault, one owner and one question.
fn refuse_occupied(path: &Path) -> EvalResult<()> {
    match std::fs::read_dir(path) {
        Ok(mut entries) => match entries.next() {
            None => Ok(()),
            Some(_) => Err(failure(format!(
                "--vault {} is not empty; each run makes a fresh vault",
                path.display()
            ))),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(failure(format!("--vault {}: {error}", path.display()))),
    }
}
