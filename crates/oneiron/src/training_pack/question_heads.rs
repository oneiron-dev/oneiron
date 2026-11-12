//! A trained question head bound to one typed question (FIX 3864, OF-577).
//!
//! A question run trains one small model for one exact detector question
//! (FIX 7263). It binds no role: the owner binds its returned checkpoint to
//! the typed question it answers (a `DecisionQuestion` id and version), and
//! the host's Local rung answers that question with it from then on. Every
//! other question keeps its model call.
//!
//! ARCH-0076, loop tier 3: a small model for one question "must win on
//! held-out quality, cost and latency before it replaces a rung". An
//! evaluated binding therefore needs the run's checks and evaluation and a
//! paired held-out trial against the question's current answerer: quality not
//! worse within the question's measured noise, cost and latency both lower.
//! The three numbers go in the binding. A trial not yet measured blocks it;
//! only the owner's explicit choice with a reason binds the head then.

use serde::{Deserialize, Serialize};

use super::{
    ExportCheck, HeldOutResult, PinnedCheckpoint, QuestionTarget, RUNS, SwapChoice, TrainingOwner,
    TrainingRun, TrainingState, invalid, run_in_txn,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::decision::ProviderPin;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

const QUESTION_HEADS: SideTable<String, QuestionHeadBinding, Named> =
    SideTable::new(&side_table::TRAINING_PACK_QUESTION_HEAD);
const QUESTION_TRIALS: SideTable<EntityId, QuestionHeadTrial, Named> =
    SideTable::new(&side_table::TRAINING_PACK_QUESTION_TRIAL);

/// A question run's paired held-out trial against the question's current
/// answerer: both read the same held-out rows. Quality is the low end of the
/// paired interval of the head's minus the incumbent's agreement with the
/// labels, grouped by source family (NOT-WORSE = A); `noise` is the
/// question's measured retest noise. Cost is per thousand units, latency the
/// median per unit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionHeadTrial {
    /// The answerer the head was paired with: the rung and model that answer
    /// the question today.
    pub incumbent: ProviderPin,
    pub cases: u64,
    pub quality_low: f64,
    pub noise: f64,
    pub head_cost_per_thousand: f64,
    pub incumbent_cost_per_thousand: f64,
    pub head_latency_ms: f64,
    pub incumbent_latency_ms: f64,
}

impl QuestionHeadTrial {
    /// Whether the head may replace the incumbent's rung (ARCH-0076 tier 3):
    /// quality not worse within the noise, cost and latency both lower, on a
    /// measured set of finite numbers.
    #[must_use]
    pub fn wins(&self) -> bool {
        [
            self.quality_low,
            self.noise,
            self.head_cost_per_thousand,
            self.incumbent_cost_per_thousand,
            self.head_latency_ms,
            self.incumbent_latency_ms,
        ]
        .iter()
        .all(|value| value.is_finite())
            && self.cases > 0
            && self.noise >= 0.0
            && self.quality_low >= -self.noise
            && self.head_cost_per_thousand < self.incumbent_cost_per_thousand
            && self.head_latency_ms < self.incumbent_latency_ms
    }
}

/// The owner's binding of a question run's head to one typed question
/// version: what the host loads and answers that question with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuestionHeadBinding {
    pub id: EntityId,
    /// The typed question it answers: a call whose question has this id and
    /// version reaches the head.
    pub question: EntityId,
    pub question_version: u32,
    pub run: EntityId,
    pub owner: TrainingOwner,
    pub at: u64,
    /// The exact detector question the head was trained on.
    pub target: QuestionTarget,
    pub checkpoint: PinnedCheckpoint,
    /// The evaluation's fitted temperature: P(yes) is the sigmoid of the
    /// logit margin over it.
    pub temperature: f64,
    pub evaluation: HeldOutResult,
    pub checks: ExportCheck,
    pub exact_hash_overlaps: u64,
    /// The paired trial the binding rests on; `None` on an explicit choice
    /// made before one was measured.
    pub trial: Option<QuestionHeadTrial>,
    pub choice: SwapChoice,
    /// The run whose head answered the question before this one, if any.
    pub previous_run: Option<EntityId>,
}

/// The binding table's key for one typed question version.
fn question_head_key(question: EntityId, version: u32) -> String {
    format!("{}@{version}", question.to_hex())
}

impl TrainingRun {
    /// Whether a question run's own checks let its head bind on evaluation:
    /// no exact-hash overlap, passed export checks (candle parity included),
    /// a passed evaluation under the plan's harness, and a fitted
    /// temperature. The paired trial is checked beside this.
    #[must_use]
    pub fn can_bind_question_head(&self) -> bool {
        self.plan.target.question().is_some()
            && self.corpus.exact_hash_overlaps == 0
            && self
                .result
                .as_ref()
                .is_some_and(|result| result.checks.passed())
            && self.evaluation.as_ref().is_some_and(|eval| {
                eval.passed && eval.harness == self.plan.harness && eval.calibration.is_some()
            })
    }
}

/// The question head table's declared scrub. An erased approver is named
/// no more, and the head stays bound, as a role keeps its swap (FIX 3520).
/// An erased id that is a typed question loses its heads, whose runs go back
/// to scored.
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn erase_question_head_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    drop_question_heads_in_txn(&vault.store, wtxn, *id, None)?;
    let mut scrubbed = Vec::new();
    for (key, mut binding) in QUESTION_HEADS.scan(&vault.store, wtxn)? {
        if binding.owner.forget(*id) {
            scrubbed.push((key, binding));
        }
    }
    for (key, binding) in scrubbed {
        QUESTION_HEADS.put(&vault.store, wtxn, &key, &binding)?;
    }
    Ok(())
}

/// Drops the heads bound to typed question `question` at `version`, or at
/// every version when `None`, in the transaction that erases that question
/// version: each head's run goes back to scored. Every door that erases a
/// question version calls it (FIX 3864).
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn drop_question_heads_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    question: EntityId,
    version: Option<u32>,
) -> Result<()> {
    let dropped: Vec<(String, EntityId)> = QUESTION_HEADS
        .scan(store, wtxn)?
        .into_iter()
        .filter(|(_, binding)| {
            binding.question == question
                && version.is_none_or(|version| version == binding.question_version)
        })
        .map(|(key, binding)| (key, binding.run))
        .collect();
    for (key, run) in dropped {
        QUESTION_HEADS.delete(store, wtxn, &key)?;
        unbound_run_in_txn(store, wtxn, &run)?;
    }
    Ok(())
}

/// Puts a run whose head no longer answers its question back to scored.
fn unbound_run_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    if let Some(mut run) = RUNS.get(store, txn, id)?
        && run.state == TrainingState::Bound
    {
        run.state = TrainingState::Scored;
        RUNS.put(store, txn, id, &run)?;
    }
    Ok(())
}

impl Vault {
    /// The owner binds question run `id`'s head to typed question `question`
    /// at `question_version` (FIX 3864). An evaluated choice needs the run's
    /// checks ([`TrainingRun::can_bind_question_head`]) and a won paired
    /// trial ([`QuestionHeadTrial::wins`]); an explicit choice records the
    /// owner's reason. The head that answered the question before goes back
    /// to scored. The same run already bound to the question returns its
    /// binding. The owner is revalidated in the writer.
    ///
    /// # Errors
    ///
    /// A role run, a run not scored, a run whose head answers another
    /// question, a choice the checks or the trial block, an empty override
    /// reason, a checkpoint whose custody does not verify, an evaluation with
    /// no temperature, or storage errors.
    pub fn approve_training_question_head(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        question: EntityId,
        question_version: u32,
        choice: SwapChoice,
    ) -> Result<QuestionHeadBinding> {
        self.recheck_owner(owner)?;
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let mut run = run_in_txn(self, txn, id)?;
            let target = run
                .plan
                .target
                .question()
                .cloned()
                .ok_or_else(|| invalid("a role run swaps its role; only a question run's head binds a question"))?;
            let key = question_head_key(question, question_version);
            let previous = QUESTION_HEADS.get(&self.store, txn, &key)?;
            if let Some(current) = &previous
                && current.run == *id
            {
                return Ok(current.clone());
            }
            if run.state == TrainingState::Bound {
                return Err(invalid(
                    "this head answers another question; unbind it there first",
                ));
            }
            if run.state != TrainingState::Scored {
                return Err(invalid(
                    "a question head binds once its held-out evaluation is recorded",
                ));
            }
            let trial = QUESTION_TRIALS.get(&self.store, txn, id)?;
            match &choice {
                SwapChoice::Evaluated if !run.can_bind_question_head() => {
                    return Err(invalid(
                        "training export, overlap or held-out checks block binding this head",
                    ));
                }
                SwapChoice::Evaluated if !trial.as_ref().is_some_and(QuestionHeadTrial::wins) => {
                    return Err(invalid(
                        "the head has no won paired trial against the question's current \
                         answerer (quality not worse within its noise, cost and latency both \
                         lower); an explicit choice records your reason",
                    ));
                }
                SwapChoice::ExplicitOverride { reason } if reason.trim().is_empty() => {
                    return Err(invalid(
                        "an explicit head choice records the owner's reason",
                    ));
                }
                _ => {}
            }
            let result = run
                .result
                .as_ref()
                .ok_or_else(|| invalid("training checkpoint has not returned"))?;
            result.exported_checkpoint.verify(self, txn)?;
            let evaluation = run.evaluation.clone().ok_or_else(|| {
                invalid("a question head binds once its held-out evaluation is recorded")
            })?;
            let temperature = evaluation
                .calibration
                .as_ref()
                .map(|calibration| calibration.temperature)
                .filter(|temperature| temperature.is_finite() && *temperature > 0.0)
                .ok_or_else(|| {
                    invalid("a question head answers at its fitted temperature; the evaluation reports none")
                })?;
            let binding = QuestionHeadBinding {
                id: self.store.clock.entity_id()?,
                question,
                question_version,
                run: *id,
                owner: TrainingOwner::Actor(actor),
                at: self.store.clock.now_recorded_at(),
                target,
                checkpoint: result.exported_checkpoint.clone(),
                temperature,
                evaluation,
                checks: result.checks.clone(),
                exact_hash_overlaps: run.corpus.exact_hash_overlaps,
                trial,
                choice,
                previous_run: previous.as_ref().map(|previous| previous.run),
            };
            if let Some(previous) = &previous {
                unbound_run_in_txn(&self.store, txn, &previous.run)?;
            }
            QUESTION_HEADS.put(&self.store, txn, &key, &binding)?;
            run.state = TrainingState::Bound;
            RUNS.put(&self.store, txn, id, &run)?;
            Ok(binding)
        })
    }

    /// The owner takes the head off typed question `question` at
    /// `question_version`: the question keeps its model call from then on,
    /// and the head's run goes back to scored. Answers the binding removed,
    /// `None` when no head answered it.
    ///
    /// # Errors
    ///
    /// A stale owner proof, or storage errors.
    pub fn unbind_training_question_head(
        &self,
        owner: &AuthenticatedOwner,
        question: EntityId,
        question_version: u32,
    ) -> Result<Option<QuestionHeadBinding>> {
        self.recheck_owner(owner)?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let key = question_head_key(question, question_version);
            let Some(binding) = QUESTION_HEADS.get(&self.store, txn, &key)? else {
                return Ok(None);
            };
            QUESTION_HEADS.delete(&self.store, txn, &key)?;
            unbound_run_in_txn(&self.store, txn, &binding.run)?;
            Ok(Some(binding))
        })
    }

    /// The head bound to typed question `question` at `question_version`, if
    /// any: the host loader's seam. Read-only; the loader rechecks every
    /// file's custody hash as it reads the bytes.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn training_question_head(
        &self,
        question: EntityId,
        question_version: u32,
    ) -> Result<Option<QuestionHeadBinding>> {
        let txn = self.store.env.read_txn()?;
        QUESTION_HEADS.get(
            &self.store,
            &txn,
            &question_head_key(question, question_version),
        )
    }

    /// Every bound question head: what a host keeps loaded.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn training_question_heads(&self) -> Result<Vec<QuestionHeadBinding>> {
        let txn = self.store.env.read_txn()?;
        Ok(QUESTION_HEADS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, binding)| binding)
            .collect())
    }

    /// The binding of question run `run`'s head, if it answers a question.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn training_run_question_head(
        &self,
        run: &EntityId,
    ) -> Result<Option<QuestionHeadBinding>> {
        let txn = self.store.env.read_txn()?;
        Ok(QUESTION_HEADS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, binding)| binding)
            .find(|binding| binding.run == *run))
    }

    /// Question run `run`'s paired held-out trial, once measured.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn training_question_trial(&self, run: &EntityId) -> Result<Option<QuestionHeadTrial>> {
        QUESTION_TRIALS.get(&self.store, &self.store.env.read_txn()?, run)
    }
}
