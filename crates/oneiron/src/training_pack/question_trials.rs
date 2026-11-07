//! A question head's paired held-out trial against its typed question's
//! current answerer (FIX 3864, ARCH-0076 tier 3).
//!
//! The owner names the run and the standing typed question the head would
//! answer. [`Vault::open_question_head_trial`] serves the run's sealed
//! held-out cohort once more, as one counted OF-578 exposure, and the host
//! reads every held-out row twice through the question's current answerer
//! (its ladder at the question's own dial, never past the Big rung) and
//! once through the head. [`Vault::record_question_head_trial`] reduces
//! those reads with the eval estimator: each case scores `1 - (P(yes) -
//! label)^2` per side, the delta is head minus incumbent, grouped by source
//! family, and the noise is the incumbent's disagreement with its own second
//! read. The head runs on this host and bills no catalog cost.
//!
//! The head wins when the interval's low end is not below minus the noise
//! (NOT-WORSE = A) and its cost and latency are both lower. A trial pins the
//! head bound to the question when it opened; a bind takes it only while that
//! is still so. A head never bills less than another head, so replacing one
//! bound head with another takes the owner's explicit choice. A case missing a
//! read, too few families, or an incumbent cost no receipt names leaves the
//! trial unknown, and an unknown trial never wins.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::question_heads::bound_run_in_txn;
use super::{PinnedCheckpoint, QuestionTarget, SplitSide, TrainingState, invalid};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::decision::{AnswerContract, DecisionQuestion, ProviderPin};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::{
    EstimateGap, EvalExposure, EvalExposureKind, MeasurementMethodPin, PairedScores,
    estimate_paired,
};
use crate::store::Store;

pub(super) const QUESTION_TRIALS: SideTable<EntityId, QuestionHeadTrial, Named> =
    SideTable::new(&side_table::TRAINING_PACK_QUESTION_TRIAL);

/// Domain mixed into a trial's resampling seed.
const TRIAL_SEED_DOMAIN: &[u8] = b"oneiron.question-head-trial/1";
/// What a head on this host bills per thousand calls: no catalog cost.
const HEAD_COST_PER_THOUSAND: f64 = 0.0;

/// Question run `run`'s trial against one typed question version: the
/// counted serving it read, and what it measured once recorded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionHeadTrial {
    /// The typed question whose current answerer the head was paired with.
    pub question: EntityId,
    pub question_version: u32,
    /// The counted serving of the run's sealed held-out cohort it read.
    pub exposure: EvalExposure,
    /// The run whose head the question version was bound to when the trial
    /// opened, `None` when none was: the answerer it was paired with. A bind
    /// takes the trial only while that is still so.
    pub incumbent_head: Option<EntityId>,
    /// The pin of every rung the host's ladder held when the trial opened:
    /// the configured answerer the head was paired with. An evaluated bind
    /// takes the trial only while the host's ladder holds the same.
    pub answerer: Vec<ProviderPin>,
    /// `None` while the host has not recorded its reads.
    pub measured: Option<QuestionTrialMeasure>,
}

/// A recorded trial's numbers. Every number that can be unknown is an
/// `Option`; an unknown is never read as zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionTrialMeasure {
    pub at: u64,
    pub cases: u64,
    pub families: u64,
    /// Cases missing a head read or either incumbent read. While nonzero,
    /// the quality numbers are unknown.
    pub unknown_cases: u64,
    /// Every pin that answered an incumbent read, in order.
    pub incumbent: Vec<ProviderPin>,
    /// Family mean of head minus incumbent agreement; positive favours the
    /// head.
    pub delta: Option<f64>,
    pub quality_low: Option<f64>,
    pub quality_high: Option<f64>,
    /// Family mean of the incumbent's disagreement with its second read.
    pub noise: Option<f64>,
    /// Why no interval was drawn, when none was.
    pub gap: Option<EstimateGap>,
    pub method: MeasurementMethodPin,
    pub head_cost_per_thousand: f64,
    /// The mean cost per thousand the incumbent's receipts name; `None` when
    /// a read's receipt names none.
    pub incumbent_cost_per_thousand: Option<f64>,
    /// Mean wall clock per read; the head's one load is not counted.
    pub head_latency_ms: f64,
    pub incumbent_latency_ms: f64,
}

impl QuestionHeadTrial {
    /// Whether the head may replace the incumbent's rung (ARCH-0076 tier 3):
    /// a recorded trial whose [`QuestionTrialMeasure::wins`] holds.
    #[must_use]
    pub fn wins(&self) -> bool {
        self.measured
            .as_ref()
            .is_some_and(QuestionTrialMeasure::wins)
    }
}

impl QuestionTrialMeasure {
    /// Quality not worse within the noise, cost and latency both lower, on a
    /// complete set of finite numbers.
    #[must_use]
    pub fn wins(&self) -> bool {
        let (Some(low), Some(noise), Some(incumbent_cost)) = (
            self.quality_low,
            self.noise,
            self.incumbent_cost_per_thousand,
        ) else {
            return false;
        };
        [
            low,
            noise,
            incumbent_cost,
            self.head_cost_per_thousand,
            self.head_latency_ms,
            self.incumbent_latency_ms,
        ]
        .iter()
        .all(|value| value.is_finite())
            && self.cases > 0
            && self.unknown_cases == 0
            && noise >= 0.0
            && low >= -noise
            && self.head_cost_per_thousand < incumbent_cost
            && self.head_latency_ms < self.incumbent_latency_ms
    }
}

/// What the host reads a trial from.
#[derive(Debug)]
pub struct QuestionTrialInput {
    pub exposure: EvalExposure,
    /// The typed question at the named version, as its asker saved it.
    pub question: DecisionQuestion,
    /// The question's asker: the principal its reads run for.
    pub principal: EntityId,
    /// The question's own posture, when it names one: its reads keep unit
    /// text where the graph path keeps it.
    pub posture: Option<crate::config::HostingPrivacyPosture>,
    /// The question's own dial; the host never reads past the Big rung.
    pub dial: crate::llm::decision::DecisionDial,
    pub target: QuestionTarget,
    pub checkpoint: PinnedCheckpoint,
    pub temperature: f64,
    pub held_out_jsonl: Vec<u8>,
}

/// One held-out case as the host read it.
#[derive(Debug, Clone, PartialEq)]
pub struct QuestionTrialCase {
    pub row: String,
    pub family: EntityId,
    pub label: bool,
    /// The head's P(yes) at its fitted temperature; `None` when it could
    /// not read the row.
    pub head: Option<f64>,
    pub head_ms: f64,
    /// The incumbent's P(yes) on its first and second read; `None` for a
    /// read that gave no answer.
    pub incumbent: Option<f64>,
    pub retest: Option<f64>,
    /// The first incumbent read's wall clock, answering pin and cost.
    pub incumbent_ms: f64,
    pub incumbent_pin: Option<ProviderPin>,
    pub incumbent_cost_per_thousand: Option<f64>,
}

/// A side's agreement with the label, higher is better.
fn agreement(yes: f64, label: bool) -> f64 {
    1.0 - (yes - f64::from(u8::from(label))).powi(2)
}

fn probability_valid(value: Option<f64>) -> bool {
    value.is_none_or(|value| value.is_finite() && (0.0..=1.0).contains(&value))
}

fn mean(values: impl Iterator<Item = f64>) -> f64 {
    let (sum, count) = values.fold((0.0, 0_u32), |(sum, count), value| (sum + value, count + 1));
    sum / f64::from(count.max(1))
}

/// The resampling seed: the run, the exposure and every case's reads.
fn trial_digest(run: &EntityId, exposure: &EntityId, cases: &[QuestionTrialCase]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TRIAL_SEED_DOMAIN);
    hasher.update(run.as_bytes());
    hasher.update(exposure.as_bytes());
    for case in cases {
        hasher.update(case.row.as_bytes());
        hasher.update(&[0, u8::from(case.label)]);
        for value in [case.head, case.incumbent, case.retest] {
            hasher.update(&value.unwrap_or(f64::NAN).to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

/// `cases` reduced to a trial's numbers.
fn measure(
    run: &EntityId,
    exposure: &EntityId,
    cases: &[QuestionTrialCase],
    at: u64,
) -> QuestionTrialMeasure {
    let families: BTreeSet<EntityId> = cases.iter().map(|case| case.family).collect();
    let mut incumbent = Vec::new();
    for pin in cases.iter().filter_map(|case| case.incumbent_pin.as_ref()) {
        if !incumbent.contains(pin) {
            incumbent.push(pin.clone());
        }
    }
    let scores: Vec<PairedScores<'_>> = cases
        .iter()
        .filter_map(|case| {
            Some(PairedScores {
                family: case.family,
                stratum: None,
                incumbent: agreement(case.incumbent?, case.label),
                candidate: agreement(case.head?, case.label),
                retest: agreement(case.retest?, case.label),
            })
        })
        .collect();
    let unknown_cases = (cases.len() - scores.len()) as u64;
    let (delta, interval, noise, gap) = if unknown_cases == 0 {
        let found = estimate_paired(
            &scores,
            &BTreeSet::new(),
            0,
            &trial_digest(run, exposure, cases),
        );
        (
            found.mean_delta,
            found.interval,
            found.retest_noise,
            found.gap,
        )
    } else {
        (None, None, None, None)
    };
    let incumbent_cost_per_thousand = cases
        .iter()
        .map(|case| case.incumbent_cost_per_thousand)
        .collect::<Option<Vec<f64>>>()
        .map(|costs| mean(costs.into_iter()));
    QuestionTrialMeasure {
        at,
        cases: cases.len() as u64,
        families: families.len() as u64,
        unknown_cases,
        incumbent,
        delta,
        quality_low: interval.map(|(low, _)| low),
        quality_high: interval.map(|(_, high)| high),
        noise,
        gap,
        method: MeasurementMethodPin::current(),
        head_cost_per_thousand: HEAD_COST_PER_THOUSAND,
        incumbent_cost_per_thousand,
        head_latency_ms: mean(cases.iter().map(|case| case.head_ms)),
        incumbent_latency_ms: mean(cases.iter().map(|case| case.incumbent_ms)),
    }
}

/// The trial table's declared scrub: an erased run or typed question loses
/// its trials.
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn erase_question_trial_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    QUESTION_TRIALS.delete(&vault.store, wtxn, id)?;
    drop_question_trials_in_txn(&vault.store, wtxn, *id, None)
}

/// Drops the trials against typed question `question` at `version`, or at
/// every version when `None`, in the transaction that erases that question
/// version. Every door that erases a question version calls it, beside
/// [`super::drop_question_heads_in_txn`] (FIX 3864).
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn drop_question_trials_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    question: EntityId,
    version: Option<u32>,
) -> Result<()> {
    let dropped: Vec<EntityId> = QUESTION_TRIALS
        .scan(store, wtxn)?
        .into_iter()
        .filter(|(_, trial)| {
            trial.question == question
                && version.is_none_or(|version| version == trial.question_version)
        })
        .map(|(run, _)| run)
        .collect();
    for run in dropped {
        QUESTION_TRIALS.delete(store, wtxn, &run)?;
    }
    Ok(())
}

impl Vault {
    /// The owner tries question run `id`'s head against typed question
    /// `question` at `question_version`: the run's sealed held-out cohort is
    /// served once more, counted, and its rows go to the host with the
    /// question and the head. Opening replaces the run's earlier trial.
    ///
    /// # Errors
    ///
    /// `answerer` is the pin of every rung the host's ladder holds now.
    ///
    /// A role run, a run not scored, an evaluation with no temperature, no
    /// such question version (or one erased while it opened), a question that
    /// is not yes/no, a cohort that
    /// no longer holds the held-out rows, a stale owner proof, or storage
    /// errors.
    pub fn open_question_head_trial(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        question: EntityId,
        question_version: u32,
        answerer: Vec<ProviderPin>,
    ) -> Result<QuestionTrialInput> {
        self.recheck_owner(owner)?;
        let run = self
            .training_run(id)?
            .ok_or_else(|| invalid("training run not found"))?;
        let target = run
            .plan
            .target
            .question()
            .cloned()
            .ok_or_else(|| invalid("a role run has no question head to try"))?;
        if run.state != TrainingState::Scored {
            return Err(invalid(
                "a question head is tried once its held-out evaluation is recorded, before it binds",
            ));
        }
        let result = run
            .result
            .as_ref()
            .ok_or_else(|| invalid("training checkpoint has not returned"))?;
        let temperature = run
            .evaluation
            .as_ref()
            .and_then(|evaluation| evaluation.calibration.as_ref())
            .map(|calibration| calibration.temperature)
            .filter(|temperature| temperature.is_finite() && *temperature > 0.0)
            .ok_or_else(|| {
                invalid("a question head answers at its fitted temperature; the evaluation reports none")
            })?;
        let record = crate::llm::decision::questions::read_question_version(
            self,
            question,
            question_version,
        )?
        .ok_or_else(|| invalid("no typed question at that id and version"))?;
        if !matches!(record.definition.question.contract, AnswerContract::Noul) {
            return Err(invalid("a question head answers a yes/no question only"));
        }
        let candidate = blake3::Hash::from(result.exported_checkpoint.content_hash()?)
            .to_hex()
            .to_string();
        let release = self.open_eval_cohort(
            &run.corpus.cohort.id,
            EvalExposureKind::Candidate,
            &run.admission_ref(),
            Some(&candidate),
            self.store.clock.now_recorded_at(),
        )?;
        let receipts: BTreeSet<&str> = release
            .cases
            .iter()
            .flat_map(|case| case.receipts.iter().map(String::as_str))
            .collect();
        if run
            .corpus
            .rows
            .iter()
            .any(|row| row.side == SplitSide::HeldOut && !receipts.contains(row.receipt.as_str()))
        {
            return Err(invalid(
                "training held-out rows must be cases in the sealed cohort",
            ));
        }
        let held_out_jsonl = self.read_training_artifact(&run.corpus.held_out)?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            // The question may have been erased since it was read: its trial
            // is never written then (the erase dropped its trials already).
            if crate::llm::decision::questions::read_question_version_in_txn(
                self,
                txn,
                question,
                question_version,
            )?
            .is_none()
            {
                return Err(invalid(
                    "the typed question was erased while its trial opened",
                ));
            }
            let opened = QuestionHeadTrial {
                question,
                question_version,
                exposure: release.exposure.clone(),
                incumbent_head: bound_run_in_txn(&self.store, txn, question, question_version)?,
                answerer: answerer.clone(),
                measured: None,
            };
            QUESTION_TRIALS.put(&self.store, txn, id, &opened)
        })?;
        Ok(QuestionTrialInput {
            exposure: release.exposure,
            principal: record.principal,
            posture: record.definition.posture,
            dial: record.definition.dial,
            question: record.definition.question,
            target,
            checkpoint: result.exported_checkpoint.clone(),
            temperature,
            held_out_jsonl,
        })
    }

    /// The host records its reads of the trial it opened under `exposure`;
    /// answers the trial with its numbers. A trusted host supplies
    /// measurements; nothing here binds the head.
    ///
    /// # Errors
    ///
    /// No open trial under `exposure` for the run, no cases, a case repeated
    /// or out of range, or storage errors.
    pub fn record_question_head_trial(
        &self,
        id: &EntityId,
        exposure: &EntityId,
        cases: &[QuestionTrialCase],
    ) -> Result<QuestionHeadTrial> {
        let mut rows = BTreeSet::new();
        if cases.is_empty()
            || cases.iter().any(|case| {
                !rows.insert(case.row.as_str())
                    || !probability_valid(case.head)
                    || !probability_valid(case.incumbent)
                    || !probability_valid(case.retest)
                    || ![case.head_ms, case.incumbent_ms]
                        .iter()
                        .all(|ms| ms.is_finite() && *ms >= 0.0)
                    || case
                        .incumbent_cost_per_thousand
                        .is_some_and(|cost| !cost.is_finite() || cost < 0.0)
            })
        {
            return Err(invalid(
                "a question head trial records each held-out row once, with finite reads",
            ));
        }
        let measured = measure(id, exposure, cases, self.store.clock.now_recorded_at());
        self.with_write_txn_grouped(|txn| {
            let mut trial = QUESTION_TRIALS
                .get(&self.store, txn, id)?
                .filter(|trial| trial.exposure.id == *exposure && trial.measured.is_none())
                .ok_or_else(|| invalid("no open question head trial under that exposure"))?;
            trial.measured = Some(measured.clone());
            QUESTION_TRIALS.put(&self.store, txn, id, &trial)?;
            Ok(trial)
        })
    }

    /// Question run `run`'s latest trial, open or recorded.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn training_question_trial(&self, run: &EntityId) -> Result<Option<QuestionHeadTrial>> {
        QUESTION_TRIALS.get(&self.store, &self.store.env.read_txn()?, run)
    }
}
