//! The Coach's paired eval measurement (FIX 574, OF-578). Each released case
//! of the cohort is answered by the incumbent, the candidate and an
//! incumbent retest, with the same task and route prompt, varying only the
//! exact model; the replay judge scores each answer blind; the engine's
//! estimator reads the card. One clock and one budget per job. A job that
//! cannot run yet (no judge, an arm this host does not serve exactly)
//! leaves the row Pending and spends nothing. A gap after the claim settles
//! it Partial at once: survivors of a failed set are never estimated. A
//! skill arm answers under the exact skill content it pins, loaded on the
//! job's own attempt through the pinned-pack load (FIX 10677).

use std::time::Duration;

use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::learning::{Retest, RetestScore, record_retest};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_optimize::{
    EvalCaseMeasurement, EvalLegRecord, EvalMeasurement, EvalTaskInput, HeldOutReplayNotes,
    JudgeRubric, MeasurementState, MeasurementUnavailable, seat_model_role,
};
use oneiron::{BudgetExhaustionPolicy, Vault};

use crate::replay_judge::ServeReplayJudge;
use crate::server::SyncServer;

mod helper;
mod legs;
mod offer;
mod score;

pub(super) use helper::request_helper_measurements;
pub(super) use offer::attach_measured_card;

use legs::{Arms, Generated, Opened};
use score::Scored;

/// The job's clock: every generation and judgment of one measurement runs
/// within it (CALL).
const MEASUREMENT_CLOCK: Duration = Duration::from_secs(3600);
/// What one measurement's model calls may spend, every leg together (CALL).
const MEASUREMENT_BUDGET_UNITS: u64 = 1 << 24;
/// The legs of a case, in the order they are sent.
const LEGS: [Leg; 3] = [Leg::Incumbent, Leg::Candidate, Leg::Retest];

/// One leg of a case.
#[derive(Clone, Copy)]
enum Leg {
    Incumbent,
    Candidate,
    Retest,
}

impl Leg {
    const fn name(self) -> &'static str {
        match self {
            Self::Incumbent => "incumbent",
            Self::Candidate => "candidate",
            Self::Retest => "retest",
        }
    }
}

/// One claimed measurement's run.
struct Job<'a> {
    server: &'a SyncServer,
    vault: &'a Vault,
    judge: &'static ServeReplayJudge,
    row: EvalMeasurement,
    digest: [u8; 32],
    arms: Arms,
    run: oneiron::llm::run_admission::RunAdmission,
    clock: RetrievalDeadline,
    rubric: Option<JudgeRubric>,
}

/// Why the row cannot be measured at all, read before the claim: settled
/// Partial at once, with nothing counted or paid.
fn refusal(judge: &ServeReplayJudge, row: &EvalMeasurement) -> Option<MeasurementUnavailable> {
    let request = &row.request;
    if seat_model_role(&request.seat).is_none() {
        return Some(MeasurementUnavailable::NoModelRole);
    }
    (judge.judge_revision() != request.scorer).then_some(MeasurementUnavailable::ScorerMoved)
}

/// Runs one leased `coach.eval_measurement` attempt.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let digest = vault.coach_eval_measurement_target(admitted)?;
    let Some(row) = vault.eval_measurement(&digest)? else {
        return Ok(());
    };
    if !matches!(
        row.state,
        MeasurementState::Pending | MeasurementState::Claimed
    ) {
        return Ok(());
    }
    // No judge here: the next request queues the job again.
    let Some(judge) = crate::replay_judge::registered() else {
        return Ok(());
    };
    if let Some(reason) = refusal(judge, &row) {
        vault.fail_eval_measurement(&digest, &[reason], now)?;
        return Ok(());
    }
    let arms = match legs::open(server, vault, &row, &admitted.status.attempt, now)? {
        Opened::Ready(arms) => arms,
        Opened::Unserved => return Ok(()),
        Opened::Refused(reason) => {
            vault.fail_eval_measurement(&digest, &[reason], now)?;
            return Ok(());
        }
    };
    let row = vault.claim_eval_measurement(&digest, now)?;
    if row.state != MeasurementState::Claimed {
        return Ok(());
    }
    let run_id = format!("coach-eval-measurement:{}", row.digest);
    let guard = vault.policy_budget_guard(
        run_id.clone(),
        MEASUREMENT_BUDGET_UNITS,
        oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS,
        BudgetExhaustionPolicy::Suspend,
        vault.coach_authority()?,
    )?;
    let job = Job {
        server,
        vault,
        judge,
        digest,
        arms,
        run: server.ai.model_runtime().undeclared_run(run_id, guard),
        clock: RetrievalDeadline::after(MEASUREMENT_CLOCK),
        rubric: judge.rubric()?,
        row,
    };
    if let Some(reason) = job.measure_cases()? {
        vault.fail_eval_measurement(&digest, &[reason], vault.now_recorded_at())?;
        return Ok(());
    }
    let finished = vault.finish_eval_measurement(&digest, vault.now_recorded_at())?;
    tracing::debug!(state = ?finished.state, "the Coach's eval measurement");
    Ok(())
}

impl Job<'_> {
    /// Every open case in cohort order; the reason the set cannot be
    /// complete, at the first gap.
    fn measure_cases(&self) -> oneiron::Result<Option<MeasurementUnavailable>> {
        for (case, started) in self.vault.eval_measurement_open_cases(&self.digest)? {
            // A past run marked it started: its legs may have been sent,
            // and none is paid for twice.
            if started {
                return Ok(Some(MeasurementUnavailable::UncertainLeg));
            }
            let task = match self.vault.released_eval_task(&self.digest, &case)? {
                Ok(task) => task,
                Err(reason) => return Ok(Some(reason)),
            };
            if task.labels.is_empty() {
                return Ok(Some(MeasurementUnavailable::NoLabel));
            }
            if let Some(reason) = self.measure_case(&task)? {
                return Ok(Some(reason));
            }
        }
        Ok(None)
    }

    /// One case: marked started, its three legs answered and scored, then
    /// recorded settled, its retest recorded beside it. The reason the set
    /// cannot be complete, when a leg has no score.
    fn measure_case(
        &self,
        task: &EvalTaskInput,
    ) -> oneiron::Result<Option<MeasurementUnavailable>> {
        let mut record = EvalCaseMeasurement {
            case: task.case,
            family: task.family,
            stratum: task.stratum.clone(),
            task_hash: Some(
                blake3::Hash::from(task.task_hash)
                    .to_hex()
                    .as_str()
                    .to_owned(),
            ),
            incumbent: EvalLegRecord::default(),
            candidate: EvalLegRecord::default(),
            retest: EvalLegRecord::default(),
            started_at: self.vault.now_recorded_at(),
            recorded_at: None,
            source_rows: task.source_rows.clone(),
        };
        self.vault
            .record_eval_case_measurement(&self.digest, record.clone())?;
        let mut gap = None;
        for leg in LEGS {
            let answered = match gap {
                Some(reason) => EvalLegRecord::unavailable(reason),
                None => self.leg(task, leg)?,
            };
            gap = gap.or(answered.unavailable);
            match leg {
                Leg::Incumbent => record.incumbent = answered,
                Leg::Candidate => record.candidate = answered,
                Leg::Retest => record.retest = answered,
            }
        }
        let now = self.vault.now_recorded_at();
        record.recorded_at = Some(now);
        self.vault
            .record_eval_case_measurement(&self.digest, record.clone())?;
        if gap.is_none() {
            self.retest(&record, now)?;
        }
        Ok(gap)
    }

    /// One leg: the arm's answer, kept, then scored blind.
    fn leg(&self, task: &EvalTaskInput, leg: Leg) -> oneiron::Result<EvalLegRecord> {
        let arm = match leg {
            Leg::Candidate => &self.arms.candidate,
            Leg::Incumbent | Leg::Retest => &self.arms.incumbent,
        };
        let prompt = legs::task_text(task);
        let (answer, served) = match self.arms.generate(
            self.server,
            self.vault,
            &self.run,
            arm,
            &prompt,
            &self.clock,
        ) {
            Generated::Answer { text, served } => (text, served),
            Generated::Unavailable(reason) => return Ok(EvalLegRecord::unavailable(reason)),
        };
        let output = oneiron::compaction::output::store_output(self.vault, answer.as_bytes())?;
        let mut record = EvalLegRecord {
            output: Some(output),
            receipt: Some(format!(
                "eval_measurement:{}:{}:{}",
                self.row.digest,
                task.case.to_hex(),
                leg.name()
            )),
            served,
            ..EvalLegRecord::default()
        };
        match score::score(
            self.vault,
            self.judge,
            &self.clock,
            self.rubric.as_ref(),
            task,
            &prompt,
            &answer,
        )? {
            Scored::Score { value, judge } => {
                record.score = Some(value);
                record.judge = judge;
            }
            Scored::Unavailable(reason) => record.unavailable = Some(reason),
        }
        Ok(record)
    }

    /// The incumbent's two answers on one case, recorded as one retest of
    /// the judge on the incumbent. With no judge rubric in force there is no
    /// scoring subject to keep it under.
    fn retest(&self, record: &EvalCaseMeasurement, now: u64) -> oneiron::Result<()> {
        let (Some(rubric), Some(first), Some(second)) = (
            self.rubric.as_ref(),
            record.incumbent.score,
            record.retest.score,
        ) else {
            return Ok(());
        };
        let retest = Retest {
            scorer: rubric.skill,
            executor: self.row.request.incumbent.label(),
            axis: self.row.request.axis.axis.clone(),
            type_ref: None,
            receipt: format!("measurement:{}:{}", self.row.digest, record.case.to_hex()),
            first: RetestScore::Value(first),
            second: RetestScore::Value(second),
            at: now,
        };
        record_retest(self.vault, &retest, now)?;
        Ok(())
    }
}
