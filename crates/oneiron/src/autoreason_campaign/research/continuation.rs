//! The host continuation of a campaign bound with an execution spec (FIX 886,
//! OF-351). The Coach tick still selects; this carries out what it selected.
//!
//! One continuation per unit of work: the bootstrap measure of the incumbent
//! root, or one selection round's fork. Each holds an ordered task list and
//! at most one task in flight. A task reserves its RSI units, then dispatches
//! the spec's agent with a JSON briefing; a later pass reads the finished
//! run's one JSON answer and records it through the campaign's own doors.
//! A measurement is a fresh run under the root, outside the experiment's
//! write scope. A consumed confirmation shot stays spent: a referee that does
//! not answer holds the campaign, and is never asked again.
use std::collections::{BTreeMap, BTreeSet};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::super::CampaignDatasetRef;
use super::super::beam_promotion::SealedRefereeMeasurement;
use super::super::general::Measurement;
use super::budget::is_budget_refusal;
use super::estimator::{self, ENGINE_ESTIMATOR_VERSION};
use super::{
    BINDING, CandidateRef, ConfirmationOutcome, ExperimentNode, ForkInput, ForkKind, HeldOutCall,
    NODE, PromotionBasis, PromotionDisposition, ROUND, ResearchBinding, ResearchExecution,
    ResearchReservation, ResearchStep, ResearchTarget, SearchEvidence, SelectionReceipt, hex,
    invalid, nodes_in_txn, promote_measured, promotion_basis, record_fork,
    record_held_out_measurement, record_invalid_experiment, record_search_measurement,
    refund_research_work, research_binding, research_incumbent, research_promotions,
    research_reservations, reserve_confirmation, reserve_research_work, settle_research_work,
};
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use crate::attempt_queue::{AttemptRecord, AttemptState};
use crate::context_projection::ContextSpec;
use crate::llm::RsiSpendPurpose;
use crate::llm::run_admission::LeaseUnit;
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::{EvalRelease, SufficiencyInput};
use crate::{AttemptId, AttemptQueue, EntityId, Error, Result, Vault};

/// One unit of host work, keyed by root attempt then work: `0` the
/// bootstrap, `n + 1` selection round `n`.
const CONTINUATION: SideTable<([u8; 16], u64), ResearchContinuation, Named> =
    SideTable::new(&side_table::AUTORESEARCH_CONTINUATION);

/// Steps one continuation takes in one pass.
const MAX_STEPS_PER_PASS: usize = 16;
/// Campaigns one pass advances.
const MAX_ROOTS_PER_PASS: usize = 32;
/// The one hold a pass retries: the reservation found no room.
const BUDGET_HELD: &str = "budget";
const SHOT_SPENT: &str = "the sealed shot is spent; the referee did not answer";
const NO_SEAT: &str = "no confirmation seat: promotion waits";
const TRADEOFF: &str = "tradeoff escalates to the goal's decision path";
/// The answer each briefing asks its agent for.
const EXPERIMENT_ANSWER: &str =
    r#"{"config_ref": "...", "config_sha256": "<64 hex>"} or {"failed": "why"}"#;
const SCORE_ANSWER: &str = r#"{"scores": {axis: number}, "confirmed_hits": n, "attribution": 0..1, "hop_cost": n, "receipt_refs": [..]} or {"invalid": "why", "evidence_refs": [..]}"#;
const REFEREE_ANSWER: &str = r#"{"candidate": 0..1, "incumbent": 0..1, "referee_pin": "identity@sha256:<hex>", "sufficiency": SufficiencyInput}"#;

/// Which campaign work a continuation carries out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchWork {
    /// Measure the unmeasured incumbent root on the search split.
    Bootstrap,
    /// Carry out selection round `n`'s fork.
    Round(u64),
}

impl ResearchWork {
    fn key(self) -> u64 {
        match self {
            Self::Bootstrap => 0,
            Self::Round(round) => round.saturating_add(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchSplit {
    Search,
    HeldOut,
}

/// One unit of work a continuation runs, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchTask {
    /// Score `node`'s candidate on a split with the scorer, outside the
    /// experiment's write scope.
    Measure {
        node: AttemptId,
        split: ResearchSplit,
    },
    /// Run the experimenter under `parent` for one child candidate.
    Experiment { parent: AttemptId, kind: ForkKind },
    /// Decide promotion of `candidate` against the incumbent once.
    Basis { candidate: AttemptId },
    /// Spend the sealed confirmation shot and run the referee on it.
    Confirm { candidate: AttemptId },
}

/// The task in flight: its reservation and, once dispatched, its run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchRunning {
    pub task: ResearchTask,
    /// The RSI reservation the task's run spends.
    pub reservation: EntityId,
    pub run: Option<AttemptId>,
    /// A confirmation's sealed release, kept once `reserve_confirmation`
    /// returned it: a restart re-briefs the referee and never spends a
    /// second shot.
    pub release: Option<EvalRelease>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchContinuationState {
    Open,
    Held { reason: String },
    Done { note: String },
    Failed { reason: String },
}

impl ResearchContinuationState {
    /// Open, or held for budget: the states a pass takes up.
    fn live(&self) -> bool {
        match self {
            Self::Open => true,
            Self::Held { reason } => reason == BUDGET_HELD,
            Self::Done { .. } | Self::Failed { .. } => false,
        }
    }
}

/// One campaign's host work: what is left to run, what is running, and
/// every run it dispatched.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchContinuation {
    pub root: AttemptId,
    pub work: ResearchWork,
    /// The tasks still to run; the front runs next.
    pub pending: Vec<ResearchTask>,
    pub running: Option<ResearchRunning>,
    pub state: ResearchContinuationState,
    /// Every run this continuation dispatched, in order: the receipt trail.
    pub runs: Vec<AttemptId>,
    /// Whether this work already took its one debug child.
    pub debug_spawned: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

/// The experimenter's answer: the candidate it wrote, or why it could not.
#[derive(Deserialize)]
#[serde(untagged)]
enum ExperimentAnswer {
    Candidate(CandidateRef),
    Failed { failed: String },
}

/// The scorer's numbers for one candidate on one split. Search evidence
/// needs the hits, attribution and hop cost; held-out evidence only scores.
#[derive(Deserialize)]
struct Scores {
    scores: BTreeMap<String, f64>,
    confirmed_hits: Option<f64>,
    attribution: Option<f64>,
    hop_cost: Option<f64>,
    #[serde(default)]
    receipt_refs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ScoreAnswer {
    Scores(Scores),
    Invalid {
        invalid: String,
        #[serde(default)]
        evidence_refs: Vec<String>,
    },
}

/// The sealed referee's answer. Its raw scores stay in the sealed
/// measurement; only its win bit and digest are recorded.
#[derive(Deserialize)]
struct RefereeAnswer {
    candidate: f64,
    incumbent: f64,
    referee_pin: String,
    sufficiency: SufficiencyInput,
}

/// Whether a pass takes another step on a continuation.
enum Flow {
    Next,
    Stop,
}

/// Create the continuations bound campaigns with an execution spec are owed:
/// a bootstrap for an unmeasured root, one per forking selection round.
/// Paused, stopped and escalated rounds get none.
/// # Errors
/// Storage errors.
pub fn ensure_research_continuations(
    vault: &Vault,
    now: u64,
) -> Result<Vec<(AttemptId, ResearchWork)>> {
    let txn = vault.store.env.read_txn()?;
    let bindings = executed_bindings(vault, &txn)?;
    drop(txn);
    let mut live = Vec::new();
    for binding in &bindings {
        create_missing(vault, binding.root, now)?;
        let txn = vault.store.env.read_txn()?;
        live.extend(
            CONTINUATION
                .scan_from(&vault.store, &txn, binding.root.as_bytes())?
                .into_iter()
                .filter(|(_, row)| row.state.live())
                .map(|(_, row)| (binding.root, row.work)),
        );
    }
    Ok(live)
}

/// Whether any campaign with an execution spec has host work: a
/// continuation owed, open, or held for budget. The host enqueues its Coach
/// job on it.
/// # Errors
/// Storage errors.
pub fn research_work_pending(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    for binding in executed_bindings(vault, &txn)? {
        if !missing_work(vault, &txn, binding.root)?.is_empty()
            || CONTINUATION
                .scan_from(&vault.store, &txn, binding.root.as_bytes())?
                .iter()
                .any(|(_, row)| row.state.live())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The Coach host's pass: create what is owed, then advance each live
/// continuation until a run is still going, it holds or it ends. A refused
/// record door fails that continuation alone; a storage error stops the pass.
/// # Errors
/// Storage errors, or another pass advancing a continuation concurrently.
pub fn advance_research_continuations(
    vault: &Vault,
    coach_attempt: AttemptId,
    now: u64,
) -> Result<()> {
    let live = ensure_research_continuations(vault, now)?;
    let mut roots: Vec<AttemptId> = Vec::new();
    for (root, work) in &live {
        if !roots.contains(root) {
            if roots.len() == MAX_ROOTS_PER_PASS {
                continue;
            }
            roots.push(*root);
        }
        let Some(binding) = research_binding(vault, *root)? else {
            continue;
        };
        let Some(execution) = &binding.execution else {
            continue;
        };
        Pass {
            vault,
            binding: &binding,
            execution,
            now,
        }
        .advance(*work)?;
    }
    tracing::debug!(
        coach_attempt = %hex(&coach_attempt),
        continuations = live.len(),
        "autoresearch continuations advanced"
    );
    Ok(())
}

/// What the round continuations say about the next selection round:
/// `Some(false)` while one is open or waits on budget, `Some(true)` once the
/// last round's ended any other way (it may have added no node, so an
/// unchanged branch set must not wedge the loop), `None` to keep the
/// record's own rule. A promotion held for the owner or a spent shot does
/// not stop the search.
pub(super) fn round_due_gate(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
    last: Option<&SelectionReceipt>,
) -> Result<Option<bool>> {
    let mut last_ended = false;
    for (_, row) in CONTINUATION.scan_from(&vault.store, txn, root.as_bytes())? {
        let ResearchWork::Round(round) = row.work else {
            continue;
        };
        match &row.state {
            ResearchContinuationState::Open => return Ok(Some(false)),
            ResearchContinuationState::Held { reason } if reason == BUDGET_HELD => {
                return Ok(Some(false));
            }
            ResearchContinuationState::Held { .. }
            | ResearchContinuationState::Failed { .. }
            | ResearchContinuationState::Done { .. } => {
                last_ended |= last.is_some_and(|last| last.round == round);
            }
        }
    }
    Ok(last_ended.then_some(true))
}

fn executed_bindings(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<ResearchBinding>> {
    Ok(BINDING
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, binding)| binding)
        .filter(|binding| binding.execution.is_some())
        .collect())
}

/// The work a campaign is owed and has no continuation for: the bootstrap
/// of an unmeasured root, and each forking round's experiment. Select never
/// picks a buggy parent, so a round's own fork is a variation.
fn missing_work(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
) -> Result<Vec<(ResearchWork, Vec<ResearchTask>)>> {
    let have: BTreeSet<u64> = CONTINUATION
        .scan_from(&vault.store, txn, root.as_bytes())?
        .into_iter()
        .map(|((_, work), _)| work)
        .collect();
    let mut missing = Vec::new();
    let unmeasured = NODE
        .get(&vault.store, txn, &(*root.as_bytes(), *root.as_bytes()))?
        .is_some_and(|node| node.search.is_none());
    if unmeasured && !have.contains(&ResearchWork::Bootstrap.key()) {
        missing.push((
            ResearchWork::Bootstrap,
            vec![ResearchTask::Measure {
                node: root,
                split: ResearchSplit::Search,
            }],
        ));
    }
    for (_, round) in ROUND.scan_from(&vault.store, txn, root.as_bytes())? {
        let ResearchStep::Fork { parent, .. } = round.step else {
            continue;
        };
        let work = ResearchWork::Round(round.round);
        if !have.contains(&work.key()) {
            missing.push((
                work,
                vec![ResearchTask::Experiment {
                    parent,
                    kind: ForkKind::Variation,
                }],
            ));
        }
    }
    Ok(missing)
}

/// Create the owed continuations, each once: contains-then-put in one write.
fn create_missing(vault: &Vault, root: AttemptId, now: u64) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    let missing = missing_work(vault, &txn, root)?;
    drop(txn);
    if missing.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        for (work, pending) in missing {
            let key = (*root.as_bytes(), work.key());
            if CONTINUATION.contains(&vault.store, txn, &key)? {
                continue;
            }
            let row = ResearchContinuation {
                root,
                work,
                pending,
                running: None,
                state: ResearchContinuationState::Open,
                runs: Vec::new(),
                debug_spawned: false,
                created_at: now,
                updated_at: now,
            };
            CONTINUATION.put(&vault.store, txn, &key, &row)?;
        }
        Ok(())
    })
}

/// One campaign's continuations under one pass.
struct Pass<'a> {
    vault: &'a Vault,
    binding: &'a ResearchBinding,
    execution: &'a ResearchExecution,
    now: u64,
}

impl Pass<'_> {
    fn root(&self) -> AttemptId {
        self.binding.root
    }

    fn load(&self, work: ResearchWork) -> Result<Option<ResearchContinuation>> {
        let txn = self.vault.store.env.read_txn()?;
        CONTINUATION.get(
            &self.vault.store,
            &txn,
            &(*self.root().as_bytes(), work.key()),
        )
    }

    /// Up to [`MAX_STEPS_PER_PASS`] steps, each persisted on its own.
    fn advance(&self, work: ResearchWork) -> Result<()> {
        for _ in 0..MAX_STEPS_PER_PASS {
            let Some(row) = self.load(work)? else {
                return Ok(());
            };
            if !row.state.live() {
                return Ok(());
            }
            match self.step(&row) {
                Ok(Flow::Next) => {}
                Ok(Flow::Stop) => return Ok(()),
                Err(Error::InvalidConfig(reason)) => return self.fail(&row, reason),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Store `next` over `row` in one write, unless another pass moved the
    /// row since it was read.
    fn save(&self, row: &ResearchContinuation, mut next: ResearchContinuation) -> Result<()> {
        next.updated_at = self.now;
        let key = (*row.root.as_bytes(), row.work.key());
        self.vault.with_write_txn_grouped(|txn| {
            if CONTINUATION.get(&self.vault.store, txn, &key)?.as_ref() != Some(row) {
                return Err(Error::ConcurrentWrite(
                    "another pass advanced this research continuation",
                ));
            }
            CONTINUATION.put(&self.vault.store, txn, &key, &next)
        })
    }

    /// End a continuation on a refusal. A reservation nothing was dispatched
    /// on is refunded; a dispatched run's stays as the run left it.
    fn fail(&self, row: &ResearchContinuation, reason: String) -> Result<()> {
        let mut next = row.clone();
        if let Some(running) = &row.running
            && running.run.is_none()
        {
            match self.refund(running.reservation) {
                Ok(()) | Err(Error::InvalidConfig(_)) => {}
                Err(error) => return Err(error),
            }
            next.running = None;
        }
        next.state = failed(reason);
        self.save(row, next)
    }

    fn step(&self, row: &ResearchContinuation) -> Result<Flow> {
        if let Some(running) = &row.running {
            return match running.run {
                None => self.dispatch(row, running),
                Some(run) => self.observe(row, running, run),
            };
        }
        let mut next = row.clone();
        // A budget hold retries its task now.
        next.state = ResearchContinuationState::Open;
        if next.pending.is_empty() {
            next.state = ResearchContinuationState::Done {
                note: "every task ran".to_owned(),
            };
            self.save(row, next)?;
            return Ok(Flow::Stop);
        }
        let task = next.pending.remove(0);
        let execution = self.execution;
        let (purpose, units, attempt) = match task {
            ResearchTask::Basis { candidate } => return self.basis(row, next, candidate),
            ResearchTask::Measure { node, split } => {
                let purpose = match split {
                    ResearchSplit::Search => RsiSpendPurpose::Judge,
                    ResearchSplit::HeldOut => RsiSpendPurpose::HeldOut,
                };
                (purpose, execution.measure_units, node)
            }
            ResearchTask::Experiment { parent, .. } => (
                RsiSpendPurpose::Experiment,
                execution.experiment_units,
                parent,
            ),
            ResearchTask::Confirm { candidate } => {
                (RsiSpendPurpose::HeldOut, execution.confirm_units, candidate)
            }
        };
        match reserve_research_work(
            self.vault,
            self.root(),
            purpose,
            units,
            Some(attempt),
            self.now,
        ) {
            Ok(reservation) => {
                next.running = Some(ResearchRunning {
                    task,
                    reservation,
                    run: None,
                    release: None,
                });
                self.save(row, next)?;
                Ok(Flow::Next)
            }
            // No room: the task waits at the front, as a round pauses.
            Err(error) if is_budget_refusal(&error) => {
                next.pending.insert(0, task);
                next.state = ResearchContinuationState::Held {
                    reason: BUDGET_HELD.to_owned(),
                };
                self.save(row, next)?;
                Ok(Flow::Stop)
            }
            Err(error) => Err(error),
        }
    }

    /// The held-out basis needs no run. Only a Promote goes on, and only to
    /// a confirmation seat with a referee.
    fn basis(
        &self,
        row: &ResearchContinuation,
        mut next: ResearchContinuation,
        candidate: AttemptId,
    ) -> Result<Flow> {
        let basis = match self.basis_of(candidate)? {
            Some(basis) => basis,
            None => promotion_basis(self.vault, self.root(), candidate, None, self.now)?,
        };
        let confirms = self.binding.confirmation.is_some() && self.execution.referee.is_some();
        next.state = match basis.call {
            HeldOutCall::Promote if confirms => {
                next.pending.insert(0, ResearchTask::Confirm { candidate });
                ResearchContinuationState::Open
            }
            HeldOutCall::Promote => ResearchContinuationState::Held {
                reason: NO_SEAT.to_owned(),
            },
            HeldOutCall::Reject => ResearchContinuationState::Done {
                note: "the held-out basis rejected the candidate".to_owned(),
            },
            HeldOutCall::EscalateTradeoff => ResearchContinuationState::Held {
                reason: TRADEOFF.to_owned(),
            },
        };
        self.save(row, next)?;
        Ok(Flow::Next)
    }

    /// Dispatch the task in flight. After a crash the same dedupe key brings
    /// back the run already made. A refused dispatch refunds and fails.
    fn dispatch(&self, row: &ResearchContinuation, running: &ResearchRunning) -> Result<Flow> {
        let root = self.root();
        let (agent, parent, briefing) = match running.task {
            ResearchTask::Experiment { parent, kind } => (
                self.execution.experimenter,
                parent,
                self.experimenter_briefing(parent, kind)?,
            ),
            ResearchTask::Measure { node, split } => (
                self.execution.scorer,
                root,
                self.scorer_briefing(node, split)?,
            ),
            ResearchTask::Confirm { candidate } => {
                let Some(release) = &running.release else {
                    return self.release(row, running, candidate);
                };
                let referee = self
                    .execution
                    .referee
                    .ok_or(invalid("the campaign names no referee"))?;
                (referee, root, self.referee_briefing(candidate, release)?)
            }
            ResearchTask::Basis { .. } => {
                return Err(invalid("a held-out basis dispatches no run"));
            }
        };
        let outcome = AgentDispatcher::new(self.vault).dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: Some(parent),
                dedupe_key: Some(format!(
                    "research:{}:{}:{}",
                    hex(&root),
                    row.work.key(),
                    row.runs.len()
                )),
                run_id: Some(self.binding.run_id.clone()),
                now: self.now,
            },
            AgentSpawnContext::default()
                .with_context_spec(ContextSpec::excluded().with_briefing(briefing)),
        );
        let reason = match outcome {
            Ok(
                AgentDispatchOutcome::Dispatched(status) | AgentDispatchOutcome::Existing(status),
            ) => {
                let mut next = row.clone();
                if let Some(running) = &mut next.running {
                    running.run = Some(status.attempt.id);
                }
                next.runs.push(status.attempt.id);
                self.save(row, next)?;
                return Ok(Flow::Next);
            }
            Ok(_) => "the dispatcher parked the run rather than start it".to_owned(),
            Err(error @ (Error::InvalidConfig(_) | Error::Artifact(_) | Error::Gate(_))) => {
                error.to_string()
            }
            Err(error) => return Err(error),
        };
        self.refund(running.reservation)?;
        let mut next = row.clone();
        next.running = None;
        next.state = failed(reason);
        self.save(row, next)?;
        Ok(Flow::Stop)
    }

    /// Spend the candidate's sealed confirmation and keep its release on the
    /// task. A shot already spent, here or before a crash, is never spent
    /// again: the campaign holds.
    fn release(
        &self,
        row: &ResearchContinuation,
        running: &ResearchRunning,
        candidate: AttemptId,
    ) -> Result<Flow> {
        let mut next = row.clone();
        if !self.shot_spent(candidate)? {
            match reserve_confirmation(self.vault, self.root(), candidate, self.now) {
                Ok(release) => {
                    if let Some(running) = &mut next.running {
                        running.release = Some(release);
                    }
                    self.save(row, next)?;
                    return Ok(Flow::Next);
                }
                Err(Error::InvalidConfig(reason)) => {
                    // Refused before the shot was consumed: nothing was spent.
                    if !self.shot_spent(candidate)? {
                        self.refund(running.reservation)?;
                        next.running = None;
                        next.state = failed(reason);
                        self.save(row, next)?;
                        return Ok(Flow::Stop);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        self.refund(running.reservation)?;
        next.running = None;
        next.state = ResearchContinuationState::Held {
            reason: SHOT_SPENT.to_owned(),
        };
        self.save(row, next)?;
        Ok(Flow::Stop)
    }

    /// Read a dispatched run: wait while it goes; once it ends, record its
    /// answer, settle what it spent, and move on.
    fn observe(
        &self,
        row: &ResearchContinuation,
        running: &ResearchRunning,
        run: AttemptId,
    ) -> Result<Flow> {
        let record = AttemptQueue::new(self.vault).get(run)?;
        if record
            .as_ref()
            .is_some_and(|record| !record.state.is_terminal())
        {
            return Ok(Flow::Stop);
        }
        let answer = match &record {
            Some(record) if matches!(record.state, AttemptState::Completed) => {
                run_answer_text(self.vault, record)?
            }
            _ => None,
        };
        let text = answer.as_deref();
        let mut next = row.clone();
        next.running = None;
        match running.task {
            ResearchTask::Experiment { parent, kind } => {
                self.experimented(&mut next, parent, kind, run, text)?;
            }
            ResearchTask::Measure { node, split } => {
                self.measured(&mut next, node, split, run, text)?;
            }
            ResearchTask::Confirm { candidate } => self.confirmed(&mut next, candidate, text)?,
            ResearchTask::Basis { .. } => {
                return Err(invalid("a held-out basis dispatches no run"));
            }
        }
        self.settle(running.reservation, run)?;
        self.save(row, next)?;
        Ok(Flow::Next)
    }

    /// A written candidate becomes the child node, then is measured on the
    /// search split. No candidate, no node: a child without a pin is none.
    fn experimented(
        &self,
        next: &mut ResearchContinuation,
        parent: AttemptId,
        kind: ForkKind,
        run: AttemptId,
        text: Option<&str>,
    ) -> Result<()> {
        let candidate = match text.and_then(answer_object::<ExperimentAnswer>) {
            Some(ExperimentAnswer::Candidate(candidate)) => candidate,
            Some(ExperimentAnswer::Failed { failed: why }) => {
                next.state = failed(format!("the experimenter gave up: {why}"));
                return Ok(());
            }
            None => {
                next.state = failed("the experimenter's run ended without an answer");
                return Ok(());
            }
        };
        if matches!(self.binding.target, ResearchTarget::Skill { .. })
            && proposal_of(&candidate).is_none()
        {
            next.state =
                failed("a skill experiment names its staged proposal as skill_proposal:<32 hex>");
            return Ok(());
        }
        if self.node(run)?.is_none() {
            let fork = ForkInput {
                parent,
                child: run,
                kind,
                candidate,
            };
            if refused(record_fork(self.vault, self.root(), fork, self.now), next)?.is_none() {
                return Ok(());
            }
        }
        next.pending.insert(
            0,
            ResearchTask::Measure {
                node: run,
                split: ResearchSplit::Search,
            },
        );
        Ok(())
    }

    fn measured(
        &self,
        next: &mut ResearchContinuation,
        node: AttemptId,
        split: ResearchSplit,
        run: AttemptId,
        text: Option<&str>,
    ) -> Result<()> {
        let Some(answer) = text.and_then(answer_object::<ScoreAnswer>) else {
            next.state = failed("the scorer's run ended without an answer");
            return Ok(());
        };
        match (answer, split) {
            (ScoreAnswer::Scores(scores), ResearchSplit::Search) => {
                self.searched(next, node, run, scores)
            }
            (ScoreAnswer::Scores(scores), ResearchSplit::HeldOut) => {
                let mut receipt_refs = scores.receipt_refs;
                receipt_refs.push(hex(&run));
                if self.node(node)?.is_none_or(|row| row.held_out.is_none()) {
                    let measurement =
                        self.measurement(&self.binding.config.splits.held_out, scores.scores);
                    refused(
                        record_held_out_measurement(
                            self.vault,
                            self.root(),
                            node,
                            measurement,
                            receipt_refs,
                            self.now,
                        ),
                        next,
                    )?;
                }
                Ok(())
            }
            (ScoreAnswer::Invalid { invalid: why, .. }, ResearchSplit::HeldOut) => {
                next.state = failed(format!("held-out scoring refused the candidate: {why}"));
                Ok(())
            }
            (
                ScoreAnswer::Invalid {
                    invalid: why,
                    mut evidence_refs,
                },
                ResearchSplit::Search,
            ) => {
                if node == self.root() {
                    next.state = failed(format!("the incumbent root measured invalid: {why}"));
                    return Ok(());
                }
                evidence_refs.push(hex(&run));
                if self.node(node)?.is_none_or(|row| row.invalid.is_none())
                    && refused(
                        record_invalid_experiment(
                            self.vault,
                            self.root(),
                            node,
                            &why,
                            evidence_refs,
                            self.now,
                        ),
                        next,
                    )?
                    .is_none()
                {
                    return Ok(());
                }
                if next.debug_spawned {
                    next.state = ResearchContinuationState::Done {
                        note: "the debug child measured invalid too".to_owned(),
                    };
                } else {
                    next.pending.insert(
                        0,
                        ResearchTask::Experiment {
                            parent: node,
                            kind: ForkKind::Debug,
                        },
                    );
                    next.debug_spawned = true;
                }
                Ok(())
            }
        }
    }

    /// Record search evidence. A child that beats the incumbent's search
    /// reward goes on to held-out evidence for both, then the basis.
    fn searched(
        &self,
        next: &mut ResearchContinuation,
        node: AttemptId,
        run: AttemptId,
        scores: Scores,
    ) -> Result<()> {
        let root = self.root();
        let (Some(confirmed_hits), Some(attribution), Some(hop_cost)) =
            (scores.confirmed_hits, scores.attribution, scores.hop_cost)
        else {
            next.state =
                failed("the scorer's search answer names no hits, attribution or hop cost");
            return Ok(());
        };
        let mut receipt_refs = scores.receipt_refs;
        receipt_refs.push(hex(&run));
        if self.node(node)?.is_none_or(|row| row.search.is_none()) {
            let mut evidence = SearchEvidence {
                measurement: self.measurement(&self.binding.config.splits.search, scores.scores),
                confirmed_hits,
                attribution,
                hop_cost,
                expected_gain: 0.0,
                estimator_version: ENGINE_ESTIMATOR_VERSION.to_owned(),
                knob_reliability: None,
                receipt_refs,
            };
            evidence.expected_gain = expected_gain_for(self.vault, self.binding, node, &evidence)?;
            if refused(
                record_search_measurement(self.vault, root, node, evidence),
                next,
            )?
            .is_none()
            {
                return Ok(());
            }
        }
        if node == root {
            return Ok(());
        }
        let nodes = self.nodes()?;
        let incumbent = research_incumbent(self.vault, root)?;
        let reward = |attempt: AttemptId| {
            nodes
                .get(attempt.as_bytes())
                .and_then(|row| row.search.as_ref())
                .map(SearchEvidence::reward)
        };
        let beats = reward(node)
            .zip(reward(incumbent))
            .is_some_and(|(candidate, held)| candidate > held);
        if incumbent == node || !beats {
            return Ok(());
        }
        let mut follow = Vec::new();
        if nodes
            .get(incumbent.as_bytes())
            .is_some_and(|row| row.held_out.is_none())
        {
            follow.push(ResearchTask::Measure {
                node: incumbent,
                split: ResearchSplit::HeldOut,
            });
        }
        follow.push(ResearchTask::Measure {
            node,
            split: ResearchSplit::HeldOut,
        });
        follow.push(ResearchTask::Basis { candidate: node });
        follow.append(&mut next.pending);
        next.pending = follow;
        Ok(())
    }

    /// Settle the candidate on the referee's sealed answer. One that does
    /// not come back, or does not parse, holds: the shot is spent.
    fn confirmed(
        &self,
        next: &mut ResearchContinuation,
        candidate: AttemptId,
        text: Option<&str>,
    ) -> Result<()> {
        let answer = text.and_then(answer_object::<RefereeAnswer>);
        let sealed = answer.as_ref().and_then(|answer| {
            SealedRefereeMeasurement::from_referee_scores(
                answer.candidate,
                answer.incumbent,
                &answer.referee_pin,
            )
            .ok()
        });
        let (Some(answer), Some(sealed)) = (answer, sealed) else {
            next.state = ResearchContinuationState::Held {
                reason: SHOT_SPENT.to_owned(),
            };
            return Ok(());
        };
        let basis = self.basis_of(candidate)?;
        if let Some(receipt) = basis.as_ref().and_then(|basis| basis.promotion.as_ref()) {
            next.state = settled(receipt.disposition);
            return Ok(());
        }
        let skill_proposal = match self.binding.target {
            ResearchTarget::Skill { .. } => basis
                .as_ref()
                .and_then(|basis| proposal_of(&basis.candidate_pin)),
            ResearchTarget::Config { .. } => None,
        };
        let outcome = ConfirmationOutcome {
            sealed,
            sufficiency: answer.sufficiency,
            skill_proposal,
        };
        if let Some(receipt) = refused(
            promote_measured(self.vault, self.root(), candidate, outcome, self.now),
            next,
        )? {
            next.state = settled(receipt.disposition);
        }
        Ok(())
    }

    fn node(&self, attempt: AttemptId) -> Result<Option<ExperimentNode>> {
        let txn = self.vault.store.env.read_txn()?;
        NODE.get(
            &self.vault.store,
            &txn,
            &(*self.root().as_bytes(), *attempt.as_bytes()),
        )
    }

    fn nodes(&self) -> Result<BTreeMap<[u8; 16], ExperimentNode>> {
        let txn = self.vault.store.env.read_txn()?;
        nodes_in_txn(self.vault, &txn, self.root())
    }

    fn basis_of(&self, candidate: AttemptId) -> Result<Option<PromotionBasis>> {
        Ok(research_promotions(self.vault, self.root())?
            .into_iter()
            .find(|basis| basis.candidate == candidate))
    }

    fn shot_spent(&self, candidate: AttemptId) -> Result<bool> {
        Ok(self
            .basis_of(candidate)?
            .is_some_and(|basis| basis.confirmation.is_some()))
    }

    fn measurement(
        &self,
        split: &CampaignDatasetRef,
        scores: BTreeMap<String, f64>,
    ) -> Measurement {
        let metric_set = &self.binding.config.metric_set;
        Measurement {
            dataset: split.clone(),
            metric_set_id: metric_set.set_id.clone(),
            metric_set_revision: metric_set.revision.clone(),
            scores,
        }
    }

    fn reservation(&self, id: EntityId) -> Result<Option<ResearchReservation>> {
        Ok(research_reservations(self.vault, self.root())?
            .into_iter()
            .find(|row| row.id == id))
    }

    /// Settle a finished run's reservation with what it spent, once.
    fn settle(&self, id: EntityId, run: AttemptId) -> Result<()> {
        if let Some(row) = self.reservation(id)?
            && row.settlement.is_none()
        {
            let actual = run_spend_units(self.vault, run, row.units)?;
            settle_research_work(self.vault, self.root(), id, actual)?;
        }
        Ok(())
    }

    /// Refund a reservation nothing was dispatched on, once.
    fn refund(&self, id: EntityId) -> Result<()> {
        if self
            .reservation(id)?
            .is_some_and(|row| row.settlement.is_none())
        {
            refund_research_work(self.vault, self.root(), id)?;
        }
        Ok(())
    }

    fn experimenter_briefing(&self, parent: AttemptId, kind: ForkKind) -> Result<String> {
        let node = self
            .node(parent)?
            .ok_or(invalid("the experiment's parent is not a campaign node"))?;
        let kind = match kind {
            ForkKind::Variation => "variation",
            ForkKind::Debug => "debug",
        };
        Ok(json!({
            "campaign": hex(&self.root()),
            "target": self.binding.target,
            "kind": kind,
            "parent": {
                "attempt": hex(&parent),
                "candidate": node.candidate,
                "search": node.search,
                "invalid": node.invalid,
            },
            "metric_set": self.binding.config.metric_set,
            "answer": EXPERIMENT_ANSWER,
        })
        .to_string())
    }

    fn scorer_briefing(&self, node: AttemptId, split: ResearchSplit) -> Result<String> {
        let row = self
            .node(node)?
            .ok_or(invalid("the measured node is not a campaign node"))?;
        let splits = &self.binding.config.splits;
        let split = match split {
            ResearchSplit::Search => &splits.search,
            ResearchSplit::HeldOut => &splits.held_out,
        };
        Ok(json!({
            "campaign": hex(&self.root()),
            "target": self.binding.target,
            "candidate": row.candidate,
            "split": split,
            "metric_set": self.binding.config.metric_set,
            "answer": SCORE_ANSWER,
        })
        .to_string())
    }

    fn referee_briefing(&self, candidate: AttemptId, release: &EvalRelease) -> Result<String> {
        let basis = self
            .basis_of(candidate)?
            .ok_or(invalid("the candidate has no held-out basis"))?;
        let cases = serde_json::to_value(&release.cases)
            .map_err(|_| invalid("the sealed cases cannot be briefed"))?;
        Ok(json!({
            "campaign": hex(&self.root()),
            "target": self.binding.target,
            "candidate": basis.candidate_pin,
            "incumbent": basis.incumbent_pin,
            "cases": cases,
            "metric_set": self.binding.config.metric_set,
            "answer": REFEREE_ANSWER,
        })
        .to_string())
    }
}

fn failed(reason: impl Into<String>) -> ResearchContinuationState {
    ResearchContinuationState::Failed {
        reason: reason.into(),
    }
}

/// A record door's refusal fails the continuation; any other error stops
/// the pass.
fn refused<T>(result: Result<T>, next: &mut ResearchContinuation) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Error::InvalidConfig(reason)) => {
            next.state = failed(reason);
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn settled(disposition: PromotionDisposition) -> ResearchContinuationState {
    let note = match disposition {
        PromotionDisposition::Promoted => "confirmed: promoted",
        PromotionDisposition::LostSealed => "confirmed: the sealed referee saw no strict win",
        PromotionDisposition::HeldInsufficient => {
            "confirmed: held, the card did not read not-worse"
        }
        PromotionDisposition::HeldGate => "confirmed: held at the skill gate",
    };
    ResearchContinuationState::Done {
        note: note.to_owned(),
    }
}

/// The engine estimator's information gain for the branch, under
/// ENGINE_ESTIMATOR_VERSION. CALLS: OF-351 host gain.
fn expected_gain_for(
    vault: &Vault,
    binding: &ResearchBinding,
    node: AttemptId,
    evidence: &SearchEvidence,
) -> Result<f64> {
    let txn = vault.store.env.read_txn()?;
    let mut nodes = nodes_in_txn(vault, &txn, binding.root)?;
    drop(txn);
    if let Some(row) = nodes.get_mut(node.as_bytes()) {
        row.search = Some(SearchEvidence {
            expected_gain: 0.0,
            ..evidence.clone()
        });
    }
    Ok(
        estimator::branch_beliefs(&nodes, binding.root, &binding.prior_ladder)
            .and_then(|beliefs| {
                beliefs
                    .get(node.as_bytes())
                    .map(|belief| belief.information_gain)
            })
            .filter(|gain| gain.is_finite())
            .map_or(0.0, |gain| gain.max(0.0)),
    )
}

/// What a finished run spent, at most its reservation: the metered tokens of
/// the spend scope it ran under.
fn run_spend_units(vault: &Vault, run: AttemptId, reserved: u64) -> Result<u64> {
    let dispatcher = AgentDispatcher::new(vault);
    let scope = match dispatcher.spend_scope_for_attempt(run)? {
        Some(id) => dispatcher.read_spend_scope(&id)?,
        None => None,
    };
    Ok(match scope {
        Some(scope) if scope.unit == LeaseUnit::tokens() => scope.spent_units.min(reserved),
        // FIX: a run under an unmetered campaign root, or in a non-token
        // unit, reports no token spend; it settles the whole reservation
        // until the research dispatch opens a token spend scope for its runs.
        _ => reserved,
    })
}

/// The text of a finished agent run's answer: the observation its result
/// TURN names (`attach_resident_run_result`), read from the run's own rows.
/// `None` when the run left no answer.
fn run_answer_text(vault: &Vault, record: &AttemptRecord) -> Result<Option<String>> {
    let Some(turn) = record
        .result_ref
        .as_ref()
        .and_then(|result| EntityId::from_hex(result.as_str()).ok())
    else {
        return Ok(None);
    };
    let Some(bytes) = vault.get(&turn)? else {
        return Ok(None);
    };
    let Ok(artifact) = rmpv::decode::read_value(&mut bytes.as_slice()) else {
        return Ok(None);
    };
    if field(&artifact, "kind").and_then(rmpv::Value::as_str) != Some("resident.run_result") {
        return Ok(None);
    }
    let run = field(&artifact, "run_ref")
        .and_then(rmpv::Value::as_str)
        .and_then(|run| EntityId::from_hex(run).ok());
    let handle = field(&artifact, "answer")
        .and_then(|answer| field(answer, "handle"))
        .and_then(rmpv::Value::as_str);
    let (Some(run), Some(handle)) = (run, handle) else {
        return Ok(None);
    };
    let Some(replay) = vault.get_code_run_replay_record(&run)? else {
        return Ok(None);
    };
    let Some(output) = replay.outputs.iter().find(|output| output.handle == handle) else {
        return Ok(None);
    };
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .code_run_result_body_in_txn(&txn, output)?
        .map(|body| String::from_utf8_lossy(&body).into_owned()))
}

fn field<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// The one JSON object in an answer: its first `{` to its last `}`.
fn answer_object<T: DeserializeOwned>(text: &str) -> Option<T> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    serde_json::from_str(text.get(start..=end)?).ok()
}

/// The staged skill proposal a skill candidate names: `skill_proposal:<32 hex>`.
fn proposal_of(candidate: &CandidateRef) -> Option<EntityId> {
    let id = candidate.config_ref.strip_prefix("skill_proposal:")?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    EntityId::from_hex(id).ok()
}
