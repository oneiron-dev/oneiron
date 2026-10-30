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
use std::ops::Bound::{Excluded, Unbounded};

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
    invalid, nodes_in_txn, promote_measured, promotion_basis, proposal_of, record_fork,
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
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::skill_optimize::{EvalRelease, SufficiencyInput};
use crate::{AttemptId, AttemptQueue, EntityId, Error, Result, Vault};

mod pass;

/// One unit of host work, keyed by root attempt then work: `0` the
/// bootstrap, `n + 1` selection round `n`.
const CONTINUATION: SideTable<([u8; 16], u64), ResearchContinuation, Named> =
    SideTable::new(&side_table::AUTORESEARCH_CONTINUATION);
/// The root the continuation sweep served last, for fair rotation. Key: ().
const CONTINUATION_CURSOR: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTORESEARCH_CONTINUATION_CURSOR);

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

/// The root the sweep served last, read from its cursor; `None` from the start.
fn cursor_after(cursor: &[u8]) -> Result<Option<[u8; 16]>> {
    if cursor.is_empty() {
        return Ok(None);
    }
    let key: [u8; 16] = cursor
        .try_into()
        .map_err(|_| crate::Error::CorruptedIndex("research continuation cursor"))?;
    Ok(Some(key))
}

/// One page of at most `limit` executed roots past `after`, or from the start,
/// each counted as read.
fn page_executed_roots_past(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: Option<&[u8; 16]>,
    limit: usize,
    count: &mut ScanCount,
) -> Result<Vec<AttemptId>> {
    let mut roots = Vec::new();
    for row in BINDING.iter_range(
        &vault.store,
        txn,
        after.map_or(Unbounded, Excluded),
        Unbounded,
    )? {
        let (_, binding) = row?;
        if binding.execution.is_none() {
            continue;
        }
        count.row();
        roots.push(binding.root);
        if roots.len() == limit {
            break;
        }
    }
    Ok(roots)
}

/// Whether the Coach attempt that started the pass may serve another root: its
/// queue row still exists, is still leased, and its lease never moved on.
fn coach_attempt_still_usable(
    vault: &Vault,
    coach_attempt: AttemptId,
    coach_lease: &Option<(Option<String>, u32)>,
) -> Result<bool> {
    let Some((owner, attempt_count)) = coach_lease else {
        return Ok(false);
    };
    let queue = AttemptQueue::new(vault);
    Ok(queue.get(coach_attempt)?.is_some_and(|record| {
        record.state == AttemptState::Leased
            && record.lease_owner == *owner
            && record.attempt_count == *attempt_count
    }))
}

/// The Coach host's pass: serve one rotating page of executed roots past the
/// persisted cursor, wrapping from the start once past the last, then advance
/// each served root's owed and live continuations until a run is still going,
/// it holds or it ends. Every inspected root moves the cursor, budget-held
/// ones included, so no funded campaign starves past the page. A refused
/// record door fails that continuation alone; a storage error stops the pass.
/// # Errors
/// Storage errors, or another pass advancing a continuation concurrently.
pub fn advance_research_continuations(
    vault: &Vault,
    coach_attempt: AttemptId,
    now: u64,
) -> Result<()> {
    let queue = AttemptQueue::new(vault);
    let coach_lease = queue.get(coach_attempt)?.and_then(|record| {
        (record.state == AttemptState::Leased).then(|| (record.lease_owner, record.attempt_count))
    });
    let txn = vault.store.env.read_txn()?;
    let after = cursor_after(
        &CONTINUATION_CURSOR
            .get(&vault.store, &txn, &())?
            .unwrap_or_default(),
    )?;
    let mut count = ScanCount::start(
        &vault.store,
        &txn,
        EngineScan::ResearchContinuationRoots,
        &[],
    )?;
    let mut roots =
        page_executed_roots_past(vault, &txn, after.as_ref(), MAX_ROOTS_PER_PASS, &mut count)?;
    if roots.is_empty() && after.is_some() {
        roots = page_executed_roots_past(vault, &txn, None, MAX_ROOTS_PER_PASS, &mut count)?;
    }
    drop(txn);
    count.finish(vault);
    let Some(last) = roots.last() else {
        return Ok(());
    };
    let last = last.as_bytes().to_vec();
    vault.with_write_txn_grouped(|txn| {
        CONTINUATION_CURSOR.put(&vault.store, txn, &(), &last)?;
        Ok(())
    })?;
    let mut served = 0;
    for root in roots {
        if !coach_attempt_still_usable(vault, coach_attempt, &coach_lease)? {
            break;
        }
        create_missing(vault, root, now)?;
        let Some(binding) = research_binding(vault, root)? else {
            continue;
        };
        let Some(execution) = &binding.execution else {
            continue;
        };
        let txn = vault.store.env.read_txn()?;
        let live: Vec<ResearchWork> = CONTINUATION
            .scan_from(&vault.store, &txn, root.as_bytes())?
            .into_iter()
            .filter(|(_, row)| row.state.live())
            .map(|(_, row)| row.work)
            .collect();
        drop(txn);
        for work in live {
            served += 1;
            Pass {
                vault,
                binding: &binding,
                execution,
                now,
            }
            .advance(work)?;
        }
    }
    tracing::debug!(
        coach_attempt = %hex(&coach_attempt),
        continuations = served,
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
    let incumbent = research_incumbent(vault, binding.root)?;
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
        estimator::branch_beliefs(&nodes, binding.root, incumbent, &binding.prior_ladder)
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
/// TURN names (`attach_agent_run_result`), read from the run's own rows.
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
    if field(&artifact, "kind").and_then(rmpv::Value::as_str) != Some("agent.run_result") {
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
