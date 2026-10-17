//! Exploration trials: an open optimizer proposal runs on live work as a
//! version choice for the active skill it revises (ARCH-0053: "Primary axes
//! are measured online."; ARCH-0076: "Trial cost is computed before the
//! trial runs. Inside the exploration budget on the goal record, the trial
//! runs itself. Over it, the loop asks.").
//!
//! ```text
//! Coach ─▶ offline preflight passed ─▶ trial opens (bound = host pull cap)
//! load door ─▶ requested ACTIVE incumbent whose proposal is on trial
//!        ├─ proposal still open on it, same bodies, same goal revision
//!        ├─ an agent-dispatch attempt of the goal's own project
//!        ├─ a launch estimate in the goal budget's unit
//!        ├─ inside the goal claim's slice ─▶ reserve, route, load the PROPOSAL
//!        └─ past it ─▶ the incumbent loads; the trial asks about that charge
//! spend scope settles ─▶ the reservation becomes what the run spent
//! bound reached · live report kept · verdict recorded ─▶ trial closes
//! ```
//!
//! The slice belongs to one goal claim: a goal revision is a new claim and a
//! fresh slice. A run's charge is its whole attempt's launch estimate,
//! reserved in the transaction that loads the proposal. An attempt with no
//! estimate, an estimate in another unit, no agent dispatch, or another
//! project loads the incumbent: never a free trial. Admission stays the
//! gate's; a trial only gathers the live runs the bandit slice measures.

use serde::{Deserialize, Serialize};

use super::SkillRecord;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason,
    HumanDecisionRequest, ProviderPin,
};
use crate::llm::run_admission::LeaseUnit;
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::{HeldOutReplayNotes, SkillEditTrialBasis};
use crate::{EntityId, Error, Result, Vault};

/// Each proposal's trial. Key: the proposal.
const TRIALS: SideTable<EntityId, ExplorationTrial, Named> =
    SideTable::new(&side_table::SKILL_EXPLORATION_TRIAL);
/// The proposal on trial for an incumbent. Key: the incumbent.
const TARGETS: SideTable<EntityId, EntityId, Named> =
    SideTable::new(&side_table::SKILL_EXPLORATION_TARGET);
/// Each routed attempt's charge. Key: the attempt.
const ROUTES: SideTable<[u8; 16], TrialRoute, Named> =
    SideTable::new(&side_table::SKILL_EXPLORATION_ROUTE);
/// Each goal claim's slice ledger. Key: the goal claim.
const SLICES: SideTable<EntityId, SliceLedger, Named> =
    SideTable::new(&side_table::SKILL_EXPLORATION_SLICE);

/// Retry lineages are walked to this depth, as the spend lease walks them.
const MAX_LINEAGE: usize = 1024;

/// The engine's own versioned queue identity for an overrun ask: the cost
/// comparison is deterministic, so no model read precedes it.
const OVERRUN_QUEUE: &str = "skill.exploration_slice";
const OVERRUN_QUEUE_VERSION: &str = "v1";

fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

/// Why a trial stopped routing live runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExplorationTrialClose {
    /// Its routed runs reached the host's live pull cap.
    BoundReached,
    /// The proposal's live goal-axis report was kept.
    ReportStored,
    /// The gate recorded a verdict on the proposal.
    VerdictRecorded,
    /// The owner declined a run past the goal's exploration slice.
    OverrunDeclined,
    /// An offline floor regressed on the held-out set.
    FloorsRegressed,
}

/// What the Coach does with a proposal's live slice on this wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExplorationTrialStatus {
    /// An offline floor regressed: no trial runs, and the gate rules on the
    /// failed preflight.
    FloorsRegressed,
    /// The trial routes live runs, or waits on its owner's answer.
    Waiting,
    /// The trial is closed: measure the live runs it routed.
    Measurable,
}

/// One ask about a run past the slice, for exactly the charge it would take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingOverrun {
    /// The run's launch estimate, in the trial's unit.
    charge: u64,
    /// The goal claim's slice, its charges and what was left of it (approved
    /// overruns included) when the ask was put.
    slice: u64,
    charged: u64,
    remaining: u64,
    /// The question version; each new charge is a new version.
    version: u32,
    /// The decision ask's arrival number, once queued.
    seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TrialState {
    Open,
    AskPending(PendingOverrun),
    /// The owner approved one run of up to `charge` past the slice.
    Approved {
        charge: u64,
    },
    Closed(ExplorationTrialClose),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplorationTrial {
    target: EntityId,
    project: EntityId,
    goal_claim: EntityId,
    goal_revision: String,
    proposal_digest: String,
    target_digest: String,
    /// The goal budget's unit when the trial bound its basis.
    unit: LeaseUnit,
    /// The host's live pull cap when the trial opened: the most attempts it
    /// routes to the proposal.
    exposure_bound: u32,
    routed: u32,
    /// The overrun question this trial asks under.
    question: EntityId,
    asks: u32,
    state: TrialState,
    opened_at: u64,
}

impl ExplorationTrial {
    fn binds(&self, basis: &SkillEditTrialBasis) -> bool {
        self.target == basis.target
            && self.proposal_digest == basis.proposal_digest
            && self.target_digest == basis.target_digest
            && self.goal_revision == basis.goal_revision
            && self.goal_claim == basis.goal_claim
            && self.unit == basis.budget.unit
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrialRoute {
    proposal: EntityId,
    goal_claim: EntityId,
    unit: LeaseUnit,
    /// The attempt's launch estimate, reserved when the proposal loaded.
    reserved: u64,
    /// What the attempt's spend scope settled at, once it did.
    settled: Option<u64>,
    at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SliceLedger {
    project: EntityId,
    unit: LeaseUnit,
    /// Each routed run's charge: its reservation, or what it spent once its
    /// scope settled.
    charged: u64,
    /// The overruns the owner approved past the slice, summed.
    approved_overrun: u64,
}

/// The proposal a routed attempt loads in place of the incumbent.
pub(super) struct TrialLoad {
    pub(super) entity: EntityId,
    pub(super) record: SkillRecord,
    pub(super) source_files: Option<Vec<crate::skill_hub::HubFile>>,
}

/// What the load door does: load the proposal, and whether an over-slice
/// trial must ask its owner once the door's transaction has committed.
#[derive(Default)]
pub(super) struct Routed {
    pub(super) load: Option<TrialLoad>,
    pub(super) ask: Option<EntityId>,
}

/// The proposal's load for a trial still bound to this snapshot: an open
/// optimizer proposal of exactly `incumbent`, the bodies and goal revision
/// the trial opened on, and the incumbent's interface. A gate read that fails
/// leaves the incumbent's own load untouched.
fn trial_load_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal: &EntityId,
    incumbent: &EntityId,
    current: &SkillRecord,
    trial: &ExplorationTrial,
) -> Result<Option<(TrialLoad, u64)>> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, proposal)?.is_live() {
        return Ok(None);
    }
    let Ok(Some(basis)) =
        crate::skill_optimize::skill_edit_trial_basis_in_txn(vault, txn, proposal)
    else {
        return Ok(None);
    };
    if basis.target != *incumbent || !trial.binds(&basis) {
        return Ok(None);
    }
    let record = basis.proposal;
    // A trial swaps the body, never the interface its caller loads.
    if record.role != current.role || record.call != current.call {
        return Ok(None);
    }
    let Ok(source_files) = vault
        .runtime_skill_package_in_txn(txn, proposal, &record)
        .map(|package| package.map(|package| package.files))
    else {
        return Ok(None);
    };
    let held = vault
        .runtime_skill_package_in_txn(txn, incumbent, current)?
        .map(|package| package.files);
    let covers = match (&held, &source_files) {
        (None, None) => true,
        (Some(held), Some(files)) => held
            .iter()
            .all(|file| files.iter().any(|own| own.path == file.path)),
        _ => false,
    };
    if !covers {
        return Ok(None);
    }
    Ok(Some((
        TrialLoad {
            entity: *proposal,
            record,
            source_files,
        },
        basis.budget.exploration_slice,
    )))
}

/// The route of `attempt`'s retry lineage, with the try it was put on.
fn lineage_route_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<(AttemptId, TrialRoute)>> {
    let queue = AttemptQueue::new(vault);
    let mut cursor = attempt;
    for _ in 0..MAX_LINEAGE {
        if let Some(route) = ROUTES.get(&vault.store, txn, cursor.as_bytes())? {
            return Ok(Some((cursor, route)));
        }
        match queue.get_in_txn(txn, cursor)?.and_then(|row| row.retry_of) {
            Some(previous) => cursor = previous,
            None => return Ok(None),
        }
    }
    Ok(None)
}

/// The whole attempt's launch estimate, when it is an agent dispatch for
/// `project` whose estimate is a nonzero amount of `unit`. `None` is no trial.
fn dispatch_charge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    project: EntityId,
    unit: &LeaseUnit,
) -> Result<Option<u64>> {
    let Some(record) = AttemptQueue::new(vault).get_in_txn(txn, attempt)? else {
        return Ok(None);
    };
    if record.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(None);
    }
    let Ok(payload) = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload) else {
        return Ok(None);
    };
    if payload.attempt_type != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(None);
    }
    let Ok(input) = crate::agent_dispatch::decode_agent_dispatch_input(&payload.input) else {
        return Ok(None);
    };
    if input.project_ref != Some(project) {
        return Ok(None);
    }
    Ok(input
        .launch
        .filter(|launch| launch.unit == *unit && launch.expected.units > 0)
        .map(|launch| launch.expected.units))
}

/// The trial state an owner's answer to an overrun ask leaves: a yes covers
/// one run of up to `charge` past the slice; anything else declines.
fn answered(charge: u64, answer: &DecisionAnswer) -> TrialState {
    match answer {
        DecisionAnswer::Noul(true) => TrialState::Approved { charge },
        _ => TrialState::Closed(ExplorationTrialClose::OverrunDeclined),
    }
}

/// Applies the owner's answer to the trial's queued overrun ask, once one is
/// given. `true` when the state moved.
fn take_answer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    trial: &mut ExplorationTrial,
) -> Result<bool> {
    let TrialState::AskPending(PendingOverrun {
        seq: Some(seq),
        charge,
        ..
    }) = trial.state
    else {
        return Ok(false);
    };
    let Some(answer) = vault
        .decision_ask_in_txn(txn, seq)?
        .and_then(|ask| ask.answer)
    else {
        return Ok(false);
    };
    trial.state = answered(charge, &answer.answer);
    Ok(true)
}

/// What the goal claim's slice says to one run's charge.
enum SliceAnswer {
    /// Inside the slice, or inside an approved overrun: the ledger to keep.
    Charge(SliceLedger),
    /// Past it: the trial now asks its owner about this exact charge.
    Ask,
    /// The ledger is another project's or unit's: no trial.
    Refuse,
}

fn slice_answer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    trial: &mut ExplorationTrial,
    charge: u64,
    slice: u64,
) -> Result<SliceAnswer> {
    let mut ledger = SLICES
        .get(&vault.store, txn, &trial.goal_claim)?
        .unwrap_or_else(|| SliceLedger {
            project: trial.project,
            unit: trial.unit.clone(),
            charged: 0,
            approved_overrun: 0,
        });
    if ledger.unit != trial.unit || ledger.project != trial.project {
        return Ok(SliceAnswer::Refuse);
    }
    let remaining = slice
        .saturating_add(ledger.approved_overrun)
        .saturating_sub(ledger.charged);
    if charge > remaining {
        match trial.state {
            // The owner's yes covers this one run: the approved overrun
            // joins the slice and is spent by it.
            TrialState::Approved { charge: approved } if charge <= approved => {
                ledger.approved_overrun =
                    ledger.approved_overrun.saturating_add(charge - remaining);
                trial.state = TrialState::Open;
            }
            _ => {
                trial.asks = trial
                    .asks
                    .checked_add(1)
                    .ok_or(Error::IndexOverflow("exploration trial ask version"))?;
                trial.state = TrialState::AskPending(PendingOverrun {
                    charge,
                    slice,
                    charged: ledger.charged,
                    remaining,
                    version: trial.asks,
                    seq: None,
                });
                return Ok(SliceAnswer::Ask);
            }
        }
    }
    ledger.charged = ledger.charged.saturating_add(charge);
    Ok(SliceAnswer::Charge(ledger))
}

/// What `attempt` loads when it asks for `incumbent`, chosen inside the load
/// door's write transaction. Without an open trial whose every condition
/// holds, the incumbent loads: the request was for it. A routed run's charge
/// is reserved here, so the load and its charge commit together.
pub(super) fn route_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    incumbent: &EntityId,
    current: &SkillRecord,
    at: u64,
) -> Result<Routed> {
    let Some(proposal) = TARGETS.get(&vault.store, txn, incumbent)? else {
        return Ok(Routed::default());
    };
    let Some(mut trial) = TRIALS.get(&vault.store, txn, &proposal)? else {
        return Ok(Routed::default());
    };
    let lineage = lineage_route_in_txn(vault, txn, attempt)?;
    if lineage.is_none() && matches!(trial.state, TrialState::Closed(_)) {
        return Ok(Routed::default());
    }
    let Some((load, slice)) = trial_load_in_txn(vault, txn, &proposal, incumbent, current, &trial)?
    else {
        return Ok(Routed::default());
    };
    // One launch is one trial run, and a run carries one trial: a retry, or
    // a later load in the same attempt, keeps the version its lineage loaded
    // and is not charged again, even once the trial has closed.
    if let Some((_, route)) = lineage {
        return Ok(if route.proposal == proposal {
            Routed {
                load: Some(load),
                ask: None,
            }
        } else {
            Routed::default()
        });
    }
    if take_answer_in_txn(vault, txn, &mut trial)? {
        TRIALS.put(&vault.store, txn, &proposal, &trial)?;
    }
    match &trial.state {
        TrialState::Closed(_) => return Ok(Routed::default()),
        // One question at a time: the open ask stands until it is answered.
        TrialState::AskPending(pending) => {
            return Ok(Routed {
                load: None,
                ask: pending.seq.is_none().then_some(proposal),
            });
        }
        TrialState::Open | TrialState::Approved { .. } => {}
    }
    if trial.routed >= trial.exposure_bound {
        trial.state = TrialState::Closed(ExplorationTrialClose::BoundReached);
        TRIALS.put(&vault.store, txn, &proposal, &trial)?;
        return Ok(Routed::default());
    }
    let Some(charge) = dispatch_charge_in_txn(vault, txn, attempt, trial.project, &trial.unit)?
    else {
        return Ok(Routed::default());
    };
    let ledger = match slice_answer_in_txn(vault, txn, &mut trial, charge, slice)? {
        SliceAnswer::Charge(ledger) => ledger,
        SliceAnswer::Ask => {
            TRIALS.put(&vault.store, txn, &proposal, &trial)?;
            return Ok(Routed {
                load: None,
                ask: Some(proposal),
            });
        }
        SliceAnswer::Refuse => return Ok(Routed::default()),
    };
    trial.routed += 1;
    if trial.routed >= trial.exposure_bound {
        trial.state = TrialState::Closed(ExplorationTrialClose::BoundReached);
    }
    ROUTES.put(
        &vault.store,
        txn,
        attempt.as_bytes(),
        &TrialRoute {
            proposal,
            goal_claim: trial.goal_claim,
            unit: trial.unit.clone(),
            reserved: charge,
            settled: None,
            at,
        },
    )?;
    SLICES.put(&vault.store, txn, &trial.goal_claim, &ledger)?;
    TRIALS.put(&vault.store, txn, &proposal, &trial)?;
    Ok(Routed {
        load: Some(load),
        ask: None,
    })
}

/// Settles the slice charge of a run a trial routed when `attempt`'s spend
/// scope settles: its reservation becomes what the run spent, when the scope
/// spends in the trial's unit. A run that never settles keeps its
/// reservation as its charge. No routed try in the lineage: nothing to do.
/// # Errors
/// An unreadable row, or storage errors.
pub(crate) fn settle_exploration_route_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    unit: &LeaseUnit,
    spent: u64,
) -> Result<()> {
    let Some((routed, mut route)) = lineage_route_in_txn(vault, txn, attempt)? else {
        return Ok(());
    };
    if route.settled.is_some() || route.unit != *unit {
        return Ok(());
    }
    if let Some(mut ledger) = SLICES.get(&vault.store, txn, &route.goal_claim)? {
        ledger.charged = ledger
            .charged
            .saturating_sub(route.reserved)
            .saturating_add(spent);
        SLICES.put(&vault.store, txn, &route.goal_claim, &ledger)?;
    }
    route.settled = Some(spent);
    ROUTES.put(&vault.store, txn, routed.as_bytes(), &route)
}

/// Stops `proposal`'s trial from routing more runs. Runs already routed keep
/// their charges and settle as usual. No trial: nothing to close.
/// # Errors
/// An unreadable row, or storage errors.
pub(crate) fn close_exploration_trial_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    proposal: &EntityId,
    reason: ExplorationTrialClose,
) -> Result<()> {
    let Some(mut trial) = TRIALS.get(&vault.store, txn, proposal)? else {
        return Ok(());
    };
    if matches!(trial.state, TrialState::Closed(_)) {
        return Ok(());
    }
    trial.state = TrialState::Closed(reason);
    TRIALS.put(&vault.store, txn, proposal, &trial)
}

/// Opens `proposal`'s trial on its passed preflight, or binds an unclosed
/// trial to its current basis. A new goal claim is a fresh slice, so an ask
/// about the old one lapses. `None`: the proposal is not trial-eligible in
/// this snapshot, its preflight no longer binds, or another proposal's trial
/// still serves the same incumbent.
fn open_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    proposal: &EntityId,
    exposure_bound: u32,
    at: u64,
) -> Result<Option<TrialState>> {
    let Some(basis) = crate::skill_optimize::skill_edit_trial_basis_in_txn(vault, txn, proposal)?
    else {
        return Ok(None);
    };
    if !crate::skill_optimize::skill_edit_preflight_passed_in_txn(vault, txn, proposal, &basis)? {
        return Ok(None);
    }
    if let Some(serving) = TARGETS.get(&vault.store, txn, &basis.target)?
        && serving != *proposal
        && TRIALS
            .get(&vault.store, txn, &serving)?
            .is_some_and(|other| !matches!(other.state, TrialState::Closed(_)))
    {
        return Ok(None);
    }
    let trial = match TRIALS.get(&vault.store, txn, proposal)? {
        Some(trial) if matches!(trial.state, TrialState::Closed(_)) => trial,
        Some(mut trial) => {
            if trial.goal_claim != basis.goal_claim {
                trial.state = TrialState::Open;
            }
            trial.target = basis.target;
            trial.project = basis.project;
            trial.goal_claim = basis.goal_claim;
            trial.goal_revision = basis.goal_revision;
            trial.proposal_digest = basis.proposal_digest;
            trial.target_digest = basis.target_digest;
            trial.unit = basis.budget.unit;
            trial
        }
        None => ExplorationTrial {
            target: basis.target,
            project: basis.project,
            goal_claim: basis.goal_claim,
            goal_revision: basis.goal_revision,
            proposal_digest: basis.proposal_digest,
            target_digest: basis.target_digest,
            unit: basis.budget.unit,
            exposure_bound,
            routed: 0,
            question: vault.store.clock.entity_id()?,
            asks: 0,
            state: TrialState::Open,
            opened_at: at,
        },
    };
    if !matches!(trial.state, TrialState::Closed(_)) {
        TARGETS.put(&vault.store, txn, &trial.target, proposal)?;
    }
    TRIALS.put(&vault.store, txn, proposal, &trial)?;
    Ok(Some(trial.state))
}

/// The owner's answer to a pending overrun ask, applied while the trial
/// still waits on that ask.
fn answer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    proposal: &EntityId,
    seq: u64,
    answer: &DecisionAnswer,
) -> Result<TrialState> {
    let Some(mut trial) = TRIALS.get(&vault.store, txn, proposal)? else {
        return Err(Error::EntityNotFound);
    };
    if let TrialState::AskPending(PendingOverrun {
        seq: Some(held),
        charge,
        ..
    }) = trial.state
        && held == seq
    {
        trial.state = answered(charge, answer);
        TRIALS.put(&vault.store, txn, proposal, &trial)?;
    }
    Ok(trial.state)
}

/// The versioned yes/no question about one overrun's exact charge.
fn overrun_request(
    proposal: &EntityId,
    record: &SkillRecord,
    trial: &ExplorationTrial,
    pending: &PendingOverrun,
) -> HumanDecisionRequest {
    let unit = trial.unit.as_str();
    let over = pending.charge.saturating_sub(pending.remaining);
    HumanDecisionRequest {
        question: DecisionQuestion {
            id: trial.question,
            version: pending.version,
            text: format!(
                "Run the trial of {}@{} (proposal {}) on one more live run, estimated at {} {unit}? \
                 Its project goal's exploration slice is {} {unit}, {} {unit} charged, {} {unit} \
                 left: this run passes it by {over} {unit}.",
                record.skill_id,
                record.version,
                proposal.to_hex(),
                pending.charge,
                pending.slice,
                pending.charged,
                pending.remaining,
            ),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        principal: trial.project,
        evidence: vec![*proposal, trial.target, trial.goal_claim],
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: OVERRUN_QUEUE.to_owned(),
            version: OVERRUN_QUEUE_VERSION.to_owned(),
        },
    }
}

/// Queues the owner ask of `proposal`'s pending overrun and keeps its
/// arrival number on the trial. Outside any write transaction: the queue
/// opens its own. An ask already queued, or no pending overrun: nothing.
/// # Errors
/// An unreadable row, an invalid question, or storage errors.
pub(super) fn queue_trial_ask(vault: &Vault, proposal: &EntityId) -> Result<()> {
    let trial = {
        let txn = vault.store.env.read_txn()?;
        TRIALS.get(&vault.store, &txn, proposal)?
    };
    let Some(trial) = trial else {
        return Ok(());
    };
    let TrialState::AskPending(pending) = &trial.state else {
        return Ok(());
    };
    if pending.seq.is_some() {
        return Ok(());
    }
    let record = vault
        .get_skill_record(proposal)?
        .ok_or(Error::EntityNotFound)?;
    let seq = vault.queue_decision_ask(&overrun_request(proposal, &record, &trial, pending))?;
    vault.with_write_txn_grouped(|txn| {
        let Some(mut now) = TRIALS.get(&vault.store, txn, proposal)? else {
            return Ok(());
        };
        let unqueued = matches!(
            &now.state,
            TrialState::AskPending(held) if held.version == pending.version && held.seq.is_none()
        );
        if unqueued {
            if let TrialState::AskPending(held) = &mut now.state {
                held.seq = Some(seq);
            }
            TRIALS.put(&vault.store, txn, proposal, &now)?;
        }
        Ok(())
    })
}

/// The Coach's step for an open proposal whose project goal waits on a live
/// report. A trial still bound to both bodies and the goal keeps running on
/// the preflight it opened on, since its own runs move the reserved evidence.
/// Otherwise the offline floors are judged first: a regressing floor closes
/// any trial and leaves the ruling to the gate; a passed preflight opens or
/// rebinds the trial with `exposure_bound`, the host's live pull cap. A
/// pending overrun ask is queued, or its answer applied.
/// # Errors
/// A zero cap, an unreadable proposal, goal or row, preflight and scorer
/// errors, or storage errors.
pub(crate) fn drive_exploration_trial(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayNotes,
    exposure_bound: u32,
    at: u64,
) -> Result<ExplorationTrialStatus> {
    if exposure_bound == 0 {
        return Err(invalid(
            "an exploration trial needs the host's live pull cap",
        ));
    }
    let (trial, basis) = {
        let txn = vault.store.env.read_txn()?;
        (
            TRIALS.get(&vault.store, &txn, proposal)?,
            crate::skill_optimize::skill_edit_trial_basis_in_txn(vault, &txn, proposal)?,
        )
    };
    // A stale target or an unjoined goal is the gate's to rule on.
    let Some(basis) = basis else {
        return Ok(ExplorationTrialStatus::Waiting);
    };
    let state = match trial.filter(|trial| trial.binds(&basis)) {
        Some(trial) => trial.state,
        None => {
            let preflight = crate::skill_optimize::preflight_skill_edit_offline_floors(
                vault, proposal, scorer,
            )?;
            if !preflight.passed {
                vault.with_write_txn_grouped(|txn| {
                    close_exploration_trial_in_txn(
                        vault,
                        txn,
                        proposal,
                        ExplorationTrialClose::FloorsRegressed,
                    )
                })?;
                return Ok(ExplorationTrialStatus::FloorsRegressed);
            }
            let opened = vault.with_write_txn_grouped(|txn| {
                open_in_txn(vault, txn, proposal, exposure_bound, at)
            })?;
            let Some(state) = opened else {
                return Ok(ExplorationTrialStatus::Waiting);
            };
            state
        }
    };
    let state = match state {
        TrialState::AskPending(PendingOverrun { seq: None, .. }) => {
            queue_trial_ask(vault, proposal)?;
            return Ok(ExplorationTrialStatus::Waiting);
        }
        TrialState::AskPending(PendingOverrun { seq: Some(seq), .. }) => {
            let Some(answer) = vault.decision_ask(seq)?.and_then(|ask| ask.answer) else {
                return Ok(ExplorationTrialStatus::Waiting);
            };
            vault.with_write_txn_grouped(|txn| {
                answer_in_txn(vault, txn, proposal, seq, &answer.answer)
            })?
        }
        state => state,
    };
    Ok(match state {
        TrialState::Closed(ExplorationTrialClose::FloorsRegressed) => {
            ExplorationTrialStatus::FloorsRegressed
        }
        TrialState::Closed(_) => ExplorationTrialStatus::Measurable,
        TrialState::Open | TrialState::AskPending(_) | TrialState::Approved { .. } => {
            ExplorationTrialStatus::Waiting
        }
    })
}
