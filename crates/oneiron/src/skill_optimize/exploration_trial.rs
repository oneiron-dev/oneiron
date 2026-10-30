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
//!        ├─ an agent-dispatch attempt of the goal's project or one below it
//!        ├─ a launch estimate in the goal budget's unit
//!        ├─ inside the goal claim's slice ─▶ reserve, route, load the PROPOSAL
//!        └─ past it ─▶ the incumbent loads; the trial asks about that charge
//! pinned load of the proposal ─▶ the same charge, reserved; the pinned arm loads
//! spend scope settles ─▶ the reservation becomes what the run spent
//! unmetered launch ─▶ the estimate is the run's final charge at its route
//! bound reached · live report kept · verdict recorded ─▶ trial closes
//! ```
//!
//! The slice belongs to one goal claim: a goal revision is a new claim and a
//! fresh slice. A run's charge is its whole attempt's launch estimate,
//! reserved in the transaction that loads the proposal. An attempt with no
//! estimate, an estimate in another unit, no agent dispatch, or a project
//! outside the goal's loads the incumbent: never a free trial. A run in a
//! project below the goal's (through any of its parents) is the goal's work
//! and charges the goal's slice, even when that project has a goal of its
//! own: the skill joined this goal, and the trial was bound to it. Admission
//! stays the gate's; a trial only gathers the live runs the bandit slice
//! measures.

use std::collections::{BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::llm::decision::{
    AnswerContract, AskAct, AskAnswer, AskRole, AskTo, DecisionAnswer, DecisionClass,
    DecisionQuestion, DecisionRung, HumanAskReason, HumanDecisionRequest, ProviderPin, RoleRank,
};
use crate::llm::run_admission::LeaseUnit;
use crate::side_table::{self, Named, SideTable};
use crate::skill::SkillRecord;
use crate::skill_optimize::{HeldOutReplayNotes, SkillEditTrialBasis};
use crate::{EntityId, Error, Result, Vault};

mod overrun_ask;
mod routing;

use self::overrun_ask::{answer_in_txn, climb_stale_ask};
use self::routing::lineage_route_in_txn;

pub(crate) use self::overrun_ask::queue_trial_ask;
pub(crate) use self::routing::{charge_pinned_in_txn, route_in_txn};

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
/// A run's project is walked up to the goal's through at most this many
/// distinct projects, as the project lineage walk bounds it.
const MAX_PROJECT_LINEAGE: usize = 256;

/// Hours an unanswered overrun ask waits on the role it went to before it
/// climbs to the next role up its chain: the ask's reminder. At the chain's
/// top it waits on, until [`EXPLORATION_ASK_LAPSE_HOURS`].
pub(crate) const EXPLORATION_ASK_CLIMB_HOURS: crate::learning_setting::SettingSpec =
    crate::learning_setting::SettingSpec {
        key: "exploration.ask.climb_hours",
        min: 1.0,
        max: 720.0,
        seed: 24.0,
    };

/// Hours an unanswered overrun ask waits at the top of its chain, counted
/// from its last climb, before it lapses as a decline: the trial closes and
/// its routed runs are measured. Checked once the climb window has passed too.
pub(crate) const EXPLORATION_ASK_LAPSE_HOURS: crate::learning_setting::SettingSpec =
    crate::learning_setting::SettingSpec {
        key: "exploration.ask.lapse_hours",
        min: 1.0,
        max: 2160.0,
        seed: 72.0,
    };

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
    /// The board declined a run past the goal's exploration slice.
    OverrunDeclined,
    /// The overrun ask went unanswered at the top of its chain for
    /// [`EXPLORATION_ASK_LAPSE_HOURS`].
    OverrunLapsed,
    /// An offline floor regressed on the held-out set.
    FloorsRegressed,
}

/// What the Coach does with a proposal's live slice on this wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExplorationTrialStatus {
    /// An offline floor regressed: no trial runs, and the gate rules on the
    /// failed preflight.
    FloorsRegressed,
    /// The trial routes live runs, or waits on its board's answer.
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
    /// When the ask last climbed, unix seconds; its next climb counts from
    /// here, else from when it was asked.
    #[serde(default)]
    climbed_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TrialState {
    Open,
    AskPending(PendingOverrun),
    /// The board approved one run of up to `charge` past the slice.
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
    /// The run's final charge: what its spend scope settled at, once it did,
    /// or its launch estimate from the route on when it launched unmetered.
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
    /// The overruns the board approved past the slice, summed.
    approved_overrun: u64,
}

/// Settles the slice charge of a run a trial routed when `attempt`'s spend
/// scope settles: its reservation becomes what the run spent, when the scope
/// spends in the trial's unit. A run that never settles keeps its
/// reservation as its charge; an unmetered run's was final at its route.
/// No routed try in the lineage: nothing to do.
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
        TrialState::AskPending(PendingOverrun {
            seq: Some(seq),
            climbed_at,
            ..
        }) => {
            let Some(ask) = vault.decision_ask(seq)? else {
                return Ok(ExplorationTrialStatus::Waiting);
            };
            let Some(answer) = ask.answer else {
                let since = climbed_at.unwrap_or(ask.asked_at);
                return Ok(if climb_stale_ask(vault, proposal, seq, since, at)? {
                    ExplorationTrialStatus::Measurable
                } else {
                    ExplorationTrialStatus::Waiting
                });
            };
            let state = vault
                .with_write_txn_grouped(|txn| answer_in_txn(vault, txn, proposal, seq, &answer))?;
            if let TrialState::AskPending(PendingOverrun { seq: None, .. }) = state {
                queue_trial_ask(vault, proposal)?;
            }
            state
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
