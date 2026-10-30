//! Load-door routing: the version an attempt loads, and the slice charge it reserves.
//! Entry function: `route_in_txn`.
//! Trial, route and slice rows and their tables remain defined in `super`.

use super::overrun_ask::take_answer_in_txn;
use super::*;

/// The proposal a routed attempt loads in place of the incumbent.
pub(crate) struct TrialLoad {
    pub(crate) entity: EntityId,
    pub(crate) record: SkillRecord,
    pub(crate) source_files: Option<Vec<crate::skill_hub::HubFile>>,
}

/// What the load door does: load the proposal, and whether an over-slice
/// trial must ask its project's board once the door's transaction has
/// committed.
#[derive(Default)]
pub(crate) struct Routed {
    pub(crate) load: Option<TrialLoad>,
    pub(crate) ask: Option<EntityId>,
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
pub(super) fn lineage_route_in_txn(
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

/// Whether `project` is `goal_project` or sits below it through its
/// effective parents. A project the read fold does not serve, a parent that
/// does not parse, or a walk past the bound proves nothing.
fn within_project_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    goal_project: EntityId,
    project: EntityId,
) -> bool {
    let mut pending = VecDeque::from([project]);
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop_front() {
        if id == goal_project {
            return true;
        }
        // A diamond reaches one ancestor twice.
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > MAX_PROJECT_LINEAGE {
            return false;
        }
        let Ok(Some((_, effective))) = vault.effective_project_in_txn(txn, id) else {
            continue;
        };
        pending.extend(
            effective
                .parents
                .iter()
                .filter_map(|parent| EntityId::from_hex(parent).ok()),
        );
    }
    false
}

/// The whole attempt's launch estimate, when it is an agent dispatch for
/// `project` or a project below it whose estimate is a nonzero amount of
/// `unit`. `None` is no trial.
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
    let Some(charge) = input
        .launch
        .filter(|launch| launch.unit == *unit && launch.expected.units > 0)
        .map(|launch| launch.expected.units)
    else {
        return Ok(None);
    };
    Ok(input
        .project_ref
        .filter(|own| within_project_in_txn(vault, txn, project, *own))
        .map(|_| charge))
}

/// What the goal claim's slice says to one run's charge.
enum SliceAnswer {
    /// Inside the slice, or inside an approved overrun: the ledger to keep.
    Charge(SliceLedger),
    /// Past it: the trial now asks its project's board about this exact charge.
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
            // The board's yes covers this one run: the approved overrun
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
                    climbed_at: None,
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
pub(crate) fn route_in_txn(
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
    reserve_in_txn(vault, txn, attempt, &proposal, &trial, &ledger, charge, at)?;
    Ok(Routed {
        load: Some(load),
        ask: None,
    })
}

/// Keeps `attempt`'s charge on `proposal`'s trial: its route row, the
/// slice's ledger and the trial, in the load's transaction.
#[expect(
    clippy::too_many_arguments,
    reason = "the route row names the run, its arm, its trial, its ledger, its charge and its time"
)]
fn reserve_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    proposal: &EntityId,
    trial: &ExplorationTrial,
    ledger: &SliceLedger,
    charge: u64,
    at: u64,
) -> Result<()> {
    // An unmetered launch has no spend scope to settle: its estimate is its
    // final charge.
    let settled = crate::agent_dispatch::AgentDispatcher::new(vault)
        .attempt_spend_scope_in_txn(txn, attempt)?
        .is_none()
        .then_some(charge);
    ROUTES.put(
        &vault.store,
        txn,
        attempt.as_bytes(),
        &TrialRoute {
            proposal: *proposal,
            goal_claim: trial.goal_claim,
            unit: trial.unit.clone(),
            reserved: charge,
            settled,
            at,
        },
    )?;
    SLICES.put(&vault.store, txn, &trial.goal_claim, ledger)?;
    TRIALS.put(&vault.store, txn, proposal, trial)
}

/// Reserves the trial-slice charge of a load of `proposal` that a job
/// pinned as `incumbent`'s arm (FIX 10306): the job's first load was routed
/// to the proposal, and each run that loads the pinned arm again is charged
/// to the trial's slice as a routed run is, by its whole attempt's launch
/// estimate. Charge only: the pinned arm loads whatever this answers, and
/// the trial's routed count stays. A retry, or a later load in the same
/// attempt, was charged once already. A trial that no longer serves the
/// incumbent, binds another basis, or has closed charges nothing; so does a
/// run the slice does not count (no agent dispatch of the goal's project, no
/// estimate in its unit). Past the slice, the trial asks its board about
/// this exact charge, as it does for a routed run: the proposal is returned
/// for the caller to queue that ask once its transaction commits.
///
/// # Errors
///
/// An unreadable row, or storage errors.
pub(crate) fn charge_pinned_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    incumbent: &EntityId,
    proposal: &EntityId,
    at: u64,
) -> Result<Option<EntityId>> {
    if TARGETS.get(&vault.store, txn, incumbent)? != Some(*proposal) {
        return Ok(None);
    }
    let Some(mut trial) = TRIALS.get(&vault.store, txn, proposal)? else {
        return Ok(None);
    };
    if lineage_route_in_txn(vault, txn, attempt)?.is_some() {
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
    if take_answer_in_txn(vault, txn, &mut trial)? {
        TRIALS.put(&vault.store, txn, proposal, &trial)?;
    }
    match &trial.state {
        TrialState::Closed(_) => return Ok(None),
        TrialState::AskPending(pending) => {
            return Ok(pending.seq.is_none().then_some(*proposal));
        }
        TrialState::Open | TrialState::Approved { .. } => {}
    }
    let Some(charge) = dispatch_charge_in_txn(vault, txn, attempt, trial.project, &trial.unit)?
    else {
        return Ok(None);
    };
    let slice = basis.budget.exploration_slice;
    match slice_answer_in_txn(vault, txn, &mut trial, charge, slice)? {
        SliceAnswer::Charge(ledger) => {
            reserve_in_txn(vault, txn, attempt, proposal, &trial, &ledger, charge, at)?;
            Ok(None)
        }
        SliceAnswer::Ask => {
            TRIALS.put(&vault.store, txn, proposal, &trial)?;
            Ok(Some(*proposal))
        }
        SliceAnswer::Refuse => Ok(None),
    }
}
