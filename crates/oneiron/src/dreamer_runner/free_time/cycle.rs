//! A free-time cycle (FIX 4453): its owner-set clock, its opening on the
//! elected home, and its end.
//!
//! A cycle opens once per owner-set boundary, one local time a day in the
//! policy's IANA zone ("daily" and "nightly" name the same clock). A missed
//! boundary is not caught up: a home back after days opens one cycle, for
//! the latest boundary, with one allowance. A spring-forward gap skips that
//! date's boundary; a fall-back fold takes its earlier instant, as the
//! calendar border does. Each cycle's root spend scope holds the owner's
//! total under the cap the owner was shown and accepted when setting the
//! policy; the scheduler never claims a showing of its own, and a restore or
//! a resume mints no fresh allowance (the clock is live).
//!
//! A cycle ends at its next boundary, when the owner clears the policy, or
//! once every item has its receipt. An ended cycle admits no new item; a
//! call already made settles normally.

use chrono::Datelike;
use serde::{Deserialize, Serialize};

use super::items::FreeTimeItemBinding;
use super::policy::{FreeTimePolicy, FreeTimeSchedule, FreeTimeSplit, effective_policy};
use super::{CLOCK, CYCLE, FreeTimeClock, FreeTimeKind, ITEM, POLICY};
use crate::agent_dispatch::{AgentDispatcher, ChildSpend, SpendScopeId};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND, DREAMER_RESIDENT_DREAM_ATTEMPT_KIND,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use crate::{EntityId, Error, Result, Vault};

/// How many local dates a boundary search walks: a skipped date (a gap)
/// and the date on either side.
const BOUNDARY_SEARCH_DAYS: usize = 4;

/// Whether a cycle still admits its items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimeCycleState {
    Open,
    /// Ended: no new item runs; calls already made settle normally.
    Closed,
}

/// What the agent chose for its own time, in its free time for its human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimeOwnTimeChoice {
    /// Its own dreaming.
    Reflect,
    /// Rest: no call, no spend, no text. It meets the floor.
    Rest,
}

/// One item a cycle opened with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeItemRef {
    pub item: EntityId,
    pub kind: FreeTimeKind,
    /// The attempt that runs it; `None` for an own-time item of a resident
    /// whose dreaming is off, which only rest can end.
    pub attempt: Option<[u8; 16]>,
}

/// The agent's short note to its human on what it got up to. Only the
/// resident writes it, in its item's own result; never its diary, never a
/// stored response, never the engine's words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeNote {
    pub author: EntityId,
    /// Vault clock seconds.
    pub at: u64,
    pub text: String,
}

/// One free-time cycle of one agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeCycle {
    pub agent: EntityId,
    /// Derived from the agent and the boundary: one cycle per boundary.
    pub cycle: EntityId,
    /// The policy revision it opened under, and that policy's total and
    /// split as they stood.
    pub policy_revision: u64,
    pub total_units: u64,
    pub pinned_split: Option<FreeTimeSplit>,
    /// The boundary before this one (Unix seconds), from which its records
    /// are read; 0 when none was found.
    pub period_start: u64,
    /// The owner-set boundary it opened at (Unix seconds).
    pub boundary: u64,
    /// The next boundary, at which it ends at the latest.
    pub next_boundary: Option<u64>,
    pub opened_at: u64,
    pub closed_at: Option<u64>,
    pub state: FreeTimeCycleState,
    /// The root spend scope holding the owner's total.
    pub root_scope: SpendScopeId,
    pub items: Vec<FreeTimeItemRef>,
    pub owner_note: Option<FreeTimeNote>,
    pub own_time_choice: Option<FreeTimeOwnTimeChoice>,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("free-time cycle: {reason}"))
}

/// The local date `at` falls on in the schedule's zone.
fn local_date(schedule: &FreeTimeSchedule, at: u64) -> Result<chrono::NaiveDate> {
    let wall = crate::calendar::utc_to_wall(at, &schedule.zone)
        .map_err(|_| invalid("the clock reads no local date in its zone"))?;
    chrono::NaiveDate::from_ymd_opt(wall.y, u32::from(wall.mo), u32::from(wall.d))
        .ok_or_else(|| invalid("the local date is not a date"))
}

/// The schedule's boundary on local `date`, in Unix seconds; `None` when its
/// time falls in that date's spring-forward gap.
fn boundary_on(schedule: &FreeTimeSchedule, date: chrono::NaiveDate) -> Result<Option<u64>> {
    let wall = crate::calendar::WallTime {
        y: date.year(),
        mo: u8::try_from(date.month()).map_err(|_| invalid("the month is not a month"))?,
        d: u8::try_from(date.day()).map_err(|_| invalid("the day is not a day"))?,
        h: schedule.hour,
        mi: schedule.minute,
        s: 0,
    };
    match crate::calendar::wall_to_utc(&wall, &schedule.zone) {
        Ok(at) => Ok(Some(at)),
        Err(crate::calendar::CalendarError::NonexistentWallTime { .. }) => Ok(None),
        Err(_) => Err(invalid("the schedule does not convert in its zone")),
    }
}

/// The latest boundary at or before `now`.
pub(super) fn boundary_at_or_before(schedule: &FreeTimeSchedule, now: u64) -> Result<Option<u64>> {
    let mut date = local_date(schedule, now)?;
    for _ in 0..BOUNDARY_SEARCH_DAYS {
        if let Some(at) = boundary_on(schedule, date)?
            && at <= now
        {
            return Ok(Some(at));
        }
        let Some(previous) = date.pred_opt() else {
            return Ok(None);
        };
        date = previous;
    }
    Ok(None)
}

/// The first boundary after `after`.
fn boundary_after(schedule: &FreeTimeSchedule, after: u64) -> Result<Option<u64>> {
    let mut date = local_date(schedule, after)?;
    for _ in 0..BOUNDARY_SEARCH_DAYS {
        if let Some(at) = boundary_on(schedule, date)?
            && at > after
        {
            return Ok(Some(at));
        }
        let Some(next) = date.succ_opt() else {
            return Ok(None);
        };
        date = next;
    }
    Ok(None)
}

/// The boundary a policy's next cycle must pass: the last one this node
/// opened or passed, and never one at or before the owner set the policy.
fn due_floor(clock: Option<FreeTimeClock>, policy: &FreeTimePolicy) -> u64 {
    clock
        .map_or(0, |clock| clock.last_boundary)
        .max(policy.set_at)
}

/// The cycle id of `agent`'s cycle at `boundary`.
fn cycle_id(agent: EntityId, boundary: u64) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(
        b"oneiron:free_time:cycle:v1",
        &[
            agent.as_bytes().as_slice(),
            boundary.to_be_bytes().as_slice(),
        ],
    )
}

/// The id of a cycle's item of `kind`: the same for every try of it.
fn item_id(cycle: EntityId, kind: FreeTimeKind) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(
        b"oneiron:free_time:item:v1",
        &[cycle.as_bytes().as_slice(), [kind.code()].as_slice()],
    )
}

/// What one due boundary came to.
enum Opened {
    Cycle,
    /// The boundary passed with no cycle: the agent is off or gone, or the
    /// boundary was already taken.
    Passed,
    /// This node is not the vault's elected home: nothing opens here.
    NotHome,
}

impl Vault {
    /// The next owner-set free-time boundary any policy waits on, in Unix
    /// seconds (FIX 4453). The home's timer arms on it, and the Timer pass
    /// it wakes opens the cycle. `None` when no agent has a policy.
    ///
    /// # Errors
    /// A store read that fails or a row that does not decode.
    pub fn next_free_time_due_at(&self) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        let mut next: Option<u64> = None;
        for row in POLICY.iter_from(&self.store, &txn, &[])? {
            let (agent, record) = row?;
            // A cleared policy's row is only its witness (FIX 5661).
            let Some(policy) = record.policy else {
                continue;
            };
            let floor = due_floor(CLOCK.get(&self.store, &txn, &agent)?, &policy);
            if let Some(at) = boundary_after(&policy.schedule, floor)? {
                next = Some(next.map_or(at, |next| next.min(at)));
            }
        }
        Ok(next)
    }

    /// Opens each free-time cycle whose owner-set boundary has come by
    /// `now` (FIX 4453), on the elected home only: `local_node_id` must be
    /// this vault's node and its MACRO home, or nothing opens. Each cycle
    /// opens in its own commit, with its root spend scope and its items. A
    /// boundary that cannot open is passed and logged, never retried in a
    /// loop. Returns how many opened.
    ///
    /// On a new home, a home move's carried state adopted before this pass
    /// (FIX 5661, `handoff`) is what it reads: the carried clock is the due
    /// floor and the carried cycle takes its boundary, so the home opens no
    /// fresh cycle and no second allowance for it, while a later boundary
    /// still ends it. Each opening writer reads both again, so an adoption
    /// that lands after the scan is kept too. With no carried state, or an
    /// incomplete one, the home opens as before.
    ///
    /// # Errors
    /// A store read or write that fails.
    pub fn enqueue_due_free_time_cycles(&self, now: u64, local_node_id: u64) -> Result<usize> {
        let due = {
            let txn = self.store.env.read_txn()?;
            let mut due = Vec::new();
            for row in POLICY.iter_from(&self.store, &txn, &[])? {
                let (agent, record) = row?;
                let Some(policy) = record.policy else {
                    continue;
                };
                let floor = due_floor(CLOCK.get(&self.store, &txn, &agent)?, &policy);
                if let Some(boundary) = boundary_at_or_before(&policy.schedule, now)?
                    && boundary > floor
                {
                    due.push((agent, boundary));
                }
            }
            due
        };
        let mut opened = 0;
        let mut moved = false;
        for (agent, boundary) in due {
            match self.with_write_txn_grouped(|txn| {
                open_cycle_in_txn(self, txn, agent, boundary, now, local_node_id)
            }) {
                Ok(Opened::Cycle) => opened += 1,
                Ok(Opened::Passed) => {}
                Ok(Opened::NotHome) => break,
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        agent = %agent.to_hex(),
                        "a free-time cycle did not open; its boundary is passed"
                    );
                    self.with_write_txn_grouped(|txn| {
                        pass_boundary_in_txn(self, txn, agent, boundary)
                    })?;
                }
            }
            moved = true;
        }
        if opened > 0 {
            self.store.notify_attempt_observers();
        }
        // The home's timer re-reads the next boundary each clock waits on.
        if moved {
            self.store.notify_proactivity_changes();
        }
        Ok(opened)
    }
}

/// Whether this node is the vault's own node and its elected MACRO home.
fn home_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, local_node_id: u64) -> Result<bool> {
    if local_node_id == 0
        || crate::identity::load_or_mint_client_id_in_txn(vault, txn)? != local_node_id
    {
        return Ok(false);
    }
    Ok(DreamerRunnerStore::new(vault)
        .home_node_designation_in_txn(txn)?
        .is_some_and(|home| home.node_id == local_node_id))
}

/// Marks `boundary` taken for `agent` with no cycle opened.
fn pass_boundary_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    agent: EntityId,
    boundary: u64,
) -> Result<()> {
    let mut clock = CLOCK.get(&vault.store, txn, &agent)?.unwrap_or_default();
    clock.last_boundary = clock.last_boundary.max(boundary);
    CLOCK.put(&vault.store, txn, &agent, &clock)
}

fn open_cycle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    agent: EntityId,
    boundary: u64,
    now: u64,
    local_node_id: u64,
) -> Result<Opened> {
    if !home_in_txn(vault, txn, local_node_id)? {
        return Ok(Opened::NotHome);
    }
    let Some(policy) = effective_policy(
        POLICY
            .get(&vault.store, txn, &agent)?
            .and_then(|record| record.policy),
    ) else {
        return Ok(Opened::Passed);
    };
    if boundary <= due_floor(CLOCK.get(&vault.store, txn, &agent)?, &policy) {
        return Ok(Opened::Passed);
    }
    // The cycle before ends at this boundary: it admits no new item, and
    // calls it already made settle normally.
    close_open_cycle_in_txn(vault, txn, agent, now)?;
    let dreams = match vault.read_agent_definition_in_txn(txn, &agent) {
        Ok(definition) if definition.enabled => {
            Some(definition.dreaming_mode() != crate::agent_def::DreamingMode::Off)
        }
        Ok(_) | Err(Error::EntityNotFound) => None,
        Err(error) => return Err(error),
    };
    let opened = match dreams {
        Some(dreams) if !CYCLE.contains(&vault.store, txn, &(agent, boundary))? => {
            open_items_in_txn(vault, txn, &policy, boundary, now, dreams)?;
            true
        }
        // An agent that is off or gone opens no cycle; its boundary passes.
        _ => false,
    };
    CLOCK.put(
        &vault.store,
        txn,
        &agent,
        &FreeTimeClock {
            last_boundary: boundary,
            open: opened.then_some(boundary),
        },
    )?;
    Ok(if opened {
        Opened::Cycle
    } else {
        Opened::Passed
    })
}

/// Opens `policy`'s cycle at `boundary`: its root scope under the owner's
/// total and saved say-so, its two items, and its row.
fn open_items_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    policy: &FreeTimePolicy,
    boundary: u64,
    now: u64,
    dreams: bool,
) -> Result<()> {
    let agent = policy.agent;
    let cycle = cycle_id(agent, boundary)?;
    let root_scope = SpendScopeId::launch(format!("free_time:{}", cycle.to_hex()))?;
    // The standing-policy start: the owner's total, under the cap the owner
    // was shown and accepted when setting the policy. Never a showing the
    // scheduler claims now, and JobMaximum's start rule still runs.
    AgentDispatcher::new(vault).open_root_spend_scope_in_txn(
        txn,
        root_scope.clone(),
        DeclaredMaximum {
            units: policy.total_units,
            unit: LeaseUnit::tokens(),
        },
        Some(MaximumShown {
            at_ms: policy.cap_shown_at_ms,
        }),
        now,
    )?;
    let mut opened = FreeTimeCycle {
        agent,
        cycle,
        policy_revision: policy.revision,
        total_units: policy.total_units,
        pinned_split: policy.pinned_split,
        period_start: boundary_at_or_before(&policy.schedule, boundary.saturating_sub(1))?
            .unwrap_or(0),
        boundary,
        next_boundary: boundary_after(&policy.schedule, boundary)?,
        opened_at: now,
        closed_at: None,
        state: FreeTimeCycleState::Open,
        root_scope,
        items: Vec::new(),
        owner_note: None,
        own_time_choice: None,
    };
    for kind in [FreeTimeKind::ForHuman, FreeTimeKind::OwnTime] {
        let item = item_id(cycle, kind)?;
        // A resident whose dreaming is off has no dreaming to run as its own
        // time; only its choice of rest ends that item.
        let attempt = if kind == FreeTimeKind::OwnTime && !dreams {
            None
        } else {
            Some(*enqueue_item_in_txn(vault, txn, &opened, kind, item, now)?.as_bytes())
        };
        opened.items.push(FreeTimeItemRef {
            item,
            kind,
            attempt,
        });
    }
    CYCLE.put(&vault.store, txn, &(agent, boundary), &opened)
}

/// Queues one item of `cycle` under the resident's own stamp, reserves its
/// spend scope under the cycle's root and stamps its binding, in the
/// cycle's commit.
fn enqueue_item_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cycle: &FreeTimeCycle,
    kind: FreeTimeKind,
    item: EntityId,
    now: u64,
) -> Result<AttemptId> {
    let attempt = match DreamerRunnerStore::new(vault).enqueue_free_time_item_in_txn(
        txn,
        item_queue_kind(kind),
        cycle.agent,
        cycle.cycle,
        now,
    )? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
    };
    let dispatcher = AgentDispatcher::new(vault);
    if dispatcher
        .attempt_spend_scope_in_txn(txn, attempt)?
        .is_none()
    {
        // Each item draws on its cycle's root: its pinned share as a hard
        // carve, else a hold of nothing that tops up from the shared total
        // as it spends. No share is a minimum or a target.
        let ask = match (cycle.pinned_split, kind) {
            (Some(split), FreeTimeKind::ForHuman) => ChildSpend::Carve {
                cap_units: split.for_human_units,
            },
            (Some(split), FreeTimeKind::OwnTime) => ChildSpend::Carve {
                cap_units: split.own_time_units,
            },
            (None, _) => ChildSpend::Hold { expected_units: 0 },
        };
        dispatcher.reserve_child_in_txn(txn, &cycle.root_scope, &attempt, ask, now)?;
    }
    ITEM.put(
        &vault.store,
        txn,
        &attempt,
        &FreeTimeItemBinding {
            agent: cycle.agent,
            cycle: cycle.cycle,
            boundary: cycle.boundary,
            period_start: cycle.period_start,
            item,
            kind,
            policy_revision: cycle.policy_revision,
            attempt: *attempt.as_bytes(),
            spend_scope: SpendScopeId::for_attempt(&attempt),
        },
    )?;
    Ok(attempt)
}

/// The queue an item of `kind` waits in: the for-human queue, or the
/// resident's dreaming as its own time.
pub(super) fn item_queue_kind(kind: FreeTimeKind) -> &'static str {
    match kind {
        FreeTimeKind::ForHuman => DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND,
        FreeTimeKind::OwnTime => DREAMER_RESIDENT_DREAM_ATTEMPT_KIND,
    }
}

/// FIX 5661: queues again here an item a home move carried, whose try never
/// started on its old home: the same attempt id, kind and payload, under the
/// resident's stamp, beside its carried binding. Unlike a fresh opening
/// ([`enqueue_item_in_txn`]) it opens no root and reserves no scope: the
/// cycle's root and the item's own scope came carried, with the original
/// cap and what was spent and held. `false`: other work holds the item's
/// place here.
#[cfg(feature = "sync")]
pub(super) fn resume_item_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: &FreeTimeItemBinding,
    enqueued_at: u64,
) -> Result<bool> {
    let attempt = AttemptId::from_bytes(&binding.attempt)?;
    if !DreamerRunnerStore::new(vault).resume_free_time_item_in_txn(
        txn,
        item_queue_kind(binding.kind),
        binding.agent,
        binding.cycle,
        attempt,
        enqueued_at,
    )? {
        return Ok(false);
    }
    ITEM.put(&vault.store, txn, &attempt, binding)?;
    Ok(true)
}

/// FIX 5661: lands a cycle a home move carried, as its old home kept it:
/// its opening, its state, its note and its choice. The note is the agent's
/// own words, admitted at the side-row wall here too; a note the wall
/// refuses is dropped and the cycle lands.
#[cfg(feature = "sync")]
pub(super) fn put_carried_cycle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cycle: &FreeTimeCycle,
) -> Result<()> {
    let key = (cycle.agent, cycle.boundary);
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match CYCLE.put(&vault.store, &mut savepoint, &key, cycle) {
        Ok(()) => savepoint.commit()?,
        Err(error) => {
            drop(savepoint);
            tracing::warn!(
                kind = ?error.kind(),
                agent = %cycle.agent.to_hex(),
                "a carried free-time note was not admitted"
            );
            let mut cycle = cycle.clone();
            cycle.owner_note = None;
            CYCLE.put(&vault.store, txn, &key, &cycle)?;
        }
    }
    Ok(())
}

/// Ends `agent`'s open cycle, if any, at `now`.
pub(super) fn close_open_cycle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    agent: EntityId,
    now: u64,
) -> Result<()> {
    let Some(mut clock) = CLOCK.get(&vault.store, txn, &agent)? else {
        return Ok(());
    };
    let Some(open) = clock.open.take() else {
        return Ok(());
    };
    if let Some(mut cycle) = CYCLE.get(&vault.store, txn, &(agent, open))? {
        close_cycle_in_txn(vault, txn, &mut cycle, now)?;
    }
    CLOCK.put(&vault.store, txn, &agent, &clock)
}

/// Ends `cycle`: it admits no new item, and its root takes no new child.
/// Spend already made, and late spend, still lands on it whole.
pub(super) fn close_cycle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cycle: &mut FreeTimeCycle,
    now: u64,
) -> Result<()> {
    if cycle.state == FreeTimeCycleState::Closed {
        return Ok(());
    }
    cycle.state = FreeTimeCycleState::Closed;
    cycle.closed_at = Some(now);
    AgentDispatcher::new(vault).close_root_spend_scope_in_txn(txn, &cycle.root_scope, now)?;
    CYCLE.put(&vault.store, txn, &(cycle.agent, cycle.boundary), cycle)?;
    let Some(mut clock) = CLOCK.get(&vault.store, txn, &cycle.agent)? else {
        return Ok(());
    };
    if clock.open == Some(cycle.boundary) {
        clock.open = None;
        CLOCK.put(&vault.store, txn, &cycle.agent, &clock)?;
    }
    Ok(())
}
