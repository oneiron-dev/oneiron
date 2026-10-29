//! Row-backed wake admission. The host supplies liveness; the vault owns the decision.
use crate::Vault;
use crate::agent_def::{AgentDefinition, AgentWakeCadence};
use crate::claim::{ClaimLifecycleStatus, ClaimSource, decode_claim_body};
use crate::dreamer_runner::{
    DreamerRunnerStore, DreamerTurnRole, EnqueueDreamerAttemptOutcome, dreamer_turn_role,
};
use crate::error::{Error, Result};
use crate::ports::{ChangeLogStoreRead, EntityStoreRead, TombstoneStore};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::side_table::{self, LegacyJson, SideTable};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;

mod observation;
pub use observation::*;

const POLICY: SideTable<(), DreamerWakePolicy, LegacyJson> =
    SideTable::new(&side_table::DREAMER_WAKE_POLICY);
const STATE: SideTable<(), WakeState, LegacyJson> = SideTable::new(&side_table::DREAMER_WAKE_STATE);
const OUTBOX: SideTable<[u8; 1], WakePolicyTrigger, LegacyJson> =
    SideTable::new(&side_table::DREAMER_WAKE_RECIPE_INPUT);
const DEFAULT_POLICY: &str = include_str!("wake_policy_defaults.json");

fn invalid() -> Error {
    Error::InvalidConfig("invalid dreamer wake policy row".into())
}

/// Per-vault recipe dials. An owner may write a different v1 row; these are
/// data, not compiled thresholds. `new_records` excludes Generated claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerWakePolicy {
    pub wake_grain_turns: u64,
    /// Resident trigger table, missing-role rule and nested rate precedence.
    pub agent_cadence: AgentWakePolicy,
    /// New explicit CLAIMs plus user TURNs since the last weave.
    pub new_records: u64,
    pub longest_wait_secs: u64,
    pub nightly_secs: u64,
    /// Minimum inbound silence for any idle recipe to run.
    pub idle_secs: u64,
    /// Independent quiet-window trigger for Weave, even below accumulation.
    pub quiet_weave_secs: u64,
    /// Where the per-vault workflow skill competes with connector events.
    /// Cleanup and maintenance retain their protected priority; consolidation
    /// stays after these two lanes so its home-node stop cannot starve them.
    pub weave_recipe_priority: WeaveRecipePriority,
    /// The surprise floor, in thousandths (OF-138, ARCH-0036): a turn whose
    /// re-tag moved at least this far beside the set it replaced is a
    /// surprise signal for a resident's wake. The tagger measures the delta;
    /// a role's trigger table decides whether surprise may wake it.
    pub surprise_permille: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WeaveRecipePriority {
    BeforeConnectorEvent,
    AfterConnectorEvent,
}
/// Which role a definition without an explicit cadence dial receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentWakeRole {
    Companion,
    Leader,
    Worker,
}

/// The owner-selected cadence precedence. The shipped default lets an
/// agent's explicit interval override the vault grain (FIX 8727); an owner
/// who wants no agent woken more often than the vault picks the vault floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CadencePrecedence {
    VaultFloor,
    AgentOverride,
}

/// Which signal classes admit a wake for one role. Each bit is policy data,
/// not a hardcoded role switch in the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentWakeTriggers {
    pub cadence: bool,
    pub surprise: bool,
    pub agency: bool,
    pub event: bool,
}

/// Role table on the owner-editable wake-policy row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentWakePolicy {
    pub absent_role: AgentWakeRole,
    pub precedence: CadencePrecedence,
    pub companion: AgentWakeTriggers,
    pub leader: AgentWakeTriggers,
    pub worker: AgentWakeTriggers,
}

/// Trigger facts supplied to the engine scheduler; the policy selects which
/// facts a resident role may use. Cadence is derived, never caller asserted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentWakeSignals {
    pub surprise: bool,
    pub agency: bool,
    pub event: bool,
}

impl AgentWakePolicy {
    /// Resolve role, interval and trigger permissions under a single row.
    #[must_use]
    pub fn due(
        self,
        definition: &AgentDefinition,
        vault_grain: u64,
        ordinal: u64,
        signals: AgentWakeSignals,
    ) -> bool {
        if !definition.enabled || definition.dreaming_mode() == crate::agent_def::DreamingMode::Off
        {
            return false;
        }
        let (role, interval) = match definition.wake_cadence {
            Some(AgentWakeCadence::Companion { every_turns }) => {
                (AgentWakeRole::Companion, every_turns)
            }
            Some(AgentWakeCadence::Leader { every_turns }) => (AgentWakeRole::Leader, every_turns),
            Some(AgentWakeCadence::Worker) => (AgentWakeRole::Worker, None),
            None => (self.absent_role, None),
        };
        let triggers = match role {
            AgentWakeRole::Companion => self.companion,
            AgentWakeRole::Leader => self.leader,
            AgentWakeRole::Worker => self.worker,
        };
        let interval = match self.precedence {
            CadencePrecedence::VaultFloor => interval.unwrap_or(vault_grain).max(vault_grain),
            CadencePrecedence::AgentOverride => interval.unwrap_or(vault_grain),
        };
        (triggers.cadence && ordinal != 0 && interval != 0 && ordinal.is_multiple_of(interval))
            || (triggers.surprise && signals.surprise)
            || (triggers.agency && signals.agency)
            || (triggers.event && signals.event)
    }
}

impl DreamerWakePolicy {
    pub(crate) fn validate(self) -> Result<Self> {
        if self.wake_grain_turns == 0
            || self.new_records == 0
            || self.longest_wait_secs == 0
            || self.nightly_secs == 0
            || self.idle_secs == 0
            || self.quiet_weave_secs < self.idle_secs
            || self.surprise_permille > 1000
        {
            return Err(invalid());
        }
        Ok(self)
    }
}

/// Liveness is sampled by the host at the same instant as the policy check.
/// `last_inbound_at` is seconds on the vault clock. A running turn or live
/// background job cancels the quiet timer rather than merely postponing work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeIdleState {
    pub running_turns: bool,
    pub live_background_work: bool,
    /// False when the vault has no usable compute lease; idle must suspend.
    pub compute_available: bool,
    pub last_inbound_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum WakePolicyDecision {
    Silent,
    ArmIdle { due_at: u64 },
    Enqueue { recipe: WakeRecipe },
}

/// Which workflow recipe receives the durable wake signal. This is not a
/// consolidation scope: a policy trigger alone has no partition payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WakeRecipe {
    Continuous,
    Nightly,
    Weave,
}
impl WakeRecipe {
    const fn key(self) -> u8 {
        match self {
            Self::Continuous => 0,
            Self::Nightly => 1,
            Self::Weave => 2,
        }
    }
}

/// Durable recipe-input cursor range. The log identifies changed entities but
/// does not itself retain their content; recipe workers must resolve the
/// appropriate revision and provenance before acting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakePolicyTrigger {
    pub recipe: WakeRecipe,
    pub turn_count: u64,
    pub record_count: u64,
    pub nightly_count: u64,
    pub after_nightly: Option<[u8; 16]>,
    pub after_turn: Option<[u8; 16]>,
    pub after_record: Option<[u8; 16]>,
    pub through: [u8; 16],
    pub observed_at: u64,
    // The latest snapshot for each component is distinct from the EARLIEST
    // cursor above. A later wake can overlap this snapshot after another
    // recipe advanced its own cursor; compare to this segment, not the origin.
    latest_after_turn: Option<[u8; 16]>,
    latest_after_record: Option<[u8; 16]>,
    latest_after_nightly: Option<[u8; 16]>,
    latest_turn_count: u64,
    latest_record_count: u64,
    latest_nightly_count: u64,
}

/// Exclusive in-process timer ownership for one open vault. The private
/// constructor and Drop release make two live idle sleeps on that vault
/// impossible without process-global state.
pub struct WakePolicyTimerLease<'a> {
    vault: &'a Vault,
}
impl Drop for WakePolicyTimerLease<'_> {
    fn drop(&mut self) {
        self.vault
            .wake_policy_timer_owned
            .store(false, Ordering::Release);
    }
}

/// A policy check either enqueues a single attempt or returns the next quiet
/// deadline. The host can arm ONE cancellable sleep per vault for `ArmIdle`.
#[derive(Debug, Clone, PartialEq)]
pub struct WakePolicyOutcome {
    pub decision: WakePolicyDecision,
    pub attempt: Option<EnqueueDreamerAttemptOutcome>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WakeState {
    cadence: Option<WakeCadenceReceipt>,
    last_weave_at: Option<u64>,
    last_nightly_at: Option<u64>,
    // Each recipe consumes its own ordered prefix. Continuous turn wakes
    // must not erase accumulated explicit records waiting for a weave.
    turn_change_id: Option<[u8; 16]>,
    record_change_id: Option<[u8; 16]>,
    nightly_change_id: Option<[u8; 16]>,
    // A cached follower prefix. Each real event is decoded once per commit;
    // pending maps keep only eligible current rows since each recipe's cursor.
    processed_change_id: Option<[u8; 16]>,
    pending_turns: std::collections::BTreeMap<String, u64>,
    pending_records: std::collections::BTreeMap<String, u64>,
    pending_nightly: std::collections::BTreeMap<String, u64>,
    /// The curator's cadence slot the idle trigger last asked for (OF-191):
    /// an idle host asks once per slot, never again for a slot whose pass
    /// already ran.
    #[serde(default)]
    idle_curator_slot: Option<u64>,
}

fn row_error(error: Error, invalid_row: Error) -> Error {
    match error {
        Error::Store(crate::error::StoreError::SideTableRow { .. }) => invalid_row,
        other => other,
    }
}

pub(crate) fn policy_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<DreamerWakePolicy> {
    let policy = match POLICY
        .get(&vault.store, txn, &())
        .map_err(|e| row_error(e, invalid()))?
    {
        Some(row) => row,
        None => serde_json::from_str(DEFAULT_POLICY).map_err(|_| invalid())?,
    };
    policy.validate()
}
fn state_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<WakeState> {
    Ok(STATE
        .get(&vault.store, txn, &())
        .map_err(|e| row_error(e, invalid()))?
        .unwrap_or_default())
}

/// Read one snapshot of live rows. Full role/source validation happens before
/// counting; no caller-supplied counter can manufacture a wake. Both the
/// evaluation and enqueue call this under a single LMDB transaction.
struct WakeCounts {
    turns: u64,
    records: u64,
    nightly: u64,
    first: Option<u64>,
    first_nightly: Option<u64>,
    last: Option<[u8; 16]>,
}

fn count_new(vault: &Vault, txn: &heed::RoTxn<'_>, state: &mut WakeState) -> Result<WakeCounts> {
    let mut last = state.processed_change_id;
    let mut changed = std::collections::BTreeSet::new();
    for entry in vault
        .store
        .port_changelog_after(txn, state.processed_change_id)?
    {
        let (id, change) = entry.map_err(|error| match error {
            Error::Store(crate::error::StoreError::SideTableRow {
                problem: crate::error::SideTableRowProblem::KeyShape,
                ..
            }) => Error::CorruptedIndex("dreamer wake mutation cursor"),
            other => row_error(other, Error::CorruptedIndex("dreamer wake mutation row")),
        })?;
        if last.is_some_and(|last| id <= last) {
            return Err(Error::CorruptedIndex("dreamer wake mutation order"));
        }
        if change.id != id {
            return Err(Error::CorruptedIndex("dreamer wake mutation identity"));
        }
        last = Some(id);
        changed.insert(change.entity);
    }
    // Re-validate the current row under this SAME snapshot. A superseded or
    // deleted candidate must leave every pending queue; a Generated-to-explicit
    // rewrite has a new log id and enters it, even with an older learned_at.
    for id in changed {
        let key = id.to_hex();
        let row = vault.store.port_entity_record(txn, &id)?;
        let row = match row {
            Some(row) if !vault.port_tombstone_is_deleted(txn, &id)? => Some(row),
            _ => None,
        };
        let (eligible, turn, learned_at) = match row {
            Some(row) if row.entity_type == ENTITY_TYPE_CLAIM => {
                let body = decode_claim_body(&row.body, true)?;
                (
                    body.lifecycle == ClaimLifecycleStatus::Active
                        && !crate::claim::is_reserved_predicate(&body.predicate)
                        && body
                            .source
                            .is_some_and(|source| source != ClaimSource::Generated)
                        // A claim awaiting its owner's critical confirm seeds
                        // no Dreamer pass.
                        && crate::gate::claim_consolidation_eligible_in_txn(
                            &vault.store,
                            txn,
                            &id,
                            crate::gate::ConsolidationReader::WakeCount,
                        )?,
                    false,
                    row.learned_at,
                )
            }
            Some(row) if row.entity_type == ENTITY_TYPE_TURN => {
                let speaker = crate::dreamer_consolidation::decode_turn_body(&row.body).speaker;
                let user =
                    dreamer_turn_role(speaker.as_deref(), &vault.config.assistant_display_names)
                        == DreamerTurnRole::User;
                (user, user, row.learned_at)
            }
            _ => (false, false, 0),
        };
        if eligible {
            state.pending_records.insert(key.clone(), learned_at);
            state.pending_nightly.insert(key.clone(), learned_at);
            if turn {
                state.pending_turns.insert(key, learned_at);
            } else {
                state.pending_turns.remove(&key);
            }
        } else {
            state.pending_turns.remove(&key);
            state.pending_records.remove(&key);
            state.pending_nightly.remove(&key);
        }
    }
    state.processed_change_id = last;
    Ok(WakeCounts {
        turns: state.pending_turns.len() as u64,
        records: state.pending_records.len() as u64,
        nightly: state.pending_nightly.len() as u64,
        first: state
            .pending_records
            .values()
            .chain(state.pending_turns.values())
            .copied()
            .min(),
        first_nightly: state.pending_nightly.values().copied().min(),
        last,
    })
}

fn decide(
    policy: DreamerWakePolicy,
    state: &WakeState,
    counts: &WakeCounts,
    idle: WakeIdleState,
    now: u64,
) -> WakePolicyDecision {
    if counts.turns == 0 && counts.records == 0 && counts.nightly == 0 {
        return WakePolicyDecision::Silent;
    }
    if !idle.compute_available || idle.running_turns || idle.live_background_work {
        return WakePolicyDecision::Silent;
    }
    let idle_due = idle.last_inbound_at.saturating_add(policy.idle_secs);
    if now < idle_due {
        return WakePolicyDecision::ArmIdle { due_at: idle_due };
    }
    if counts.turns >= policy.wake_grain_turns {
        return WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Continuous,
        };
    }
    let longest_due = state
        .last_weave_at
        .or(counts.first)
        .unwrap_or(now)
        .saturating_add(policy.longest_wait_secs);
    let quiet_due = idle.last_inbound_at.saturating_add(policy.quiet_weave_secs);
    let nightly_due = state
        .last_nightly_at
        .or(counts.first_nightly)
        .unwrap_or(now)
        .saturating_add(policy.nightly_secs);
    if counts.records > 0
        && (counts.records >= policy.new_records || now >= quiet_due || now >= longest_due)
    {
        return WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Weave,
        };
    }
    if counts.nightly > 0 && now >= nightly_due {
        return WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Nightly,
        };
    }
    let weave_deadline = if counts.records > 0 {
        quiet_due.min(longest_due)
    } else {
        u64::MAX
    };
    let nightly_deadline = if counts.nightly > 0 {
        nightly_due
    } else {
        u64::MAX
    };
    WakePolicyDecision::ArmIdle {
        due_at: weave_deadline.min(nightly_deadline),
    }
}

/// Combine the distinct prefix already in the outbox with the latest
/// snapshot. An unchanged segment cursor means the new count REPLACES that
/// segment, rather than adding its older rows again.
fn merge_component(
    new_count: u64,
    new_after: Option<[u8; 16]>,
    old_total: u64,
    old_latest_count: u64,
    old_latest_after: Option<[u8; 16]>,
) -> Result<u64> {
    if new_after < old_latest_after {
        return Err(Error::CorruptedIndex("dreamer wake outbox cursor rewound"));
    }
    Ok(if new_after == old_latest_after {
        old_total
            .saturating_sub(old_latest_count)
            .saturating_add(new_count)
    } else {
        old_total.saturating_add(new_count)
    })
}

/// A policy dispatch receipt may complete only while its recipe input is
/// still durably reachable. A newer coalesced input covers the older range.
pub(crate) fn wake_policy_input_covers(vault: &Vault, trigger: &WakePolicyTrigger) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let key = [trigger.recipe.key()];
    let Some(pending) = OUTBOX
        .get(&vault.store, &txn, &key)
        .map_err(|e| row_error(e, Error::CorruptedIndex("dreamer wake recipe input row")))?
    else {
        return Ok(false);
    };
    Ok(covers(&pending, trigger))
}

fn covers(pending: &WakePolicyTrigger, trigger: &WakePolicyTrigger) -> bool {
    pending.recipe == trigger.recipe
        && pending.through >= trigger.through
        && pending.after_turn <= trigger.after_turn
        && pending.after_record <= trigger.after_record
        && pending.after_nightly <= trigger.after_nightly
}

/// Takes the recipe input a receipt for `trigger` names out of the outbox,
/// in the caller's write, so the input leaves with the work its body
/// commits. The row taken is the coalesced one: it covers every receipt for
/// its recipe still queued. `None` when an earlier receipt already took it,
/// or a newer wake replaced it after the range was consumed.
pub(crate) fn take_wake_recipe_input_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    trigger: &WakePolicyTrigger,
) -> Result<Option<WakePolicyTrigger>> {
    let key = [trigger.recipe.key()];
    let Some(pending) = OUTBOX
        .get(&vault.store, txn, &key)
        .map_err(|e| row_error(e, Error::CorruptedIndex("dreamer wake recipe input row")))?
    else {
        return Ok(None);
    };
    if !covers(&pending, trigger) {
        return Ok(None);
    }
    OUTBOX.delete(&vault.store, txn, &key)?;
    Ok(Some(pending))
}

impl Vault {
    /// Claims the single cancellable idle timer slot for this open vault.
    pub fn claim_dreamer_wake_timer(&self) -> Result<WakePolicyTimerLease<'_>> {
        self.wake_policy_timer_owned
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::InvalidConfig("Dreamer wake timer already owned".into()))?;
        Ok(WakePolicyTimerLease { vault: self })
    }

    /// An owner-authenticated v1 policy write; no chat text can impersonate a policy row.
    pub fn set_dreamer_wake_policy(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        policy: DreamerWakePolicy,
    ) -> Result<()> {
        policy.validate()?;
        self.with_write_txn_grouped(|txn| {
            crate::dreamer_runner::maintenance::validate_owner_in_txn(self, txn, owner)?;
            POLICY
                .put(&self.store, txn, &(), &policy)
                .map_err(|e| row_error(e, invalid()))?;
            Ok(())
        })
    }

    /// [`Self::set_dreamer_wake_policy`], recording the owner's act with the
    /// policy it replaces when `surface` names where the owner said so
    /// (WILL-PLAN L13 row 01), in the same commit.
    pub(crate) fn set_dreamer_wake_policy_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        surface: Option<crate::authority::ActSurface>,
        policy: DreamerWakePolicy,
    ) -> Result<()> {
        policy.validate()?;
        self.with_write_txn_grouped(|txn| {
            let actor =
                crate::dreamer_runner::maintenance::validate_owner_in_txn(self, txn, owner)?;
            let prior = policy_in_txn(self, txn)?;
            POLICY
                .put(&self.store, txn, &(), &policy)
                .map_err(|e| row_error(e, invalid()))?;
            crate::policy_setting_doors::record_policy_setting_act_in_txn(
                self,
                txn,
                crate::policy_setting_doors::PolicySetting::DreamerWakePolicy,
                actor,
                surface,
                &prior,
                &policy,
            )
        })
    }
    /// Update just the grain on the same owner-authenticated policy row used
    /// by the host tick scheduler and the projector's turn door.
    pub fn set_wake_grain(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        grain: super::grain::WakeGrain,
    ) -> Result<()> {
        super::grain::WakeGrain::new(grain.turns_per_wake)?;
        self.with_write_txn_grouped(|txn| {
            crate::dreamer_runner::maintenance::validate_owner_in_txn(self, txn, owner)?;
            let mut policy = policy_in_txn(self, txn)?;
            policy.wake_grain_turns = grain.turns_per_wake;
            POLICY
                .put(&self.store, txn, &(), &policy)
                .map_err(|e| row_error(e, invalid()))?;
            Ok(())
        })
    }

    pub fn dreamer_wake_policy(&self) -> Result<DreamerWakePolicy> {
        let txn = self.store.env.read_txn()?;
        policy_in_txn(self, &txn)
    }
    /// Read-only policy query. The due time is a one-shot sleep target, not a poll rate.
    pub fn evaluate_dreamer_wake(
        &self,
        idle: WakeIdleState,
        now: u64,
    ) -> Result<WakePolicyDecision> {
        if !idle.compute_available || idle.running_turns || idle.live_background_work {
            return Ok(WakePolicyDecision::Silent);
        }
        let txn = self.store.env.read_txn()?;
        let policy = policy_in_txn(self, &txn)?;
        let mut state = state_in_txn(self, &txn)?;
        let counts = count_new(self, &txn, &mut state)?;
        Ok(decide(policy, &state, &counts, idle, now))
    }
    /// At most one outstanding input span per recipe. Repeated wake receipts
    /// merge their spans until a recipe consumer can settle that recipe; a
    /// busy vault never grows an unbounded policy outbox.
    pub fn dreamer_wake_recipe_inputs(&self) -> Result<Vec<WakePolicyTrigger>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for entry in OUTBOX.iter_from(&self.store, &txn, &[])? {
            let (key, trigger) = entry.map_err(|e| {
                row_error(e, Error::CorruptedIndex("dreamer wake recipe input row"))
            })?;
            if key != [trigger.recipe.key()] {
                return Err(Error::CorruptedIndex("dreamer wake recipe input key"));
            }
            rows.push(trigger);
        }
        Ok(rows)
    }
}

#[cfg(test)]
impl Vault {
    /// The explicit records a wake would count now, without moving its state,
    /// for the consolidation reader table.
    pub(crate) fn wake_pending_records_for_test(&self) -> Result<Vec<String>> {
        let txn = self.store.env.read_txn()?;
        let mut state = state_in_txn(self, &txn)?;
        count_new(self, &txn, &mut state)?;
        Ok(state.pending_records.into_keys().collect())
    }
}

#[cfg(test)]
#[path = "policy/tests.rs"]
mod tests;
