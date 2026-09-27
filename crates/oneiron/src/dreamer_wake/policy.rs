//! Row-backed wake admission. The host supplies liveness; the vault owns the decision.
use crate::Vault;
use crate::claim::{ClaimLifecycleStatus, ClaimSource, decode_claim_body};
use crate::dreamer_runner::{
    DreamerRunnerStore, DreamerTurnRole, EnqueueDreamerAttemptOutcome, dreamer_turn_role,
};
use crate::error::{Error, Result};
use crate::ports::{ChangeLogRecord, EntityStoreRead, TombstoneStore};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;

const POLICY_KEY: &[u8] = b"settings:dreamer:wake-policy:v1";
const STATE_KEY: &[u8] = b"dreamer:wake-policy:state:v1";
const OUTBOX_PREFIX: &[u8] = b"dreamer:wake-policy:recipe-input:v1:";
const DEFAULT_POLICY: &str = include_str!("wake_policy_defaults.json");

fn invalid() -> Error {
    Error::InvalidConfig("invalid dreamer wake policy row".into())
}

/// Per-vault recipe dials. An owner may write a different v1 row; these are
/// data, not compiled thresholds. `new_records` excludes Generated claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamerWakePolicy {
    pub wake_grain_turns: u64,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WeaveRecipePriority {
    BeforeConnectorEvent,
    AfterConnectorEvent,
}
impl DreamerWakePolicy {
    pub(crate) fn validate(self) -> Result<Self> {
        if self.wake_grain_turns == 0
            || self.new_records == 0
            || self.longest_wait_secs == 0
            || self.nightly_secs == 0
            || self.idle_secs == 0
            || self.quiet_weave_secs < self.idle_secs
        {
            return Err(invalid());
        }
        Ok(self)
    }
}

/// Liveness is sampled by the host at the same instant as the policy check.
/// `last_inbound_at` is seconds on the vault clock. A running turn or live
/// background job cancels the quiet timer rather than merely postponing work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeIdleState {
    pub running_turns: bool,
    pub live_background_work: bool,
    /// False when the vault has no usable compute lease; idle must suspend.
    pub compute_available: bool,
    pub last_inbound_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakePolicyDecision {
    Silent,
    ArmIdle { due_at: u64 },
    Enqueue { recipe: WakeRecipe },
}

/// Which workflow recipe receives the durable wake signal. This is not a
/// consolidation scope: a policy trigger alone has no partition payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
}

fn policy_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<DreamerWakePolicy> {
    let row = vault.store.vault_meta.get(txn, POLICY_KEY)?;
    let policy: DreamerWakePolicy = match row {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|_| invalid())?,
        None => serde_json::from_str(DEFAULT_POLICY).map_err(|_| invalid())?,
    };
    policy.validate()
}
fn state_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<WakeState> {
    vault
        .store
        .vault_meta
        .get(txn, STATE_KEY)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| invalid()))
        .transpose()
        .map(Option::unwrap_or_default)
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
    let prefix = crate::ports::CHANGE_LOG_KEY_PREFIX;
    let mut start = prefix.to_vec();
    if let Some(id) = state.processed_change_id {
        start.extend_from_slice(&id);
    }
    let mut upper = prefix.to_vec();
    *upper.last_mut().expect("nonempty prefix") += 1;
    let mut last = state.processed_change_id;
    let mut changed = std::collections::BTreeSet::new();
    for entry in vault.store.vault_meta.range(
        txn,
        &(
            if state.processed_change_id.is_some() {
                std::ops::Bound::Excluded(start.as_slice())
            } else {
                std::ops::Bound::Included(start.as_slice())
            },
            std::ops::Bound::Excluded(upper.as_slice()),
        ),
    )? {
        let (key, value) = entry?;
        let id: [u8; 16] = key
            .get(prefix.len()..)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::CorruptedIndex("dreamer wake mutation cursor"))?;
        if last.is_some_and(|last| id <= last) {
            return Err(Error::CorruptedIndex("dreamer wake mutation order"));
        }
        let change: ChangeLogRecord = rmp_serde::from_slice(&value)
            .map_err(|_| Error::CorruptedIndex("dreamer wake mutation row"))?;
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
                            .is_some_and(|source| source != ClaimSource::Generated),
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
    let key = [OUTBOX_PREFIX, &[trigger.recipe.key()]].concat();
    let Some(bytes) = vault.store.vault_meta.get(&txn, &key)? else {
        return Ok(false);
    };
    let pending: WakePolicyTrigger = serde_json::from_slice(&bytes)
        .map_err(|_| Error::CorruptedIndex("dreamer wake recipe input row"))?;
    Ok(pending.recipe == trigger.recipe
        && pending.through >= trigger.through
        && pending.after_turn <= trigger.after_turn
        && pending.after_record <= trigger.after_record
        && pending.after_nightly <= trigger.after_nightly)
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
        let bytes = serde_json::to_vec(&policy).map_err(|_| invalid())?;
        self.with_write_txn(|txn| {
            crate::dreamer_runner::maintenance::validate_owner_in_txn(self, txn, owner)?;
            self.store.vault_meta.put(txn, POLICY_KEY, &bytes)?;
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
        for entry in self.store.vault_meta.prefix_iter(&txn, OUTBOX_PREFIX)? {
            let (key, raw) = entry?;
            let trigger: WakePolicyTrigger = serde_json::from_slice(&raw)
                .map_err(|_| Error::CorruptedIndex("dreamer wake recipe input row"))?;
            if key.get(OUTBOX_PREFIX.len()..) != Some(&[trigger.recipe.key()][..]) {
                return Err(Error::CorruptedIndex("dreamer wake recipe input key"));
            }
            rows.push(trigger);
        }
        Ok(rows)
    }

    /// Re-evaluate against the writer snapshot and co-commit wake + cursor.
    /// A competing check cannot enqueue again for the same rows.
    pub fn enqueue_due_dreamer_wake(
        &self,
        idle: WakeIdleState,
        now: u64,
    ) -> Result<WakePolicyOutcome> {
        if !idle.compute_available || idle.running_turns || idle.live_background_work {
            return Ok(WakePolicyOutcome {
                decision: WakePolicyDecision::Silent,
                attempt: None,
            });
        }
        self.with_write_txn(|txn| {
            let policy = policy_in_txn(self, txn)?;
            let mut state = state_in_txn(self, txn)?;
            let previous_processed = state.processed_change_id;
            let counts = count_new(self, txn, &mut state)?;
            let decision = decide(policy, &state, &counts, idle, now);
            let WakePolicyDecision::Enqueue { recipe } = decision else {
                // Irrelevant rows advance only their own recipe cursor;
                // pending explicit records survive continuous turn wakes.
                let mut changed = false;
                if counts.turns == 0 && state.turn_change_id != counts.last {
                    state.turn_change_id = counts.last;
                    changed = true;
                }
                if counts.records == 0 && state.record_change_id != counts.last {
                    state.record_change_id = counts.last;
                    changed = true;
                }
                if counts.nightly == 0 && state.nightly_change_id != counts.last {
                    state.nightly_change_id = counts.last;
                    changed = true;
                }
                if changed || state.processed_change_id != previous_processed {
                    self.store.vault_meta.put(
                        txn,
                        STATE_KEY,
                        &serde_json::to_vec(&state).map_err(|_| invalid())?,
                    )?;
                }
                return Ok(WakePolicyOutcome {
                    decision,
                    attempt: None,
                });
            };
            let trigger = WakePolicyTrigger {
                recipe,
                turn_count: counts.turns,
                record_count: counts.records,
                nightly_count: counts.nightly,
                after_nightly: state.nightly_change_id,
                after_turn: state.turn_change_id,
                after_record: state.record_change_id,
                through: counts
                    .last
                    .ok_or(Error::CorruptedIndex("wake policy mutation head"))?,
                observed_at: now,
                latest_after_turn: state.turn_change_id,
                latest_after_record: state.record_change_id,
                latest_after_nightly: state.nightly_change_id,
                latest_turn_count: counts.turns,
                latest_record_count: counts.records,
                latest_nightly_count: counts.nightly,
            };
            let attempt =
                DreamerRunnerStore::new(self).enqueue_policy_wake_in_txn(txn, &trigger, now)?;
            let key = [OUTBOX_PREFIX, &[recipe.key()]].concat();
            let mut pending = trigger;
            if let Some(bytes) = self.store.vault_meta.get(txn, &key)? {
                let prior: WakePolicyTrigger = serde_json::from_slice(&bytes)
                    .map_err(|_| Error::CorruptedIndex("dreamer wake recipe input row"))?;
                if prior.recipe != recipe {
                    return Err(Error::CorruptedIndex("dreamer wake recipe input key"));
                }
                pending.turn_count = merge_component(
                    pending.turn_count,
                    pending.latest_after_turn,
                    prior.turn_count,
                    prior.latest_turn_count,
                    prior.latest_after_turn,
                )?;
                pending.record_count = merge_component(
                    pending.record_count,
                    pending.latest_after_record,
                    prior.record_count,
                    prior.latest_record_count,
                    prior.latest_after_record,
                )?;
                pending.nightly_count = merge_component(
                    pending.nightly_count,
                    pending.latest_after_nightly,
                    prior.nightly_count,
                    prior.latest_nightly_count,
                    prior.latest_after_nightly,
                )?;
                pending.after_turn = prior.after_turn;
                pending.after_record = prior.after_record;
                pending.after_nightly = prior.after_nightly;
            }
            self.store.vault_meta.put(
                txn,
                &key,
                &serde_json::to_vec(&pending).map_err(|_| invalid())?,
            )?;
            match recipe {
                WakeRecipe::Continuous => {
                    state.turn_change_id = counts.last;
                    state.pending_turns.clear();
                }
                WakeRecipe::Weave => {
                    state.record_change_id = counts.last;
                    state.pending_records.clear();
                    state.last_weave_at = Some(now);
                }
                WakeRecipe::Nightly => {
                    state.nightly_change_id = counts.last;
                    state.pending_nightly.clear();
                    state.last_nightly_at = Some(now);
                }
            }
            if counts.turns == 0 {
                state.turn_change_id = counts.last;
            }
            if counts.records == 0 {
                state.record_change_id = counts.last;
            }
            if counts.nightly == 0 {
                state.nightly_change_id = counts.last;
            }
            self.store.vault_meta.put(
                txn,
                STATE_KEY,
                &serde_json::to_vec(&state).map_err(|_| invalid())?,
            )?;
            Ok(WakePolicyOutcome {
                decision,
                attempt: Some(attempt),
            })
        })
    }
}

#[cfg(test)]
#[path = "policy/tests.rs"]
mod tests;
