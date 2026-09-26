//! Row-backed wake admission. The host supplies liveness; the vault owns the decision.
use crate::Vault;
use crate::claim::{ClaimLifecycleStatus, ClaimSource, decode_claim_body};
use crate::dreamer_runner::{
    DreamerRunnerStore, DreamerTurnRole, EnqueueDreamerAttemptOutcome, dreamer_turn_role,
};
use crate::error::{Error, Result};
use crate::ports::{ChangeLogRecord, ChangeOp, EntityStoreRead, TombstoneStore};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use serde::{Deserialize, Serialize};

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
    pub idle_secs: u64,
}
impl DreamerWakePolicy {
    fn validate(self) -> Result<Self> {
        if self.wake_grain_turns == 0
            || self.new_records == 0
            || self.longest_wait_secs == 0
            || self.nightly_secs == 0
            || self.idle_secs == 0
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
        .map(|state| state.unwrap_or_default())
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

fn count_new(vault: &Vault, txn: &heed::RoTxn<'_>, state: &WakeState) -> Result<WakeCounts> {
    let prefix = crate::ports::CHANGE_LOG_KEY_PREFIX;
    let cursor = [
        state.turn_change_id,
        state.record_change_id,
        state.nightly_change_id,
    ]
    .into_iter()
    .flatten()
    .min();
    let cursor = if state.turn_change_id.is_none()
        || state.record_change_id.is_none()
        || state.nightly_change_id.is_none()
    {
        None
    } else {
        cursor
    };
    let mut start = prefix.to_vec();
    if let Some(id) = cursor {
        start.extend_from_slice(&id);
    }
    let mut upper = prefix.to_vec();
    *upper.last_mut().expect("nonempty prefix") += 1;
    let mut last = cursor;
    let mut turn_candidates = std::collections::BTreeSet::new();
    let mut record_candidates = std::collections::BTreeSet::new();
    let mut nightly_candidates = std::collections::BTreeSet::new();
    for entry in vault.store.vault_meta.range(
        txn,
        &(
            if cursor.is_some() {
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
        if matches!(change.op, ChangeOp::Create | ChangeOp::Update) {
            if state.turn_change_id.is_none_or(|seen| id > seen) {
                turn_candidates.insert(change.entity);
            }
            if state.record_change_id.is_none_or(|seen| id > seen) {
                record_candidates.insert(change.entity);
            }
            if state.nightly_change_id.is_none_or(|seen| id > seen) {
                nightly_candidates.insert(change.entity);
            }
        }
    }
    let mut out = WakeCounts {
        turns: 0,
        records: 0,
        nightly: 0,
        first: None,
        first_nightly: None,
        last,
    };
    let candidates: std::collections::BTreeSet<_> = turn_candidates
        .union(&record_candidates)
        .copied()
        .chain(nightly_candidates.iter().copied())
        .collect();
    for id in &candidates {
        let Some(row) = vault.store.port_entity_record(txn, id)? else {
            continue;
        };
        if vault.port_tombstone_is_deleted(txn, id)? {
            continue;
        }
        let eligible = match row.entity_type {
            ENTITY_TYPE_CLAIM => {
                let body = decode_claim_body(&row.body, true)?;
                body.lifecycle == ClaimLifecycleStatus::Active
                    && !crate::claim::is_reserved_predicate(&body.predicate)
                    && body
                        .source
                        .is_some_and(|source| source != ClaimSource::Generated)
            }
            ENTITY_TYPE_TURN => {
                let speaker = crate::dreamer_consolidation::decode_turn_body(&row.body).speaker;
                dreamer_turn_role(speaker.as_deref(), &vault.config.assistant_display_names)
                    == DreamerTurnRole::User
            }
            _ => false,
        };
        if !eligible {
            continue;
        }
        if row.entity_type == ENTITY_TYPE_TURN && turn_candidates.contains(id) {
            out.turns = out.turns.saturating_add(1);
        }
        if record_candidates.contains(id) {
            out.records = out.records.saturating_add(1);
        }
        if nightly_candidates.contains(id) {
            out.nightly = out.nightly.saturating_add(1);
            out.first_nightly = Some(
                out.first_nightly
                    .map_or(row.learned_at, |earliest: u64| earliest.min(row.learned_at)),
            );
        }
        if turn_candidates.contains(id) || record_candidates.contains(id) {
            out.first = Some(
                out.first
                    .map_or(row.learned_at, |earliest: u64| earliest.min(row.learned_at)),
            );
        }
    }
    Ok(out)
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
    if idle.running_turns || idle.live_background_work {
        return WakePolicyDecision::Silent;
    }
    let quiet_due = idle.last_inbound_at.saturating_add(policy.idle_secs);
    if now < quiet_due {
        return WakePolicyDecision::ArmIdle { due_at: quiet_due };
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
    let nightly_due = state
        .last_nightly_at
        .or(counts.first_nightly)
        .unwrap_or(now)
        .saturating_add(policy.nightly_secs);
    if counts.records > 0 && (counts.records >= policy.new_records || now >= longest_due) {
        return WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Weave,
        };
    }
    if counts.nightly > 0 && now >= nightly_due {
        return WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Nightly,
        };
    }
    WakePolicyDecision::ArmIdle {
        due_at: if counts.records > 0 {
            longest_due
        } else {
            nightly_due
        }
        .min(if counts.nightly > 0 {
            nightly_due
        } else {
            longest_due
        }),
    }
}

impl Vault {
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
        let txn = self.store.env.read_txn()?;
        let policy = policy_in_txn(self, &txn)?;
        let state = state_in_txn(self, &txn)?;
        let counts = count_new(self, &txn, &state)?;
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
        self.with_write_txn(|txn| {
            let policy = policy_in_txn(self, txn)?;
            let mut state = state_in_txn(self, txn)?;
            let counts = count_new(self, txn, &state)?;
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
                if changed {
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
                pending.after_turn = prior.after_turn;
                pending.after_record = prior.after_record;
                pending.after_nightly = prior.after_nightly;
                pending.turn_count = pending.turn_count.saturating_add(prior.turn_count);
                pending.record_count = pending.record_count.saturating_add(prior.record_count);
                pending.nightly_count = pending.nightly_count.saturating_add(prior.nightly_count);
            }
            self.store.vault_meta.put(
                txn,
                &key,
                &serde_json::to_vec(&pending).map_err(|_| invalid())?,
            )?;
            match recipe {
                WakeRecipe::Continuous => state.turn_change_id = counts.last,
                WakeRecipe::Weave => {
                    state.record_change_id = counts.last;
                    state.last_weave_at = Some(now);
                }
                WakeRecipe::Nightly => {
                    state.nightly_change_id = counts.last;
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
