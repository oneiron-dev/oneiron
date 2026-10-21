//! The shared scheduler's last committed cadence decision, not a second tick source.
use super::*;
use crate::EntityId;
use crate::consent::AuthenticatedOwner;

/// One real scheduler check. Reads of this receipt never run the scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeCadenceReceipt {
    pub sequence: u64,
    pub observed_at: u64,
    /// The deadline the preceding check armed, if any.
    pub previous_due_at: Option<u64>,
    pub boundary_reached: bool,
    /// Sticky across later checks, so child completions cannot hide a boundary.
    pub last_boundary_at: Option<u64>,
    pub idle: WakeIdleState,
    pub decision: WakePolicyDecision,
    pub wake: Option<EntityId>,
    pub processed_change_id: Option<[u8; 16]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakeCadenceRequest {}

/// The policy, durable decision and unconsumed recipe ranges in one snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeCadenceView {
    pub policy: DreamerWakePolicy,
    /// Absent until the production scheduler has made its first check.
    pub receipt: Option<WakeCadenceReceipt>,
    pub pending: Vec<WakeRecipeInputView>,
}

/// The public identity and evidence range of a recipe's durable input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeRecipeInputView {
    pub recipe: WakeRecipe,
    pub turn_count: u64,
    pub record_count: u64,
    pub nightly_count: u64,
    pub after_turn: Option<[u8; 16]>,
    pub after_record: Option<[u8; 16]>,
    pub after_nightly: Option<[u8; 16]>,
    pub through: [u8; 16],
    pub observed_at: u64,
}

impl From<&WakePolicyTrigger> for WakeRecipeInputView {
    fn from(input: &WakePolicyTrigger) -> Self {
        Self {
            recipe: input.recipe,
            turn_count: input.turn_count,
            record_count: input.record_count,
            nightly_count: input.nightly_count,
            after_turn: input.after_turn,
            after_record: input.after_record,
            after_nightly: input.after_nightly,
            through: input.through,
            observed_at: input.observed_at,
        }
    }
}

pub fn cadence_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &WakeCadenceRequest,
) -> Result<WakeCadenceView> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_as_vault_owner_in_txn(vault, &txn)?;
    let mut pending = Vec::new();
    for row in OUTBOX.iter_from(&vault.store, &txn, &[])? {
        let (key, input) = row?;
        if key != [input.recipe.key()] {
            return Err(Error::CorruptedIndex("dreamer wake recipe input key"));
        }
        pending.push(WakeRecipeInputView::from(&input));
    }
    Ok(WakeCadenceView {
        policy: policy_in_txn(vault, &txn)?,
        receipt: state_in_txn(vault, &txn)?.cadence,
        pending,
    })
}

fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    idle: WakeIdleState,
    now: u64,
    outcome: &WakePolicyOutcome,
) -> Result<()> {
    let mut state = state_in_txn(vault, txn)?;
    let previous_due_at = state
        .cadence
        .as_ref()
        .and_then(|receipt| match receipt.decision {
            WakePolicyDecision::ArmIdle { due_at } => Some(due_at),
            _ => None,
        });
    let wake = outcome
        .attempt
        .as_ref()
        .map(|attempt| {
            let (EnqueueDreamerAttemptOutcome::Enqueued(status)
            | EnqueueDreamerAttemptOutcome::Existing(status)) = attempt;
            EntityId::from_bytes(*status.attempt.id.as_bytes())
        })
        .transpose()?;
    state.cadence = Some(WakeCadenceReceipt {
        sequence: state
            .cadence
            .as_ref()
            .map_or(1, |receipt| receipt.sequence + 1),
        observed_at: now,
        previous_due_at,
        boundary_reached: previous_due_at.is_some_and(|due| now >= due),
        last_boundary_at: if previous_due_at.is_some_and(|due| now >= due) {
            Some(now)
        } else {
            state
                .cadence
                .as_ref()
                .and_then(|receipt| receipt.last_boundary_at)
        },
        idle,
        decision: outcome.decision,
        wake,
        processed_change_id: state.processed_change_id,
    });
    STATE.put(&vault.store, txn, &(), &state)
}

/// The curator's cadence slot `now` falls in and the wake state, once the
/// idle floor has passed; `None` before it.
fn idle_curator_slot_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    idle: WakeIdleState,
    now: u64,
) -> Result<Option<(u64, WakeState)>> {
    let policy = policy_in_txn(vault, txn)?;
    if now < idle.last_inbound_at.saturating_add(policy.idle_secs) {
        return Ok(None);
    }
    let slot = crate::dreamer_runner::maintenance::curator_slot_in_txn(vault, txn, now)?;
    Ok(Some((slot, state_in_txn(vault, txn)?)))
}

/// The curator cadence slot this check asks the idle curator pass for
/// (OF-191), if any: the host is idle as the policy's own checks read it
/// (compute available, no turn or background work running, the idle floor
/// passed) and the slot is one the idle trigger has not asked for yet. The
/// slot is taken only with the pass queued ([`queue_idle_curator_in_txn`]),
/// so a queue that fails leaves the ask for the next check (FIX 5909). A
/// future idle timer armed alone asks for nothing. A read that fails asks
/// for nothing and never fails the check.
fn idle_curator_due_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    idle: WakeIdleState,
    now: u64,
) -> Option<u64> {
    if !idle.compute_available || idle.running_turns || idle.live_background_work {
        return None;
    }
    let (slot, state) = match idle_curator_slot_in_txn(vault, txn, idle, now) {
        Ok(Some(read)) => read,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "the idle curator check did not read");
            return None;
        }
    };
    (state.idle_curator_slot != Some(slot)).then_some(slot)
}

/// Queues the idle curator pass for `slot` and takes the slot in the wake
/// check's own write, in a savepoint (FIX 5909): both land or neither does.
/// A pass that does not queue rolls back alone, is logged, never fails the
/// check, and is asked again by the next. A slot past `slot`, taken
/// meanwhile, stands.
fn queue_idle_curator_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    slot: u64,
    now: u64,
) -> Result<Option<EnqueueDreamerAttemptOutcome>> {
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let queued = (|| -> Result<EnqueueDreamerAttemptOutcome> {
        let queued = DreamerRunnerStore::new(vault).enqueue_curator_in_txn(
            &mut savepoint,
            crate::dreamer_runner::maintenance::CuratorTrigger::Idle,
            None,
            None,
            now,
        )?;
        let mut state = state_in_txn(vault, &savepoint)?;
        if !state.idle_curator_slot.is_some_and(|taken| taken >= slot) {
            state.idle_curator_slot = Some(slot);
            STATE
                .put(&vault.store, &mut savepoint, &(), &state)
                .map_err(|e| row_error(e, invalid()))?;
        }
        Ok(queued)
    })();
    match queued {
        Ok(queued) => {
            savepoint.commit()?;
            Ok(Some(queued))
        }
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "the idle curator pass was not queued; the next check asks again"
            );
            Ok(None)
        }
    }
}

impl Vault {
    /// Re-evaluate against the writer snapshot and co-commit wake + cursor.
    /// A competing check cannot enqueue again for the same rows. An idle
    /// host also asks for the curator pass (OF-191), once per rubric
    /// cadence, in the same commit ([`queue_idle_curator_in_txn`]).
    pub fn enqueue_due_dreamer_wake(
        &self,
        idle: WakeIdleState,
        now: u64,
    ) -> Result<WakePolicyOutcome> {
        let (outcome, curator) = self.enqueue_due_dreamer_wake_once(idle, now)?;
        if matches!(curator, Some(EnqueueDreamerAttemptOutcome::Enqueued(_))) {
            self.store.notify_attempt_observers();
        }
        Ok(outcome)
    }

    /// One check's commit: the wake and its cursor, and the idle curator
    /// pass with its slot, if one is asked for.
    fn enqueue_due_dreamer_wake_once(
        &self,
        idle: WakeIdleState,
        now: u64,
    ) -> Result<(WakePolicyOutcome, Option<EnqueueDreamerAttemptOutcome>)> {
        self.with_write_txn_grouped(|txn| {
            let outcome = (|| -> Result<WakePolicyOutcome> {
                if !idle.compute_available || idle.running_turns || idle.live_background_work {
                    return Ok(WakePolicyOutcome {
                        decision: WakePolicyDecision::Silent,
                        attempt: None,
                    });
                }
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
                        STATE
                            .put(&self.store, txn, &(), &state)
                            .map_err(|e| row_error(e, invalid()))?;
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
                    DreamerRunnerStore::new(self).enqueue_recipe_wake_in_txn(txn, &trigger, now)?;
                let key = [recipe.key()];
                let mut pending = trigger;
                if let Some(prior) = OUTBOX.get(&self.store, txn, &key).map_err(|e| {
                    row_error(e, Error::CorruptedIndex("dreamer wake recipe input row"))
                })? {
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
                OUTBOX
                    .put(&self.store, txn, &key, &pending)
                    .map_err(|e| row_error(e, invalid()))?;
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
                STATE
                    .put(&self.store, txn, &(), &state)
                    .map_err(|e| row_error(e, invalid()))?;
                Ok(WakePolicyOutcome {
                    decision,
                    attempt: Some(attempt),
                })
            })()?;
            record_in_txn(self, txn, idle, now, &outcome)?;
            let curator = match idle_curator_due_in_txn(self, txn, idle, now) {
                Some(slot) => queue_idle_curator_in_txn(self, txn, slot, now)?,
                None => None,
            };
            Ok((outcome, curator))
        })
    }
}
