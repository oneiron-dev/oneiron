use crate::Vault;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

use super::meter::{
    CONNECTOR_KEY_CHARTER_ROW_BASE, ConnectorDispatchTelemetry, ConnectorKeyDispatchTally,
    ConnectorKeyUsage, EffectorBudgetCharge, EffectorBudgetChargeOutcome, EffectorBudgetRead,
    EffectorBudgetRowRead, budget_exhausted_reason, budget_read_from_states, budget_row_read,
    charge_effector_budgets, connector_key_usage_row_key, load_budget_row_states,
};
use super::record::{
    ConnectorKeyStatus, EffectorBudgetDimension, EffectorBudgetOnExhaust, invalid_body,
    normalize_connector_key,
};
use super::txn::{
    append_connector_key_op_record, governing_connector_key, read_connector_key_in_txn,
    suspend_connector_key_in_txn,
};

/// Upper bound on one admit batch — keeps a single LMDB write txn bounded.
pub const CONNECTOR_KEY_MAX_DISPATCH_BATCH: u64 = 4096;

/// vault_meta spend-settlement idempotency rows: prefix ++ key id (16 bytes)
/// ++ event_ref bytes -> row_index u16 BE ++ minor_units u64 BE ++
/// cost_occurred_at u64 BE. One row per settlement event id. Replay
/// IDENTITY is the (row_index, minor_units) prefix — the settlement's
/// actual content; the trailing declared cost time is first-writer-wins
/// recorded data. A matching replay settles nothing (even with a drifted
/// declared time between honest retries); a same-id replay with different
/// content fails closed (a pre-claimed event_ref cannot force a silent
/// no-op for a different settlement).
pub(crate) const CONNECTOR_KEY_SETTLE_EVENT_PREFIX: &[u8] = b"connector_key/settle_event/v1\0";

const CONNECTOR_KEY_SETTLE_EVENT_REF_MAX_LEN: usize = 128;

/// vault_meta logical-send admission rows: prefix ++ key id (16 bytes) ++
/// `logical_send_ref` bytes -> admitted_at u64 BE ++ sends_debit u64 BE ++
/// normalized effect channel.
///
/// The row is the proof that ONE LOGICAL SEND already debited this key. The
/// admission ref is the owning TASK/intent reference and NEVER an
/// `AttemptId`: `attempt_queue::retry` re-queues the same AttemptId in place
/// (there is no `retry_of` link), so an attempt-keyed row could not tell a
/// retry of one send from a second send. Keying on the logical send makes the
/// `Sends` debit exactly-once across whatever retry shape the attempt layer
/// takes. The stored value is first-writer-wins EVIDENCE, not replay
/// identity — replay is `(key, logical_send_ref)`.
pub const CONNECTOR_KEY_SEND_ADMIT_PREFIX: &[u8] = b"connector_key/send_admit/v1\0";

const CONNECTOR_KEY_LOGICAL_SEND_REF_MAX_LEN: usize = 128;

/// Outcome of admitting ONE logical send through a connector key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorKeySendAdmission {
    /// First eligible admission of this logical send: budgets were debited
    /// and the identity row written.
    Admitted(EffectorBudgetCharge),
    /// This logical send already debited the key. Nothing was written and
    /// nothing was charged: `sends_debit` is 0, `matched_rows` and
    /// `ladder_events` are empty, and the carried `read` is a live read-only
    /// echo of the key's meter.
    Replayed(EffectorBudgetCharge),
    /// The send was refused. NO identity row is written, so the refusal does
    /// not poison a later admission of the same logical send.
    Refused {
        /// `"connector_key_not_active"`, or the exhausted row's
        /// `budget_exhausted:*` reason.
        reason: String,
        /// The first exceeding row, when a budget row refused.
        row_index: Option<u16>,
        /// Set when an `on_exhaust: Suspend` row flipped the key Suspended in
        /// the same transaction.
        suspended: bool,
        /// The evaluated (undebited) meter, when the charger ran.
        charge: Option<EffectorBudgetCharge>,
    },
}

pub(crate) fn connector_key_send_admit_key(id: &EntityId, logical_send_ref: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        CONNECTOR_KEY_SEND_ADMIT_PREFIX.len() + ENTITY_ID_LEN + logical_send_ref.len(),
    );
    key.extend_from_slice(CONNECTOR_KEY_SEND_ADMIT_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key.extend_from_slice(logical_send_ref.as_bytes());
    key
}

fn send_admit_value(admitted_at: u64, sends_debit: u64, effect_channel: &str) -> Vec<u8> {
    let mut value = Vec::with_capacity(2 * size_of::<u64>() + effect_channel.len());
    value.extend_from_slice(&admitted_at.to_be_bytes());
    value.extend_from_slice(&sends_debit.to_be_bytes());
    value.extend_from_slice(effect_channel.as_bytes());
    value
}

/// Length of the settlement-event IDENTITY prefix (row_index ++ minor_units
/// — the settlement's actual content). The declared `cost_occurred_at`
/// trails as first-writer-wins RECORDED data and is deliberately NOT part
/// of the identity: an honest retry whose declared cost time drifted
/// between attempts must stay idempotent, never fail closed into a
/// fresh-event_ref retry that double-debits.
const SETTLE_EVENT_IDENTITY_LEN: usize = size_of::<u16>() + size_of::<u64>();

/// The stored settlement-event value: identity prefix, then the declared
/// cost time from the FIRST successful write.
fn settle_event_value(row_index: u16, minor_units: u64, cost_occurred_at: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(SETTLE_EVENT_IDENTITY_LEN + size_of::<u64>());
    value.extend_from_slice(&row_index.to_be_bytes());
    value.extend_from_slice(&minor_units.to_be_bytes());
    value.extend_from_slice(&cost_occurred_at.to_be_bytes());
    value
}

pub(crate) fn connector_key_settle_event_key(id: &EntityId, event_ref: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        CONNECTOR_KEY_SETTLE_EVENT_PREFIX.len() + ENTITY_ID_LEN + event_ref.len(),
    );
    key.extend_from_slice(CONNECTOR_KEY_SETTLE_EVENT_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key.extend_from_slice(event_ref.as_bytes());
    key
}

impl Vault {
    /// The `self.*` effector-meter read (ARCHPASS A3): resolves the governing
    /// key and computes each row's live usage at `now` — no debit, no
    /// threshold firing, no usage-row writes. Liveness (window rollover,
    /// rolling prune/re-arm) is computed on the read, never stored. Rows
    /// include the key budget rows and, when a charter is stamped (GOV-10),
    /// the compiled-cap rows at `0x8000 | i`.
    pub fn effector_budget_read(
        &self,
        connector: &str,
        actor_entity_ref: Option<&EntityId>,
    ) -> Result<Option<EffectorBudgetRead>> {
        let rtxn = self.store.env.read_txn()?;
        let Some((key_id, record)) = governing_connector_key(
            &self.store,
            &rtxn,
            &normalize_connector_key(connector),
            actor_entity_ref,
        )?
        else {
            return Ok(None);
        };
        let now = crate::unix_seconds_now();
        let states =
            load_budget_row_states(&self.store, &rtxn, &key_id, &record, None, false, now)?;
        Ok(Some(budget_read_from_states(&key_id, &record, &states)))
    }

    /// Applies the existing effector-budget charger sequentially to a batch
    /// of send-like dispatches through one key.
    ///
    /// Accounting time is the ENGINE clock, sampled ONCE here: every budget
    /// window selection/roll, usage entry, suspension transition, and op
    /// record in the admission transaction takes that one sample, so a long
    /// batch cannot straddle two windows and a caller cannot pick the window
    /// it debits. `telemetry` carries the caller's own observation as a
    /// declared fact — echoed in the tally, never handed to the charger.
    pub fn admit_connector_key_dispatches(
        &self,
        id: &EntityId,
        effect_channel: &str,
        count: u64,
        telemetry: ConnectorDispatchTelemetry,
    ) -> Result<ConnectorKeyDispatchTally> {
        self.admit_connector_key_dispatch_batch(
            id,
            effect_channel,
            count,
            telemetry,
            crate::unix_seconds_now(),
        )
    }

    /// Freezes the accounting clock for a dispatch batch.
    ///
    /// The ONLY door that takes an accounting timestamp, and it exists solely
    /// so budget-window behavior is testable without sleeping. Compiled out of
    /// production builds: `test` covers this crate's own unit tests,
    /// `test-support` this crate's integration tests (self dev-dependency),
    /// `test-hooks` downstream crates' tests.
    #[cfg(any(test, feature = "test-support", feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn admit_connector_key_dispatches_at(
        &self,
        id: &EntityId,
        effect_channel: &str,
        count: u64,
        telemetry: ConnectorDispatchTelemetry,
        accounting_now: u64,
    ) -> Result<ConnectorKeyDispatchTally> {
        self.admit_connector_key_dispatch_batch(
            id,
            effect_channel,
            count,
            telemetry,
            accounting_now,
        )
    }

    /// Sole body of connector-key batch admission. `accounting_now` is the
    /// batch's single engine sample; it reaches this function from the public
    /// door above and, under test cfg only, from the freezing seam.
    fn admit_connector_key_dispatch_batch(
        &self,
        id: &EntityId,
        effect_channel: &str,
        count: u64,
        telemetry: ConnectorDispatchTelemetry,
        accounting_now: u64,
    ) -> Result<ConnectorKeyDispatchTally> {
        let effect_channel = normalize_connector_key(effect_channel);
        if effect_channel.is_empty() {
            return Err(invalid_body("effect channel must not be blank"));
        }
        if count > CONNECTOR_KEY_MAX_DISPATCH_BATCH {
            return Err(invalid_body("dispatch batch too large"));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let mut record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        let mut tally = ConnectorKeyDispatchTally {
            admitted: 0,
            refused: 0,
            ladder_events: Vec::new(),
            accounted_at: accounting_now,
            caller_observed_at: telemetry.caller_observed_at,
        };

        for i in 0..count {
            if record.status != ConnectorKeyStatus::Active {
                tally.refused = tally.refused.saturating_add(count - i);
                break;
            }
            match charge_effector_budgets(
                &self.store,
                &mut wtxn,
                id,
                &mut record,
                &effect_channel,
                true,
                accounting_now,
            )? {
                EffectorBudgetChargeOutcome::NoRows(charge)
                | EffectorBudgetChargeOutcome::Charged(charge) => {
                    tally.admitted = tally.admitted.saturating_add(1);
                    tally.ladder_events.extend(charge.ladder_events);
                }
                EffectorBudgetChargeOutcome::Exhausted {
                    row_index,
                    on_exhaust,
                    charge,
                } => {
                    if on_exhaust == EffectorBudgetOnExhaust::Suspend {
                        record = suspend_connector_key_in_txn(
                            &self.store,
                            &mut wtxn,
                            id,
                            &record,
                            budget_exhausted_reason(row_index),
                            accounting_now,
                        )?;
                        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
                        append_connector_key_op_record(
                            &self.store,
                            &mut wtxn,
                            id,
                            "gate.connector_key.dispatch_suspend",
                            &record,
                            policy.read_frontier_hash()?,
                            accounting_now,
                        )?;
                    }
                    tally.ladder_events.extend(charge.ladder_events);
                    tally.refused = tally.refused.saturating_add(count - i);
                    break;
                }
            }
        }
        wtxn.commit()?;
        Ok(tally)
    }

    /// Admits ONE LOGICAL SEND through a connector key, debiting `Sends`
    /// exactly once no matter how many physical attempts the transport layer
    /// makes.
    ///
    /// `logical_send_ref` names the owning TASK/intent, never an `AttemptId`
    /// (see [`CONNECTOR_KEY_SEND_ADMIT_PREFIX`]), and is validated like
    /// `settle_connector_spend`'s `event_ref`: nonblank, ≤128 bytes, no NUL —
    /// checked BEFORE any charge or dedupe write.
    ///
    /// Accounting time is the ENGINE clock, sampled once here, exactly as
    /// [`Self::admit_connector_key_dispatches`] does: a caller cannot pick the
    /// budget window it debits.
    ///
    /// This is the SENDS half of the split the live-transport wiring
    /// follow-on will land: `Rate` stays a per-physical-effector-call charge
    /// through `charge_effector_budgets` at the execution chokepoint, while
    /// `Sends` is charged once per logical send here. Until that follow-on,
    /// the chokepoint and consent paths keep charging as they do today.
    pub fn admit_connector_key_send(
        &self,
        id: &EntityId,
        effect_channel: &str,
        logical_send_ref: &str,
    ) -> Result<ConnectorKeySendAdmission> {
        self.admit_connector_key_send_inner(
            id,
            effect_channel,
            logical_send_ref,
            crate::unix_seconds_now(),
        )
    }

    /// Freezes the accounting clock for one logical-send admission.
    ///
    /// The same test-only seam as `admit_connector_key_dispatches_at`, and for
    /// the same reason: budget-window behavior must be testable without
    /// sleeping. Compiled out of production builds.
    #[cfg(any(test, feature = "test-support", feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn admit_connector_key_send_at(
        &self,
        id: &EntityId,
        effect_channel: &str,
        logical_send_ref: &str,
        accounting_now: u64,
    ) -> Result<ConnectorKeySendAdmission> {
        self.admit_connector_key_send_inner(id, effect_channel, logical_send_ref, accounting_now)
    }

    /// Sole body of logical-send admission. `accounting_now` reaches it from
    /// the public door above and, under test cfg only, from the freezing seam.
    fn admit_connector_key_send_inner(
        &self,
        id: &EntityId,
        effect_channel: &str,
        logical_send_ref: &str,
        accounting_now: u64,
    ) -> Result<ConnectorKeySendAdmission> {
        if logical_send_ref.trim().is_empty() {
            return Err(invalid_body("logical_send_ref must not be blank"));
        }
        if logical_send_ref.len() > CONNECTOR_KEY_LOGICAL_SEND_REF_MAX_LEN {
            return Err(invalid_body("logical_send_ref too long"));
        }
        if logical_send_ref.as_bytes().contains(&0) {
            return Err(invalid_body("logical_send_ref must not contain NUL"));
        }
        let effect_channel = normalize_connector_key(effect_channel);
        if effect_channel.is_empty() {
            return Err(invalid_body("effect channel must not be blank"));
        }

        let mut wtxn = self.store.env.write_txn()?;
        let mut record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        let admit_key = connector_key_send_admit_key(id, logical_send_ref);

        // Replay: this logical send already debited the key. Echo the meter
        // read-only (no matched rows ⇒ no amounts ⇒ nothing written) and let
        // the transaction abort, so a retried send cannot debit twice.
        if self.store.vault_meta.get(&wtxn, &admit_key)?.is_some() {
            let states = load_budget_row_states(
                &self.store,
                &wtxn,
                id,
                &record,
                None,
                false,
                accounting_now,
            )?;
            let read = budget_read_from_states(id, &record, &states);
            return Ok(ConnectorKeySendAdmission::Replayed(EffectorBudgetCharge {
                key_ref: *id,
                sends_debit: 0,
                read,
                matched_rows: Vec::new(),
                ladder_events: Vec::new(),
            }));
        }

        if record.status != ConnectorKeyStatus::Active {
            return Ok(ConnectorKeySendAdmission::Refused {
                reason: "connector_key_not_active".to_owned(),
                row_index: None,
                suspended: false,
                charge: None,
            });
        }

        match charge_effector_budgets(
            &self.store,
            &mut wtxn,
            id,
            &mut record,
            &effect_channel,
            true,
            accounting_now,
        )? {
            EffectorBudgetChargeOutcome::NoRows(charge)
            | EffectorBudgetChargeOutcome::Charged(charge) => {
                self.store.vault_meta.put(
                    &mut wtxn,
                    &admit_key,
                    &send_admit_value(accounting_now, charge.sends_debit, &effect_channel),
                )?;
                wtxn.commit()?;
                Ok(ConnectorKeySendAdmission::Admitted(charge))
            }
            EffectorBudgetChargeOutcome::Exhausted {
                row_index,
                on_exhaust,
                charge,
            } => {
                // A refusal writes NO admission row: the logical send never
                // debited, so the same ref must still be admittable once the
                // window rolls or the owner widens the budget.
                let mut suspended = false;
                if on_exhaust == EffectorBudgetOnExhaust::Suspend {
                    record = suspend_connector_key_in_txn(
                        &self.store,
                        &mut wtxn,
                        id,
                        &record,
                        budget_exhausted_reason(row_index),
                        accounting_now,
                    )?;
                    let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
                    append_connector_key_op_record(
                        &self.store,
                        &mut wtxn,
                        id,
                        "gate.connector_key.dispatch_suspend",
                        &record,
                        policy.read_frontier_hash()?,
                        accounting_now,
                    )?;
                    suspended = true;
                }
                wtxn.commit()?;
                Ok(ConnectorKeySendAdmission::Refused {
                    reason: budget_exhausted_reason(row_index),
                    row_index: Some(row_index),
                    suspended,
                    charge: Some(charge),
                })
            }
        }
    }

    /// Settles actual engine-recorded spend into a Spend row (v1 settle-only
    /// accounting; costs are never client-asserted). If the settle crosses
    /// the limit on an `on_exhaust: Suspend` row and the key is Active, the
    /// key flips Suspended in the same transaction. No retroactive refusal —
    /// the effect already occurred; the NEXT admission refuses.
    ///
    /// Two different times are deliberately kept apart. `cost_occurred_at`
    /// is the DECLARED fact — when the provider cost happened, legitimately
    /// lagging, recorded first-writer-wins in the settlement-event row and
    /// never consulted for accounting (nor for replay identity). Which budget window the debit lands in, the
    /// usage-entry chronology, and any suspension stamp all take the ENGINE
    /// clock at settle time, unconditionally: the record says when the cost
    /// happened; the ledger says when we learned of it. A caller-picked
    /// timestamp therefore cannot select, roll, or clear any window.
    pub fn settle_connector_spend(
        &self,
        id: &EntityId,
        row_index: u16,
        minor_units: u64,
        cost_occurred_at: u64,
        event_ref: &str,
    ) -> Result<EffectorBudgetRowRead> {
        if event_ref.trim().is_empty() {
            return Err(invalid_body("settle event_ref must not be blank"));
        }
        if event_ref.len() > CONNECTOR_KEY_SETTLE_EVENT_REF_MAX_LEN {
            return Err(invalid_body("settle event_ref too long"));
        }
        if event_ref.as_bytes().contains(&0) {
            return Err(invalid_body("settle event_ref must not contain NUL"));
        }
        // A zero-amount settlement records nothing and would only grow the
        // usage entry log; entry counts stay bounded by the row limit.
        if minor_units == 0 {
            return Err(invalid_body("settle amount must be at least 1"));
        }
        let settled_at = crate::unix_seconds_now();

        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        let budget = if row_index & CONNECTOR_KEY_CHARTER_ROW_BASE == 0 {
            record.budgets.get(usize::from(row_index))
        } else {
            record.charter.as_ref().and_then(|charter| {
                charter
                    .compiled
                    .channel_caps
                    .get(usize::from(row_index & !CONNECTOR_KEY_CHARTER_ROW_BASE))
            })
        };
        let Some(budget) = budget.cloned() else {
            return Err(invalid_body("spend settle on missing row"));
        };
        if budget.dimension != EffectorBudgetDimension::Spend {
            return Err(invalid_body("spend settle on non-spend row"));
        }

        let usage_key = connector_key_usage_row_key(id, row_index);
        let mut usage = match self.store.vault_meta.get(&wtxn, &usage_key)? {
            Some(bytes) => ConnectorKeyUsage::decode(&bytes)?,
            None => ConnectorKeyUsage::default(),
        };

        // Idempotency keyed on the settlement's CONTENT (row, amount): a
        // replayed event id with the same content settles nothing — even
        // when the declared cost time drifted between honest retry attempts
        // (the first write's recorded time stands) — while the same event id
        // with a DIFFERENT (row, amount) fails closed, so a pre-claimed
        // event_ref cannot force a silent no-op for a different settlement.
        let event_key = connector_key_settle_event_key(id, event_ref);
        let event_value = settle_event_value(row_index, minor_units, cost_occurred_at);
        if let Some(stored) = self.store.vault_meta.get(&wtxn, &event_key)? {
            if stored.len() < SETTLE_EVENT_IDENTITY_LEN
                || stored[..SETTLE_EVENT_IDENTITY_LEN] != event_value[..SETTLE_EVENT_IDENTITY_LEN]
            {
                return Err(invalid_body(
                    "settle event replay with different settlement",
                ));
            }
            // Read-only echo of the row's current state; nothing is written.
            usage.touch(&budget.window, budget.limit, settled_at);
            return Ok(budget_row_read(row_index, &budget, &usage));
        }

        usage.touch(&budget.window, budget.limit, settled_at);
        usage.entries.push((settled_at, minor_units));
        self.store
            .vault_meta
            .put(&mut wtxn, &event_key, &event_value)?;
        self.store
            .vault_meta
            .put(&mut wtxn, &usage_key, &usage.encode()?)?;

        let mut settled_record = record;
        if usage.used() >= budget.limit
            && budget.on_exhaust == EffectorBudgetOnExhaust::Suspend
            && settled_record.status == ConnectorKeyStatus::Active
        {
            let reason = budget_exhausted_reason(row_index);
            settled_record = suspend_connector_key_in_txn(
                &self.store,
                &mut wtxn,
                id,
                &settled_record,
                reason,
                settled_at,
            )?;
        }

        let row_read = budget_row_read(row_index, &budget, &usage);
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.spend_settle",
            &settled_record,
            policy.read_frontier_hash()?,
            settled_at,
        )?;
        wtxn.commit()?;
        Ok(row_read)
    }
}
