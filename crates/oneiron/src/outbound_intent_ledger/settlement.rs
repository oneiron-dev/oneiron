//! What a ledger row's send came to beside its state (FIX 7960, 7964,
//! 8818, 11662): the remote task a provider accepted it as, the wait a
//! provider asked for after a rate or quota refusal, the budget its
//! admission reserved, and the actual cost its provider reported. One row
//! per intent id, in its own table beside the ledger row, written in the
//! same writer as the ledger change it records; the ledger row's own fields
//! stay as they are.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::types::{IntentId, IntentLedgerRecord, IntentLedgerResult, IntentState};
use crate::Vault;
use crate::connector_key::{
    ConnectorSpendBasis, ConnectorSpendEstimate, EffectorBudgetDebit, EffectorSpendReservationRow,
};
use crate::side_table::{self, Named, SideTable};

/// Intent id -> what its send came to beside its state. Key: hash32.
const SETTLEMENT: SideTable<IntentId, IntentSettlement, Named> =
    SideTable::new(&side_table::OUTBOUND_INTENT_SETTLEMENT);

/// A provider's handle on a send it accepted as a remote task (FIX 7960):
/// the intent is Deferred, and the engine never sends it again. The id is
/// opaque, untrusted provider data: never read as a URL or an instruction,
/// and never logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTaskHandle {
    pub id: String,
    /// The provider's polling hint, in seconds, when it gave one.
    pub poll_after_secs: Option<u64>,
    /// How the served host polls the task (FIX 11023); `None` when the
    /// send's credential cannot be presented again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll: Option<super::remote_task_poll::RemoteTaskPoll>,
}

impl fmt::Debug for RemoteTaskHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTaskHandle")
            .field("id", &format_args!("[{} bytes redacted]", self.id.len()))
            .field("poll_after_secs", &self.poll_after_secs)
            .field("poll", &self.poll)
            .finish()
    }
}

/// What a provider reported of a remote task it accepted (FIX 7960), as a
/// trusted transport reads it from the provider's own status answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RemoteTaskObservation {
    /// The task completed: the send was delivered.
    Completed,
    /// The task failed or was cancelled before it delivered.
    Failed,
}

/// A remote task's post-commit state and newly fired budget thresholds.
/// The trusted status caller delivers their steering through the same
/// next-turn queue as a synchronous outbound result, not a second channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteTaskSettlement {
    pub state: IntentState,
    pub budget_events: Vec<crate::connector_key::EffectorBudgetSettlementEvents>,
}

impl RemoteTaskSettlement {
    /// Messages to forward to the trusted caller's existing next-turn queue.
    #[must_use]
    pub fn steering_messages(&self) -> Vec<String> {
        let mut messages = Vec::new();
        for event in self
            .budget_events
            .iter()
            .flat_map(|events| &events.ladder_events)
        {
            crate::connector_key::append_effector_steering_message(&mut messages, event);
        }
        messages
    }
}

/// Why a provider refused a send it says to try again later (FIX 8818).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderWaitKind {
    /// A rate limit: the provider's HTTP 429.
    RateLimit,
    /// A spent quota, such as a monthly message allowance.
    Quota,
}

impl ProviderWaitKind {
    /// Stable receipt spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RateLimit => "rate_limit",
            Self::Quota => "quota",
        }
    }
}

/// A provider's refusal as the transport saw it: its kind and the seconds
/// it asked the caller to wait, when it named them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProviderWait {
    pub kind: ProviderWaitKind,
    pub retry_after_secs: Option<u64>,
}

impl ProviderWait {
    /// The wait as kept with its send: `retry_after_secs` from `now`, vault
    /// clock seconds.
    #[must_use]
    pub fn directive_at(self, now: u64) -> ProviderRetryDirective {
        ProviderRetryDirective {
            kind: self.kind,
            not_before: self.retry_after_secs.map(|secs| now.saturating_add(secs)),
        }
    }
}

/// A queued send's provider wait (FIX 8818): the send certainly did not go,
/// it stays queued, and no attempt goes before `not_before` (vault clock
/// seconds) when the provider named an edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderRetryDirective {
    pub kind: ProviderWaitKind,
    pub not_before: Option<u64>,
}

impl ProviderRetryDirective {
    /// The provider's edge, when it is still ahead of `now`.
    #[must_use]
    pub fn waits_at(&self, now: u64) -> Option<u64> {
        self.not_before.filter(|edge| *edge > now)
    }
}

/// Where a send's reserved budget stands (FIX 7964).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    /// Admitted and not settled: the send may still go, or may have gone.
    Reserved,
    /// The send was delivered: the reserved debit is its charge.
    Settled,
    /// The send certainly did not go: its debits are out. A still-pending
    /// retry restores them before transport.
    Released,
}

impl ReservationStatus {
    /// Stable receipt spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Released => "released",
        }
    }
}

/// The budget one admission reserved for its send (FIX 7964): every usage
/// entry its charge wrote, the co-actor's and the catalog pool's included.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetReservation {
    pub debits: Vec<EffectorBudgetDebit>,
    pub status: ReservationStatus,
    /// What a preauthorizing Spend row reserved for this send stood on (FIX
    /// 8689): the verb's declared price, whose debit is among `debits` and
    /// stays the send's charge once it is delivered unless its provider
    /// reports the actual cost (FIX 11662), or no price in the row's unit.
    /// `None` when no row preauthorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend: Option<ConnectorSpendBasis>,
    /// Every preauthorizing Spend row the send met, priced or not: where a
    /// reported actual cost is reconciled (FIX 11662).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spend_rows: Vec<EffectorSpendReservationRow>,
}

/// One intent's row in [`SETTLEMENT`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IntentSettlement {
    pub(crate) remote_task: Option<RemoteTaskHandle>,
    pub(crate) provider_wait: Option<ProviderRetryDirective>,
    pub(crate) reservation: Option<BudgetReservation>,
    /// The actual cost the send's provider reported for it (FIX 11662),
    /// kept before its Done, which reconciles the reservation to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reported_cost: Option<ConnectorSpendEstimate>,
}

/// Row `id`'s settlement as `txn` reads it; an empty one when none was
/// written.
///
/// # Errors
/// Storage and row-codec faults.
pub(crate) fn intent_settlement_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &IntentId,
) -> IntentLedgerResult<IntentSettlement> {
    Ok(SETTLEMENT.get(&vault.store, txn, id)?.unwrap_or_default())
}

/// Row `id`'s settlement, read in a snapshot of its own.
///
/// # Errors
/// Storage and row-codec faults.
pub(crate) fn intent_settlement(
    vault: &Vault,
    id: &IntentId,
) -> IntentLedgerResult<IntentSettlement> {
    let txn = vault
        .store
        .env
        .read_txn()
        .map_err(crate::error::Error::from)?;
    intent_settlement_in_txn(vault, &txn, id)
}

/// Rewrites row `id`'s settlement with `change` in `wtxn`; a settlement left
/// empty is not kept.
fn update_settlement_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &IntentId,
    change: impl FnOnce(&mut IntentSettlement),
) -> IntentLedgerResult<()> {
    let mut settlement = intent_settlement_in_txn(vault, wtxn, id)?;
    change(&mut settlement);
    if settlement == IntentSettlement::default() {
        SETTLEMENT.delete(&vault.store, wtxn, id)?;
    } else {
        SETTLEMENT.put(&vault.store, wtxn, id, &settlement)?;
    }
    Ok(())
}

/// Keeps the budget admission reserved for row `id`, in the admission's
/// writer (FIX 7964), with what its preauthorized spend stood on (FIX
/// 8689) and the preauthorizing rows it met (FIX 11662). A charge that
/// wrote no usage entry and met no preauthorizing row reserves nothing.
///
/// # Errors
/// Storage faults.
pub(crate) fn reserve_budget_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &IntentId,
    debits: Vec<EffectorBudgetDebit>,
    spend: Option<(ConnectorSpendBasis, Vec<EffectorSpendReservationRow>)>,
) -> IntentLedgerResult<()> {
    if debits.is_empty() && spend.is_none() {
        return Ok(());
    }
    crate::connector_key::set_effector_debits_reserved_in_txn(&vault.store, wtxn, &debits, true)?;
    let (spend, spend_rows) = spend.map_or((None, Vec::new()), |(basis, rows)| (Some(basis), rows));
    update_settlement_in_txn(vault, wtxn, id, |settlement| {
        settlement.reservation = Some(BudgetReservation {
            debits,
            status: ReservationStatus::Reserved,
            spend,
            spend_rows,
        });
    })
}

/// Keeps the actual cost the provider reported for row `id`'s send, in a
/// writer of its own before its Done commits (FIX 11662), when its
/// admission reserved a preauthorized spend that is not settled yet: that
/// Done reconciles the reservation to it. Any other send keeps nothing.
///
/// # Errors
/// Storage and row-codec faults.
pub(crate) fn keep_reported_cost(
    vault: &Vault,
    id: &IntentId,
    cost: ConnectorSpendEstimate,
) -> IntentLedgerResult<()> {
    let mut wtxn = vault
        .store
        .env
        .write_txn()
        .map_err(crate::error::Error::from)?;
    let reserved = intent_settlement_in_txn(vault, &wtxn, id)?
        .reservation
        .is_some_and(|reservation| {
            reservation.status == ReservationStatus::Reserved && reservation.spend.is_some()
        });
    if !reserved {
        return Ok(());
    }
    update_settlement_in_txn(vault, &mut wtxn, id, |settlement| {
        settlement.reported_cost = Some(cost);
    })?;
    wtxn.commit().map_err(crate::error::Error::from)?;
    Ok(())
}

/// Releases a certain non-delivery's budget in the outcome writer.
/// Prior possible delivery keeps it. Each charter debit must still name its
/// original approval before release can touch the current usage row.
pub(super) fn release_non_delivery_reservation_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &IntentLedgerRecord,
) -> IntentLedgerResult<()> {
    if record.delivery_uncertain {
        return Ok(());
    }
    let mut settlement = intent_settlement_in_txn(vault, wtxn, &record.id)?;
    let Some(reservation) = settlement.reservation.as_mut() else {
        return Ok(());
    };
    if reservation.status != ReservationStatus::Reserved {
        return Ok(());
    }
    crate::connector_key::release_effector_debits_in_txn(&vault.store, wtxn, &reservation.debits)?;
    reservation.status = ReservationStatus::Released;
    SETTLEMENT.put(&vault.store, wtxn, &record.id, &settlement)?;
    Ok(())
}

/// Restores a released reservation in the retry claim's writer after all
/// still-live debits fit. A blocked claim retains its Released status; a
/// dedupe takeover has abandoned the row and never restores its debits.
pub(super) fn restore_retry_reservation_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &IntentLedgerRecord,
) -> IntentLedgerResult<crate::connector_key::BudgetBlock> {
    use crate::connector_key::BudgetBlock;

    if record.state != IntentState::Pending {
        return Ok(BudgetBlock::Open);
    }
    let mut settlement = intent_settlement_in_txn(vault, wtxn, &record.id)?;
    let Some(reservation) = settlement.reservation.as_mut() else {
        return Ok(BudgetBlock::Open);
    };
    if reservation.status != ReservationStatus::Released {
        return Ok(BudgetBlock::Open);
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let block = crate::connector_key::restore_effector_debits_in_txn(
        &vault.store,
        wtxn,
        &reservation.debits,
        now,
    )?;
    if block == BudgetBlock::Open {
        reservation.status = ReservationStatus::Reserved;
        SETTLEMENT.put(&vault.store, wtxn, &record.id, &settlement)?;
    }
    Ok(block)
}

/// Settles `record`'s live reserved budget by its terminal state in the
/// writer that moved it (FIX 7964). Delivery keeps the charge and reconciles
/// preauthorized spend to reported actual cost (FIX 11662); a certain stop
/// releases it once. Possible delivery and accepted remote tasks retain it.
/// A certain non-delivery releases in its outcome writer and restores only
/// at retry claim, so a later stop cannot release it twice.
///
/// # Errors
/// Storage faults.
pub(super) fn settle_reservation_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &IntentLedgerRecord,
) -> IntentLedgerResult<Vec<crate::connector_key::EffectorBudgetSettlementEvents>> {
    let next = match record.state {
        IntentState::Done => ReservationStatus::Settled,
        IntentState::Abandoned if !record.delivery_uncertain => ReservationStatus::Released,
        IntentState::Abandoned | IntentState::Pending | IntentState::Deferred => {
            return Ok(Vec::new());
        }
    };
    let settlement = intent_settlement_in_txn(vault, wtxn, &record.id)?;
    let Some(reservation) = settlement.reservation else {
        return Ok(Vec::new());
    };
    if reservation.status != ReservationStatus::Reserved {
        return Ok(Vec::new());
    }
    if next == ReservationStatus::Released {
        crate::connector_key::release_effector_debits_in_txn(
            &vault.store,
            wtxn,
            &reservation.debits,
        )?;
    }
    let reconciled = match (next, settlement.reported_cost.as_ref()) {
        (ReservationStatus::Settled, Some(actual)) => {
            reconcile_spend_in_txn(vault, wtxn, &reservation, actual)?
        }
        _ => None,
    };
    let mut budget_events = Vec::new();
    if next == ReservationStatus::Settled {
        let debits = reconciled
            .as_ref()
            .map_or(reservation.debits.as_slice(), |(debits, _)| {
                debits.as_slice()
            });
        crate::connector_key::set_effector_debits_reserved_in_txn(
            &vault.store,
            wtxn,
            debits,
            false,
        )?;
        let now = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
        budget_events = crate::connector_key::fire_settled_effector_debits_in_txn(
            &vault.store,
            wtxn,
            debits,
            now,
        )?;
    }
    update_settlement_in_txn(vault, wtxn, &record.id, |settlement| {
        if let Some(reservation) = settlement.reservation.as_mut() {
            reservation.status = next;
            if let Some((debits, basis)) = reconciled {
                reservation.debits = debits;
                reservation.spend = Some(basis);
            }
        }
    })?;
    Ok(budget_events)
}

/// FIX 11662: `reservation`'s preauthorized spend reconciled to `actual`,
/// in `wtxn`: its debits with the estimate's entries swapped for the
/// actual's, and the basis that records both. `None` when it reserved no
/// spend, was reconciled already, or none of its rows is a preauthorizing
/// row in `actual`'s unit: the estimate then stays the charge, with the
/// reported cost kept beside it.
fn reconcile_spend_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    reservation: &BudgetReservation,
    actual: &ConnectorSpendEstimate,
) -> IntentLedgerResult<Option<(Vec<EffectorBudgetDebit>, ConnectorSpendBasis)>> {
    let estimated = match &reservation.spend {
        Some(ConnectorSpendBasis::Estimated(estimate)) => Some(estimate.clone()),
        Some(ConnectorSpendBasis::Unpriced) => None,
        Some(ConnectorSpendBasis::Reconciled { .. }) | None => return Ok(None),
    };
    // The meter's own trusted clock: the ledger says when it learned the
    // cost, as a settlement does.
    let now = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let reconciliation = crate::connector_key::reconcile_connector_spend_in_txn(
        &vault.store,
        wtxn,
        &reservation.spend_rows,
        &reservation.debits,
        actual,
        now,
    )?;
    if reconciliation.released.is_empty() && reconciliation.written.is_empty() {
        return Ok(None);
    }
    let mut debits = reservation.debits.clone();
    for released in &reconciliation.released {
        if let Some(position) = debits.iter().position(|debit| debit == released) {
            debits.remove(position);
        }
    }
    debits.extend(reconciliation.written);
    Ok(Some((
        debits,
        ConnectorSpendBasis::Reconciled {
            estimated,
            actual: actual.clone(),
        },
    )))
}

/// Keeps the provider's wait with row `id`'s definite non-delivery, in the
/// writer that records it (FIX 8818).
pub(super) fn keep_provider_wait_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &IntentId,
    directive: ProviderRetryDirective,
) -> IntentLedgerResult<()> {
    update_settlement_in_txn(vault, wtxn, id, |settlement| {
        settlement.provider_wait = Some(directive);
    })
}

/// Clears row `id`'s provider wait at the retry claim that ends it.
pub(super) fn clear_provider_wait_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &IntentId,
) -> IntentLedgerResult<()> {
    update_settlement_in_txn(vault, wtxn, id, |settlement| {
        settlement.provider_wait = None;
    })
}

/// Keeps the remote task handle of row `id`, which its provider accepted as
/// one, in the writer that moves it to Deferred (FIX 7960).
pub(super) fn keep_remote_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &IntentId,
    handle: RemoteTaskHandle,
) -> IntentLedgerResult<()> {
    update_settlement_in_txn(vault, wtxn, id, |settlement| {
        settlement.remote_task = Some(handle);
    })
}

/// Drops row `id`'s remote task handle when an erase takes the send's
/// request (FIX 9283, 10953): the provider's task id names that send. The
/// row's provider wait and reserved budget stay.
pub(super) fn forget_remote_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &IntentId,
) -> IntentLedgerResult<()> {
    update_settlement_in_txn(vault, wtxn, id, |settlement| {
        settlement.remote_task = None;
    })
}

/// Row `id`'s provider wait and its edge, when that edge is still ahead of
/// the vault clock's `now` (FIX 8818).
///
/// # Errors
/// Storage and row-codec faults.
pub(crate) fn provider_wait_edge(
    vault: &Vault,
    id: &IntentId,
    now: u64,
) -> IntentLedgerResult<Option<(ProviderRetryDirective, u64)>> {
    Ok(intent_settlement(vault, id)?
        .provider_wait
        .and_then(|directive| directive.waits_at(now).map(|edge| (directive, edge))))
}
