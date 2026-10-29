//! What a ledger row's send came to beside its state (FIX 7960, 7964,
//! 8818): the remote task a provider accepted it as, the wait a provider
//! asked for after a rate or quota refusal, and the budget its admission
//! reserved. One row per intent id, in its own table beside the ledger row,
//! written in the same writer as the ledger change it records; the ledger
//! row's own fields stay as they are.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::types::{IntentId, IntentLedgerRecord, IntentLedgerResult, IntentState};
use crate::Vault;
use crate::connector_key::EffectorBudgetDebit;
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
}

impl fmt::Debug for RemoteTaskHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTaskHandle")
            .field("id", &format_args!("[{} bytes redacted]", self.id.len()))
            .field("poll_after_secs", &self.poll_after_secs)
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
    /// The send certainly did not go and never will: its debit came out.
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
    /// stays the send's charge once it is delivered, or no price in the
    /// row's unit. `None` when no row preauthorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend: Option<crate::connector_key::ConnectorSpendBasis>,
}

/// One intent's row in [`SETTLEMENT`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IntentSettlement {
    pub(crate) remote_task: Option<RemoteTaskHandle>,
    pub(crate) provider_wait: Option<ProviderRetryDirective>,
    pub(crate) reservation: Option<BudgetReservation>,
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
/// 8689). A charge that wrote no usage entry and met no preauthorizing row
/// reserves nothing.
///
/// # Errors
/// Storage faults.
pub(crate) fn reserve_budget_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &IntentId,
    debits: Vec<EffectorBudgetDebit>,
    spend: Option<crate::connector_key::ConnectorSpendBasis>,
) -> IntentLedgerResult<()> {
    if debits.is_empty() && spend.is_none() {
        return Ok(());
    }
    update_settlement_in_txn(vault, wtxn, id, |settlement| {
        settlement.reservation = Some(BudgetReservation {
            debits,
            status: ReservationStatus::Reserved,
            spend,
        });
    })
}

/// Settles `record`'s reserved budget by the state it now stands in, in the
/// writer that moved it (FIX 7964): a delivered send's reservation is its
/// charge; a send that stopped and certainly never went gives its debit
/// back, in the window it was taken in. A send that may have gone, waits on
/// a provider or a remote task, or may still be retried keeps its
/// reservation. A reservation settles or releases once.
///
/// # Errors
/// Storage faults.
pub(super) fn settle_reservation_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &IntentLedgerRecord,
) -> IntentLedgerResult<()> {
    let next = match record.state {
        IntentState::Done => ReservationStatus::Settled,
        IntentState::Abandoned if !record.delivery_uncertain => ReservationStatus::Released,
        IntentState::Abandoned | IntentState::Pending | IntentState::Deferred => return Ok(()),
    };
    let Some(reservation) = intent_settlement_in_txn(vault, wtxn, &record.id)?.reservation else {
        return Ok(());
    };
    if reservation.status != ReservationStatus::Reserved {
        return Ok(());
    }
    if next == ReservationStatus::Released {
        crate::connector_key::release_effector_debits_in_txn(
            &vault.store,
            wtxn,
            &reservation.debits,
        )?;
    }
    update_settlement_in_txn(vault, wtxn, &record.id, |settlement| {
        if let Some(reservation) = settlement.reservation.as_mut() {
            reservation.status = next;
        }
    })
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
