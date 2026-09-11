//! Escalation write doors, N dial, per-scope stats.

use std::collections::VecDeque;

use super::storage::{
    ESCALATION_ROW_LABEL, ROW_VERSION, StoredEscalation, encode_row, escalation_key,
    escalation_key_id, escalation_row, escalation_scope_prefix, normalized_scope, ruling_parts,
};
use super::types::{EscalationReceipt, EscalationRuling, EscalationStats, EscalationTrigger};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::store::Store;
use crate::vault::Vault;

/// `vault_meta` key of the N dial: how many agreeing rulings earn a proposed
/// standing policy. The house per-feature key const (cf.
/// `inbox::INBOX_REVIEW_DIAL_KEY`); `settings.rs` is UI customization and owns
/// nothing here.
pub const ESCALATION_STANDING_N_KEY: &[u8] = b"edit_distance/escalation/standing_n/dial/v1";

/// How many of a `(scope, trigger)` pair's newest rulings [`EscalationStats`]
/// retains. A history is for reading a pattern, not for replaying an audit —
/// the receipt family is where the whole record lives.
pub const ESCALATION_LAST_RULINGS_BOUND: usize = 8;

/// Agreeing rulings that earn a proposed standing policy, absent a dial.
pub const DEFAULT_ESCALATION_STANDING_N: u32 = 3;

// ---------------------------------------------------------------------------
// The N dial
// ---------------------------------------------------------------------------

/// Agreeing rulings a `(scope, trigger)` pair owes before a standing policy is
/// proposed: the dial if one is set, else [`DEFAULT_ESCALATION_STANDING_N`].
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on an unreadable dial row, plus storage failures.
pub fn escalation_standing_n(vault: &Vault) -> Result<u32> {
    let rtxn = vault.store.env.read_txn()?;
    escalation_standing_n_in_txn(&vault.store, &rtxn)
}

pub(super) fn escalation_standing_n_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<u32> {
    let Some(raw) = store.vault_meta.get(txn, ESCALATION_STANDING_N_KEY)? else {
        return Ok(DEFAULT_ESCALATION_STANDING_N);
    };
    let bytes: [u8; 4] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("escalation standing-N dial"))?;
    Ok(u32::from_le_bytes(bytes))
}

/// Sets the N dial.
///
/// # Errors
///
/// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) when `n` is zero — a standing policy earned
/// by no rulings at all is not a learned policy — plus storage failures.
pub fn set_escalation_standing_n(vault: &Vault, n: u32) -> Result<()> {
    if n == 0 {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "a standing-policy threshold of zero rulings is not a threshold",
        )));
    }
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, ESCALATION_STANDING_N_KEY, &n.to_le_bytes())?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// The ledger
// ---------------------------------------------------------------------------

/// Appends one ruled escalation, returning the row's handle.
///
/// # Errors
///
/// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) when the scope is unusable, or when a
/// magnitude band rides a trigger that has no magnitude; plus Δ encode and
/// storage failures.
pub fn record_escalation(vault: &Vault, receipt: EscalationReceipt) -> Result<EntityId> {
    record_escalation_at(vault, receipt, crate::unix_seconds_now())
}

/// [`record_escalation`] against a caller-supplied clock.
pub(crate) fn record_escalation_at(
    vault: &Vault,
    receipt: EscalationReceipt,
    at: u64,
) -> Result<EntityId> {
    let scope = normalized_scope(&receipt.scope)?.to_owned();
    if receipt.budget_band.is_some() && receipt.trigger != EscalationTrigger::Budget {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "only a budget-triggered escalation carries a magnitude band",
        )));
    }
    let (ruling, delta) = ruling_parts(&receipt.ruling)?;
    let id = EntityId::now();
    let key = escalation_key(&scope, &id);
    let row = StoredEscalation {
        v: ROW_VERSION,
        task_ref: receipt.task_ref.to_hex(),
        scope,
        trigger: receipt.trigger.as_str().to_owned(),
        question: receipt.question,
        ruling,
        delta,
        rationale: receipt.rationale,
        budget_band: receipt.budget_band,
        at,
    };
    let data = encode_row(&row, ESCALATION_ROW_LABEL)?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &data)?;
        Ok(())
    })?;
    Ok(id)
}

/// One `(scope, trigger)` pair's folded ruling history.
///
/// Scans that scope's whole range rather than a capped suffix: counts are not
/// derivable from a prefix of the history, and the range walked is one scope's
/// rows, not the family's.
///
/// # Errors
///
/// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) on an unusable scope,
/// [`Error::CorruptedIndex`] on an unreadable row, plus storage failures.
pub fn escalation_stats(
    vault: &Vault,
    scope: &str,
    trigger: EscalationTrigger,
) -> Result<EscalationStats> {
    let rtxn = vault.store.env.read_txn()?;
    let mut stats = EscalationStats::default();
    let mut recent: VecDeque<EscalationRuling> = VecDeque::new();
    for (_, row) in scope_rows_in_txn(&vault.store, &rtxn, scope, trigger)? {
        let ruling = row.ruling()?;
        match ruling {
            EscalationRuling::Approve => stats.approve = stats.approve.saturating_add(1),
            EscalationRuling::Deny => stats.deny = stats.deny.saturating_add(1),
            EscalationRuling::Amend(_) => stats.amend = stats.amend.saturating_add(1),
        }
        recent.push_back(ruling);
        if recent.len() > ESCALATION_LAST_RULINGS_BOUND {
            recent.pop_front();
        }
    }
    stats.last_rulings = recent.into();
    Ok(stats)
}

/// One `(scope, trigger)` pair's rows, with their ids, in write order.
pub(super) fn scope_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scope: &str,
    trigger: EscalationTrigger,
) -> Result<Vec<(EntityId, StoredEscalation)>> {
    let scope = normalized_scope(scope)?;
    let mut rows = Vec::new();
    for entry in store
        .vault_meta
        .prefix_iter(txn, &escalation_scope_prefix(scope))?
    {
        let (key, raw) = entry?;
        let row = escalation_row(&raw)?;
        if row.trigger()? == trigger {
            rows.push((escalation_key_id(&key)?, row));
        }
    }
    Ok(rows)
}
