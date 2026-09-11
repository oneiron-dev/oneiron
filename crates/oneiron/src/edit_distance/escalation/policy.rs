//! Standing-policy proposal, read seam, and owner accept.

use super::ledger::{escalation_standing_n_in_txn, scope_rows_in_txn};
use super::storage::{
    ROW_VERSION, STANDING_POLICY_KEY_PREFIX, STANDING_POLICY_ROW_LABEL, StoredEscalation,
    StoredStandingPolicy, encode_row, escalation_receipt_id, normalized_scope, ruling_from_parts,
    ruling_parts, standing_policy_key, standing_policy_row, trigger_from_token,
};
use super::types::{EscalationTrigger, StandingPolicy, StandingPolicyStatus};
use crate::entity_id::EntityId;
use crate::error::GateError;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::vault::Vault;

// ---------------------------------------------------------------------------
// Standing policy
// ---------------------------------------------------------------------------

/// Proposes a standing policy when the newest [`escalation_standing_n`] rulings
/// on `(scope, trigger)` agree, returning the new row's handle.
///
/// `None` — never an error — for every ordinary reason not to propose: too
/// little history, rulings that disagree, or a row that already governs this
/// pair. A pattern that has not formed is not a failure.
///
/// The proposed row cites the rulings that earned it and, for an
/// [`EscalationTrigger::Budget`] pair, records the band ceiling every one of
/// them covered — the MINIMUM of their bands. That is what makes the guard
/// real: N approvals of small asks mint a policy for small asks, and one
/// approval of a large one inside that window does not widen it. A single
/// band-less ruling among them leaves the ceiling `None`, which covers no
/// banded ask at all.
///
/// # Errors
///
/// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) on an unusable scope,
/// [`Error::CorruptedIndex`] on an unreadable row, plus storage failures.
pub fn maybe_propose_standing_policy(
    vault: &Vault,
    scope: &str,
    trigger: EscalationTrigger,
) -> Result<Option<EntityId>> {
    maybe_propose_standing_policy_at(vault, scope, trigger, crate::unix_seconds_now())
}

/// [`maybe_propose_standing_policy`] against a caller-supplied clock.
pub(crate) fn maybe_propose_standing_policy_at(
    vault: &Vault,
    scope: &str,
    trigger: EscalationTrigger,
    at: u64,
) -> Result<Option<EntityId>> {
    let scope = normalized_scope(scope)?.to_owned();
    let row_ref = EntityId::now();
    vault.with_write_txn(|wtxn| {
        let key = standing_policy_key(&scope, trigger);
        if vault.store.vault_meta.get(&*wtxn, &key)?.is_some() {
            return Ok(None);
        }
        let n = escalation_standing_n_in_txn(&vault.store, &*wtxn)?;
        let rows = scope_rows_in_txn(&vault.store, &*wtxn, &scope, trigger)?;
        let Some(window) = newest_agreeing_window(&rows, n)? else {
            return Ok(None);
        };
        let row = StoredStandingPolicy {
            v: ROW_VERSION,
            row_ref: row_ref.to_hex(),
            scope,
            trigger: trigger.as_str().to_owned(),
            ruling: window.ruling,
            delta: window.delta,
            band_ceiling: window.band_ceiling,
            cited_receipts: window.cited_receipts,
            proposed_at: at,
            accepted_at: None,
        };
        let data = encode_row(&row, STANDING_POLICY_ROW_LABEL)?;
        vault.store.vault_meta.put(wtxn, &key, &data)?;
        Ok(Some(row_ref))
    })
}

/// What a policy learned from an agreeing window would carry.
struct AgreeingWindow {
    ruling: String,
    delta: Option<Vec<u8>>,
    band_ceiling: Option<u64>,
    cited_receipts: Vec<String>,
}

/// The newest `n` rows when they rule identically, else `None`.
///
/// Agreement is on the RULING, Δ included: two amendments that changed
/// different things are two answers, not a pattern.
fn newest_agreeing_window(
    rows: &[(EntityId, StoredEscalation)],
    n: u32,
) -> Result<Option<AgreeingWindow>> {
    let n = usize::try_from(n).unwrap_or(usize::MAX);
    if n == 0 || rows.len() < n {
        return Ok(None);
    }
    let window = &rows[rows.len() - n..];
    let Some(((_, head), rest)) = window.split_first() else {
        return Ok(None);
    };
    let ruling = head.ruling()?;
    for (_, row) in rest {
        if row.ruling()? != ruling {
            return Ok(None);
        }
    }
    // Every citing ruling has to cover the ceiling, so the minimum is what the
    // window is worth — and one band-less ruling in it makes the whole window
    // band-less, which `covers_ask` reads as covering nothing.
    let band_ceiling = window.iter().try_fold(u64::MAX, |floor, (_, row)| {
        row.budget_band.map(|band| floor.min(band))
    });
    let (ruling, delta) = ruling_parts(&ruling)?;
    Ok(Some(AgreeingWindow {
        ruling,
        delta,
        band_ceiling,
        cited_receipts: window
            .iter()
            .map(|(id, _)| escalation_receipt_id(id))
            .collect(),
    }))
}

/// The standing policy governing `(scope, trigger)`, if one exists.
///
/// The read ES-07 runs before repeating an ask. Its `Err` arm is load-bearing:
/// a row this engine cannot decode is UNCERTAINTY, not absence, and the caller
/// escalates rather than substituting a guess for a policy.
///
/// # Errors
///
/// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) on an unusable scope,
/// [`Error::CorruptedIndex`] on an unreadable row, plus storage failures.
pub fn standing_policy_for(
    vault: &Vault,
    scope: &str,
    trigger: EscalationTrigger,
) -> Result<Option<StandingPolicy>> {
    let scope = normalized_scope(scope)?;
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &standing_policy_key(scope, trigger))?
    else {
        return Ok(None);
    };
    standing_policy_parts(&standing_policy_row(&raw)?).map(Some)
}

fn standing_policy_parts(row: &StoredStandingPolicy) -> Result<StandingPolicy> {
    Ok(StandingPolicy {
        row_ref: EntityId::from_hex(&row.row_ref)
            .map_err(|_| Error::CorruptedIndex(STANDING_POLICY_ROW_LABEL))?,
        scope: row.scope.clone(),
        trigger: trigger_from_token(&row.trigger, STANDING_POLICY_ROW_LABEL)?,
        status: policy_status(row),
        ruling: ruling_from_parts(&row.ruling, row.delta.as_deref(), STANDING_POLICY_ROW_LABEL)?,
        budget_band_ceiling: row.band_ceiling,
        cited_receipts: row.cited_receipts.clone(),
    })
}

const fn policy_status(row: &StoredStandingPolicy) -> StandingPolicyStatus {
    if row.accepted_at.is_some() {
        StandingPolicyStatus::Accepted
    } else {
        StandingPolicyStatus::Proposed
    }
}

/// The owner's tap: flips a proposed row to [`StandingPolicyStatus::Accepted`],
/// and the only door that does.
///
/// Idempotent on a row already accepted — the act happened once, and its
/// acceptance receipt keeps the time it happened rather than the time it was
/// re-affirmed.
///
/// # Errors
///
/// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) when no row carries `row_ref`, plus
/// [`Error::CorruptedIndex`] on an unreadable row and storage failures.
pub fn accept_standing_policy(vault: &Vault, row_ref: &EntityId) -> Result<()> {
    accept_standing_policy_at(vault, row_ref, crate::unix_seconds_now())
}

/// [`accept_standing_policy`] against a caller-supplied clock.
pub(crate) fn accept_standing_policy_at(vault: &Vault, row_ref: &EntityId, at: u64) -> Result<()> {
    let wanted = row_ref.to_hex();
    vault.with_write_txn(|wtxn| {
        let found = find_standing_policy_in_txn(&vault.store, &*wtxn, &wanted)?;
        let Some((key, mut row)) = found else {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "no standing escalation policy carries this row ref",
            )));
        };
        if row.accepted_at.is_some() {
            return Ok(());
        }
        row.accepted_at = Some(at);
        let data = encode_row(&row, STANDING_POLICY_ROW_LABEL)?;
        vault.store.vault_meta.put(wtxn, &key, &data)?;
        Ok(())
    })
}

/// The standing-policy row carrying `row_ref`, with its key.
///
/// A scan, deliberately: the family is keyed by what a row GOVERNS so the hot
/// read is a lookup, and acceptance — an owner tap, once per row — is what pays
/// for it.
fn find_standing_policy_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    row_ref_hex: &str,
) -> Result<Option<(Vec<u8>, StoredStandingPolicy)>> {
    for entry in store
        .vault_meta
        .prefix_iter(txn, STANDING_POLICY_KEY_PREFIX)?
    {
        let (key, raw) = entry?;
        let row = standing_policy_row(&raw)?;
        if row.row_ref == row_ref_hex {
            return Ok(Some((key.to_vec(), row)));
        }
    }
    Ok(None)
}
