//! Judged-amendment fold writes.

use super::keys::{
    AGGREGATE_ROW_LABEL, MEMBER_KEY_PREFIX, MEMBER_ROW_LABEL, ROW_VERSION, StoredAggregate,
    StoredModelVersion, aggregate_key, decode_row, decoded_aggregate, encode_row, invalid, meta_key,
};
use super::scope::RoutingScopeKey;
use super::version::serving_model_version;
use crate::Vault;
use crate::edit_distance::attribution::{AmendmentClass, AmendmentJudgment, amendment_judgments};
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// The write door
// ---------------------------------------------------------------------------

/// Folds the amendment judged against `delta_receipt` into its scope.
///
/// **Receipt-bound.** The one argument is the receipt; the scope, the edit mass
/// and the outcome are all read back out of ED-03's judgment for it. There is
/// no path here for a caller to supply the numbers it would like folded, and
/// the ledger stays rebuildable from receipts alone (CID-7).
///
/// **First fold wins.** A run happened under exactly one generation, so a
/// receipt already bound to one is never re-folded — a second call after a
/// model swap would otherwise count the same amendment twice, once against a
/// generation that did not produce it. Re-judging a receipt is reflected by
/// [`rebuild_routing_projection`], which re-reads the ledger against the
/// bindings already recorded.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the receipt carries no judgment, or its
/// judgment's scope or edit mass is unusable; storage errors.
pub fn record_judged_amendment(vault: &Vault, delta_receipt: &str) -> Result<()> {
    let Some(judgment) = judgment_for(vault, delta_receipt)? else {
        return Err(invalid("routing projection cites an unjudged receipt"));
    };
    let member_key = meta_key(MEMBER_KEY_PREFIX, delta_receipt.as_bytes());
    let model_version = serving_model_version(vault)?;
    let fold = fold_of(&judgment)?;
    let scope = RoutingScopeKey::new(model_version.clone(), judgment.scope);
    let scope_row_key = aggregate_key(&scope)?;
    let member = encode_row(
        &StoredModelVersion {
            v: ROW_VERSION,
            model_version,
        },
        MEMBER_ROW_LABEL,
    )?;

    vault.with_write_txn(|wtxn| {
        // The binding is read in the transaction that writes it. An earlier
        // snapshot could only say the receipt was unfolded THEN, so two folds
        // of one receipt would both read "absent" and both count it — the
        // writer serialization below orders those writes without making either
        // one's decision to write correct.
        if vault.store.vault_meta.get(&*wtxn, &member_key)?.is_some() {
            return Ok(());
        }
        let mut aggregate = match vault.store.vault_meta.get(&*wtxn, &scope_row_key)? {
            Some(raw) => decoded_aggregate(&raw)?,
            None => StoredAggregate::default(),
        };
        apply_fold(&mut aggregate, fold)?;
        let encoded = encode_row(&aggregate, AGGREGATE_ROW_LABEL)?;
        vault.store.vault_meta.put(wtxn, &scope_row_key, &encoded)?;
        vault.store.vault_meta.put(wtxn, &member_key, &member)?;
        Ok(())
    })
}

/// The generation `delta_receipt`'s amendment was folded under, on the
/// caller's snapshot — or `None` when nothing folded it.
///
/// This is the binding [`record_judged_amendment`] wrote, read back: history,
/// not [`serving_model_version`], which answers for the model serving NOW and
/// would re-attribute an old amendment to a generation that never produced it.
/// A consumer tagging amendments with the model behind them reads THIS.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on an undecodable row; storage errors.
pub(crate) fn folded_model_version_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    delta_receipt: &str,
) -> Result<Option<String>> {
    let key = meta_key(MEMBER_KEY_PREFIX, delta_receipt.as_bytes());
    let Some(raw) = vault.store.vault_meta.get(rtxn, &key)? else {
        return Ok(None);
    };
    let row: StoredModelVersion = decode_row(&raw, MEMBER_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(MEMBER_ROW_LABEL));
    }
    Ok(Some(row.model_version))
}

/// One judgment's contribution: its edit mass, and whether it was sound.
#[derive(Debug, Clone, Copy)]
pub(super) struct Fold {
    d_norm: f64,
    sound: bool,
}

/// What one judgment contributes.
///
/// A proposal is SOUND when the amendment says nothing was wrong with it — the
/// world moved ([`AmendmentClass::Environment`]) or the decider wanted it
/// otherwise ([`AmendmentClass::PreferenceShift`]). Every other class routes
/// from "the proposal was wrong on its own terms", including
/// [`AmendmentClass::Discovery`], which charges nobody but does not mean the
/// draft stood.
pub(super) fn fold_of(judgment: &AmendmentJudgment) -> Result<Fold> {
    let d_norm = f64::from(judgment.d_norm);
    if !d_norm.is_finite() || d_norm < 0.0 {
        return Err(invalid(
            "a routing fold needs a finite non-negative edit mass",
        ));
    }
    Ok(Fold {
        d_norm,
        sound: matches!(
            judgment.class,
            AmendmentClass::Environment | AmendmentClass::PreferenceShift
        ),
    })
}

pub(super) fn apply_fold(aggregate: &mut StoredAggregate, fold: Fold) -> Result<()> {
    aggregate.v = ROW_VERSION;
    aggregate.runs = aggregate
        .runs
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("routing aggregate runs"))?;
    aggregate.d_norm_sum += fold.d_norm;
    // `sound` counts a subset of `runs`, so the bound above is its bound too.
    aggregate.sound += u64::from(fold.sound);
    Ok(())
}

fn judgment_for(vault: &Vault, receipt_id: &str) -> Result<Option<AmendmentJudgment>> {
    Ok(amendment_judgments(vault)?
        .into_iter()
        .find(|judgment| judgment.receipt_id == receipt_id))
}
