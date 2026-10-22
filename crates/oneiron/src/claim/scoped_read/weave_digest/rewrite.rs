//! A hard delete inside a saved weave period (FIX 7693, 8672). The period
//! keeps every row the deleted ref is not in: a loop row that names it
//! loses that ref, and a health card drafted from it loses its draft's
//! text, both in the erasure's own transaction, with the period's erase
//! index repaired to the refs it still carries. A source the period's own
//! checks read (a copied claim, a project, a link end, an audit's row)
//! still erases the whole period, as does a row that does not decode.
use super::{
    WireDigest, dependencies, digest_row_in, erase_weave_digest_in_txn, index_source_in_txn,
    invalid, loop_decisions, put_digest_row_in_txn, report_sources,
};
use crate::EntityId;
use crate::error::Result;
use crate::store::Store;

/// Carries out a hard delete of `source` in the saved period at
/// `digest_key`, which its erase index names: the whole period when
/// `source` gates it, else only the rows that name it. A rewritten period
/// drops its saved render, which was written over the rows as they read
/// before; its data still serves.
pub(super) fn erase_source_in_period_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    digest_key: &[u8],
    source: &EntityId,
) -> Result<()> {
    let Some(raw) = digest_row_in(store, txn, digest_key)? else {
        return Ok(());
    };
    let decoded = serde_json::from_slice::<WireDigest>(&raw)
        .ok()
        .and_then(|mut wire| {
            let rendered_at = wire.rendered_at;
            let lens_refused = wire.lens_refused.take();
            // A scheduled Owner period keeps its schedule basis (FIX 1259).
            let scheduled_basis = wire.scheduled_basis.take();
            wire.into_report()
                .ok()
                .map(|report| (rendered_at, (lens_refused, scheduled_basis), report))
        });
    let Some((rendered_at, (lens_refused, scheduled_basis), mut report)) = decoded else {
        return erase_weave_digest_in_txn(store, txn, digest_key);
    };
    let (Ok(gates), Ok(before)) = (
        report_sources(&report.value),
        dependencies::indexed_sources(&report.value),
    ) else {
        return erase_weave_digest_in_txn(store, txn, digest_key);
    };
    if gates.contains(source) {
        return erase_weave_digest_in_txn(store, txn, digest_key);
    }
    let mut rewritten = false;
    for item in report
        .value
        .sections
        .iter_mut()
        .flat_map(|section| &mut section.items)
    {
        rewritten |= loop_decisions::strip_ref(item, source);
        rewritten |= dependencies::scrub_draft_of(item, source);
    }
    // An index entry no row answers to any more: the caller drops it.
    if !rewritten {
        return Ok(());
    }
    let after = dependencies::indexed_sources(&report.value)?;
    let mut wire = WireDigest::from_report(rendered_at, &report)?;
    wire.lens_refused = lens_refused;
    wire.scheduled_basis = scheduled_basis;
    let bytes = serde_json::to_vec(&wire).map_err(|_| invalid())?;
    for gone in before.difference(&after) {
        index_source_in_txn(store, txn, gone, digest_key, false)?;
    }
    for added in after.difference(&before) {
        index_source_in_txn(store, txn, added, digest_key, true)?;
    }
    put_digest_row_in_txn(store, txn, digest_key, &bytes)
}
