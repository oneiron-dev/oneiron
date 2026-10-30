//! An erased row out of the eval cases' source sets (FIX 6933): each case's
//! own set and every label's on it; and out of the source sets of every case
//! a measurement recorded (FIX 10447).

use super::measurement::{measurements_in_txn, put_measurement_in_txn};
use super::{CASE_PREFIX, EvalCase, encode, rows_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Drops `id` from a known source set; `true` when the set named it. An
/// unknown set stays unknown, and one left empty stays known-empty.
pub(crate) fn forget_source_row(rows: &mut Option<Vec<EntityId>>, id: &EntityId) -> bool {
    let Some(rows) = rows else {
        return false;
    };
    let before = rows.len();
    rows.retain(|row| row != id);
    rows.len() != before
}

/// Drops `id` from `case`'s source rows and from every label's on it, even
/// when the case's own set is unknown; `true` when any of them named it.
pub(crate) fn forget_eval_case_source_rows(case: &mut EvalCase, id: &EntityId) -> bool {
    let mut changed = forget_source_row(&mut case.source_rows, id);
    for label in &mut case.labels {
        changed |= forget_source_row(&mut label.source_rows, id);
    }
    changed
}

/// Drops an erased row `id` from every eval case's and every label's source
/// rows (FIX 6933), rewriting only the cases that named it, in the case's own
/// encoding and never through the side-row wall: forgetting an id adds
/// nothing to admit. Each case keeps its labels, parents, receipts, family,
/// split, draw probability and times. The measurements that recorded a case
/// get the same erased form in the same pass
/// ([`forget_measurement_source_rows`]). Registered on the case table's
/// declaration; a source may be any row, so this reads every case and every
/// measurement for each erased id.
///
/// # Errors
///
/// Storage errors, or a stored case that does not decode.
pub(crate) fn erase_eval_source_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut named = Vec::new();
    for mut case in rows_in_txn::<EvalCase>(vault, wtxn, CASE_PREFIX)? {
        if forget_eval_case_source_rows(&mut case, id) {
            named.push(case);
        }
    }
    for case in named {
        let key = [CASE_PREFIX, case.id.as_bytes()].concat();
        vault.store.vault_meta.put(wtxn, &key, &encode(&case)?)?;
    }
    forget_measurement_source_rows(vault, wtxn, id)
}

/// The measurement half of [`erase_eval_source_in_txn`] (FIX 10447): drops an
/// erased row `id` from the source rows of every case a measurement recorded,
/// in the erased form an eval case gets ([`forget_source_row`]), rewriting
/// only the measurements that named it. Each keeps its request, state,
/// members, exposures, family summaries and card, and each recorded case its
/// id, family, stratum, task hash, legs and times: no output reference or
/// receipt id on a leg is copied from a source row, and every count the
/// measurement shows stays as it was measured.
///
/// # Errors
///
/// Storage errors, or a stored measurement that does not decode.
pub(crate) fn forget_measurement_source_rows(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut named = Vec::new();
    for (digest, mut row) in measurements_in_txn(vault, wtxn)? {
        let mut changed = false;
        for case in &mut row.cases {
            changed |= forget_source_row(&mut case.source_rows, id);
        }
        if changed {
            named.push((digest, row));
        }
    }
    for (digest, row) in named {
        put_measurement_in_txn(vault, wtxn, &digest, &row)?;
    }
    Ok(())
}
