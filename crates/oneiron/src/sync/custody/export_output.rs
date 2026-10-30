//! Export secret supplements on the window plane (FIX 11843): the sealed
//! copy an export secret request's holder commits rides the custody map,
//! keyed `export_output:` and the request's entry hash, in the base window
//! of the month it was sealed in, each row committed on its own, so the
//! owner's server reads it whether or not it is the holder.
//!
//! - Admission takes a row only whole, filed under its own request, in its
//!   sealing month's base window, within one row's bound, and, once this
//!   vault folds the request's signed result, only the copy that result
//!   names (FIX 12065). With no result folded yet, whether it names the
//!   copy is judged where the copy is kept.
//! - Reverse rematerialization relays each copy this vault keeps that stands
//!   on its fold (`KeptExportOutput::stands`), and drops a row once its
//!   request is refused here, its result names another copy, or its secret
//!   an admitted revoke ended or an erase here fenced. A row whose request
//!   or result this vault has not folded stays, as an input row's does; any
//!   other stays until its base window retires, as no fold says the owner
//!   imported it.
//! - Every install keeps a relayed copy that stands on its fold, once,
//!   rechecked in the writer that keeps it. Only the recipient machine opens
//!   it; no install that keeps or relays it can.

use std::collections::BTreeSet;

use loro::{LoroDoc, LoroValue, ValueOrContainer};

use super::super::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
use super::super::types::WindowKey;
use super::{CUSTODY_MAP, admission_read_fault, commit_custody, holds_custody_map, refused};
use crate::Vault;
use crate::authority::{AuthorityFold, SealedWorkOutput};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::secret_custody::holder_export::{
    KeptExportOutput, MAX_RELAYED_OUTPUT_BYTES, held_export_outputs,
    keep_relayed_export_output_in_txn, relayed_export_output_due_in_txn,
};

/// The key prefix of a sealed copy's row in the custody map, before its
/// request's entry hash in hex.
pub(crate) const EXPORT_OUTPUT_ROW_PREFIX: &str = "export_output:";

fn output_row(request: &[u8; 32]) -> String {
    format!("{EXPORT_OUTPUT_ROW_PREFIX}{}", bytes_to_hex_lower(request))
}

/// Whether `value` is a whole copy filed under `row_key`, the map key after
/// its prefix: what a checkpoint files as secret custody's.
pub(super) fn filed(row_key: &str, value: &[u8]) -> bool {
    KeptExportOutput::decode(value).is_some_and(|kept| bytes_to_hex_lower(&kept.request) == row_key)
}

/// Admits one sealed copy under `row_key`, the map key after its prefix:
/// one that decodes within one row's bound, filed under its own request, in
/// its sealing month's base window, and that the request's signed result
/// names when `vault` folds one (FIX 12065): a forged copy under a real
/// request is refused here, not carried until its window retires.
pub(super) fn admit_export_output(
    vault: &Vault,
    key: Option<&WindowKey>,
    row_key: &str,
    bytes: &[u8],
) -> Result<()> {
    if bytes.len() > MAX_RELAYED_OUTPUT_BYTES {
        return Err(refused("export secret supplement past one row's bound"));
    }
    let kept = KeptExportOutput::decode(bytes)
        .ok_or_else(|| refused("malformed export secret supplement"))?;
    if bytes_to_hex_lower(&kept.request) != row_key {
        return Err(refused(
            "export secret supplement filed under another request",
        ));
    }
    if key.is_some_and(|key| *key != WindowKey::from_timestamp(kept.sealed_at)) {
        return Err(refused(
            "export secret supplement outside its sealing month's base window",
        ));
    }
    // Reading this vault's own authority is the store's work: its fault is
    // this machine's, never the peer's refused update (FIX 5925).
    let rtxn = vault.store.env.read_txn().map_err(admission_read_fault)?;
    let fold = vault
        .authority_view_readonly_in_txn(&rtxn)
        .map_err(admission_read_fault)?;
    if fold
        .owner_work_result(&kept.request)
        .is_some_and(|answer| !names_copy(answer.outcome.sealed_output(), &kept.sealed))
    {
        // The row's key alone: never a byte of the copy.
        tracing::warn!(
            request = row_key,
            "an export secret supplement row its request's signed result does not name was refused"
        );
        return Err(refused(
            "export secret supplement its request's signed result does not name",
        ));
    }
    Ok(())
}

/// Whether `output`, what a signed result names, is the copy `sealed`: its
/// digest and length.
fn names_copy(output: Option<&SealedWorkOutput>, sealed: &[u8]) -> bool {
    output.is_some_and(|output| {
        output.digest == *blake3::hash(sealed).as_bytes()
            && usize::try_from(output.bytes).is_ok_and(|bytes| bytes == sealed.len())
    })
}

/// Relays each copy this vault keeps into window `key`, the base window of
/// its sealing month, while it stands on `fold` with `erased` as this
/// vault's erase fences, and drops from the window every row due to leave
/// it. Returns whether it wrote any.
pub(super) fn mirror_export_outputs(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    fold: &AuthorityFold,
    erased: &BTreeSet<EntityId>,
) -> Result<bool> {
    let kept = held_export_outputs(vault)?;
    let holds = holds_custody_map(doc);
    if kept.is_empty() && !holds {
        return Ok(false);
    }
    let fenced = |secret: &EntityId| erased.contains(secret);
    let mut wrote = false;
    for output in kept {
        if WindowKey::from_timestamp(output.sealed_at) != *key || !output.stands(fold, fenced) {
            continue;
        }
        let bytes = output.encode();
        if bytes.len() > MAX_RELAYED_OUTPUT_BYTES {
            tracing::debug!(
                window = %key,
                bytes = bytes.len(),
                "an export secret supplement past one row's bound stays with its keepers"
            );
            continue;
        }
        let map = doc.get_map(CUSTODY_MAP);
        let row = output_row(&output.request);
        if map_get_bytes(&map, &row).as_deref() != Some(bytes.as_slice()) {
            // Each row commits on its own: no one update outgrows a frame.
            map_insert_bytes(&map, &row, &bytes)?;
            commit_custody(doc);
            wrote = true;
        }
    }
    if holds {
        let map = doc.get_map(CUSTODY_MAP);
        let mut done = Vec::new();
        map.for_each(|map_key, value| {
            if !map_key.starts_with(EXPORT_OUTPUT_ROW_PREFIX) {
                return;
            }
            let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value else {
                return;
            };
            if KeptExportOutput::decode(&bytes).is_some_and(|output| output.row_done(fold, fenced))
            {
                done.push(map_key.to_owned());
            }
        });
        for row in done {
            map_delete(&map, &row)?;
            wrote = true;
        }
    }
    Ok(wrote)
}

/// Keeps each relayed copy, filed under its own request, that stands on
/// this vault's fold and that it keeps no copy for yet, checked again in the
/// writer that keeps it. Any other row stays in the window, unread. A row
/// that fails is logged and left.
pub(super) fn keep_relayed_export_outputs(
    vault: &Vault,
    window: &str,
    rows: Vec<(String, Vec<u8>)>,
) {
    if rows.is_empty() {
        return;
    }
    let outcome = (|| -> Result<usize> {
        let due = {
            let rtxn = vault.store.env.read_txn()?;
            let fold = vault.authority_view_readonly_in_txn(&rtxn)?;
            let mut due = Vec::new();
            for (map_key, bytes) in &rows {
                let Some(output) = KeptExportOutput::decode(bytes) else {
                    continue;
                };
                if *map_key == output_row(&output.request)
                    && relayed_export_output_due_in_txn(vault, &rtxn, &fold, &output)?
                {
                    due.push(output);
                }
            }
            due
        };
        if due.is_empty() {
            return Ok(0);
        }
        vault.with_write_txn_grouped(|wtxn| {
            let fold = vault.authority_view_readonly_in_txn(wtxn)?;
            let mut kept = 0;
            for output in &due {
                if keep_relayed_export_output_in_txn(vault, wtxn, &fold, output)? {
                    kept += 1;
                }
            }
            Ok(kept)
        })
    })();
    match outcome {
        Ok(kept) if kept > 0 => {
            tracing::debug!(window, kept, "export secret supplements kept for the owner");
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(window, error = %error, "export secret supplements not kept");
        }
    }
}
