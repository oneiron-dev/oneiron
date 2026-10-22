//! A custody input's witness parts on the window plane (FIX 8088): a
//! witness past one row rides beside its input as numbered rows of its own,
//! keyed `witness:` and the part's own key, in the base window of the month
//! it was sealed in, each committed on its own.
//!
//! - Admission takes a part only whole and signed by the signer it names,
//!   over its own frame and bytes, filed under its own key in its sealing
//!   month's window: no sibling is needed, and none is waited on.
//! - Reverse rematerialization relays each part this vault keeps while its
//!   request awaits the holder, one part to a commit, and drops a part once
//!   its request is answered, refused or on a revoked secret here. A part's
//!   request this vault has not folded stays, as an input row's does.
//! - The holder a counted, unanswered request names keeps each part it
//!   names that the request's own signer signed, rechecked in the writer
//!   that keeps it, in place of a kept part that is not; its pickup joins
//!   them. A request it does not hold stays opaque, relay-pending.

use heed::RoTxn;
use loro::{LoroDoc, LoroValue, ValueOrContainer};

use super::super::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
use super::super::types::WindowKey;
use super::{CUSTODY_MAP, commit_custody, holds_custody_map, names_input, refused};
use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityFold, AuthorityKey};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::secret_custody::{
    RelayedInput, WitnessPart, held_input_in_txn, held_witness_in_txn, held_witnesses,
    keep_witness_in_txn,
};

/// The key prefix of a witness part's row in the custody map, before its
/// own key in hex.
pub(crate) const WITNESS_ROW_PREFIX: &str = "witness:";

fn witness_row(key: &[u8; 32]) -> String {
    format!("{WITNESS_ROW_PREFIX}{}", bytes_to_hex_lower(key))
}

/// Admits one witness part under `row_key`, the map key after its prefix:
/// a part that decodes, filed under its own key, signed by the signer it
/// names, in its sealing month's base window.
pub(super) fn admit_witness_part(
    key: Option<&WindowKey>,
    row_key: &str,
    bytes: &[u8],
) -> Result<()> {
    let part = WitnessPart::decode(bytes).ok_or_else(|| refused("malformed witness part"))?;
    if bytes_to_hex_lower(&part.row_key()) != row_key {
        return Err(refused("witness part filed under another key"));
    }
    if !part.authenticated() {
        return Err(refused("witness part its signer did not sign"));
    }
    if key.is_some_and(|key| *key != WindowKey::from_timestamp(part.group.sealed_at)) {
        return Err(refused(
            "witness part outside its sealing month's base window",
        ));
    }
    Ok(())
}

/// The key that signed the request entry `request` as this vault stores
/// it: the one signer a witness part, or a reference to one, may name.
fn request_signer_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    request: &AuthorityEntryHash,
) -> Result<Option<[u8; 32]>> {
    let entry = crate::authority::stored_authority_row(&vault.store, txn, request)?;
    Ok(entry.and_then(|entry| match entry.signer_key() {
        AuthorityKey::Ed25519(key) => Some(*key),
        _ => None,
    }))
}

/// Whether `input`, a relayed input row, is one its holder keeps: its
/// request's signed entry inline, or a reference to a witness its
/// request's own signer signed.
pub(super) fn input_genuine(vault: &Vault, txn: &RoTxn<'_>, input: &RelayedInput) -> Result<bool> {
    if !input.references_witness() {
        return Ok(input.witnessed().is_some());
    }
    let Some(group) = input.witness_group() else {
        return Ok(false);
    };
    let signer = request_signer_in_txn(vault, txn, &input.request)?;
    Ok(signer.is_some_and(|signer| group.signed_by(&signer)))
}

/// Whether the holder may keep a row under input key `key`: none is kept
/// there, or the one kept is not genuine.
pub(super) fn input_slot_open(vault: &Vault, txn: &RoTxn<'_>, key: &[u8; 32]) -> Result<bool> {
    match held_input_in_txn(&vault.store, txn, key)? {
        Some(held) => Ok(!input_genuine(vault, txn, &held)?),
        None => Ok(true),
    }
}

/// Whether `part` authenticates by its request's own signer.
fn part_genuine(vault: &Vault, txn: &RoTxn<'_>, part: &WitnessPart) -> Result<bool> {
    if !part.authenticated() {
        return Ok(false);
    }
    let signer = request_signer_in_txn(vault, txn, &part.group.request)?;
    Ok(signer.is_some_and(|signer| part.group.signed_by(&signer)))
}

/// Whether the holder may keep a part under key `key`: none is kept there,
/// or the one kept is not genuine.
fn part_slot_open(vault: &Vault, txn: &RoTxn<'_>, key: &[u8; 32]) -> Result<bool> {
    match held_witness_in_txn(&vault.store, txn, key)? {
        Some(held) => Ok(!part_genuine(vault, txn, &held)?),
        None => Ok(true),
    }
}

/// Whether the request a witness part is for still awaits its holder.
fn part_pending(fold: &AuthorityFold, part: &WitnessPart) -> bool {
    fold.owner_work_request(&part.group.request).is_some()
        && fold.owner_work_result(&part.group.request).is_none()
}

/// Whether a window's witness part is due to leave it: its request is
/// folded here answered, refused, or on a secret an admitted revoke ended.
fn part_done(fold: &AuthorityFold, part: &WitnessPart) -> bool {
    let request = &part.group.request;
    fold.owner_work_result(request).is_some()
        || fold.refused_owner_work().contains(request)
        || fold
            .owner_work_request(request)
            .is_some_and(|request| fold.custody_revoked(&request.act.target))
}

/// Whether `part` is one a counted, unanswered request naming `machine` as
/// executor names, by its hash and the input digest: what that holder
/// keeps.
fn part_awaits(fold: &AuthorityFold, machine: EntityId, part: &WitnessPart) -> bool {
    fold.counted_owner_work_request(&part.group.request)
        .is_some_and(|request| {
            request.executor == machine
                && fold.owner_work_result(&part.group.request).is_none()
                && names_input(&request.work, &part.group.input)
        })
}

/// Relays each witness part this vault keeps into window `key`, the base
/// window of its sealing month, while its request awaits the holder, each
/// in a commit of its own, and drops from the window every part `fold`
/// holds done. Returns whether it wrote any.
pub(super) fn mirror_witness_parts(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    fold: &AuthorityFold,
) -> Result<bool> {
    let kept = held_witnesses(vault)?;
    let holds = holds_custody_map(doc);
    if kept.is_empty() && !holds {
        return Ok(false);
    }
    let mut wrote = false;
    for (row_key, bytes) in kept {
        let Some(part) = WitnessPart::decode(&bytes) else {
            continue;
        };
        if WindowKey::from_timestamp(part.group.sealed_at) != *key || !part_pending(fold, &part) {
            continue;
        }
        let map = doc.get_map(CUSTODY_MAP);
        let row = witness_row(&row_key);
        if map_get_bytes(&map, &row).as_deref() != Some(bytes.as_slice()) {
            map_insert_bytes(&map, &row, &bytes)?;
            commit_custody(doc);
            wrote = true;
        }
    }
    if holds {
        let map = doc.get_map(CUSTODY_MAP);
        let mut done = Vec::new();
        map.for_each(|map_key, value| {
            if !map_key.starts_with(WITNESS_ROW_PREFIX) {
                return;
            }
            if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
                && WitnessPart::decode(&bytes).is_some_and(|part| part_done(fold, &part))
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

/// Keeps each relayed witness part a counted, unanswered request naming
/// this install as its holder names, signed by that request's own signer,
/// so its pickup can join it, in place of a kept part that is not; the
/// writer that keeps it checks that again against its own fold. Any other
/// part stays in the window, unread. A part that fails is logged and left.
pub(super) fn keep_relayed_witnesses(vault: &Vault, window: &str, rows: Vec<(String, Vec<u8>)>) {
    if rows.is_empty() {
        return;
    }
    let outcome = (|| -> Result<usize> {
        let (machine, due) = {
            let rtxn = vault.store.env.read_txn()?;
            let Some(machine) = crate::identity::read_machine_id_in_txn(vault, &rtxn)? else {
                return Ok(0);
            };
            let fold = vault.authority_view_readonly_in_txn(&rtxn)?;
            let mut due = Vec::new();
            for (map_key, bytes) in &rows {
                let Some(part) = WitnessPart::decode(bytes) else {
                    continue;
                };
                let key = part.row_key();
                if *map_key == witness_row(&key)
                    && part_awaits(&fold, machine, &part)
                    && part_genuine(vault, &rtxn, &part)?
                    && part_slot_open(vault, &rtxn, &key)?
                {
                    due.push(part);
                }
            }
            (machine, due)
        };
        if due.is_empty() {
            return Ok(0);
        }
        vault.with_write_txn_grouped(|wtxn| {
            let fold = vault.authority_view_readonly_in_txn(wtxn)?;
            let mut kept = 0;
            for part in &due {
                if part_awaits(&fold, machine, part)
                    && part_genuine(vault, wtxn, part)?
                    && part_slot_open(vault, wtxn, &part.row_key())?
                {
                    keep_witness_in_txn(vault, wtxn, part)?;
                    kept += 1;
                }
            }
            Ok(kept)
        })
    })();
    match outcome {
        Ok(kept) if kept > 0 => {
            tracing::debug!(window, kept, "custody witness parts kept for this holder");
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(window, error = %error, "custody witness parts not kept");
        }
    }
}
