//! FIX 6204: the exact obligation ledger for carried `regenerates` links.
//!
//! A carried link whose MESSAGE has not arrived, or whose pair still lacks a
//! row or a sole axis, waits here as one exact obligation, never under its
//! source's `rm:` replay marker. An end that never arrives leaves a dormant
//! row: no window re-walk, no GDPR SLA breach signal, no expiry.
//!
//! An admitted MESSAGE, a ready document, or an `authored_by`/`belongs_to`
//! change on either end retries the obligations it is an end of, and every
//! recovery pass retries them all. Admission, a stored pair, a terminal
//! rejection, an erased end or the link's removal settle one.

use std::collections::{BTreeSet, HashSet};

use loro::event::MapDelta;

use super::{format_edge_key, parse_edge_key};

use crate::batch::EdgeValueFields;
use crate::conversation_dag::topology::Dependency;
use crate::edge::{EdgeKind, Regeneration, decode_edge_value_for_kind};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::sync::quarantine::{self, QuarantineContainer, remote_rejection_reason};
use crate::sync::types::WindowKey;
use crate::{EntityId, Vault};

/// One owed link: `dg:w:{window}:{src_hex}:{tgt_hex}` → its original
/// encoded value. A replaced link's value overwrites the old one, so a live
/// edge owes at most one row.
const PENDING_REGENERATES: &str = "dg:w:";
/// Each end's index: `dh:{endpoint_hex}:{full dg:w: key}` → `[1]`.
const REGENERATES_ENDPOINT: &str = "dh:";
const PENDING_ROW: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::DEFERRED_REGENERATES);
const ENDPOINT_ROW: SideTable<String, [u8; 1], Raw> =
    SideTable::new(&side_table::DEFERRED_REGENERATES_ENDPOINT);

fn obligation_key(window: &str, src: &EntityId, tgt: &EntityId) -> String {
    format!(
        "{PENDING_REGENERATES}{window}:{}:{}",
        src.to_hex(),
        tgt.to_hex()
    )
}
fn endpoint_key(id: &EntityId, obligation: &str) -> String {
    format!("{REGENERATES_ENDPOINT}{}:{obligation}", id.to_hex())
}
fn parse_obligation(row: &str) -> Result<(&str, EntityId, EntityId)> {
    let rest = row
        .strip_prefix(PENDING_REGENERATES)
        .ok_or(Error::CorruptedIndex("deferred regenerates obligation"))?;
    let mut parts = rest.split(':');
    let (Some(window), Some(src), Some(tgt), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::CorruptedIndex("deferred regenerates obligation"));
    };
    if WindowKey::try_new(window).is_none() {
        return Err(Error::CorruptedIndex("deferred regenerates obligation"));
    }
    let src = EntityId::from_hex(src)
        .map_err(|_| Error::CorruptedIndex("deferred regenerates obligation"))?;
    let tgt = EntityId::from_hex(tgt)
        .map_err(|_| Error::CorruptedIndex("deferred regenerates obligation"))?;
    if row != obligation_key(window, &src, &tgt) {
        return Err(Error::CorruptedIndex("deferred regenerates obligation"));
    }
    Ok((window, src, tgt))
}

/// The full obligation keys `id` is an end of.
fn owed_by(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Vec<String>> {
    let prefix = format!("{REGENERATES_ENDPOINT}{}:", id.to_hex());
    let mut rows = Vec::new();
    for entry in vault.store.sync_state.prefix_iter(txn, &prefix)? {
        let (key, _) = entry?;
        rows.push(
            key.strip_prefix(&prefix)
                .ok_or(Error::CorruptedIndex("deferred regenerates index"))?
                .to_string(),
        );
    }
    Ok(rows)
}

/// Owes `src -regenerates-> tgt` in `window` with its original `value`.
/// The source's replay marker is left as it stands: the wait is here.
pub(in crate::sync) fn owe_regenerates(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    src: &EntityId,
    tgt: &EntityId,
    value: &[u8],
) -> Result<()> {
    decode_edge_value_for_kind(EdgeKind::Regenerates, value)
        .map_err(|_| Error::CorruptedIndex("deferred regenerates obligation"))?;
    let row = obligation_key(window, src, tgt);
    PENDING_ROW.put(
        &vault.store,
        txn,
        &row[PENDING_REGENERATES.len()..].to_string(),
        &value.to_vec(),
    )?;
    for id in [src, tgt] {
        let index = endpoint_key(id, &row);
        ENDPOINT_ROW.put(
            &vault.store,
            txn,
            &index[REGENERATES_ENDPOINT.len()..].to_string(),
            &[1],
        )?;
    }
    Ok(())
}

/// Settles the exact obligation and both its index rows, if owed.
pub(in crate::sync) fn settle_regenerates(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    src: &EntityId,
    tgt: &EntityId,
) -> Result<()> {
    let row = obligation_key(window, src, tgt);
    if vault.store.sync_state.get(txn, &row)?.is_none() {
        return Ok(());
    }
    PENDING_ROW.delete(
        &vault.store,
        txn,
        &row[PENDING_REGENERATES.len()..].to_string(),
    )?;
    for id in [src, tgt] {
        let index = endpoint_key(id, &row);
        ENDPOINT_ROW.delete(
            &vault.store,
            txn,
            &index[REGENERATES_ENDPOINT.len()..].to_string(),
        )?;
    }
    Ok(())
}

/// Retries one owed link on the rows stored now, through the same pair
/// check and edge door its carrier used. A missing row or axis keeps it
/// owed; every other verdict settles it.
fn retry_row(vault: &Vault, txn: &mut heed::RwTxn<'_>, row: &str) -> Result<()> {
    let Some(value) = vault
        .store
        .sync_state
        .get(txn, row)?
        .map(|bytes| bytes.to_vec())
    else {
        return Ok(());
    };
    let (window, src, tgt) = parse_obligation(row)?;
    let decoded = decode_edge_value_for_kind(EdgeKind::Regenerates, &value)
        .map_err(|_| Error::CorruptedIndex("deferred regenerates obligation"))?;
    for id in [src, tgt] {
        if vault.local_hard_delete_marker_exists_in_txn(txn, &id)?
            || matches!(
                crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?,
                crate::vault::LiveEntityRow::DeletedShell
            )
        {
            return settle_regenerates(vault, txn, window, &src, &tgt);
        }
    }
    // A stored pair was proven when it landed.
    if crate::edge::regeneration_stored(&vault.store, txn, &src, &tgt)? {
        return settle_regenerates(vault, txn, window, &src, &tgt);
    }
    let rejected = match crate::edge::regeneration_pair(&vault.store, txn, &src, &tgt)? {
        Regeneration::Pending => return Ok(()),
        Regeneration::Erased => None,
        Regeneration::Refuses => Some(crate::edge::reserved_regenerates()),
        Regeneration::Admits => match vault
            .batch_in()
            .edge_with_value_fields(
                &src,
                EdgeKind::Regenerates,
                &tgt,
                EdgeValueFields::from_decoded(decoded),
            )
            .apply(txn)
        {
            Ok(()) => None,
            Err(err) if remote_rejection_reason(&err).is_some() => Some(err),
            Err(local) => return Err(local),
        },
    };
    if let Some(rejected) = rejected {
        quarantine::quarantine_rejected_op_in_txn(
            vault,
            txn,
            window,
            QuarantineContainer::Edges,
            &format_edge_key(&src, EdgeKind::Regenerates, &tgt),
            &rejected,
            &value,
        )?;
    }
    settle_regenerates(vault, txn, window, &src, &tgt)
}

/// Retries each obligation with an end in `ids`.
fn wake_owed_by(vault: &Vault, txn: &mut heed::RwTxn<'_>, ids: &[EntityId]) -> Result<()> {
    let mut rows = BTreeSet::new();
    for id in ids {
        rows.extend(owed_by(vault, txn, id)?);
    }
    for row in rows {
        retry_row(vault, txn, &row)?;
    }
    Ok(())
}

/// An admitted entity row retries the links it is an end of.
pub(super) fn wake_regenerates(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    facts: &[Dependency],
) -> Result<()> {
    let ids: Vec<_> = facts
        .iter()
        .filter_map(|fact| match fact {
            Dependency::Entity(id) => Some(*id),
            _ => None,
        })
        .collect();
    wake_owed_by(vault, txn, &ids)
}

/// An `authored_by` or `belongs_to` change on a MESSAGE, added, replaced or
/// removed, retries the links it is an end of: the pair check reads both
/// ends' sole axes. Keyed by the axis edge's source, the MESSAGE.
pub(super) fn wake_regenerates_axes(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    delta: &MapDelta<'_>,
) -> Result<()> {
    let messages: BTreeSet<_> = delta
        .updated
        .keys()
        .filter_map(|key| parse_edge_key(key))
        .filter(|(_, kind, _)| matches!(kind, EdgeKind::AuthoredBy | EdgeKind::BelongsTo))
        .map(|(message, _, _)| message)
        .collect();
    let messages: Vec<_> = messages.into_iter().collect();
    wake_owed_by(vault, txn, &messages)
}

/// A document now ready for `ids` may prove a link they are an end of. It
/// runs in its own write after the document's: a failure is logged, and
/// the next recovery pass retries what it left owed.
pub(in crate::sync) fn wake_regenerates_after_document(vault: &Vault, ids: &[EntityId]) {
    let owed = (|| -> Result<bool> {
        let txn = vault.store.env.read_txn()?;
        for id in ids {
            if !owed_by(vault, &txn, id)?.is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    })();
    let woken = match owed {
        Ok(false) => return,
        Ok(true) => vault.with_write_txn_grouped(|txn| wake_owed_by(vault, txn, ids)),
        Err(error) => Err(error),
    };
    if let Err(error) = woken {
        tracing::warn!(
            error = %error,
            "regenerates links not retried after a document landed; recovery retries them"
        );
    }
}

/// Recovery and drain: every link still owed, in key order.
pub(super) fn retry_all_regenerates(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    let rows: Vec<String> = {
        let iter = vault
            .store
            .sync_state
            .prefix_iter(&*txn, PENDING_REGENERATES)?;
        iter.map(|entry| entry.map(|(key, _)| key.to_string()))
            .collect::<Result<_>>()?
    };
    for row in rows {
        retry_row(vault, txn, &row)?;
    }
    Ok(())
}

/// The pairs `window` owes with an end in `ids`, read after their commit,
/// so their carried keys can be re-presented. A failed read re-presents
/// none: that commit's own wake retried them already.
pub(super) fn owed_in_window(
    vault: &Vault,
    window: &str,
    ids: &HashSet<EntityId>,
) -> HashSet<(EntityId, EntityId)> {
    let owed = (|| -> Result<HashSet<_>> {
        let txn = vault.store.env.read_txn()?;
        let mut owed = HashSet::new();
        for id in ids {
            for row in owed_by(vault, &txn, id)? {
                let (owner, src, tgt) = parse_obligation(&row)?;
                if owner == window {
                    owed.insert((src, tgt));
                }
            }
        }
        Ok(owed)
    })();
    owed.unwrap_or_else(|error| {
        tracing::warn!(
            window,
            error = %error,
            "regenerates obligations not re-presented"
        );
        HashSet::new()
    })
}
