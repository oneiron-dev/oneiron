//! The claims, responses and participation facts a turn door or a DAG append
//! writes for a room or thread root no loaded window carries (FIX 3786).
//!
//! Each such row is written once, and the carrier's window mirrors it as it
//! next opens; until then it rode nowhere. The carrier is marked instead,
//! and the live mirror faults its window in for it as it does a marked cell
//! (FIX 3095), when only the TURN was queued. The mark clears once a flush
//! open made the repair durable and the window holds every such row of the
//! carrier.

use std::collections::BTreeSet;

use loro::LoroDoc;

use super::{DIRTY, ROOM_FACTS_MAP, carrier_key, encode, holds_room_fact_map, is_cell, is_shared};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::sync::loro_support::map_contains_binary;
use crate::sync::types::WindowKey;
use crate::workspace_roster::{replicated_side_carriers_in, replicated_side_rows_in};

/// The dirty table key prefix of a carrier's turn fact mark. No `room_facts`
/// map key starts with it.
const TURN_FACTS: &str = "turnfacts/";

fn mark_key(carrier: EntityId) -> String {
    format!("{TURN_FACTS}{}", carrier.to_hex())
}

/// Whether `carrier` is marked for its turn facts.
pub(super) fn marked(vault: &Vault, rtxn: &heed::RoTxn<'_>, carrier: EntityId) -> bool {
    DIRTY
        .contains(&vault.store, rtxn, &mark_key(carrier))
        .unwrap_or(false)
}

/// The base window entity `id` rides, by its learned month.
pub(super) fn carrier_window(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Option<WindowKey> {
    vault
        .get_raw_in(rtxn, &id)
        .ok()
        .flatten()
        .and_then(|raw| crate::sync::residence::residence_window_for_blob(&raw).ok())
}

/// Whether `carrier` rides a base window `loaded` lacks.
fn cold(vault: &Vault, rtxn: &heed::RoTxn<'_>, carrier: EntityId, loaded: &[WindowKey]) -> bool {
    carrier_window(vault, rtxn, carrier)
        .is_some_and(|key| key.world().is_none() && !loaded.contains(&key))
}

fn mark(vault: &Vault, carriers: &BTreeSet<EntityId>) -> Result<()> {
    if carriers.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        for carrier in carriers {
            DIRTY.put(&vault.store, wtxn, &mark_key(*carrier), &())?;
        }
        Ok(())
    })
}

/// Marks each carrier of a room TURN among `edited`, rows a local write
/// committed, whose window `loaded` lacks: the DAG append that wrote the
/// TURN wrote its facts there too.
pub(crate) fn mark_cold_turn_carriers(
    vault: &Vault,
    edited: &BTreeSet<EntityId>,
    loaded: &[WindowKey],
) {
    let marked =
        cold_turn_carriers(vault, edited, loaded).and_then(|carriers| mark(vault, &carriers));
    if let Err(error) = marked {
        tracing::warn!(error = %error, "room turn fact carriers not marked");
    }
}

fn cold_turn_carriers(
    vault: &Vault,
    edited: &BTreeSet<EntityId>,
    loaded: &[WindowKey],
) -> Result<BTreeSet<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut carriers = BTreeSet::new();
    for id in edited {
        if vault.get_entity_type_in_txn(&rtxn, id).ok().flatten() == Some(ENTITY_TYPE_CONVERSATION)
        {
            continue;
        }
        let Ok(found) = replicated_side_carriers_in(vault, &rtxn, *id) else {
            continue;
        };
        for (carrier, _) in found {
            if cold(vault, &rtxn, carrier, loaded) {
                carriers.insert(carrier);
            }
        }
    }
    Ok(carriers)
}

/// Mirrors the side rows of each of `carriers`, a room turn's, into the live
/// windows that carry it, after a door wrote its facts. Each one no live
/// window takes is marked, and queued for a flush into its window.
pub(super) fn mirror_or_mark(vault: &Vault, carriers: &[(EntityId, u8)]) {
    let unheld: Vec<EntityId> = carriers
        .iter()
        .filter(|carrier| !vault.mirror_carriers_in_live_windows(&[**carrier], &[]))
        .map(|(id, _)| *id)
        .collect();
    if unheld.is_empty() {
        return;
    }
    let flush = vault.store.env.read_txn().map(|rtxn| {
        unheld
            .into_iter()
            .filter(|carrier| cold(vault, &rtxn, *carrier, &[]))
            .collect::<BTreeSet<_>>()
    });
    match flush {
        Ok(flush) => match mark(vault, &flush) {
            Ok(()) if flush.is_empty() => {}
            Ok(()) => vault.queue_room_fact_flush(flush),
            Err(error) => tracing::warn!(error = %error, "room turn fact carriers not marked"),
        },
        Err(error) => tracing::warn!(error = %error, "room turn fact carriers not marked"),
    }
}

/// Clears the mark of each carrier `doc`, a window a flush opened, carries
/// with every claim, response and participation fact this vault holds for
/// it: the open made that repair durable before it returned.
pub(crate) fn clear_turn_marks(vault: &Vault, doc: &LoroDoc) {
    let cleared = held_marks(vault, doc).and_then(|held| {
        if held.is_empty() {
            return Ok(());
        }
        vault.with_write_txn_grouped(|wtxn| {
            for key in &held {
                DIRTY.delete(&vault.store, wtxn, key)?;
            }
            Ok(())
        })
    });
    if let Err(error) = cleared {
        tracing::warn!(error = %error, "room turn fact marks not cleared");
    }
}

/// The marks of the carriers `doc` carries with each of their written-once
/// rows.
fn held_marks(vault: &Vault, doc: &LoroDoc) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let entities = doc.get_map("entities");
    let map = holds_room_fact_map(doc).then(|| doc.get_map(ROOM_FACTS_MAP));
    let mut held = Vec::new();
    for key in DIRTY.scan_keys(&vault.store, &rtxn, TURN_FACTS.as_bytes())? {
        let Some(carrier) = key.strip_prefix(TURN_FACTS).and_then(super::named) else {
            continue;
        };
        if !map_contains_binary(&entities, &carrier.to_hex()) {
            continue;
        }
        let entity_type = match vault.get_entity_type_in_txn(&rtxn, &carrier)? {
            Some(ENTITY_TYPE_CONVERSATION) => ENTITY_TYPE_CONVERSATION,
            _ => ENTITY_TYPE_TURN,
        };
        let mut whole = true;
        for row in replicated_side_rows_in(vault, &rtxn, carrier, entity_type)? {
            let row_key = carrier_key(&row, &encode(&row)?);
            whole &= is_cell(&row_key)
                || is_shared(&row_key)
                || map
                    .as_ref()
                    .is_some_and(|map| map_contains_binary(map, &row_key));
        }
        if whole {
            held.push(key);
        }
    }
    Ok(held)
}
