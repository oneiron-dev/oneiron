//! Egress withholding of a row a record use limit keeps for storage only on
//! this vault ([`crate::store::legal_hold::use_limit_in_txn`]): a privacy
//! erase a standing customer hold refused (C6), or a cooperative review
//! restriction. The owner's devices lose such a row as they lose an erased
//! one, and it packs again once the limit goes inert (Engine ANSWER
//! SERVING-DOORS-OWNER-WINDOW-USE-LIMIT = B, 20 Nov 21:19; LEGAL-HOLD-USE = B).
//!
//! Packing skips it (`egress::window_packing_excludes_entity_with`). A window
//! that already carries it, or an edge naming it, loses them before any side
//! row of it is scrubbed ([`withhold_use_limited_carriers`]), so its message
//! document, quote pins, office proposals, typed body receipts and repo
//! manifest leave with it. A raw send queued before the limit took effect is
//! read again at release ([`use_limit_update_verdict`]).

use std::collections::BTreeSet;
use std::sync::Arc;

use loro::json::{JsonOpContent, JsonSchema, MapOp};
use loro::{CommitOptions, ContainerID, ContainerType, LoroDoc, VersionVector};

use super::super::bridge::{BRIDGE_ORIGIN, parse_edge_key};
use super::super::loro_support::{json_covers_blob, map_for_each_value_bytes};
use super::super::manager::WindowManager;
use super::super::types::WindowKey;
use super::UpdateVerdict;
use super::egress::require_history_free_window;
use super::reverse::remove_entity_crdt_carriers;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::source_audience::carried::{CarrierKey, parse_key};

/// Takes out of `doc` each row a use limit keeps for storage only on this
/// vault that `doc` carries or names in an edge. An edge rides in its
/// target's window when its two rows live in different windows (a base
/// row's edge to a world row, `types::edge_belongs_to_window`), so a limited
/// endpoint can be named here with its carrier elsewhere. Its carrier (under
/// any spelling of its id), edges, birth and binding go, and a withholding
/// marker naming this machine takes their place, so the owner's devices hold
/// the row back and read it to no one, as they would had the erase run; this
/// vault keeps its stored copy for the hold. The marker lifts, and the row
/// rides again, once the limit goes inert and the row packs
/// (`source_audiences::refresh_and_scrub`). Each scrub sequence (export,
/// persist, sweep) runs this before its side-row scrubs, which drop the side
/// rows of a row the window no longer carries. `pin` names the window pinned
/// history-free before anything goes, so its history never ships the row's
/// bytes; the sweep passes `None`. A vault with no use limit carries no such
/// row. Whether anything went, committed.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn withhold_use_limited_carriers(
    vault: &Vault,
    doc: &LoroDoc,
    pin: Option<&WindowKey>,
) -> Result<bool> {
    let (withheld, by) = {
        let rtxn = vault.store.env.read_txn()?;
        if !crate::store::legal_hold::any_record_use_limit_in_txn(&vault.store, &rtxn)? {
            return Ok(false);
        }
        let mut named = BTreeSet::new();
        map_for_each_value_bytes(&doc.get_map("entities"), |key, _| {
            named.extend(EntityId::from_hex(key).ok());
        });
        map_for_each_value_bytes(&doc.get_map("edges"), |key, _| {
            if let Some((source, _, target)) = parse_edge_key(key) {
                named.extend([source, target]);
            }
        });
        let mut withheld = Vec::new();
        for id in named {
            if crate::store::legal_hold::use_limit_in_txn(&vault.store, &rtxn, &id)?.is_some() {
                withheld.push(id);
            }
        }
        (
            withheld,
            crate::identity::read_machine_id_in_txn(vault, &rtxn)?,
        )
    };
    if withheld.is_empty() {
        return Ok(false);
    }
    if let Some(key) = pin {
        require_history_free_window(vault, key)?;
    }
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    for id in &withheld {
        remove_entity_crdt_carriers(&entities, &edges, id)?;
    }
    crate::sync::source_audiences::mark_withheld(doc, &withheld, by.as_ref())?;
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}

/// The verdict a record use limit gives raw `update` bytes of window
/// `window_key` at the door that sends them, after the device-only verdict
/// let them pass: withheld when they carry a row a use limit keeps for
/// storage only here, in the state they stand for or in an operation that
/// inserts its carrier, edge, birth or binding. So a send queued before the
/// limit took effect ships no such row after it; one that carries only the
/// withholding marker passes. A receiver a withheld send left behind
/// catches up from the window's next scrubbed export, which carries the
/// marker, as one a device-only verdict left behind does. Portable on a
/// vault with no use limit.
///
/// # Errors
///
/// Storage failures; the caller reads any error as uninspectable bytes.
pub(super) fn use_limit_update_verdict(
    manager: &Arc<WindowManager>,
    window_key: &str,
    update: &[u8],
) -> Result<UpdateVerdict> {
    let vault = manager.vault();
    if !any_use_limit(vault)? {
        return Ok(UpdateVerdict::Portable);
    }
    let Some(key) = WindowKey::try_new(window_key) else {
        return Ok(UpdateVerdict::Uninspectable);
    };
    let rows = match update_rows(update) {
        UpdateRows::Read(rows) => rows,
        UpdateRows::Range(meta) => {
            let window = manager.open_window(&key)?;
            let history = window
                .doc
                .export_json_updates(&meta.partial_start_vv, &meta.partial_end_vv);
            if !json_covers_blob(&history, &meta) {
                return Ok(UpdateVerdict::Uninspectable);
            }
            let mut rows = BTreeSet::new();
            history_rows(&history, &mut rows);
            rows
        }
        UpdateRows::Unreadable => return Ok(UpdateVerdict::Uninspectable),
    };
    use_limited_among(vault, rows)
}

/// [`use_limit_update_verdict`] for bytes that stand alone (a selector's
/// synthetic update): bytes that do not are uninspectable.
///
/// # Errors
///
/// Storage failures.
pub(super) fn standalone_use_limit_verdict(vault: &Vault, update: &[u8]) -> Result<UpdateVerdict> {
    if !any_use_limit(vault)? {
        return Ok(UpdateVerdict::Portable);
    }
    match update_rows(update) {
        UpdateRows::Read(rows) => use_limited_among(vault, rows),
        UpdateRows::Range(_) | UpdateRows::Unreadable => Ok(UpdateVerdict::Uninspectable),
    }
}

fn any_use_limit(vault: &Vault) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    crate::store::legal_hold::any_record_use_limit_in_txn(&vault.store, &rtxn)
}

fn use_limited_among(vault: &Vault, rows: BTreeSet<EntityId>) -> Result<UpdateVerdict> {
    let rtxn = vault.store.env.read_txn()?;
    for id in rows {
        if crate::store::legal_hold::use_limit_in_txn(&vault.store, &rtxn, &id)?.is_some() {
            return Ok(UpdateVerdict::Withheld);
        }
    }
    Ok(UpdateVerdict::Portable)
}

/// What raw window bytes name, read as `device_only::bytes_verdict` reads
/// them.
enum UpdateRows {
    /// Bytes that stand alone: the rows of their state, of a snapshot's
    /// encoded or shallow root, and of every operation they hold.
    Read(BTreeSet<EntityId>),
    /// An operation range the live window must hold in full.
    Range(loro::ImportBlobMetadata),
    /// Bytes that cannot be read in full.
    Unreadable,
}

fn update_rows(update: &[u8]) -> UpdateRows {
    let Ok(meta) = LoroDoc::decode_import_blob_meta(update, true) else {
        return UpdateRows::Unreadable;
    };
    let alone = LoroDoc::new();
    if !alone
        .import(update)
        .is_ok_and(|status| status.pending.is_none())
    {
        return if meta.mode.is_snapshot() {
            UpdateRows::Unreadable
        } else {
            UpdateRows::Range(meta)
        };
    }
    let mut rows = BTreeSet::new();
    if meta.mode.is_snapshot() {
        let Some(root) = super::encoded_root_state(update) else {
            return UpdateRows::Unreadable;
        };
        if let Some(root) = root {
            state_rows(&root, &mut rows);
        }
    }
    if alone.is_shallow() {
        let at_root = alone.fork();
        if at_root.checkout(&alone.shallow_since_frontiers()).is_err() {
            return UpdateRows::Unreadable;
        }
        state_rows(&at_root, &mut rows);
    }
    state_rows(&alone, &mut rows);
    history_rows(
        &alone.export_json_updates(&VersionVector::default(), &alone.oplog_vv()),
        &mut rows,
    );
    UpdateRows::Read(rows)
}

/// The row a source-audience carrier binds: a record or a derived row's
/// policies. A withholding marker binds nothing, so the send that carries
/// one is never withheld for the row it names.
fn bound_row(map_key: &str) -> Option<EntityId> {
    match parse_key(map_key)? {
        CarrierKey::Record(row) | CarrierKey::Derived(row, _) => Some(row),
        CarrierKey::Withheld(_) | CarrierKey::Policy(..) | CarrierKey::Event(..) => None,
    }
}

fn state_rows(doc: &LoroDoc, rows: &mut BTreeSet<EntityId>) {
    map_for_each_value_bytes(&doc.get_map("entities"), |key, _| {
        rows.extend(EntityId::from_hex(key).ok());
    });
    map_for_each_value_bytes(&doc.get_map("edges"), |key, _| {
        if let Some((source, _, target)) = parse_edge_key(key) {
            rows.extend([source, target]);
        }
    });
    map_for_each_value_bytes(
        &doc.get_map(crate::sync::row_birth::ROW_BIRTHS_MAP),
        |key, _| rows.extend(EntityId::from_hex(key).ok()),
    );
    map_for_each_value_bytes(
        &doc.get_map(crate::sync::source_audiences::SOURCE_AUDIENCES_MAP),
        |key, _| rows.extend(bound_row(key)),
    );
}

fn history_rows(history: &JsonSchema, rows: &mut BTreeSet<EntityId>) {
    let entities = ContainerID::new_root("entities", ContainerType::Map);
    let edges = ContainerID::new_root("edges", ContainerType::Map);
    let births = ContainerID::new_root(crate::sync::row_birth::ROW_BIRTHS_MAP, ContainerType::Map);
    let source_audiences = ContainerID::new_root(
        crate::sync::source_audiences::SOURCE_AUDIENCES_MAP,
        ContainerType::Map,
    );
    for op in history.changes.iter().flat_map(|change| &change.ops) {
        let JsonOpContent::Map(MapOp::Insert { key, .. }) = &op.content else {
            continue;
        };
        if op.container == entities || op.container == births {
            rows.extend(EntityId::from_hex(key).ok());
        } else if op.container == edges
            && let Some((source, _, target)) = parse_edge_key(key)
        {
            rows.extend([source, target]);
        } else if op.container == source_audiences {
            rows.extend(bound_row(key));
        }
    }
}
