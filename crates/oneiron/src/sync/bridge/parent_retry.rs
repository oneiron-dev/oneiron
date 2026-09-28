//! Transactional Parent admission, exact pending work and dependency wake-up.

use std::collections::BTreeSet;

use crate::batch::EdgeValueFields;
use crate::conversation_dag::topology::{
    Dependency, NonEmptyDependencies, ParentAdmission, ValidatedParent,
};
use crate::edge::{EdgeKind, decode_edge_value_for_kind};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::sync::quarantine::{self, QuarantineContainer, remote_rejection_reason};
use crate::sync::types::WindowKey;
use crate::{EntityId, Vault};

use super::format_edge_key;

const PENDING: &str = "dp:w:";
const INDEX: &str = "di:";
const SOURCE_INDEX: &str = "ps:";
const ANCHOR: &str = "sa:w:";
const ANCHOR_INDEX: &str = "se:";
const VALUE_LEN: usize = 12;
const MAX_DEPENDENCIES: usize = 8;
const PENDING_ROW: SideTable<String, Vec<u8>, Raw> = SideTable::new(&side_table::DEFERRED_PARENT);
const INDEX_ROW: SideTable<String, [u8; 1], Raw> =
    SideTable::new(&side_table::DEFERRED_PARENT_DEPENDENCY);
const SOURCE_INDEX_ROW: SideTable<String, [u8; 1], Raw> =
    SideTable::new(&side_table::DEFERRED_PARENT_SOURCE);
const ANCHOR_ROW: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::DEFERRED_SPAWNED_BY);
const ANCHOR_INDEX_ROW: SideTable<String, [u8; 1], Raw> =
    SideTable::new(&side_table::DEFERRED_SPAWNED_BY_ENDPOINT);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::sync) enum ParentOutcome {
    Written,
    Unchanged,
    Waiting,
    Rejected,
    Ignored,
}

fn key(window: &str, source: &EntityId, target: &EntityId) -> String {
    format!("{PENDING}{window}:{}:{}", source.to_hex(), target.to_hex())
}

fn dep_parts(dep: Dependency) -> (u8, EntityId) {
    match dep {
        Dependency::Entity(id) => (b'e', id),
        Dependency::ConversationMembership(id) => (b'm', id),
        Dependency::SessionAnchor(id) => (b's', id),
        Dependency::ParentOf(id) => (b'p', id),
    }
}
fn dep_from_parts(kind: u8, id: EntityId) -> Result<Dependency> {
    match kind {
        b'e' => Ok(Dependency::Entity(id)),
        b'm' => Ok(Dependency::ConversationMembership(id)),
        b's' => Ok(Dependency::SessionAnchor(id)),
        b'p' => Ok(Dependency::ParentOf(id)),
        _ => Err(Error::CorruptedIndex("deferred Parent dependency")),
    }
}
fn index_prefix(dep: Dependency) -> String {
    let (kind, id) = dep_parts(dep);
    format!("{INDEX}{}:{}:", char::from(kind), id.to_hex())
}
fn index_key(dep: Dependency, obligation: &str) -> String {
    format!("{}{obligation}", index_prefix(dep))
}

fn source_index_key(source: &EntityId, obligation: &str) -> String {
    format!("{SOURCE_INDEX}{}:{obligation}", source.to_hex())
}

/// Maintenance checks the exact pending source in its per-conversation
/// transaction before choosing a trunk root or writing HEAD.
pub(crate) fn has_unresolved_parent_for_source_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &EntityId,
) -> Result<bool> {
    let prefix = format!("{SOURCE_INDEX}{}:", source.to_hex());
    let mut rows = vault.store.sync_state.prefix_iter(txn, &prefix)?;
    Ok(rows.next().transpose()?.is_some())
}

fn encode_pending(value: &[u8], deps: &NonEmptyDependencies) -> Result<Vec<u8>> {
    let items: Vec<_> = deps.iter().collect();
    if value.len() != VALUE_LEN || items.is_empty() || items.len() > MAX_DEPENDENCIES {
        return Err(Error::CorruptedIndex("deferred Parent obligation"));
    }
    let mut encoded = Vec::with_capacity(VALUE_LEN + 1 + 17 * items.len());
    encoded.extend_from_slice(value);
    encoded.push(items.len() as u8);
    for dep in items {
        let (kind, id) = dep_parts(dep);
        encoded.push(kind);
        encoded.extend_from_slice(id.as_bytes());
    }
    Ok(encoded)
}
fn decode_pending(raw: &[u8]) -> Result<(&[u8], Vec<Dependency>)> {
    let count = usize::from(
        *raw.get(VALUE_LEN)
            .ok_or(Error::CorruptedIndex("deferred Parent obligation"))?,
    );
    if count == 0 || count > MAX_DEPENDENCIES || raw.len() != VALUE_LEN + 1 + 17 * count {
        return Err(Error::CorruptedIndex("deferred Parent obligation"));
    }
    let mut deps = Vec::with_capacity(count);
    for bytes in raw[VALUE_LEN + 1..].chunks_exact(17) {
        let id = EntityId::from_bytes(
            bytes[1..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("deferred Parent dependency"))?,
        )
        .map_err(|_| Error::CorruptedIndex("deferred Parent dependency"))?;
        deps.push(dep_from_parts(bytes[0], id)?);
    }
    Ok((&raw[..VALUE_LEN], deps))
}

fn parse_key(row: &str) -> Result<(&str, EntityId, EntityId)> {
    let rest = row
        .strip_prefix(PENDING)
        .ok_or(Error::CorruptedIndex("deferred Parent obligation"))?;
    let mut parts = rest.split(':');
    let (Some(window), Some(source), Some(target), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::CorruptedIndex("deferred Parent obligation"));
    };
    if WindowKey::try_new(window).is_none() {
        return Err(Error::CorruptedIndex("deferred Parent obligation"));
    }
    let source_id = EntityId::from_hex(source)
        .map_err(|_| Error::CorruptedIndex("deferred Parent obligation"))?;
    let target_id = EntityId::from_hex(target)
        .map_err(|_| Error::CorruptedIndex("deferred Parent obligation"))?;
    if source_id.to_hex() != source || target_id.to_hex() != target {
        return Err(Error::CorruptedIndex("deferred Parent obligation"));
    }
    Ok((window, source_id, target_id))
}

pub(in crate::sync) fn has_pending_source_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    window: &str,
    source: &EntityId,
) -> Result<bool> {
    let prefix = format!("{PENDING}{window}:{}:", source.to_hex());
    let mut rows = vault.store.sync_state.prefix_iter(txn, &prefix)?;
    if rows.next().transpose()?.is_some() {
        return Ok(true);
    }
    let anchor_prefix = format!("{ANCHOR}{window}:{}:", source.to_hex());
    let mut anchors = vault.store.sync_state.prefix_iter(txn, &anchor_prefix)?;
    if anchors.next().transpose()?.is_some() {
        return Ok(true);
    }
    super::childof::has_pending_child_of_source_in_txn(vault, txn, window, source)
}

/// Remove an exact obligation and every dependency-index entry it owns.
fn settle(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    source: &EntityId,
    target: &EntityId,
) -> Result<()> {
    let obligation = key(window, source, target);
    let Some(raw) = vault
        .store
        .sync_state
        .get(txn, &obligation)?
        .map(|raw| raw.to_vec())
    else {
        return Ok(());
    };
    let (_, deps) = decode_pending(&raw)?;
    for dep in deps {
        let index = index_key(dep, &obligation);
        INDEX_ROW.delete(&vault.store, txn, &index[INDEX.len()..].to_string())?;
    }
    PENDING_ROW.delete(&vault.store, txn, &obligation[PENDING.len()..].to_string())?;
    let source_index = source_index_key(source, &obligation);
    SOURCE_INDEX_ROW.delete(
        &vault.store,
        txn,
        &source_index[SOURCE_INDEX.len()..].to_string(),
    )?;
    if !has_pending_source_in_txn(vault, txn, window, source)? {
        quarantine::clear_replay_remat_marker_in_txn(vault, txn, window, source)?;
    }
    Ok(())
}

fn wait(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    source: &EntityId,
    target: &EntityId,
    value: &[u8],
    deps: &NonEmptyDependencies,
) -> Result<()> {
    let obligation = key(window, source, target);
    if let Some(raw) = vault.store.sync_state.get(txn, &obligation)? {
        let (_, prior) = decode_pending(&raw)?;
        for dep in prior {
            let index = index_key(dep, &obligation);
            INDEX_ROW.delete(&vault.store, txn, &index[INDEX.len()..].to_string())?;
        }
    }
    PENDING_ROW.put(
        &vault.store,
        txn,
        &obligation[PENDING.len()..].to_string(),
        &encode_pending(value, deps)?,
    )?;
    let source_index = source_index_key(source, &obligation);
    SOURCE_INDEX_ROW.put(
        &vault.store,
        txn,
        &source_index[SOURCE_INDEX.len()..].to_string(),
        &[1],
    )?;
    for dep in deps.iter() {
        let index = index_key(dep, &obligation);
        INDEX_ROW.put(&vault.store, txn, &index[INDEX.len()..].to_string(), &[1])?;
    }
    quarantine::set_replay_remat_marker_in_txn(vault, txn, window, source)
}

fn quarantine_parent(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    source: EntityId,
    target: EntityId,
    value: &[u8],
    error: &Error,
) -> Result<()> {
    quarantine::quarantine_rejected_op_in_txn(
        vault,
        txn,
        window,
        QuarantineContainer::Edges,
        &format_edge_key(&source, EdgeKind::Parent, &target),
        error,
        value,
    )?;
    settle(vault, txn, window, &source, &target)
}

fn apply_ready(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    parent: ValidatedParent,
    value: &[u8],
) -> Result<ParentOutcome> {
    let src = parent.source;
    let tgt = parent.target;
    let out_same = crate::ports::EdgeStoreStaging::port_edge_encoded(
        &vault.store,
        &*txn,
        &src,
        EdgeKind::Parent,
        &tgt,
    )?
    .as_deref()
        == Some(value);
    if out_same
        && crate::ports::EdgeStoreRead::port_edge_consistent(
            &vault.store,
            &*txn,
            &src,
            EdgeKind::Parent,
            &tgt,
        )?
    {
        settle(vault, txn, window, &src, &tgt)?;
        return Ok(ParentOutcome::Unchanged);
    }
    let decoded = decode_edge_value_for_kind(EdgeKind::Parent, value)
        .map_err(|_| Error::CorruptedIndex("deferred Parent obligation"))?;
    match vault
        .batch_in()
        .edge_with_value_fields(
            &src,
            EdgeKind::Parent,
            &tgt,
            EdgeValueFields::from_decoded(decoded),
        )
        .apply(txn)
    {
        Ok(()) => {
            settle(vault, txn, window, &src, &tgt)?;
            Ok(ParentOutcome::Written)
        }
        Err(err) if remote_rejection_reason(&err).is_some() => {
            quarantine_parent(vault, txn, window, src, tgt, value, &err)?;
            Ok(ParentOutcome::Rejected)
        }
        Err(local) => Err(local),
    }
}

/// Single Parent door for forward remat, live delta and durable retries.
/// All outcomes, including Wait, settle atomically with the candidate's txn.
pub(in crate::sync) fn submit(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    source: EntityId,
    target: EntityId,
    value: &[u8],
    tombstoned: bool,
) -> Result<ParentOutcome> {
    let decoded = match decode_edge_value_for_kind(EdgeKind::Parent, value) {
        Ok(decoded) => decoded,
        Err(remote) => {
            quarantine_parent(vault, txn, window, source, target, value, &remote)?;
            return Ok(ParentOutcome::Rejected);
        }
    };
    if let Err(remote) =
        crate::conversation_dag::validate_received_parent_value(source, target, decoded)
    {
        quarantine_parent(vault, txn, window, source, target, value, &remote)?;
        return Ok(ParentOutcome::Rejected);
    }
    if tombstoned
        || vault.local_hard_delete_marker_exists_in_txn(txn, &source)?
        || vault.local_hard_delete_marker_exists_in_txn(txn, &target)?
    {
        settle(vault, txn, window, &source, &target)?;
        return Ok(ParentOutcome::Ignored);
    }
    match crate::conversation_dag::topology::prospective_parent(&vault.store, txn, source, target)?
    {
        ParentAdmission::Ready(parent) => apply_ready(vault, txn, window, parent, value),
        ParentAdmission::Wait(deps) => {
            wait(vault, txn, window, &source, &target, value, &deps)?;
            Ok(ParentOutcome::Waiting)
        }
        ParentAdmission::Reject(rejected) => {
            quarantine_parent(
                vault,
                txn,
                window,
                source,
                target,
                value,
                &rejected.into_error(),
            )?;
            Ok(ParentOutcome::Rejected)
        }
    }
}

fn anchor_key(window: &str, session: &EntityId, turn: &EntityId) -> String {
    format!("{ANCHOR}{window}:{}:{}", session.to_hex(), turn.to_hex())
}
fn anchor_index_key(endpoint: &EntityId, row: &str) -> String {
    format!("{ANCHOR_INDEX}{}:{row}", endpoint.to_hex())
}
fn parse_anchor_key(row: &str) -> Result<(&str, EntityId, EntityId)> {
    let rest = row
        .strip_prefix(ANCHOR)
        .ok_or(Error::CorruptedIndex("deferred SpawnedBy obligation"))?;
    let mut parts = rest.split(':');
    let (Some(window), Some(session), Some(turn), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::CorruptedIndex("deferred SpawnedBy obligation"));
    };
    if WindowKey::try_new(window).is_none() {
        return Err(Error::CorruptedIndex("deferred SpawnedBy obligation"));
    }
    let session = EntityId::from_hex(session)
        .map_err(|_| Error::CorruptedIndex("deferred SpawnedBy obligation"))?;
    let turn = EntityId::from_hex(turn)
        .map_err(|_| Error::CorruptedIndex("deferred SpawnedBy obligation"))?;
    if row != anchor_key(window, &session, &turn) {
        return Err(Error::CorruptedIndex("deferred SpawnedBy obligation"));
    }
    Ok((window, session, turn))
}

pub(in crate::sync) fn defer_spawned_by(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    session: &EntityId,
    turn: &EntityId,
    value: &[u8],
) -> Result<()> {
    let decoded = decode_edge_value_for_kind(EdgeKind::SpawnedBy, value)
        .map_err(|_| Error::CorruptedIndex("deferred SpawnedBy obligation"))?;
    if session == turn
        || decoded.weight != 1.0
        || decoded.vad.is_some()
        || decoded.provenance.is_some()
    {
        let err =
            crate::error::RecordError::InvalidConversationDag("invalid received SpawnedBy value");
        quarantine::quarantine_rejected_op_in_txn(
            vault,
            txn,
            window,
            QuarantineContainer::Edges,
            &format_edge_key(session, EdgeKind::SpawnedBy, turn),
            &err.into(),
            value,
        )?;
        return Ok(());
    }
    let row = anchor_key(window, session, turn);
    ANCHOR_ROW.put(
        &vault.store,
        txn,
        &row[ANCHOR.len()..].to_string(),
        &value.to_vec(),
    )?;
    for endpoint in [session, turn] {
        let index = anchor_index_key(endpoint, &row);
        ANCHOR_INDEX_ROW.put(
            &vault.store,
            txn,
            &index[ANCHOR_INDEX.len()..].to_string(),
            &[1],
        )?;
    }
    quarantine::set_replay_remat_marker_in_txn(vault, txn, window, session)
}

fn settle_spawned_by(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    session: &EntityId,
    turn: &EntityId,
) -> Result<()> {
    let row = anchor_key(window, session, turn);
    if vault.store.sync_state.get(txn, &row)?.is_none() {
        return Ok(());
    }
    ANCHOR_ROW.delete(&vault.store, txn, &row[ANCHOR.len()..].to_string())?;
    for endpoint in [session, turn] {
        let index = anchor_index_key(endpoint, &row);
        ANCHOR_INDEX_ROW.delete(&vault.store, txn, &index[ANCHOR_INDEX.len()..].to_string())?;
    }
    let prefix = format!("{ANCHOR}{window}:{}:", session.to_hex());
    if vault
        .store
        .sync_state
        .prefix_iter(&*txn, &prefix)?
        .next()
        .transpose()?
        .is_none()
    {
        quarantine::clear_replay_remat_marker_in_txn(vault, txn, window, session)?;
    }
    Ok(())
}

fn replay_spawned_by(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &str,
) -> Result<Option<Dependency>> {
    let Some(value) = vault
        .store
        .sync_state
        .get(txn, row)?
        .map(|raw| raw.to_vec())
    else {
        return Ok(None);
    };
    let (window, session, turn) = parse_anchor_key(row)?;
    let decoded = decode_edge_value_for_kind(EdgeKind::SpawnedBy, &value)
        .map_err(|_| Error::CorruptedIndex("deferred SpawnedBy obligation"))?;
    for id in [session, turn] {
        match crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)? {
            crate::vault::LiveEntityRow::Absent => return Ok(None),
            crate::vault::LiveEntityRow::DeletedShell => {
                settle_spawned_by(vault, txn, window, &session, &turn)?;
                return Ok(None);
            }
            crate::vault::LiveEntityRow::Live { .. } => {}
        }
    }
    let verdict = crate::conversation_dag::validate_received_edge(
        &vault.store,
        &*txn,
        session,
        EdgeKind::SpawnedBy,
        turn,
        decoded,
    );
    match verdict {
        Ok(()) => match vault
            .batch_in()
            .edge_with_value_fields(
                &session,
                EdgeKind::SpawnedBy,
                &turn,
                EdgeValueFields::from_decoded(decoded),
            )
            .apply(txn)
        {
            Ok(()) => {
                settle_spawned_by(vault, txn, window, &session, &turn)?;
                Ok(Some(Dependency::SessionAnchor(session)))
            }
            Err(err) if remote_rejection_reason(&err).is_some() => {
                quarantine::quarantine_rejected_op_in_txn(
                    vault,
                    txn,
                    window,
                    QuarantineContainer::Edges,
                    &format_edge_key(&session, EdgeKind::SpawnedBy, &turn),
                    &err,
                    &value,
                )?;
                settle_spawned_by(vault, txn, window, &session, &turn)?;
                Ok(None)
            }
            Err(local) => Err(local),
        },
        Err(rejected) if remote_rejection_reason(&rejected).is_some() => {
            quarantine::quarantine_rejected_op_in_txn(
                vault,
                txn,
                window,
                QuarantineContainer::Edges,
                &format_edge_key(&session, EdgeKind::SpawnedBy, &turn),
                &rejected,
                &value,
            )?;
            settle_spawned_by(vault, txn, window, &session, &turn)?;
            Ok(None)
        }
        Err(local) => Err(local),
    }
}

fn anchors_for_endpoint(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<Vec<String>> {
    let prefix = format!("{ANCHOR_INDEX}{}:", id.to_hex());
    let mut rows = Vec::new();
    for entry in vault.store.sync_state.prefix_iter(txn, &prefix)? {
        let (row, _) = entry?;
        rows.push(
            row.strip_prefix(&prefix)
                .ok_or(Error::CorruptedIndex("deferred SpawnedBy index"))?
                .to_string(),
        );
    }
    Ok(rows)
}

fn indexed(vault: &Vault, txn: &heed::RoTxn<'_>, fact: Dependency) -> Result<Vec<String>> {
    let prefix = index_prefix(fact);
    let mut keys = Vec::new();
    for entry in vault.store.sync_state.prefix_iter(txn, &prefix)? {
        let (key, _) = entry?;
        let obligation = key
            .strip_prefix(&prefix)
            .ok_or(Error::CorruptedIndex("deferred Parent index"))?;
        if !obligation.starts_with(PENDING) {
            return Err(Error::CorruptedIndex("deferred Parent index"));
        }
        keys.push(obligation.to_string());
    }
    Ok(keys)
}

/// Index-driven, bounded fixed point. Each settled Parent emits ParentOf,
/// which can wake another parent in this SAME transaction. Unsettled rows
/// and their rm: summaries survive a budget boundary and restart.
fn process(vault: &Vault, txn: &mut heed::RwTxn<'_>, mut ready: BTreeSet<String>) -> Result<()> {
    // This is a bounded fixed point, NOT an ancestor-depth budget. There may
    // be more independent shallow branches than MAX_ANCESTOR_DEPTH. Each
    // obligation has at most MAX_DEPENDENCIES successive missing facts; if
    // the bound is ever exceeded, abort rather than report a successful
    // receive that silently drops ready work.
    let mut pending = 0usize;
    for entry in vault.store.sync_state.prefix_iter(&*txn, PENDING)? {
        entry?;
        pending = pending.saturating_add(1);
    }
    let budget = pending
        .saturating_mul(MAX_DEPENDENCIES + 2)
        .max(ready.len());
    let mut examined = 0usize;
    while let Some(obligation) = ready.pop_first() {
        if examined >= budget {
            return Err(Error::IndexOverflow("dag_parent_ready"));
        }
        examined += 1;
        let Some(raw) = vault
            .store
            .sync_state
            .get(txn, &obligation)?
            .map(|raw| raw.to_vec())
        else {
            continue;
        };
        let (window, source, target) = parse_key(&obligation)?;
        let (value, _) = decode_pending(&raw)?;
        let outcome = submit(vault, txn, window, source, target, value, false)?;
        if matches!(outcome, ParentOutcome::Written | ParentOutcome::Unchanged) {
            ready.extend(indexed(vault, txn, Dependency::ParentOf(source))?);
        }
    }
    Ok(())
}

pub(in crate::sync) fn wake_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    facts: &[Dependency],
) -> Result<()> {
    let mut anchor_rows = BTreeSet::new();
    for &fact in facts {
        if let Dependency::Entity(id) | Dependency::SessionAnchor(id) = fact {
            anchor_rows.extend(anchors_for_endpoint(vault, txn, id)?);
        }
    }
    let mut changed = facts.to_vec();
    changed.extend(super::childof::wake_pending_child_of(vault, txn, facts)?);
    for row in anchor_rows {
        if let Some(anchor) = replay_spawned_by(vault, txn, &row)? {
            changed.push(anchor);
        }
    }
    let mut ready = BTreeSet::new();
    for fact in changed {
        ready.extend(indexed(vault, txn, fact)?);
    }
    process(vault, txn, ready)
}

/// Recovery/drain entrypoint: reconstruct work from durable anchor and
/// Parent obligations. Neither a process restart nor a consumed event loses
/// a missing dependency or a ready Parent.
pub(in crate::sync) fn retry_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    // A pending ChildOf can be the prerequisite for both a Parent and a
    // spawned session anchor. Replay it through winner arbitration first.
    super::childof::retry_all_pending_child_of(vault, txn)?;
    let anchors: Vec<String> = {
        let iter = vault.store.sync_state.prefix_iter(&*txn, ANCHOR)?;
        iter.map(|entry| entry.map(|(key, _)| key.to_string()))
            .collect::<Result<_>>()?
    };
    for row in anchors {
        replay_spawned_by(vault, txn, &row)?;
    }
    let rows: BTreeSet<String> = {
        let iter = vault.store.sync_state.prefix_iter(&*txn, PENDING)?;
        iter.map(|entry| entry.map(|(key, _)| key.to_string()))
            .collect::<Result<_>>()?
    };
    process(vault, txn, rows)
}
