//! Transactional Parent admission, exact pending work and dependency wake-up.

use std::collections::BTreeSet;

use crate::batch::EdgeValueFields;
use crate::conversation_dag::topology::{
    Dependency, NonEmptyDependencies, ParentAdmission, ValidatedParent,
};
use crate::edge::{EdgeKind, decode_edge_value_for_kind};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::sync::quarantine::{self, QuarantineContainer, remote_rejection_reason};
use crate::sync::types::WindowKey;
use crate::{EntityId, Vault};

use super::format_edge_key;

const PENDING: &str = "dp:w:";
const INDEX: &str = "di:";
const VALUE_LEN: usize = 12;
const MAX_DEPENDENCIES: usize = 8;

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
    Ok(rows.next().transpose()?.is_some())
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
        vault
            .store
            .sync_state
            .delete(txn, &index_key(dep, &obligation))?;
    }
    vault.store.sync_state.delete(txn, &obligation)?;
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
            vault
                .store
                .sync_state
                .delete(txn, &index_key(dep, &obligation))?;
        }
    }
    vault
        .store
        .sync_state
        .put(txn, &obligation, &encode_pending(value, deps)?)?;
    for dep in deps.iter() {
        vault
            .store
            .sync_state
            .put(txn, &index_key(dep, &obligation), &[1])?;
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
    let out_key = Store::encode_edge_key(&src, EdgeKind::Parent, &tgt);
    let in_key = Store::encode_edge_key(&tgt, EdgeKind::Parent, &src);
    let out_same = vault
        .store
        .edges_out
        .get(&*txn, &out_key)?
        .is_some_and(|stored| stored == value);
    let in_same = vault
        .store
        .edges_in
        .get(&*txn, &in_key)?
        .is_some_and(|stored| stored == value);
    if out_same && in_same {
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
    let mut examined = 0usize;
    while let Some(obligation) = ready.pop_first() {
        if examined >= crate::limits::MAX_ANCESTOR_DEPTH {
            break;
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
    let mut ready = BTreeSet::new();
    for &fact in facts {
        ready.extend(indexed(vault, txn, fact)?);
    }
    process(vault, txn, ready)
}

/// Recovery/drain entrypoint: reconstruct ready work from durable dp: rows.
/// The bounded processor leaves excess rows and their indexes for the next
/// drain pass; no dependency is lost when the process stops.
pub(in crate::sync) fn retry_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    let rows: BTreeSet<String> = {
        let iter = vault.store.sync_state.prefix_iter(&*txn, PENDING)?;
        iter.map(|entry| entry.map(|(key, _)| key.to_string()))
            .collect::<Result<_>>()?
    };
    process(vault, txn, rows)
}
