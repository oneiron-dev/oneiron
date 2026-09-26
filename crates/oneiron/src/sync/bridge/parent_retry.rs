//! Exact, durable received-Parent obligations and dependency-triggered replay.

use crate::batch::EdgeValueFields;
use crate::conversation_dag::ReceivedEdgeAdmission;
use crate::edge::{EdgeKind, decode_edge_value_for_kind};
use crate::error::{Error, Result};
use crate::sync::quarantine::{self, QuarantineContainer, remote_rejection_reason};
use crate::sync::types::WindowKey;
use crate::{EntityId, Vault};

use super::format_edge_key;

const PREFIX: &str = "dp:w:";

fn key(window: &str, source: &EntityId, target: &EntityId) -> String {
    format!("{PREFIX}{window}:{}:{}", source.to_hex(), target.to_hex())
}

/// A source-scoped rm: marker alone can be cleared by an unrelated ChildOf
/// heal. This exact source/target obligation survives until THIS Parent is
/// applied or receives a terminal verdict. The stored payload is the validated
/// 12-byte structural value, not a reconstructed timestamp or peer text.
pub(in crate::sync) fn defer(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    source: &EntityId,
    target: &EntityId,
    value: &[u8],
) -> Result<()> {
    vault
        .store
        .sync_state
        .put(txn, &key(window, source, target), value)?;
    quarantine::set_replay_remat_marker_in_txn(vault, txn, window, source)
}

pub(in crate::sync) fn has_pending_source_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    window: &str,
    source: &EntityId,
) -> Result<bool> {
    let prefix = format!("{PREFIX}{window}:{}:", source.to_hex());
    let mut rows = vault.store.sync_state.prefix_iter(txn, &prefix)?;
    Ok(rows.next().transpose()?.is_some())
}

/// Clear only our exact Parent intent. A second Parent intent on this source,
/// or an unproven delete-safety marker, must not be discharged by this write.
pub(in crate::sync) fn settle(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    source: &EntityId,
    target: &EntityId,
) -> Result<()> {
    let obligation = key(window, source, target);
    let existed = vault.store.sync_state.get(txn, &obligation)?.is_some();
    vault.store.sync_state.delete(txn, &obligation)?;
    if existed && !has_pending_source_in_txn(vault, txn, window, source)? {
        quarantine::clear_replay_remat_marker_in_txn(vault, txn, window, source)?;
    }
    Ok(())
}

fn parse_key(row: &str) -> Result<(&str, EntityId, EntityId)> {
    let Some(rest) = row.strip_prefix(PREFIX) else {
        return Err(Error::CorruptedIndex("deferred Parent obligation"));
    };
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

/// Retry after a committed dependency enters this write transaction. The
/// caller owns the txn, so the edge verdict, write and obligation settlement
/// are atomic. Unresolved rows remain pending; local faults still abort.
pub(in crate::sync) fn retry_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    let rows: Vec<(String, Vec<u8>)> = {
        let iter = vault.store.sync_state.prefix_iter(&*txn, PREFIX)?;
        iter.map(|entry| {
            let (key, value) = entry?;
            Ok((key.to_string(), value.to_vec()))
        })
        .collect::<Result<_>>()?
    };
    for (row, buf) in rows {
        let (window, source, target) = parse_key(&row)?;
        let decoded = decode_edge_value_for_kind(EdgeKind::Parent, &buf)
            .map_err(|_| Error::CorruptedIndex("deferred Parent obligation"))?;
        // A missing TURN is also an out-of-order dependency. The original
        // shape was checked before this bounded obligation was persisted.
        let mut missing = false;
        let mut deleted = false;
        for id in [source, target] {
            match crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)? {
                crate::vault::LiveEntityRow::Absent => missing = true,
                crate::vault::LiveEntityRow::DeletedShell => deleted = true,
                crate::vault::LiveEntityRow::Live { .. } => {}
            }
        }
        if deleted {
            settle(vault, txn, window, &source, &target)?;
            continue;
        }
        if missing {
            continue;
        }
        let verdict = crate::conversation_dag::validate_received_edge(
            &vault.store,
            &*txn,
            source,
            EdgeKind::Parent,
            target,
            decoded,
        );
        match verdict {
            Ok(ReceivedEdgeAdmission::Deferred) => continue,
            Ok(ReceivedEdgeAdmission::Admit) => {
                match vault
                    .batch_in()
                    .edge_with_value_fields(
                        &source,
                        EdgeKind::Parent,
                        &target,
                        EdgeValueFields::from_decoded(decoded),
                    )
                    .apply(txn)
                {
                    Ok(()) => settle(vault, txn, window, &source, &target)?,
                    Err(err) if remote_rejection_reason(&err).is_some() => {
                        quarantine::quarantine_rejected_op_in_txn(
                            vault,
                            txn,
                            window,
                            QuarantineContainer::Edges,
                            &format_edge_key(&source, EdgeKind::Parent, &target),
                            &err,
                            &buf,
                        )?;
                        settle(vault, txn, window, &source, &target)?;
                    }
                    Err(local) => return Err(local),
                }
            }
            Err(rejected) if remote_rejection_reason(&rejected).is_some() => {
                quarantine::quarantine_rejected_op_in_txn(
                    vault,
                    txn,
                    window,
                    QuarantineContainer::Edges,
                    &format_edge_key(&source, EdgeKind::Parent, &target),
                    &rejected,
                    &buf,
                )?;
                settle(vault, txn, window, &source, &target)?;
            }
            Err(local) => return Err(local),
        }
    }
    Ok(())
}
