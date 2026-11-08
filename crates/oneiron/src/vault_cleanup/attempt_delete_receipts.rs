//! The truthful, payload-free history of explicit archived-attempt deletion.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::run_tree::RunTreeDeletion;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

const DELETIONS: SideTable<AttemptId, Deletion, Named> =
    SideTable::new(&side_table::VAULT_CLEANUP_ATTEMPT_DELETE);

#[derive(Serialize, Deserialize)]
struct Deletion {
    deleted_by: Option<EntityId>,
    deleted_at: u64,
    run_id: Option<String>,
}

pub(super) fn stamp_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    actor: EntityId,
    at: u64,
    run: Option<&str>,
) -> Result<String> {
    DELETIONS.put(
        &vault.store,
        txn,
        &attempt,
        &Deletion {
            deleted_by: Some(actor),
            deleted_at: at,
            run_id: run.map(str::to_owned),
        },
    )?;
    Ok(format!(
        "attempt_delete:{}",
        bytes_to_hex_lower(attempt.as_bytes())
    ))
}

/// The run's deletion lines in time/id order, read beside its remaining rows.
pub(crate) fn deletions_for_run_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    run_id: &str,
) -> Result<Vec<RunTreeDeletion>> {
    let mut lines = Vec::new();
    for entry in DELETIONS.iter_from(store, txn, &[])? {
        let (attempt, deletion) = entry?;
        if deletion.run_id.as_deref() == Some(run_id) {
            lines.push(RunTreeDeletion {
                attempt_id: bytes_to_hex_lower(attempt.as_bytes()),
                deleted_by: deletion.deleted_by.map(|actor| actor.to_hex()),
                deleted_at: deletion.deleted_at,
            });
        }
    }
    lines.sort_by(|left, right| {
        (left.deleted_at, &left.attempt_id).cmp(&(right.deleted_at, &right.attempt_id))
    });
    Ok(lines)
}

/// Receipts keep their time, not an erased actor (FIX 812). Attempt ids are
/// not entity ids: the deletion's attempt key remains the historical fact.
/// Only the resident-run producer embeds a proven actor in its run tag.
pub(crate) fn erase_attempt_delete_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::typed_body::names_no_actor(vault, txn, actor)? {
        return Ok(());
    }
    let resident_run = format!("resident:{}", actor.to_hex());
    let rows = DELETIONS
        .iter_raw_from(&vault.store, txn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, raw) in rows {
        let attempt = AttemptId::from_bytes(&key)?;
        let mut row = match DELETIONS.decode_value(&raw) {
            Ok(row) => row,
            Err(error) => {
                tracing::warn!(%error, "unreadable attempt deletion receipt removed during erase");
                DELETIONS.delete(&vault.store, txn, &attempt)?;
                continue;
            }
        };
        let mut changed = false;
        if row.deleted_by == Some(*actor) {
            row.deleted_by = None;
            changed = true;
        }
        // agent_dispatch::resident::resident_run_id is this exact producer.
        if row.run_id.as_deref() == Some(resident_run.as_str()) {
            row.run_id = None;
            changed = true;
        }
        if changed {
            DELETIONS.put(&vault.store, txn, &attempt, &row)?;
        }
    }
    Ok(())
}
