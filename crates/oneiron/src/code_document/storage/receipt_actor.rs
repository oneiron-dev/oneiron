//! Whose operation a code-document receipt records, and the erase that
//! forgets it (FIX 3520). An operation's Loro stamp names no actor, so the
//! erase rewrites the receipts alone: every operation, frontier, hash and
//! sequence stays, and blame, ops and range changes read it as no one's.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use super::{CODE_DOCUMENT_HEAD, CODE_DOCUMENT_INGRESS};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;

#[doc(hidden)]
pub(crate) use oneiron_records::code_document::storage::receipt_actor::ReceiptActor;

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the receipts.
use crate::deletion::names_no_actor;

/// Erasing `actor` from the ingress receipts (FIX 3520): each operation it
/// made keeps its receipt, edit, frontiers and sequence and names no one, and
/// a replay of that ingress identity refuses. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a receipt row that cannot be read.
pub(crate) fn erase_ingress_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut named = Vec::new();
    for row in CODE_DOCUMENT_INGRESS.iter_from(&vault.store, wtxn, &[])? {
        let (operation, mut receipt) = row?;
        if receipt.actor.forget(*actor) {
            named.push((operation, receipt));
        }
    }
    for (operation, receipt) in named {
        CODE_DOCUMENT_INGRESS.put(&vault.store, wtxn, &operation, &receipt)?;
    }
    Ok(())
}

/// Erasing `actor` from the document heads (FIX 3520): a head keeps its
/// snapshot and its whole receipt history, and each operation the actor made
/// names no one there. One-way, in the erase's own transaction. An id whose
/// entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a head row that cannot be read.
pub(crate) fn erase_head_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut named = Vec::new();
    for row in CODE_DOCUMENT_HEAD.iter_from(&vault.store, wtxn, &[])? {
        let (document, mut head) = row?;
        let mut forgot = false;
        for receipt in &mut head.receipts {
            forgot |= receipt.actor.forget(*actor);
        }
        if forgot {
            named.push((document, head));
        }
    }
    for (document, head) in named {
        CODE_DOCUMENT_HEAD.put(&vault.store, wtxn, &document, &head)?;
    }
    Ok(())
}
