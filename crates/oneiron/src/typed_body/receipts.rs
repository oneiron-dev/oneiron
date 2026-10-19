//! Who made each typed-body commit, kept beside the body (FIX 4513).
//!
//! A commit's Loro message names its verb alone, so the body's history, which
//! never changes, names no one. The fresh peer the commit ran under keys a
//! receipt row holding its actor and MadeBy. A reader resolves each change
//! through that row, and an actor's erase rewrites the row naming no one, so
//! its commits read as unreceipted and a fold of them fails closed.

use std::collections::BTreeMap;
use std::ops::ControlFlow;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{DOCS, HEADS, invalid, load, made_by_names, names_no_actor, require_live};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::made_by::MadeBy;
use crate::provenance::text_commit::TextCommitReceipt;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::write_envelope::WriteActor;

/// The stamp every commit message starts with; the verb follows it and no
/// actor does.
const STAMP: &str = "oneiron.typed_body.v2";

/// Each commit's receipt, by body and commit peer.
const RECEIPTS: SideTable<(EntityId, u64), StoredReceipt, Named> =
    SideTable::new(&side_table::TYPED_BODY_RECEIPT);

/// One commit's receipt: its actor, the actor's class token and its MadeBy
/// while the actor stands, or the commit time alone once it was erased.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum StoredReceipt {
    Live {
        actor: EntityId,
        class: String,
        made_by: MadeBy,
    },
    Erased {
        at: u64,
    },
}

impl StoredReceipt {
    /// The actor and receipt, while the actor is not erased.
    fn live(&self) -> Option<(WriteActor, &MadeBy)> {
        match self {
            Self::Live {
                actor,
                class,
                made_by,
            } => {
                let class = crate::edit_distance::actor_class_from_token(class)?;
                Some((WriteActor::new(*actor, class), made_by))
            }
            Self::Erased { .. } => None,
        }
    }
}

/// The message one commit carries: its verb, naming no one.
pub(super) fn commit_message(verb: &str) -> String {
    format!("{STAMP} {verb}")
}

/// Records `peer`'s commit on `entity` as `actor`'s, under `made_by`. A peer
/// is fresh per call, so a row already there refuses rather than being
/// replaced: an erased receipt never names a live actor again.
pub(super) fn record_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entity: EntityId,
    peer: u64,
    actor: WriteActor,
    made_by: &MadeBy,
) -> Result<()> {
    let key = (entity, peer);
    if RECEIPTS.contains(store, txn, &key)? {
        return Err(invalid("a typed body commit peer was reused"));
    }
    let receipt = StoredReceipt::Live {
        actor: actor.entity_ref(),
        class: crate::edit_distance::actor_class_token(actor.actor_class()).to_owned(),
        made_by: made_by.clone(),
    };
    RECEIPTS.put(store, txn, &key, &receipt)
}

/// The actor `peer`'s commit on `entity` names, while that actor is not
/// erased. `None` for an erased actor or a commit with no receipt.
pub(crate) fn receipt_actor_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    peer: u64,
) -> Result<Option<EntityId>> {
    Ok(RECEIPTS
        .get(store, txn, &(*entity, peer))?
        .and_then(|receipt| receipt.live().map(|(actor, _)| actor.entity_ref())))
}

/// Drops every receipt of `entity`'s body, with the body.
pub(super) fn erase_in_txn(store: &Store, txn: &mut RwTxn<'_>, entity: &EntityId) -> Result<()> {
    RECEIPTS.delete_from(store, txn, entity.as_bytes())?;
    Ok(())
}

/// Every commit's receipt on `entity`'s head history, oldest first. A commit
/// whose receipt row is missing, erased, or not honored for its peer is
/// `None`, so a fold of the list fails closed.
pub(super) fn receipts_in(
    vault: &Vault,
    entity: &EntityId,
) -> Result<Vec<Option<TextCommitReceipt>>> {
    let (doc, rows) = {
        let txn = vault.store.env.read_txn()?;
        require_live(&vault.store, &txn, entity)?;
        let head = HEADS
            .get(&vault.store, &txn, entity)?
            .ok_or(Error::EntityNotFound)?;
        let doc = load(DOCS.get(&vault.store, &txn, entity)?, Some(&head.frontier))?;
        let rows: BTreeMap<u64, StoredReceipt> = RECEIPTS
            .scan_from(&vault.store, &txn, entity.as_bytes())?
            .into_iter()
            .map(|((_, peer), receipt)| (peer, receipt))
            .collect();
        (doc, rows)
    };
    let mut metas = Vec::new();
    doc.travel_change_ancestors(&doc.oplog_frontiers().to_vec(), &mut |meta| {
        metas.push(meta);
        ControlFlow::Continue(())
    })
    .map_err(|_| Error::CorruptedIndex("typed body change history"))?;
    // Loro walks ancestors newest first.
    metas.reverse();
    let mut receipts = Vec::with_capacity(metas.len());
    for meta in metas {
        let stamped = meta
            .message
            .as_deref()
            .and_then(|message| message.strip_prefix(STAMP))
            .is_some_and(|rest| rest.starts_with(' '));
        let Some((actor, made_by)) = rows
            .get(&meta.id.peer)
            .and_then(StoredReceipt::live)
            .filter(|_| stamped)
        else {
            receipts.push(None);
            continue;
        };
        let honored = u64::try_from(meta.timestamp).ok() == Some(made_by.at)
            && made_by_names(actor, made_by)
            && crate::edit_distance::peer_actor_stamp_is_honored(
                vault,
                meta.id.peer,
                made_by.at,
                &actor,
            )?;
        let end = i32::try_from(meta.len)
            .ok()
            .and_then(|len| meta.id.counter.checked_add(len));
        receipts.push(match end {
            Some(end) if honored => Some(TextCommitReceipt {
                document: *entity,
                peer: meta.id.peer,
                start: meta.id.counter,
                end,
                made_by: made_by.clone(),
            }),
            _ => None,
        });
    }
    Ok(receipts)
}

/// Erasing `actor` from the typed-body receipts (FIX 4513): each commit it
/// made keeps its row and commit time and names no one, and its MadeBy goes.
/// The body's history never named it, so the snapshots stay as they are; a
/// reader finds no receipt for those commits. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a receipt row that cannot be read.
pub(crate) fn erase_receipt_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut erased = Vec::new();
    for (key, receipt) in RECEIPTS.scan(&vault.store, wtxn)? {
        if let StoredReceipt::Live {
            actor: named,
            made_by,
            ..
        } = &receipt
            && (named == actor || made_by.process.actor == *actor)
        {
            erased.push((key, StoredReceipt::Erased { at: made_by.at }));
        }
    }
    for (key, receipt) in erased {
        RECEIPTS.put(&vault.store, wtxn, &key, &receipt)?;
    }
    Ok(())
}
