//! Core half of `entity_doc::commit_receipts`: its store-layer items live in `oneiron_store::entity_doc::commit_receipts` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::entity_doc::commit_receipts::*;

use super::document::{Stamped, cut_stamp, parse_stamp};
use super::{EntityDoc, invalid};
use crate::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;
use crate::write_envelope::provenance::ActorStamp;
use crate::write_envelope::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
};
use crate::write_envelope::provenance::text_commit::{RowProvenance, TextCommitReceipt};
use loro::ChangeMeta;
use sha2::{Digest, Sha256};

/// `stamped`, one commit's engine stamp, with its receipt: the actor whose
/// token is `stamp` wrote it at `at` through the operation `verb`, reading
/// `sources`.
pub(super) fn receipted(
    stamped: &str,
    stamp: ActorStamp,
    at: u64,
    verb: &str,
    sources: &[EntityId],
) -> Result<String> {
    let made_by = MadeBy {
        inputs: sources
            .iter()
            .map(|&row| MadeByInput {
                row,
                role: MadeByInputRole::Input,
            })
            .collect(),
        process: engine_process(stamp, verb),
        at,
        trigger: None,
    };
    if !made_by.process.is_valid() {
        return Err(invalid("document commit process"));
    }
    receipted_as(stamped, &made_by)
}

impl crate::Vault {
    /// Each retained commit's made_by receipt (FIX 7790), in causal order
    /// (Lamport, then peer), one entry per commit: `None` for a commit with
    /// no receipt its writing peer's binding vouches for. A history an owner
    /// purge cut lists only the commits it keeps.
    pub fn entity_text_commit_receipts(
        &self,
        entity: &EntityId,
    ) -> Result<Vec<Option<TextCommitReceipt>>> {
        Ok(commit_receipts(self, entity)?.1)
    }

    /// The text's provenance, folded over its complete history (FIX 7790):
    /// `None` when any commit lacks a vouched receipt, or an owner purge cut
    /// the history before the oldest commit it keeps.
    pub fn entity_text_provenance(&self, entity: &EntityId) -> Result<Option<RowProvenance>> {
        let (document, receipts, purged) = commit_receipts(self, entity)?;
        if purged {
            return Ok(None);
        }
        Ok(RowProvenance::fold(document, receipts))
    }
}

/// `entity`'s document (its birth's entity), each retained commit's receipt
/// in causal order, and whether a purge cut its history.
fn commit_receipts(
    vault: &crate::Vault,
    entity: &EntityId,
) -> Result<(EntityId, Vec<Option<TextCommitReceipt>>, bool)> {
    let snapshot = vault.read_entity_doc(entity, EntityDoc::export_snapshot)??;
    let doc = EntityDoc::from_snapshot(&snapshot)?;
    let document = EntityId::from_hex(&doc.birth().entity)?;
    let mut changes: Vec<ChangeMeta> = Vec::new();
    doc.doc
        .travel_change_ancestors(&doc.doc.oplog_frontiers().to_vec(), &mut |meta| {
            changes.push(meta);
            std::ops::ControlFlow::Continue(())
        })
        .map_err(|_| Error::CorruptedIndex("document receipt history"))?;
    changes.sort_by_key(|meta| (meta.lamport, meta.id.peer));
    // The document's reader has closed: each peer binding opens its own. A
    // replayed commit reads the row's birth, read once here (FIX 10929).
    let birth = vault.row_birth(&document)?.map(|birth| birth.made_by);
    let receipts: Vec<Option<TextCommitReceipt>> = changes
        .iter()
        .map(|meta| receipt_of(vault, document, birth.as_ref(), meta))
        .collect::<Result<_>>()?;
    Ok((document, receipts, doc.doc.is_shallow()))
}

/// One commit's receipt, over a nonempty span. A replayed commit's is the
/// row's surviving `birth` (FIX 10929). Any other's message carries one that
/// names its live stamp's token, whose token resolves here to an actor of the
/// stamp's class (FIX 10930), whose class that actor may hold, whose time is
/// the commit's, whose trigger, if it names one, has its record here, that
/// names no absent prompt, and whose actor the writing peer's binding vouches
/// for at that time. It is handed back naming the resolved actor.
fn receipt_of(
    vault: &crate::Vault,
    document: EntityId,
    birth: Option<&MadeBy>,
    meta: &ChangeMeta,
) -> Result<Option<TextCommitReceipt>> {
    receipt_of_with(&OwnedReads { vault }, document, birth, meta)
}

struct OwnedReads<'v> {
    vault: &'v crate::Vault,
}

impl ReceiptReads for OwnedReads<'_> {
    fn trigger_recorded(&self, trigger: Option<&MadeByTrigger>) -> Result<bool> {
        trigger_recorded(self.vault, trigger)
    }

    fn prompt_input_present(&self, row: &EntityId) -> Result<bool> {
        Ok(self.vault.get_entity_type(row)?.is_some())
    }

    fn resolve_actor(&self, token: &EntityId) -> Result<Option<WriteActor>> {
        crate::provenance::resolve_actor_stamp(self.vault, token)
    }

    fn peer_honors(&self, peer: u64, at: u64, actor: &WriteActor) -> Result<bool> {
        crate::edit_distance::peer_actor_stamp_is_honored(self.vault, peer, at, actor)
    }
}

struct TxnReads<'v, 't, 'db> {
    vault: &'v crate::Vault,
    txn: &'t heed::RoTxn<'db>,
}

impl ReceiptReads for TxnReads<'_, '_, '_> {
    fn trigger_recorded(&self, trigger: Option<&MadeByTrigger>) -> Result<bool> {
        let Some(trigger) = trigger else {
            return Ok(true);
        };
        crate::store::birth_record::trigger_is_live_in_txn(&self.vault.store, self.txn, trigger)
    }

    fn prompt_input_present(&self, row: &EntityId) -> Result<bool> {
        Ok(self.vault.get_entity_type_in_txn(self.txn, row)?.is_some())
    }

    fn resolve_actor(&self, token: &EntityId) -> Result<Option<WriteActor>> {
        crate::provenance::resolve_actor_stamp_in_txn(self.vault, self.txn, token)
    }

    fn peer_honors(&self, peer: u64, at: u64, actor: &WriteActor) -> Result<bool> {
        crate::edit_distance::peer_actor_stamp_is_honored_in_txn(
            self.vault, self.txn, peer, at, actor,
        )
    }
}

fn receipt_of_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
    birth: Option<&MadeBy>,
    meta: &ChangeMeta,
) -> Result<Option<TextCommitReceipt>> {
    receipt_of_with(&TxnReads { vault, txn }, document, birth, meta)
}

/// The inputs of `row`'s retained, vouched later text commits, all read under
/// the caller's transaction (FIX 11172). A row with no live document head has
/// no commit inputs; an unvouched commit contributes none.
pub(crate) fn commit_input_rows_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    row: &EntityId,
) -> Result<std::collections::BTreeSet<EntityId>> {
    let mut inputs = std::collections::BTreeSet::new();
    let head = match super::storage::head(&vault.store, txn, row) {
        Ok(head) => head,
        Err(Error::EntityNotFound) => return Ok(inputs),
        Err(error) => return Err(error),
    };
    let doc = super::storage::load(&vault.store, txn, &head)?;
    let document = EntityId::from_hex(&doc.birth().entity)?;
    let birth = crate::store::birth_record::row_birth_in_txn(&vault.store, txn, &document)?
        .map(|birth| birth.made_by);
    let mut changes: Vec<ChangeMeta> = Vec::new();
    doc.doc
        .travel_change_ancestors(&doc.doc.oplog_frontiers().to_vec(), &mut |meta| {
            changes.push(meta);
            std::ops::ControlFlow::Continue(())
        })
        .map_err(|_| Error::CorruptedIndex("document receipt history"))?;
    changes.sort_by_key(|meta| (meta.lamport, meta.id.peer));
    for meta in &changes {
        let Some(receipt) = receipt_of_in_txn(vault, txn, document, birth.as_ref(), meta)? else {
            continue;
        };
        inputs.extend(
            receipt
                .made_by
                .inputs
                .iter()
                .filter(|input| input.role == MadeByInputRole::Input)
                .map(|input| input.row),
        );
    }
    Ok(inputs)
}

/// Whether a receipt's `trigger`, if it names one, is a known kind with its
/// own record here: a live task, ask or skill row, or a run's stored replay
/// record, as a row's birth requires (FIX 10929). No trigger needs none.
fn trigger_recorded(vault: &crate::Vault, trigger: Option<&MadeByTrigger>) -> Result<bool> {
    let Some(trigger) = trigger else {
        return Ok(true);
    };
    let txn = vault.store.env.read_txn()?;
    crate::store::birth_record::trigger_is_live_in_txn(&vault.store, &txn, trigger)
}
