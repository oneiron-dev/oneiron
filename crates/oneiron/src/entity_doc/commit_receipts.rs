//! Every generic entity-document commit carries its made_by receipt (FIX
//! 7790, ARCH-0035): the engine stamp, then `|made_by=` and the commit's
//! [`MadeBy`] envelope as JSON, in the commit message the operation log
//! keeps, replicates and checkpoints with the change itself. The change is
//! the receipt's operation span, and the document's birth names its entity
//! (a SWITCH moves its storage slot, never its birth). No side table holds a
//! receipt.
//!
//! The envelope says what the engine knows: the writing actor and its class,
//! the engine operation that wrote the change ([`engine_process`]), the rows
//! a writer named as read for it, and the commit time. It names no model,
//! prompt or trigger the engine did not see. A message alone authenticates
//! nothing: a receipt is read only where the writing peer's binding vouches
//! for its actor, as the attribution reader asks. A commit with none (an
//! unstamped, erased, malformed or unvouched one) reads as unknown
//! provenance, never as refused text.
//!
//! Canonical recovery replays a document into fresh operations, whose
//! writers are gone. Each replayed commit restates the row's birth instead
//! ([`ROW_BIRTH_RESTATED`], FIX 10929): it names no one itself, and reads as
//! the row's surviving `RowBirth.made_by`, the vault's own record. Once an
//! erase drops that birth, the restated commits read as unknown again. A
//! door whose row already holds its birth gives the document's birth commit
//! that same envelope ([`receipted_as`]). A receipt naming a trigger is
//! vouched only when the trigger is a known kind with its own record here: a
//! live task, ask or skill row, or a run's stored replay record.

use loro::ChangeMeta;
use sha2::{Digest, Sha256};

use super::document::{Stamped, cut_stamp, parse_stamp};
use super::{EntityDoc, invalid};
use crate::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
};
use crate::provenance::text_commit::{RowProvenance, TextCommitReceipt};
use crate::write_envelope::WriteActor;

/// What joins a commit's engine stamp to its receipt.
pub(super) const RECEIPT_PREFIX: &str = "|made_by=";

/// The whole message of a commit canonical recovery replayed: it restates
/// the row's birth, whose surviving `RowBirth.made_by` is its receipt (FIX
/// 10929). It names no actor, so no erase has anything to take from it.
pub(super) const ROW_BIRTH_RESTATED: &str = "oneiron.entity_doc.v1 row_birth";

/// The process a generic commit's receipt names (C-ENTITY-PROCESS): the
/// engine operation `oneiron.entity_doc.<verb>` at version 1, which takes no
/// render parameters, so its parameter hash is the empty input's. It is the
/// operation that wrote the change, not a model.
fn engine_process(actor: WriteActor, verb: &str) -> MadeByProcess {
    MadeByProcess {
        actor: actor.entity_ref(),
        class: MadeByClass::of_writer(actor.actor_class()),
        identity: format!("oneiron.entity_doc.{verb}"),
        version: "1".to_owned(),
        params_hash: format!("{:x}", Sha256::digest([])),
    }
}

/// `stamped`, one commit's engine stamp, with its receipt: `actor` wrote it
/// at `at` through the operation `verb`, reading `sources`.
pub(super) fn receipted(
    stamped: &str,
    actor: WriteActor,
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
        process: engine_process(actor, verb),
        at,
        trigger: None,
    };
    if !made_by.process.is_valid() {
        return Err(invalid("document commit process"));
    }
    receipted_as(stamped, &made_by)
}

/// `stamped` with `made_by` as its receipt: the generic receipt, or a row's
/// own birth envelope that names the stamp's actor at the commit's time (FIX
/// 10929).
pub(super) fn receipted_as(stamped: &str, made_by: &MadeBy) -> Result<String> {
    let receipt = serde_json::to_string(made_by)
        .map_err(|_| Error::InvariantViolation("document receipt encoding"))?;
    Ok(format!("{stamped} {RECEIPT_PREFIX}{receipt}"))
}

/// The engine stamp and the receipt `message` carries, when it carries both
/// as [`receipted`] spells them.
fn decode(message: &str) -> Option<(&str, MadeBy)> {
    let (stamped, receipt) = message.split_once(RECEIPT_PREFIX)?;
    let stamped = stamped.strip_suffix(' ')?;
    cut_stamp(stamped)?;
    Some((stamped, serde_json::from_str(receipt).ok()?))
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
/// row's surviving `birth` (FIX 10929). Any other's message carries one whose
/// actor its live stamp names, whose class that actor may hold, whose time is
/// the commit's, whose trigger, if it names one, has its record here, that
/// names no absent prompt, and whose actor the writing peer's binding vouches
/// for at that time.
fn receipt_of(
    vault: &crate::Vault,
    document: EntityId,
    birth: Option<&MadeBy>,
    meta: &ChangeMeta,
) -> Result<Option<TextCommitReceipt>> {
    let len = i32::try_from(meta.len).ok().filter(|&len| len > 0);
    let Some(end) = len.and_then(|len| meta.id.counter.checked_add(len)) else {
        return Ok(None);
    };
    let receipt = |made_by: MadeBy| TextCommitReceipt {
        document,
        peer: meta.id.peer,
        start: meta.id.counter,
        end,
        made_by,
    };
    if meta.message.as_deref() == Some(ROW_BIRTH_RESTATED) {
        return Ok(birth.cloned().map(receipt));
    }
    let Some((stamped, made_by)) = meta.message.as_deref().and_then(decode) else {
        return Ok(None);
    };
    let Stamped::Live(actor) = parse_stamp(Some(stamped)) else {
        return Ok(None);
    };
    let states = made_by.process.class == MadeByClass::Stated;
    if made_by.process.actor != actor.entity_ref()
        || (states && actor.actor_class() != EdgeActorClass::Human)
        || !made_by.process.is_valid()
        || u64::try_from(meta.timestamp).ok() != Some(made_by.at)
        || !trigger_recorded(vault, made_by.trigger.as_ref())?
    {
        return Ok(None);
    }
    for input in &made_by.inputs {
        if input.role == MadeByInputRole::Prompt && vault.get_entity_type(&input.row)?.is_none() {
            return Ok(None);
        }
    }
    let vouched =
        crate::edit_distance::peer_actor_stamp_is_honored(vault, meta.id.peer, made_by.at, &actor)?;
    Ok(vouched.then(|| receipt(made_by)))
}

/// Whether a receipt's `trigger`, if it names one, is a known kind with its
/// own record here: a live task, ask or skill row, or a run's stored replay
/// record, as a row's birth requires (FIX 10929). No trigger needs none.
fn trigger_recorded(vault: &crate::Vault, trigger: Option<&MadeByTrigger>) -> Result<bool> {
    let Some(trigger) = trigger else {
        return Ok(true);
    };
    let txn = vault.store.env.read_txn()?;
    crate::provenance::birth::trigger_is_live_in_txn(&vault.store, &txn, trigger)
}
