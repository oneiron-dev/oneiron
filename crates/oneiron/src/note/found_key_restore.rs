//! A found key's value back in a NOTE's texts (FIX
//! L6-03-NOTE-RULING-KEEPS-DOC-HANDLE). Every NOTE read serves its document,
//! and the mask on write stored the key's handle there (`admit_body`), so the
//! owner's "not a secret" or "kept as text" answer puts the value back into
//! the document as an edit by the person who answered, persisted as every
//! edit is: snapshot, native revision, text, title and pin indexes.
//!
//! A pending fork keeps its text in a stored proposal, which the mask
//! admitted under the fork head's id (`store_doc`), so a key found there
//! names the head, which is no entity (NOTE-PROPOSAL-FORK-RULING-KEEPS-HANDLE).
//! The answer puts the value back in each pending fork of the NOTE that
//! holds the handle, and in the texts a merge lands from, so a land after
//! the ruling carries the value. A land moves the fork's keys to the NOTE
//! (`proposals::land`), so an answer after it reaches the NOTE.

use super::document::{NoteDocument, TITLE, encode_title};
use super::document_store::{load, persist_authoritative};
use super::documents::{NOTE_PROPOSAL_DOC, proposal_value, snapshot};
use super::operations::record_authorship;
use super::proposals::{NOTE_FORK, replace_fork_row_in_txn};
use super::token_uses::record_token_uses_in_txn;
use super::{NoteActor, NoteAuthorship};
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::file_secret_marks::as_text;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_NOTE;
use crate::vault::live_entity_row_in_txn;
use crate::{Vault, WriteActor};

/// The field a pending fork's body is admitted as (`store_doc`); a NOTE's
/// own body is `markdown`.
const FORK_BODY_FIELD: &str = "body";

/// Puts `value` back where the mask left `text_form`, a found key's handle
/// as text, in the texts of the NOTE that `record` is, or that `record`
/// forks, for a key found in a body or a title (`field` "markdown",
/// "title" or a fork's "body"): the NOTE's live body and title, as an edit
/// stamped by `actor`, the person whose ruling it is, and each pending fork
/// of the NOTE. One value takes one handle in all of them: a write admits
/// body and title with one plan, and a later write marks a value custody
/// holds with its handle (REVIEW-7876 F1). The ruling already stands, so the
/// write door reads the value as no hit there. Returns `false` when `record`
/// is no live NOTE and no fork of one, or `field` none of its texts: the
/// caller's index restore stands for it.
pub(crate) fn restore_found_key_text_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: EntityId,
    field: &str,
    text_form: &str,
    value: &[u8],
    actor: EntityId,
) -> Result<bool> {
    if !matches!(field, "markdown" | "title" | FORK_BODY_FIELD) {
        return Ok(false);
    }
    let note = if is_live_note_in_txn(vault, txn, record)? {
        record
    } else if let Some(fork) = NOTE_FORK.get(&vault.store, txn, &record)? {
        fork.note
    } else {
        return Ok(false);
    };
    if note == record || is_live_note_in_txn(vault, txn, note)? {
        restore_live_in_txn(vault, txn, note, text_form, value, actor)?;
    }
    restore_pending_forks_in_txn(vault, txn, note, text_form, value, actor)?;
    Ok(true)
}

/// Whether `record` is a NOTE whose row is live.
fn is_live_note_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, record: EntityId) -> Result<bool> {
    let raw = EntityStoreRead::port_entity_raw(&vault.store, txn, &record)?;
    let note = raw
        .as_deref()
        .and_then(EntityMetadataHeader::parse)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_NOTE);
    Ok(note && live_entity_row_in_txn(&vault.store, txn, &record)?.is_live())
}

/// The value back in the live body and title of `note`, where they hold
/// `text_form`.
fn restore_live_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    text_form: &str,
    value: &[u8],
    actor: EntityId,
) -> Result<()> {
    let doc = load(vault, txn, note)?;
    if restore_document_in_txn(vault, txn, &doc, text_form, value, actor)? {
        persist_authoritative(vault, txn, &doc)?;
    }
    Ok(())
}

/// The value back in the body and title of `doc` where they hold
/// `text_form`, as an edit stamped by `actor`. Returns whether either held
/// it; the caller stores `doc`.
fn restore_document_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &NoteDocument,
    text_form: &str,
    value: &[u8],
    actor: EntityId,
) -> Result<bool> {
    let body = Some(doc.view()?.markdown).filter(|text| text.contains(text_form));
    let title = doc.title()?.filter(|text| text.contains(text_form));
    if body.is_none() && title.is_none() {
        return Ok(false);
    }
    let value = as_text(value)?;
    // The commit names the ruling person's stamp token (FIX 10930).
    let writer = WriteActor::new(actor, EdgeActorClass::Human);
    let stamp = crate::provenance::actor_stamp_in_txn(vault, txn, writer)?;
    if let Some(body) = body {
        doc.restore_body(&body.replace(text_form, value), stamp)?;
    }
    if let Some(title) = title {
        doc.set_title(&title.replace(text_form, value), stamp)?;
    }
    record_authorship(
        doc,
        &NoteAuthorship {
            operation: vault.new_entity_id()?,
            actor: NoteActor::Actor(stamp.token),
            actor_class: EdgeActorClass::Human.gate_actor_class().to_owned(),
            grant: None,
            command_hash: *blake3::hash(text_form.as_bytes()).as_bytes(),
        },
        stamp,
    )?;
    Ok(true)
}

/// The value back in each pending fork of `note` that holds `text_form`:
/// its stored proposal and the texts a merge lands from
/// (`NoteFork::recovery_merge`). A value carrier, which `store_doc` keeps
/// for a masked fork (no pins, no authorship), is rebuilt with the value. A
/// declared rewrite that keeps its operations takes the value as an edit by
/// `actor`, since a switch lands its document whole (REVIEW-7904 F2). A
/// merge fork that keeps its operations stays as it is: a merge imports
/// them into the NOTE, whose own edit by the ruling already holds the
/// value. A decided fork stays as it was decided.
fn restore_pending_forks_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    text_form: &str,
    value: &[u8],
    actor: EntityId,
) -> Result<()> {
    let prefix = format!("{}:", note.to_hex());
    let mut restored = false;
    for (key, raw) in NOTE_PROPOSAL_DOC.scan_from(&vault.store, txn, prefix.as_bytes())? {
        let Some(fork) = NOTE_FORK
            .get(&vault.store, txn, &(key.1).0)?
            .filter(|fork| !fork.decided && fork.note == note)
        else {
            continue;
        };
        let carrier = NoteDocument::load(note, &raw)?;
        let view = carrier.view()?;
        let title = carrier.title()?.filter(|title| title.contains(text_form));
        let held = view.markdown.contains(text_form) || title.is_some();
        if held && view.pins.is_empty() && view.authorship.is_empty() {
            let value = as_text(value)?;
            let mut metadata = carrier.metadata()?;
            if let Some(title) = title {
                metadata.insert(
                    TITLE.to_owned(),
                    encode_title(&title.replace(text_form, value))?,
                );
            }
            let text = view.markdown.replace(text_form, value);
            let bytes = snapshot(&proposal_value(note, &text, &metadata)?)?;
            NOTE_PROPOSAL_DOC.put(&vault.store, txn, &key, &bytes)?;
            restored = true;
        } else if held
            && fork.rewrite
            && restore_document_in_txn(vault, txn, &carrier, text_form, value, actor)?
        {
            // Stored as `store_doc` stores a fork that keeps its operations.
            record_token_uses_in_txn(vault, txn, note, &carrier.doc, None)?;
            NOTE_PROPOSAL_DOC.put(&vault.store, txn, &key, &snapshot(&carrier.doc)?)?;
            restored = true;
        }
        if let Some((base, merged)) = &fork.recovery_merge
            && (base.contains(text_form) || merged.contains(text_form))
        {
            // Both texts take the value: a base left with the handle would
            // read the ruling's own edit of the NOTE as an edit of the same
            // span as the fork's, and refuse the merge (REVIEW-7904 F1).
            let value = as_text(value)?;
            let mut value_fork = fork.clone();
            value_fork.recovery_merge = Some((
                base.replace(text_form, value),
                merged.replace(text_form, value),
            ));
            replace_fork_row_in_txn(vault, txn, &fork, &value_fork)?;
            restored = true;
        }
    }
    if restored {
        // The NOTE's subscribers read its pending forks again.
        vault.queue_note_document_update_in_txn(txn, note);
    }
    Ok(())
}
