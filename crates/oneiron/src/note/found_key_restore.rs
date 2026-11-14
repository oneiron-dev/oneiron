//! A found key's value back in a NOTE's live text (FIX
//! L6-03-NOTE-RULING-KEEPS-DOC-HANDLE). Every NOTE read serves its document,
//! and the mask on write stored the key's handle there (`admit_body`), so the
//! owner's "not a secret" or "kept as text" answer puts the value back into
//! the document as an edit by the person who answered, persisted as every
//! edit is: snapshot, native revision, text, title and pin indexes.

use super::document_store::{load, persist_authoritative};
use super::operations::record_authorship;
use super::{NoteActor, NoteAuthorship};
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::file_secret_marks::as_text;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_NOTE;
use crate::{Vault, WriteActor};

/// Puts `value` back where the mask left `text_form`, a found key's handle
/// as text, in the NOTE `record`'s live body and title, for a key found in
/// either (`field` "markdown" or "title"), as an edit stamped by `actor`,
/// the person whose ruling it is. One value takes one handle in both texts:
/// a write admits body and title with one plan, and a later write marks a
/// value custody holds with its handle (REVIEW-7876 F1). The ruling already
/// stands, so the write door reads the value as no hit there. Returns
/// `false` when `record` is no NOTE or `field` none of its texts: the
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
    let raw = EntityStoreRead::port_entity_raw(&vault.store, &*txn, &record)?;
    let note = raw
        .as_deref()
        .and_then(EntityMetadataHeader::parse)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_NOTE);
    if !note || !matches!(field, "markdown" | "title") {
        return Ok(false);
    }
    let doc = load(vault, txn, record)?;
    let body = Some(doc.view()?.markdown).filter(|text| text.contains(text_form));
    let title = doc.title()?.filter(|text| text.contains(text_form));
    if body.is_none() && title.is_none() {
        return Ok(true);
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
        &doc,
        &NoteAuthorship {
            operation: vault.new_entity_id()?,
            actor: NoteActor::Actor(stamp.token),
            actor_class: EdgeActorClass::Human.gate_actor_class().to_owned(),
            grant: None,
            command_hash: *blake3::hash(text_form.as_bytes()).as_bytes(),
        },
        stamp,
    )?;
    persist_authoritative(vault, txn, &doc)?;
    Ok(true)
}
