//! MESSAGE terminal commits join the common EntityDoc storage transaction.
//! The stream witness path calls this adapter after the canonical ceiling;
//! a quote of an atomic MESSAGE births its document here too (FIX 7743).
use super::storage::ENTITY_DOC_HEAD;
use super::{EntityDoc, TextField, invalid, storage};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::ports::EntityStoreMaintenance;
use crate::side_table::HexId;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// Birth occurs only after put_witness_message proved and staged canonical bytes.
pub(crate) fn birth_message_stream_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    actor: WriteActor,
    at: u64,
) -> Result<()> {
    birth_message_in_txn(vault, txn, entity, actor, at, "entity_doc.message_stream")
}

/// Whether a quote of the atomic MESSAGE `entity` by `citer` can birth its
/// document in `author`'s name (FIX 7743): no document stands yet, its body
/// is the canonical envelope a stream birth takes, its text passes the scan
/// every document write takes, no pin a window carried here already sits on
/// it (the birth pins its body quotes under their citers), and both actors
/// are live and active as their class, as the birth's peer binding and the
/// citation pin require. `false` keeps the quote on its hash-bound span, as
/// today; it is never a refusal. Only a store failure is an error.
pub(crate) fn quote_birth_admits_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    author: WriteActor,
    citer: WriteActor,
) -> Result<bool> {
    if ENTITY_DOC_HEAD.contains(&vault.store, txn, &HexId(*entity))? {
        return Ok(false);
    }
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, entity)?
    else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(false);
    };
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    if header.entity_type != crate::registry::ENTITY_TYPE_MESSAGE
        || crate::gate::validate_canonical_witness_message_body(body).is_err()
    {
        return Ok(false);
    }
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut std::io::Cursor::new(body))
    else {
        return Ok(false);
    };
    let Some(text) = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("content"))
        .and_then(|(_, value)| value.as_str())
    else {
        return Ok(false);
    };
    let carried = super::pins::ENTITY_DOC_PIN.scan_from(
        &vault.store,
        txn,
        format!("{}:", entity.to_hex()).as_bytes(),
    )?;
    Ok(carried.is_empty()
        && crate::batch::secret_scan::scan_content_in_txn(&vault.store, txn, text.as_bytes())
            .is_ok()
        && super::forks::validate_actor(vault, txn, author).is_ok()
        && super::forks::validate_actor(vault, txn, citer).is_ok())
}

/// Births, in a quote's writer, the document of the atomic MESSAGE `entity`
/// its first quote anchors to (FIX 7743, Engine B1), unless one stands now:
/// in `author`'s name, the MESSAGE's own, at its own time, as a stream would
/// have born it. Its caller ran [`quote_birth_admits_in`] in this same
/// transaction, and the quote asks no edit grant. The MESSAGE's earlier body
/// quotes are pinned at the birth frontier, as a stream birth pins them.
pub(crate) fn ensure_quote_document_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    author: WriteActor,
) -> Result<()> {
    if ENTITY_DOC_HEAD.contains(&vault.store, txn, &HexId(*entity))? {
        return Ok(());
    }
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, entity)?
        .ok_or(Error::EntityNotFound)?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("message header"))?;
    let at = header.occurred_start;
    birth_message_in_txn(vault, txn, entity, author, at, "entity_doc.message_quote")
}

/// A MESSAGE document's birth from its canonical text, through `door`.
fn birth_message_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    actor: WriteActor,
    at: u64,
    door: &str,
) -> Result<()> {
    if ENTITY_DOC_HEAD.contains(&vault.store, txn, &HexId(*entity))? {
        return Err(invalid("stream birth cannot replace an existing document"));
    }
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, entity)?
        .ok_or(Error::EntityNotFound)?
        .to_vec();
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("message header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_MESSAGE {
        return Err(invalid("stream birth requires MESSAGE"));
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    crate::gate::validate_canonical_witness_message_body(body)?;
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(body))
        .map_err(|_| Error::CorruptedIndex("message canonical body"))?;
    let rmpv::Value::Map(mut fields) = value else {
        return Err(invalid("message body is not a map"));
    };
    let slot = fields
        .iter()
        .position(|(key, _)| key.as_str() == Some("content"))
        .ok_or(Error::CorruptedIndex("message canonical content"))?;
    let (_, value) = fields.remove(slot);
    let text = value
        .as_str()
        .ok_or(Error::CorruptedIndex("message text"))?;
    let doc = EntityDoc::open(*entity, text, actor, at)?;
    super::forks::bind_actor(vault, txn, &doc, actor, at)?;
    fields.push((
        rmpv::Value::from("entity_doc_ref"),
        rmpv::Value::from(entity.to_hex()),
    ));
    let mut pointer = Vec::new();
    rmpv::encode::write_value(&mut pointer, &rmpv::Value::Map(fields))
        .map_err(|_| invalid("message document pointer"))?;
    vault
        .store
        .port_entity_document_pointer_put(txn, entity, &pointer)?;
    let mut head = storage::Head {
        entity: entity.to_hex(),
        incarnation: EntityId::now().to_hex(),
        document: entity.to_hex(),
        field: TextField::MapField("content".to_owned()),
        generation: 0,
        pending: 0,
        birth_frontier: Some(doc.frontier()),
    };
    storage::stamp_document_birth(&vault.store, txn, entity, actor, at, door)?;
    storage::persist(vault, txn, entity, &mut head, &doc, None)?;
    // Quotes taken of the atomic text are pinned at the birth frontier,
    // before any appended delta moves the head.
    crate::conversation_dag::pin_body_quotes_at_message_birth_in_txn(
        vault, txn, entity, text, actor,
    )?;
    Ok(())
}

/// Continuation appends to the live head, preserving concurrent head edits.
/// It never rewrites the MESSAGE envelope or creates another document.
pub(crate) fn append_message_stream_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    delta: &str,
    actor: WriteActor,
    at: u64,
) -> Result<()> {
    authorize_message_continuation_in_txn(vault, txn, entity, actor)?;
    if delta.is_empty() {
        return Ok(());
    }
    crate::batch::secret_scan::scan_content_in_txn(&vault.store, txn, delta.as_bytes())?;
    if !ENTITY_DOC_HEAD.contains(&vault.store, txn, &HexId(*entity))? {
        // Atomic MESSAGEs move their original text into birth exactly once.
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, entity)?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("message header"))?;
        birth_message_stream_in_txn(vault, txn, entity, actor, header.occurred_start)?;
    }
    let mut head = storage::head(&vault.store, txn, entity)?;
    if head.field != TextField::MapField("content".to_owned()) {
        return Err(invalid("message document field"));
    }
    let mut doc = storage::load(&vault.store, txn, &head)?;
    let before = doc.doc.oplog_vv();
    doc.doc
        .set_peer_id(loro::LoroDoc::new().peer_id())
        .map_err(|_| invalid("stream continuation peer"))?;
    super::forks::bind_actor(vault, txn, &doc, actor, at)?;
    doc.edit_as(actor, at, |body| {
        body.insert(body.len_unicode(), delta)
            .map_err(|_| invalid("message continuation insert"))
    })?;
    storage::persist(vault, txn, entity, &mut head, &doc, Some(&before))?;
    Ok(())
}

/// Read-only authorization check shared by begin, presence and terminal commit.
pub(crate) fn authorize_message_continuation_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    actor: WriteActor,
) -> Result<()> {
    // A private thread's message is continued by its audience alone (FIX
    // 2951); a thread hidden from the writer reads as a missing message.
    if !crate::workspace_roster::record_thread_admits_in(vault, txn, *entity, actor.entity_ref())? {
        return Err(Error::EntityNotFound);
    }
    // Same author is already proven by the stream path's immutable edge check.
    // Human owner rights still require the live owner binding; agents need the
    // same entity-bound grant used by ordinary editable-text verbs.
    if actor.actor_class() == crate::edge::EdgeActorClass::Human {
        crate::memory::verify_owner_actor_binding_in_txn(vault, txn, actor.entity_ref())
            .map_err(|_| invalid("message continuation requires live owner authority"))?;
    } else {
        super::forks::authorize(
            vault,
            txn,
            &super::DocAuthorization::StandingGrant,
            entity,
            actor,
        )?;
    }
    Ok(())
}
