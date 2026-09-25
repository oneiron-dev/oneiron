//! MESSAGE terminal commits join the common EntityDoc storage transaction.
//! Only the stream witness path calls this adapter, after the canonical ceiling.
use super::{EntityDoc, TextField, invalid, storage};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
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
    if vault
        .store
        .vault_meta
        .get(txn, storage::head_key(entity).as_bytes())?
        .is_some()
    {
        return Err(invalid("stream birth cannot replace an existing document"));
    }
    let raw = vault
        .store
        .entities
        .get(txn, entity.as_bytes())?
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
    let mut replacement = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
    rmpv::encode::write_value(&mut replacement, &rmpv::Value::Map(fields))
        .map_err(|_| invalid("message document pointer"))?;
    vault
        .store
        .entities
        .put(txn, entity.as_bytes(), &replacement)?;
    let mut head = storage::Head {
        entity: entity.to_hex(),
        incarnation: EntityId::now().to_hex(),
        document: entity.to_hex(),
        field: TextField::MapField("content".to_owned()),
        generation: 0,
        pending: 0,
    };
    storage::persist(vault, txn, entity, &mut head, &doc, None)?;
    crate::bm25::index_text(
        &vault.store,
        txn,
        &vault.analyzer,
        entity,
        &[("content".to_owned(), doc.text())],
    )
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
    crate::batch::secret_scan::scan_metadata_field(delta)?;
    if vault
        .store
        .vault_meta
        .get(txn, storage::head_key(entity).as_bytes())?
        .is_none()
    {
        // Atomic MESSAGEs move their original text into birth exactly once.
        let raw = vault
            .store
            .entities
            .get(txn, entity.as_bytes())?
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
    crate::bm25::index_text(
        &vault.store,
        txn,
        &vault.analyzer,
        entity,
        &[("content".to_owned(), doc.text())],
    )
}

/// Read-only authorization check shared by begin, presence and terminal commit.
pub(crate) fn authorize_message_continuation_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    actor: WriteActor,
) -> Result<()> {
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
