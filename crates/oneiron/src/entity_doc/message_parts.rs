//! A continuation's ordered-parts append: its stored prefix extended by the
//! terminal's suffix, written as the row's `parts` axis alone.
//!
//! Text appends live in the Loro document; the ordered parts live in the row
//! body beside the document pointer. A Continue that carries fresh parts
//! extends that axis in the same transaction as its text append, authorized
//! as one merged envelope. This module is that axis's only Continue writer:
//! it consumes the ceiling door's token for the full merged envelope, proves
//! the stored row is that envelope's own prefix state, and rewrites only the
//! `parts` key. No batch put, no raw put, no new maintenance door.

use super::message_stream::{authorize_message_continuation_in_txn, birth_message_stream_in_txn};
use super::{invalid, storage};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::ports::EntityStoreMaintenance;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// Appends a continuation's fresh ordered parts to its MESSAGE's stored
/// prefix, in the caller's write transaction.
///
/// `authorization` is the ceiling door's token for the FULL merged envelope
/// (`stored prefix ++ terminal suffix`), checked in this same transaction
/// against this same policy snapshot. It moves in by value: one token
/// authorizes this write alone, single use. The caller proved the stream's
/// generation, author and topology and admitted the text append before
/// reaching here; this writer proves the row is that envelope's own prefix
/// state and changes only the `parts` key.
///
/// The stored prefix compares as raw MessagePack values and their canonical
/// encodings, never through a typed re-derive, so signed opaque bytes are
/// preserved exactly. No new cap, allowlist or refusal: only a corrupted or
/// mismatched row fails.
pub(crate) fn append_message_parts_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    authorization: crate::gate::WitnessMessageAuthorization<'_>,
    actor: WriteActor,
    at: u64,
) -> Result<()> {
    // The same grant a text Continue holds: a meaningful parts append writes
    // the MESSAGE row, so it authorizes as a document edit even when its text
    // delta is empty. Repeating the checker keeps this writer from ever
    // running ungranted.
    authorize_message_continuation_in_txn(vault, txn, entity, actor)?;
    // Time rides the stored header (a birth keeps the row's own time, as every
    // birth door does) and the per-generation receipt is this write's trail,
    // so this writer stages no separate timestamp.
    let _ = at;

    let auth = decode_map(authorization.body(), "merged message envelope")?;
    if auth
        .iter()
        .any(|(key, _)| key.as_str() == Some("entity_doc_ref"))
    {
        return Err(invalid(
            "a merged message envelope carries no document pointer",
        ));
    }

    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, entity)?
        .ok_or(Error::EntityNotFound)?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("message header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_MESSAGE {
        return Err(invalid("a message parts append requires MESSAGE"));
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];

    if !storage::has_record_head(&vault.store, txn, entity)? {
        return append_atomic_parts_in_txn(
            vault,
            txn,
            entity,
            &auth,
            actor,
            header.occurred_start,
            body,
        );
    }

    // The live row: its pointer core plus the document's current text, read in
    // this same transaction after the caller's text append landed.
    let resolved = storage::resolve_record_body(&vault.store, txn, entity, body)?;
    let current = decode_map(&resolved, "message body")?;
    stripped_axes_equal(&current, &auth)?;
    if !parts_delta(&current, &auth)? {
        return Ok(());
    }
    let pointer = decode_map(body, "message document pointer")?;
    if pointer
        .iter()
        .any(|(key, _)| key.as_str() == Some("content"))
    {
        return Err(Error::CorruptedIndex("message document pointer"));
    }
    let reference = field(&pointer, "entity_doc_ref")?
        .filter(|value| value.is_str())
        .ok_or(Error::CorruptedIndex("message document pointer"))?;
    let rewritten = pointer_with_parts(&auth, reference)?;
    vault.store.port_entity_document_pointer_put(
        &crate::secret_custody::CustodyWrite::of(vault),
        txn,
        entity,
        &rewritten,
    )?;
    Ok(())
}

/// The parts append on a MESSAGE whose text never left its row: compare the
/// atomic canonical body itself, birth it through the existing birth door only
/// for a meaningful delta, then rewrite the born pointer's `parts` alone.
fn append_atomic_parts_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    auth: &[(rmpv::Value, rmpv::Value)],
    actor: WriteActor,
    occurred_start: u64,
    body: &[u8],
) -> Result<()> {
    let current = decode_map(body, "message body")?;
    if current
        .iter()
        .any(|(key, _)| key.as_str() == Some("entity_doc_ref"))
    {
        return Err(Error::CorruptedIndex("message body"));
    }
    stripped_axes_equal(&current, auth)?;
    if !parts_delta(&current, auth)? {
        // Old-absent versus empty-authorized included: no document is born
        // for no delta, as an empty Continue births none.
        return Ok(());
    }
    // A meaningful suffix is not an empty Continue: birth the existing text
    // through the existing door (which keeps every axis but `content`), so
    // the pointer rewrite below has a pointer to rewrite.
    birth_message_stream_in_txn(vault, txn, entity, actor, occurred_start)?;
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, entity)?
        .ok_or(Error::EntityNotFound)?;
    let pointer = decode_map(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        "message document pointer",
    )?;
    let reference = field(&pointer, "entity_doc_ref")?
        .filter(|value| value.is_str())
        .ok_or(Error::CorruptedIndex("message document pointer"))?;
    let rewritten = pointer_with_parts(auth, reference)?;
    vault.store.port_entity_document_pointer_put(
        &crate::secret_custody::CustodyWrite::of(vault),
        txn,
        entity,
        &rewritten,
    )?;
    Ok(())
}

/// A MessagePack map body as name/value pairs, whole (no trailing bytes).
fn decode_map(body: &[u8], what: &'static str) -> Result<Vec<(rmpv::Value, rmpv::Value)>> {
    let mut cursor = std::io::Cursor::new(body);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| Error::CorruptedIndex(what))?;
    if cursor.position() != body.len() as u64 {
        return Err(Error::CorruptedIndex(what));
    }
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &value).map_err(|_| Error::CorruptedIndex(what))?;
    if encoded != body {
        return Err(Error::CorruptedIndex(what));
    }
    match value {
        rmpv::Value::Map(fields) => Ok(fields),
        _ => Err(Error::CorruptedIndex(what)),
    }
}

/// The value `fields` holds under `name`, or `None` when absent. A duplicated
/// name is corruption: canonical encoders emit each key once.
fn field<'v>(
    fields: &'v [(rmpv::Value, rmpv::Value)],
    name: &str,
) -> Result<Option<&'v rmpv::Value>> {
    let mut found = None;
    for (key, value) in fields {
        if key.as_str() == Some(name) {
            if found.is_some() {
                return Err(Error::CorruptedIndex("duplicated message body key"));
            }
            found = Some(value);
        }
    }
    Ok(found)
}

/// Proves the current resolved body is the authorized envelope's own prefix
/// state: every axis except `parts` matches by name, including `content` (the
/// resolved view carries it last, the envelope third, so order never compares).
/// A missing, extra or unequal axis is a mismatched row, never a new refusal.
fn stripped_axes_equal(
    current: &[(rmpv::Value, rmpv::Value)],
    authorized: &[(rmpv::Value, rmpv::Value)],
) -> Result<()> {
    fn stripped(fields: &[(rmpv::Value, rmpv::Value)]) -> Result<Vec<(&str, &rmpv::Value)>> {
        let mut out = Vec::with_capacity(fields.len());
        for (key, value) in fields {
            let Some(name) = key.as_str() else {
                return Err(Error::CorruptedIndex("message body key"));
            };
            if name == "parts" || name == "entity_doc_ref" {
                continue;
            }
            if out.iter().any(|(known, _)| *known == name) {
                return Err(Error::CorruptedIndex("duplicated message body key"));
            }
            out.push((name, value));
        }
        Ok(out)
    }
    let current = stripped(current)?;
    let authorized = stripped(authorized)?;
    if current.len() != authorized.len() {
        return Err(invalid("a continued MESSAGE keeps its birth axes"));
    }
    for (name, value) in &current {
        match authorized.iter().find(|(known, _)| known == name) {
            Some((_, expected)) if value == expected => {}
            _ => return Err(invalid("a continued MESSAGE keeps its birth axes")),
        }
    }
    Ok(())
}

/// Whether the authorized `parts` extend the stored ones: the stored array
/// must be an exact element-prefix of the authorized array. Each element
/// compares as a raw MessagePack value and as its canonical encoding alike,
/// so a structural alias (two encodings that decode alike but differ
/// byte-wise) fails closed and each stored element's bytes survive exactly.
/// Absent on either side is the empty prefix, so old-absent versus
/// empty-authorized is no delta.
fn parts_delta(
    current: &[(rmpv::Value, rmpv::Value)],
    authorized: &[(rmpv::Value, rmpv::Value)],
) -> Result<bool> {
    fn array<'v>(
        fields: &'v [(rmpv::Value, rmpv::Value)],
        side: &'static str,
    ) -> Result<&'v [rmpv::Value]> {
        match field(fields, "parts")? {
            None => Ok(&[]),
            Some(rmpv::Value::Array(items)) => Ok(items),
            Some(_) => Err(Error::CorruptedIndex(side)),
        }
    }
    fn encoded(element: &rmpv::Value, side: &'static str) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, element).map_err(|_| Error::CorruptedIndex(side))?;
        Ok(bytes)
    }
    let current = array(current, "message parts")?;
    let authorized = array(authorized, "merged message parts")?;
    if authorized.len() < current.len() {
        return Err(invalid(
            "a continued MESSAGE extends its stored parts prefix",
        ));
    }
    for (index, stored) in current.iter().enumerate() {
        let fresh = &authorized[index];
        if stored != fresh
            || encoded(stored, "message parts")? != encoded(fresh, "merged message parts")?
        {
            return Err(invalid(
                "a continued MESSAGE extends its stored parts prefix",
            ));
        }
    }
    Ok(authorized.len() > current.len())
}

/// The new pointer body: the authorized envelope's axes exactly as its token
/// carries them, minus `content` (which lives in the born document), plus the
/// stored `entity_doc_ref` byte-exact. Key order follows the canonical
/// envelope with the document link last, as every birth door writes it.
fn pointer_with_parts(
    auth: &[(rmpv::Value, rmpv::Value)],
    reference: &rmpv::Value,
) -> Result<Vec<u8>> {
    let mut fields = Vec::with_capacity(auth.len() + 1);
    for (key, value) in auth {
        if key.as_str() == Some("content") {
            continue;
        }
        fields.push((key.clone(), value.clone()));
    }
    fields.push((rmpv::Value::from("entity_doc_ref"), reference.clone()));
    let mut rewritten = Vec::new();
    rmpv::encode::write_value(&mut rewritten, &rmpv::Value::Map(fields))
        .map_err(|_| invalid("message document pointer"))?;
    Ok(rewritten)
}
