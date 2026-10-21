//! A quote of an atomic MESSAGE anchors to the document its first quote
//! births (FIX 7743, Engine B1; CROSS-ARCH-0010's quote amendment), as a
//! quote of a streamed MESSAGE does: the frontier, stable cursors and hash
//! sit on the citation pin, and the numeric span stays request input only.
//! The document keeps the MESSAGE's own author and time; the citing actor
//! goes on the pin; the quote asks no edit grant. A MESSAGE whose birth a
//! precondition stops (no author edge, as a system or imported row has; an
//! author or citer that is not live and active as its class; a body that is
//! not the canonical envelope) keeps the hash-bound span it is quoted by
//! today, so no quote refuses for it. Anchors already kept are not
//! rewritten, and a retry that quotes the same text again keeps its body
//! anchor.

use super::quote::{QuoteAnchor, field, message_fields, scalar_slice};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::provenance::made_by::MadeByClass;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON,
};
use crate::{EntityId, Vault, WriteActor};
use heed::RoTxn;
use rmpv::Value;

/// The author whose document a quote of the atomic MESSAGE `message` by
/// `citer` births, or `None` when a precondition stops the birth and the
/// quote keeps its body anchor.
pub(super) fn birth_author_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    message: EntityId,
    citer: WriteActor,
) -> Result<Option<WriteActor>> {
    let mut authors = Vec::new();
    for edge in vault.store.port_edges(
        txn,
        &message,
        EdgeDirection::Out,
        Some(EdgeKind::AuthoredBy),
        None,
    )? {
        authors.push(edge?.target);
        if authors.len() > 1 {
            break;
        }
    }
    let [author] = authors[..] else {
        return Ok(None);
    };
    let Some(class) = author_class_in(vault, txn, message, author)? else {
        return Ok(None);
    };
    let author = WriteActor::new(author, class);
    Ok(
        crate::entity_doc::quote_birth_admits_in(vault, txn, &message, author, citer)?
            .then_some(author),
    )
}

/// The class `author` wrote `message` in. A person's witness birth names a
/// human (Rule A); no other writer stamps one, so the class is the one its
/// entity takes: a PERSON's agent, a MACHINE's system, an AGENT_DEF's agent.
fn author_class_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    message: EntityId,
    author: EntityId,
) -> Result<Option<EdgeActorClass>> {
    if let Some(birth) = crate::provenance::birth::row_birth_in_txn(&vault.store, txn, &message)?
        && birth.made_by.process.actor == author
        && birth.made_by.process.class == MadeByClass::Stated
    {
        return Ok(Some(EdgeActorClass::Human));
    }
    let kind = vault
        .store
        .port_entity_raw(txn, &author)?
        .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
        .map(|header| header.entity_type);
    Ok(match kind {
        Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF) => Some(EdgeActorClass::Agent),
        Some(ENTITY_TYPE_MACHINE) => Some(EdgeActorClass::System),
        _ => None,
    })
}

/// Whether `stored` is the body anchor the scalar `span` of `message`'s
/// current text selects: a kept body anchor that a retry quotes again
/// (FIX 7743). It loosens nothing else: another span, text or message
/// still reads as a changed quote.
pub(super) fn is_body_anchor_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    stored: &QuoteAnchor,
    message: EntityId,
    span: (usize, usize),
) -> Result<bool> {
    let QuoteAnchor::Body {
        message: quoted,
        body_hash,
        start,
        end,
        quote_hash,
    } = *stored
    else {
        return Ok(false);
    };
    if quoted != message
        || usize::try_from(start).ok() != Some(span.0)
        || usize::try_from(end).ok() != Some(span.1)
    {
        return Ok(false);
    }
    let row = super::graph::require_type(&vault.store, txn, &message, ENTITY_TYPE_MESSAGE)?;
    let row = crate::entity_doc::resolve_record_body(&vault.store, txn, &message, &row)?;
    let fields = message_fields(&row)?;
    let Some(text) = field(&fields, "content").and_then(Value::as_str) else {
        return Ok(false);
    };
    Ok(blake3::hash(text.as_bytes()).as_bytes() == &body_hash
        && scalar_slice(text, span.0, span.1)
            .is_some_and(|quote| blake3::hash(quote.as_bytes()).as_bytes() == &quote_hash))
}
