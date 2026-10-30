//! Typed NOTE projection of an already admitted opened-item read cache.

use super::documents::{NoteDocument, invalid};
use super::reads::read_view;
use super::{NoteReadRequest, NoteReadSource, NoteReadSpan, NoteReadView};
use crate::authority::VerifiedSlip;
use crate::memory::{MemoryError, MemoryResult};
use crate::settings::ReadDestination;
use crate::sync::{OpenedItem, ThinItem};
use crate::{Vault, WriteActor};

/// The residence host has already checked the owner's own credential. It
/// passes that same proof to canonical reads; a thin cache is the state the
/// machine's existing selector-admitted touch disclosed, never a new import.
pub(crate) fn opened_note_view(
    vault: &Vault,
    opened: &OpenedItem,
    actor: WriteActor,
    proof: Option<&VerifiedSlip>,
    destination: &ReadDestination,
    reason: Option<&str>,
    spans: &[NoteReadSpan],
) -> MemoryResult<Option<NoteReadView>> {
    match opened {
        OpenedItem::Resident { entity_id, raw, .. } => {
            if crate::batch::EntityMetadataHeader::parse(raw)
                .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_NOTE)
            {
                return Ok(None);
            }
            let memory = vault
                .memory(actor.entity_ref(), actor.actor_class())
                .for_destination(destination);
            let memory = match proof {
                Some(proof) => memory.with_read_proof(proof),
                None => memory,
            };
            Ok(memory
                .read_note(&NoteReadRequest {
                    note_ref: entity_id.to_hex(),
                    reason: reason.map(str::to_owned),
                    version: None,
                    spans: spans.to_vec(),
                })?
                .value)
        }
        OpenedItem::Thin(thin) => thin_note_view(vault, thin, actor, reason, spans),
    }
}

fn thin_note_view(
    vault: &Vault,
    thin: &ThinItem,
    actor: WriteActor,
    reason: Option<&str>,
    spans: &[NoteReadSpan],
) -> MemoryResult<Option<NoteReadView>> {
    let header = crate::batch::EntityMetadataHeader::parse(&thin.raw)
        .ok_or_else(|| invalid("opened item header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_NOTE {
        return Ok(None);
    }
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let core = super::decode_note_body_in_txn(
        &vault.store,
        &txn,
        &thin.raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )?;
    let private = super::overrides::note_context_in_txn(
        &vault.store,
        &txn,
        &thin.entity_id,
        core.kind.as_str().as_ref(),
    )? == super::ContextDefault::OwnerOnly;
    // A cache has no independent grant authority. Another actor's private
    // note still requires its ordinary reasoned private-note door.
    if private && !core.author_ref.is(actor.entity_ref()) {
        return Err(MemoryError::new(
            crate::memory::MEMORY_CODE_FORBIDDEN,
            "another actor's private NOTE requires its reasoned read door",
            &[],
        ));
    }
    if private || core.kind == super::NoteKind::Diary {
        crate::memory::DiaryReadGate::new(actor, reason.unwrap_or_default())?;
    }
    let bytes = thin
        .document
        .strip_prefix(&[crate::sync::transport::TAG_DOCUMENT])
        .ok_or_else(|| invalid("opened NOTE document frame"))?;
    let frame = crate::sync::transport::decode_document(bytes)
        .map_err(|_| invalid("opened NOTE document frame"))?;
    if frame.entity != thin.entity_id
        || frame.kind != crate::sync::transport::document_sub_tags::STATE
    {
        return Err(invalid("opened NOTE requires its admitted state").into());
    }
    // The state envelope names the head, its sequence and its seal before
    // the document (FIX 2401).
    let envelope = crate::sync::documents::note_state::NoteStateEnvelope::decode(
        thin.entity_id,
        frame.payload,
    )
    .map_err(|_| invalid("opened NOTE head"))?;
    let (head, snapshot) = (envelope.head, envelope.document);
    let canonical = super::document::NoteDocument::load(thin.entity_id, snapshot)?;
    Ok(Some(read_view(
        &NoteDocument {
            note: thin.entity_id,
            head,
            doc: canonical.doc,
        },
        spans,
        NoteReadSource::Local,
    )?))
}
