//! Actor-bound NOTE creation, edit and source-entity bridge.

use super::documents::{NoteDocument, invalid, load_doc, store_doc};
use super::{NoteBody, NoteEdit, NoteEditOutcome, encode_note_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::memory::MemoryResult;
use crate::ports::{EdgeStoreRead, EntityStore};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_NOTE};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

impl Vault {
    /// A NOTE's first authored text is its birth op, not a mutable record field.
    pub fn create_note(
        &self,
        kind: &str,
        markdown: &str,
        actor: WriteActor,
    ) -> MemoryResult<EntityId> {
        let kind = self.note_kind(kind)?;
        let id = self.store.clock.entity_id()?;
        let at = self.store.clock.now_recorded_at();
        let body = encode_note_body(&NoteBody {
            document_head: None,
            kind,
            author_ref: actor.entity_ref(),
            markdown: markdown.to_owned(),
        })?;
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                let doc = NoteDocument::born(
                    id,
                    self.store.clock.entity_id()?,
                    markdown,
                    actor.entity_ref(),
                    at,
                )?;
                self.batch_in()
                    .put_authored_note(
                        &id,
                        &actor.entity_ref(),
                        TimeRange { start: at, end: at },
                        at,
                        &body,
                    )
                    .edge(&id, EdgeKind::AuthoredBy, &actor.entity_ref(), 1.0)
                    .apply(txn)?;
                store_doc(self, txn, &doc, true)?;
                Ok(id)
            })
    }

    /// Edits operate on a transaction-local document. Rejected edits cannot
    /// leave pending ops that a later author would accidentally commit.
    pub fn edit_note(
        &self,
        note: EntityId,
        edit: &NoteEdit,
        actor: WriteActor,
    ) -> MemoryResult<NoteEditOutcome> {
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                let (header, body) = note_core(self, txn, note)?;
                let doc = match load_doc(self, txn, note)? {
                    Some(doc) => {
                        if matches!(edit, NoteEdit::WholeText { base: None, .. }) {
                            return Err(invalid("whole-text edit requires its read version").into());
                        }
                        doc
                    }
                    None => NoteDocument::born(
                        note,
                        self.store.clock.entity_id()?,
                        &body.markdown,
                        body.author_ref,
                        header.learned_at,
                    )?,
                };
                let at = self.store.clock.now_recorded_at();
                if !super::proposals::grant_allows(self, txn, note, actor)? {
                    let candidate = NoteDocument {
                        note,
                        head: doc.head,
                        doc: doc
                            .doc
                            .fork_at(&doc.doc.state_frontiers())
                            .map_err(|_| invalid("fork frontier"))?,
                    };
                    let replacement =
                        candidate.apply(&self.store.clock, edit, actor.entity_ref(), at)?;
                    let rewrite = replacement.is_some();
                    let mut fork = replacement.unwrap_or(candidate);
                    fork.head = self.store.clock.entity_id()?;
                    store_doc(self, txn, &doc, true)?;
                    store_doc(self, txn, &fork, false)?;
                    super::proposals::remember_fork(
                        self,
                        txn,
                        &doc,
                        &fork,
                        actor.entity_ref(),
                        rewrite,
                    )?;
                    return Ok(NoteEditOutcome::ProposedFork { fork: fork.head });
                }
                if let Some(fork) = doc.apply(&self.store.clock, edit, actor.entity_ref(), at)? {
                    // Birth, when needed, persists without any rewrite operations.
                    store_doc(self, txn, &doc, true)?;
                    store_doc(self, txn, &fork, false)?;
                    super::proposals::remember_fork(
                        self,
                        txn,
                        &doc,
                        &fork,
                        actor.entity_ref(),
                        true,
                    )?;
                    Ok(NoteEditOutcome::RewriteFork { fork: fork.head })
                } else {
                    store_doc(self, txn, &doc, true)?;
                    Ok(NoteEditOutcome::Edited { head: doc.head })
                }
            })
    }

    /// Copies a source row's text without modifying that row. The NOTE stays
    /// document-free until its first edit; DerivedFrom permanently cites source.
    pub fn create_from_entity(
        &self,
        source: EntityId,
        kind: &str,
        actor: WriteActor,
    ) -> MemoryResult<EntityId> {
        let kind = self.note_kind(kind)?;
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                let header = live_header(self, txn, source)?;
                let (text_source, citation) = if header.entity_type == ENTITY_TYPE_ASSET {
                    let mut newest = None;
                    for entry in self.store.port_edges(
                        txn,
                        &source,
                        crate::ports::EdgeDirection::In,
                        Some(EdgeKind::DerivedFrom),
                        None,
                    )? {
                        let id = entry?.target;
                        let Some(candidate) = self.port_entity_get(txn, &id)? else {
                            continue;
                        };
                        if candidate.entity_type == ENTITY_TYPE_ASSET_TEXT {
                            let value = (candidate.learned_at, id);
                            if newest.is_none_or(|previous| value > previous) {
                                newest = Some(value);
                            }
                        }
                    }
                    (newest.ok_or(invalid("asset has no ASSET_TEXT"))?.1, source)
                } else {
                    (source, source)
                };
                create_from_text_in_txn(self, txn, text_source, citation, kind, actor)
                    .map_err(Into::into)
            })
    }

    pub fn create_note_from_asset(
        &self,
        asset: EntityId,
        kind: &str,
        actor: WriteActor,
    ) -> MemoryResult<EntityId> {
        // The generic bridge revalidates source kind and chooses its current
        // ASSET_TEXT in the same write txn that creates the NOTE and citation.
        if self.get_entity_type(&asset)? != Some(ENTITY_TYPE_ASSET) {
            return Err(invalid("source is not an ASSET").into());
        }
        self.create_from_entity(asset, kind, actor)
    }
}

fn live_header(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> crate::error::Result<EntityMetadataHeader> {
    let row = vault
        .port_entity_get(txn, &id)?
        .ok_or(invalid("source is not live"))?;
    Ok(EntityMetadataHeader {
        entity_type: row.entity_type,
        occurred_start: row.occurred.start,
        occurred_end: row.occurred.end,
        learned_at: row.learned_at,
    })
}
fn create_from_text_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: EntityId,
    citation: EntityId,
    kind: super::NoteKind,
    actor: WriteActor,
) -> crate::error::Result<EntityId> {
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let header = live_header(vault, txn, source)?;
    let text = if header.entity_type == ENTITY_TYPE_NOTE {
        match load_doc(vault, txn, source)? {
            Some(doc) => doc.text(),
            None => note_core(vault, txn, source)?.1.markdown,
        }
    } else if header.entity_type == ENTITY_TYPE_ASSET_TEXT {
        let raw = vault
            .get_raw_in(txn, &source)?
            .ok_or(invalid("source disappeared"))?;
        String::from_utf8(raw[ENTITY_METADATA_HEADER_LEN..].to_vec())
            .map_err(|_| invalid("source text is not UTF-8"))?
    } else {
        return Err(invalid("source has no supported text representation"));
    };
    let id = vault.store.clock.entity_id()?;
    let at = mutation_recorded_at;
    let body = encode_note_body(&NoteBody {
        document_head: None,
        kind,
        author_ref: actor.entity_ref(),
        markdown: text,
    })?;
    vault
        .batch_in()
        .put_authored_note(
            &id,
            &actor.entity_ref(),
            TimeRange { start: at, end: at },
            at,
            &body,
        )
        .edge(&id, EdgeKind::AuthoredBy, &actor.entity_ref(), 1.0)
        .edge(&id, EdgeKind::DerivedFrom, &citation, 1.0)
        .apply(txn)?;
    Ok(id)
}

pub(super) fn note_core(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> crate::error::Result<(EntityMetadataHeader, NoteBody)> {
    if vault.archive_tombstone_in_txn(txn, &note)?.is_some() {
        return Err(invalid("NOTE is archived"));
    }
    let raw = vault
        .get_raw_in(txn, &note)?
        .ok_or(invalid("NOTE does not exist"))?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(invalid("NOTE header"))?;
    if header.entity_type != ENTITY_TYPE_NOTE {
        return Err(invalid("entity is not a NOTE"));
    }
    let body =
        super::decode_note_body_using(&raw[ENTITY_METADATA_HEADER_LEN..], super::NoteKind::wire)?;
    Ok((header, body))
}
