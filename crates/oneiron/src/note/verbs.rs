//! Actor-bound NOTE creation, edit and source-entity bridge.

use super::documents::{NoteDocument, invalid, load_doc, store_doc};
use super::{
    NoteBody, NoteProgramEdit as NoteEdit, NoteProgramEditOutcome as NoteEditOutcome,
    encode_note_body,
};
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
            source_revision_ref: *self.store.clock.entity_id()?.as_bytes(),
            kind,
            author_ref: actor.entity_ref(),
            markdown: markdown.to_owned(),
        })?;
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
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
                let doc = super::document_store::load(self, txn, id)?;
                super::document_store::persist(self, txn, &doc)?;
                Ok(id)
            })
    }

    /// Moves a NOTE, ASSET or CLAIM to another facet the only way a facet
    /// moves: a birth under `facet` with the origin's current content and a
    /// `DerivedFrom` edge to it. With `supersede` the fork also supersedes the
    /// origin. The origin keeps its id and its stamp.
    pub fn fork_to_facet(
        &self,
        origin: EntityId,
        facet: EntityId,
        supersede: bool,
        actor: WriteActor,
    ) -> MemoryResult<EntityId> {
        let fork = self.store.clock.entity_id()?;
        let at = self.store.clock.now_recorded_at();
        let occurred = TimeRange { start: at, end: at };
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                let found = self.get_entity_type_in_txn(txn, &facet)?;
                if found != Some(crate::registry::ENTITY_TYPE_FACET) {
                    return Err(crate::Error::Registry(
                        crate::error::RegistryError::InvalidFacet { facet, found },
                    )
                    .into());
                }
                let kind = self
                    .get_entity_type_in_txn(txn, &origin)?
                    .ok_or(crate::Error::EntityNotFound)?;
                let owner = actor.actor_class() == crate::edge::EdgeActorClass::Human
                    && crate::memory::verify_owner_actor_binding_in_txn(
                        self,
                        txn,
                        actor.entity_ref(),
                    )
                    .is_ok();
                match kind {
                    ENTITY_TYPE_NOTE => {
                        let (_, core) = note_core(self, txn, origin)?;
                        if !owner && core.author_ref != actor.entity_ref() {
                            return Err(
                                invalid("NOTE fork requires its author or the owner").into()
                            );
                        }
                        let body = encode_note_body(&NoteBody {
                            source_revision_ref: *self.store.clock.entity_id()?.as_bytes(),
                            kind: core.kind,
                            author_ref: actor.entity_ref(),
                            markdown: super::documents::live_doc(self, txn, origin)?.text(),
                        })?;
                        fork_links(
                            self.batch_in()
                                .mask(Some(facet))
                                .put_authored_note(&fork, &actor.entity_ref(), occurred, at, &body)
                                .edge(&fork, EdgeKind::AuthoredBy, &actor.entity_ref(), 1.0),
                            fork,
                            origin,
                            supersede,
                        )
                        .apply(txn)?;
                        let doc = super::document_store::load(self, txn, fork)?;
                        super::document_store::persist(self, txn, &doc)?;
                    }
                    ENTITY_TYPE_ASSET => {
                        if !owner {
                            return Err(invalid("ASSET fork requires the owner").into());
                        }
                        let raw = self
                            .get_raw_in(txn, &origin)?
                            .ok_or(crate::Error::EntityNotFound)?;
                        fork_links(
                            self.batch_in().mask(Some(facet)).put(
                                &fork,
                                ENTITY_TYPE_ASSET,
                                occurred,
                                at,
                                &raw[ENTITY_METADATA_HEADER_LEN..],
                            ),
                            fork,
                            origin,
                            supersede,
                        )
                        .apply(txn)?;
                    }
                    crate::registry::ENTITY_TYPE_CLAIM => {
                        if !owner {
                            return Err(invalid("CLAIM fork requires the owner").into());
                        }
                        let mut body = self
                            .get_claim_in_txn(txn, &origin)?
                            .ok_or(crate::Error::EntityNotFound)?;
                        body.scope_facet = facet;
                        self.put_claim_in_txn(txn, &fork, &body, occurred, at)?;
                        self.batch_in()
                            .edge(&fork, EdgeKind::DerivedFrom, &origin, 1.0)
                            .apply(txn)?;
                        if supersede {
                            self.supersede_claim_in_txn(txn, &fork, &origin, at)?;
                        }
                    }
                    other => return Err(crate::Error::InvalidEntityType(other).into()),
                }
                Ok(fork)
            })
    }

    /// A proposed move of `origin` to `facet`: one pending
    /// `facet.fork_suggested` CLAIM on the origin, stamped with the origin's
    /// facet so it discloses no more than its origin. It forks nothing and
    /// stamps nothing.
    pub fn suggest_facet_fork(
        &self,
        origin: EntityId,
        facet: EntityId,
        actor: WriteActor,
    ) -> MemoryResult<EntityId> {
        let suggestion = self.store.clock.entity_id()?;
        let at = self.store.clock.now_recorded_at();
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                let found = self.get_entity_type_in_txn(txn, &facet)?;
                if found != Some(crate::registry::ENTITY_TYPE_FACET) {
                    return Err(crate::Error::Registry(
                        crate::error::RegistryError::InvalidFacet { facet, found },
                    )
                    .into());
                }
                let origin_facet = match self.get_entity_type_in_txn(txn, &origin)? {
                    Some(ENTITY_TYPE_NOTE | ENTITY_TYPE_ASSET) => {
                        crate::federation::record_scope::birth_facet(&self.store, txn, origin)?
                    }
                    Some(crate::registry::ENTITY_TYPE_CLAIM) => self
                        .get_claim_in_txn(txn, &origin)?
                        .map(|body| body.scope_facet),
                    Some(other) => return Err(crate::Error::InvalidEntityType(other).into()),
                    None => return Err(crate::Error::EntityNotFound.into()),
                }
                .ok_or(invalid("the origin carries no facet stamp"))?;
                let mut body = crate::claim::ClaimBody::new(
                    PREDICATE_FACET_FORK_SUGGESTED,
                    crate::claim::ClaimSubject::Entity(origin),
                    rmpv::Value::Binary(facet.as_bytes().to_vec()),
                    1.0,
                    crate::claim::ClaimApprovalStatus::Proposed,
                    crate::claim::ClaimLifecycleStatus::Active,
                );
                body.source = Some(crate::claim::ClaimSource::Inferred);
                body.scope_facet = origin_facet;
                self.put_claim_in_txn(
                    txn,
                    &suggestion,
                    &body,
                    TimeRange { start: at, end: at },
                    at,
                )?;
                Ok(suggestion)
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
        let result = self
            .memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                let existed = load_doc(self, txn, note)?.is_some();
                if existed && matches!(edit, NoteEdit::WholeText { base: None, .. }) {
                    return Err(invalid("whole-text edit requires its read version").into());
                }
                let doc = super::documents::live_doc(self, txn, note)?;
                let semantic = doc.semantic_edit(edit)?;
                let isolated_rewrite = if semantic.is_none() {
                    match edit {
                        NoteEdit::WholeText { text, .. } | NoteEdit::Rewrite { text } => {
                            Some(NoteEdit::Rewrite { text: text.clone() })
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                let authorized = super::proposals::grant_allows(self, txn, note, actor)?;
                if let Some((base, edits)) = semantic.filter(|_| authorized) {
                    let operation = super::NoteOperation {
                        request_id: self.store.clock.entity_id()?,
                        change: super::NoteChange::Edit { base, edits },
                    };
                    let receipt = self
                        .memory(actor.entity_ref(), actor.actor_class())
                        .apply_note_operation_in_txn(txn, note, &operation, None)?;
                    return Ok(match receipt.outcome {
                        super::NoteEditOutcome::Applied(_) => {
                            NoteEditOutcome::Edited { head: doc.head }
                        }
                        super::NoteEditOutcome::Proposed(receipt) => {
                            NoteEditOutcome::ReviewRequired { receipt }
                        }
                    });
                }
                let candidate = NoteDocument {
                    note,
                    head: note,
                    doc: doc.doc.fork(),
                };
                let replacement = candidate.apply(
                    &self.store.clock,
                    isolated_rewrite.as_ref().unwrap_or(edit),
                    actor.entity_ref(),
                    self.store.clock.now_recorded_at(),
                )?;
                let rewrite = replacement.is_some();
                let mut fork = replacement.unwrap_or(candidate);
                fork.head = self.store.clock.entity_id()?;
                store_doc(self, txn, &fork)?;
                super::proposals::remember_fork(
                    self,
                    txn,
                    &doc,
                    &fork,
                    actor.entity_ref(),
                    rewrite,
                )?;
                Ok(if authorized {
                    NoteEditOutcome::RewriteFork { fork: fork.head }
                } else {
                    NoteEditOutcome::ProposedFork { fork: fork.head }
                })
            })?;
        #[cfg(feature = "sync")]
        self.notify_note_document(note);
        Ok(result)
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
        source_revision_ref: *vault.store.clock.entity_id()?.as_bytes(),
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

/// Engine-internal predicate of a pending facet-fork suggestion: subject the
/// origin, value the proposed FACET id as 16 binary bytes.
const PREDICATE_FACET_FORK_SUGGESTED: &str = "facet.fork_suggested";

fn fork_links(
    batch: crate::batch::TxnBatchBuilder<'_>,
    fork: EntityId,
    origin: EntityId,
    supersede: bool,
) -> crate::batch::TxnBatchBuilder<'_> {
    let batch = batch.edge(&fork, EdgeKind::DerivedFrom, &origin, 1.0);
    if supersede {
        batch.edge(&fork, EdgeKind::Supersedes, &origin, 1.0)
    } else {
        batch
    }
}

pub(super) fn note_core(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> crate::error::Result<(EntityMetadataHeader, NoteBody)> {
    if vault.local_hard_delete_marker_exists_in_txn(txn, &note)? {
        return Err(invalid("NOTE was erased"));
    }
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
    let bytes = &raw[ENTITY_METADATA_HEADER_LEN..];
    #[cfg(feature = "sync")]
    let resolved = crate::entity_doc::resolve_record_body(&vault.store, txn, &note, bytes)?;
    #[cfg(feature = "sync")]
    let bytes = resolved.as_slice();
    let body = super::decode_note_body_in_txn(&vault.store, txn, bytes)?;
    Ok((header, body))
}
