//! Idle debounce and atomic BM25/vector/frontier publication.

use super::storage::{STATE, put_state, read_entity_revision_in_txn, state, text_fields};
use super::vector_refill::{self, REFILL};
use super::{
    IndexedPublication, IndexedRefreshReport, IndexedRevisionEmbedder, IndexedRevisionInput,
    ReadMode, RevisionRef,
};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, apply_ops};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

const DEBOUNCE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::ENTITY_TEXT_INDEXED_IDLE_DELAY_MS);

impl Vault {
    /// Seeds the host's loop policy once; never overwrites a live manifest edit.
    pub fn seed_indexed_idle_delay_ms(&self, delay_ms: u64) -> Result<()> {
        self.with_write_txn(|txn| {
            if DEBOUNCE.get(&self.store, txn, &())?.is_none() {
                DEBOUNCE.put(&self.store, txn, &(), &delay_ms)?;
            }
            Ok(())
        })
    }

    /// Loop-owned, hot-editable debounce. No compiled-in delay is assumed.
    pub fn set_indexed_idle_delay_ms(&self, delay_ms: u64) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        DEBOUNCE.put(&self.store, &mut txn, &(), &delay_ms)?;
        txn.commit()?;
        Ok(())
    }

    /// Re-reads dirty live documents at idle, then embeds that exact revision.
    /// A concurrent edit discards the stale work rather than publishing a
    /// vector for one revision beside the text/frontier of another, and so
    /// does an embedding-space swap: the revision stays dirty, to be embedded
    /// in the new space. A revision with nothing in its text
    /// ([`IndexedRevisionInput::payload`]) publishes with no vector.
    ///
    /// Then embeds again, at their published revision, the records an
    /// embedding-space swap left without a vector, writing the vector alone.
    pub fn refresh_indexed_at_idle(
        &self,
        now_ms: u64,
        embedder: &dyn IndexedRevisionEmbedder,
    ) -> Result<IndexedRefreshReport> {
        self.refresh_indexed(now_ms, Some(embedder), &mut |_| {})
    }

    /// Reports each successful indexed transaction as soon as it commits. A
    /// later provider failure cannot erase earlier publication notifications.
    /// A vector refill moves no frontier and is not reported here.
    /// The callback must not write to this vault or re-enter the indexer.
    pub fn refresh_indexed_at_idle_with_publication(
        &self,
        now_ms: u64,
        embedder: &dyn IndexedRevisionEmbedder,
        mut published: impl FnMut(IndexedPublication),
    ) -> Result<IndexedRefreshReport> {
        self.refresh_indexed(now_ms, Some(embedder), &mut published)
    }

    /// Publishes caller-staged text/vectors at idle without a model backend.
    /// Configure the loop-owned delay with `set_indexed_idle_delay_ms` first.
    /// A dirty entity with an existing vector needs a newly staged vector;
    /// otherwise this refuses rather than pair old vectors with new content.
    pub fn refresh_staged_indexed_at_idle(&self, now_ms: u64) -> Result<IndexedRefreshReport> {
        self.refresh_indexed(now_ms, None, &mut |_| {})
    }

    fn refresh_indexed(
        &self,
        now_ms: u64,
        embedder: Option<&dyn IndexedRevisionEmbedder>,
        published: &mut dyn FnMut(IndexedPublication),
    ) -> Result<IndexedRefreshReport> {
        let candidates = {
            let txn = self.store.env.read_txn()?;
            let delay = DEBOUNCE.get(&self.store, &txn, &())?.ok_or_else(|| {
                Error::InvalidConfig("indexed idle delay manifest row is missing".into())
            })?;
            let mut candidates = Vec::new();
            for (id, current) in STATE.scan(&self.store, &txn)? {
                if current.live == current.indexed
                    || now_ms < current.changed_at_ms.saturating_add(delay)
                {
                    continue;
                }
                let Some(raw) = read_entity_revision_in_txn(self, &txn, &id, ReadMode::Live)?
                else {
                    continue;
                };
                let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
                if raw[0] == crate::registry::ENTITY_TYPE_CLAIM {
                    let claim = crate::claim::decode_claim_body(&body, true)?;
                    if !crate::claim::claim_surfaceable(&claim) {
                        continue;
                    }
                }
                candidates.push(IndexedRevisionInput {
                    entity: id,
                    entity_type: raw[0],
                    source_revision_ref: current.live,
                    fields: text_fields(&body),
                    body,
                });
            }
            candidates
        };
        let mut report = IndexedRefreshReport::default();
        for input in candidates {
            // A revision with nothing in its text publishes with no vector.
            let embeddable = input.payload().is_some();
            // The embedding space this work is done in, read with the staged
            // inputs it starts from.
            let (staged, epoch) = {
                let txn = self.store.env.read_txn()?;
                (
                    super::pending_index::load(
                        &self.store,
                        &txn,
                        &input.entity,
                        input.source_revision_ref,
                    )?,
                    crate::hnsw::read_embedding_model_epoch(&self.store, &txn)?,
                )
            };
            let snapshot_staged = staged.vector.is_some();
            // The provider's vector, when nothing was staged.
            let generated = match staged.vector {
                Some(_) => None,
                None if !embeddable => None,
                None => match embedder {
                    Some(embedder) => match embedder.embed_revision(&input) {
                        Ok(vector) => Some(vector),
                        Err(
                            error @ (Error::InvalidConfig(_)
                            | Error::DimensionMismatch { .. }
                            | Error::InvalidVector { .. }),
                        ) => {
                            report.failed.push((
                                input.entity,
                                input.source_revision_ref,
                                error.kind(),
                            ));
                            continue;
                        }
                        Err(error) => return Err(error),
                    },
                    None if self.get_vector(&input.entity)?.is_none() => None,
                    None => {
                        report.failed.push((
                            input.entity,
                            input.source_revision_ref,
                            crate::error::ErrorKind::InvalidConfig,
                        ));
                        continue;
                    }
                },
            };
            let mut txn = self.store.env.write_txn()?;
            let Some(mut current) = state(&self.store, &txn, &input.entity)? else {
                report.superseded.push(input.entity);
                continue;
            };
            if current.live != input.source_revision_ref
                || read_entity_revision_in_txn(self, &txn, &input.entity, ReadMode::Live)?.is_none()
                || crate::hnsw::read_embedding_model_epoch(&self.store, &txn)? != epoch
            {
                report.superseded.push(input.entity);
                continue;
            }
            let staged = super::pending_index::load(
                &self.store,
                &txn,
                &input.entity,
                input.source_revision_ref,
            )?;
            if let Some(token) = staged.pending_embedding_token.as_deref()
                && !self
                    .store
                    .pending_embedding_matches_in_txn(&txn, &input.entity, token)?
            {
                report.superseded.push(input.entity);
                continue;
            }
            let generated_vector = staged.vector.is_none() && embedder.is_some();
            let vector = match staged.vector {
                Some(vector) => Some(vector),
                // The staged vector the work started from is gone, and the copy
                // read before is not written in its place.
                None if snapshot_staged => {
                    report.superseded.push(input.entity);
                    continue;
                }
                None => generated,
            };
            let codes = super::phonetic::take_phonetic(
                &self.store,
                &mut txn,
                &input.entity,
                input.source_revision_ref,
            )?;
            crate::batch::delete_from_phonetic_postings(&self.store, &mut txn, &input.entity)?;
            // Publish the stamp before the batch vector door in this SAME
            // transaction. On any text/vector failure LMDB rolls all back.
            let previous_indexed = current.indexed;
            current.indexed = current.live;
            let indexed = current.indexed;
            put_state(&self.store, &mut txn, &input.entity, &current)?;
            let mut ops = vec![
                BatchOp::Phonetic {
                    id: input.entity,
                    codes,
                },
                BatchOp::Text {
                    id: input.entity,
                    fields: staged.fields.unwrap_or(input.fields),
                },
            ];
            let wrote_vector = vector.is_some();
            if let Some(vector) = vector {
                ops.push(BatchOp::Vector {
                    id: input.entity,
                    vector,
                    pending_embedding_token: staged.pending_embedding_token,
                });
            }
            if let Err(error) = apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                &mut txn,
                ops,
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                false,
            ) {
                if matches!(
                    error,
                    Error::DimensionMismatch { .. } | Error::InvalidVector { .. }
                ) {
                    report
                        .failed
                        .push((input.entity, input.source_revision_ref, error.kind()));
                    continue;
                }
                return Err(error);
            }
            if wrote_vector && generated_vector {
                self.store
                    .clear_pending_embedding(&mut txn, &input.entity)?;
            }
            if !wrote_vector && !embeddable {
                drop_vector_state(self, &mut txn, &input.entity)?;
            }
            super::pending_index::clear(&self.store, &mut txn, &input.entity)?;
            // The published revision settled its own vector, so a refill a
            // swap left for the revision before it has nothing left to do.
            if wrote_vector || !embeddable {
                vector_refill::clear(&self.store, &mut txn, &input.entity)?;
            }
            // A moved frontier of a turn's text owes the tagger a pass again,
            // committed with the frontier (ARCH-0036), and the turn a vector
            // of its new text (ARCH-0004).
            crate::tagging::mark_on_publication_in_txn(
                self,
                &mut txn,
                &input.entity,
                input.entity_type,
            )?;
            crate::embed::mark_on_publication_in_txn(
                self,
                &mut txn,
                &input.entity,
                input.entity_type,
            )?;
            txn.commit()?;
            if self.config.tagging.is_some() {
                self.store.notify_attempt_observers();
            }
            published(IndexedPublication {
                entity: input.entity,
                previous_indexed,
                indexed,
            });
            report
                .refreshed
                .push((input.entity, input.source_revision_ref));
        }
        if let Some(embedder) = embedder {
            self.refill_vectors(embedder, &mut report)?;
        }
        Ok(report)
    }

    /// Embeds again the published revisions an embedding-space swap left
    /// without a vector ([`vector_refill`]), and writes the vector alone: the
    /// revision, its text and its citations stay exactly as they were.
    ///
    /// A revision waiting to publish is left to that publication, which
    /// settles its vector. An archived record is hidden, not gone: it keeps
    /// its marker and is refilled once restored. An edit or another swap
    /// between the embedding and the write supersedes the work, as it does
    /// for a publication, and the marker stays for the next pass.
    fn refill_vectors(
        &self,
        embedder: &dyn IndexedRevisionEmbedder,
        report: &mut IndexedRefreshReport,
    ) -> Result<()> {
        let mut gone = Vec::new();
        let (candidates, epoch) = {
            let txn = self.store.env.read_txn()?;
            let mut candidates = Vec::new();
            for (id, ()) in REFILL.scan(&self.store, &txn)? {
                if state(&self.store, &txn, &id)?.is_some_and(|s| s.live != s.indexed)
                    || self.archive_tombstone_in_txn(&txn, &id)?.is_some()
                {
                    continue;
                }
                let (Some(revision), Some(raw)) = (
                    self.indexed_revision_in_txn(&txn, &id)?,
                    read_entity_revision_in_txn(self, &txn, &id, ReadMode::Indexed)?,
                ) else {
                    gone.push(id);
                    continue;
                };
                let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
                candidates.push(IndexedRevisionInput {
                    entity: id,
                    entity_type: raw[0],
                    source_revision_ref: revision,
                    fields: text_fields(&body),
                    body,
                });
            }
            let epoch = crate::hnsw::read_embedding_model_epoch(&self.store, &txn)?;
            (candidates, epoch)
        };
        if !gone.is_empty() {
            // Nothing readable is left to embed, as this transaction sees it:
            // a record archived or readable again since keeps its marker.
            let mut txn = self.store.env.write_txn()?;
            for id in &gone {
                if self.archive_tombstone_in_txn(&txn, id)?.is_none()
                    && self.indexed_revision_in_txn(&txn, id)?.is_none()
                {
                    vector_refill::clear(&self.store, &mut txn, id)?;
                }
            }
            txn.commit()?;
        }
        for input in candidates {
            let vector = match input.payload() {
                None => None,
                Some(_) => match embedder.embed_revision(&input) {
                    Ok(vector) => Some(vector),
                    Err(
                        error @ (Error::InvalidConfig(_)
                        | Error::DimensionMismatch { .. }
                        | Error::InvalidVector { .. }),
                    ) => {
                        report
                            .failed
                            .push((input.entity, input.source_revision_ref, error.kind()));
                        continue;
                    }
                    Err(error) => return Err(error),
                },
            };
            let mut txn = self.store.env.write_txn()?;
            if !self.refill_still_due(&txn, &input.entity, input.source_revision_ref, epoch)? {
                report.superseded.push(input.entity);
                continue;
            }
            match vector {
                Some(vector) => {
                    if let Err(error) = apply_ops(
                        &self.store,
                        &self.config,
                        &self.analyzer,
                        &mut txn,
                        vec![BatchOp::Vector {
                            id: input.entity,
                            vector,
                            pending_embedding_token: None,
                        }],
                        self.text_index_trusted
                            .load(std::sync::atomic::Ordering::Acquire),
                        false,
                        false,
                    ) {
                        if matches!(
                            error,
                            Error::DimensionMismatch { .. } | Error::InvalidVector { .. }
                        ) {
                            report.failed.push((
                                input.entity,
                                input.source_revision_ref,
                                error.kind(),
                            ));
                            continue;
                        }
                        return Err(error);
                    }
                }
                None => drop_vector_state(self, &mut txn, &input.entity)?,
            }
            vector_refill::clear(&self.store, &mut txn, &input.entity)?;
            txn.commit()?;
            report
                .refreshed
                .push((input.entity, input.source_revision_ref));
        }
        Ok(())
    }

    /// Whether the refill embedded for `revision` in the space of `epoch` is
    /// still the one to write: still marked, still published as that
    /// revision, nothing waiting, and no swap since.
    fn refill_still_due(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        revision: RevisionRef,
        epoch: u64,
    ) -> Result<bool> {
        Ok(REFILL.contains(&self.store, txn, id)?
            && state(&self.store, txn, id)?.is_none_or(|s| s.live == s.indexed)
            && self.indexed_revision_in_txn(txn, id)? == Some(revision)
            && crate::hnsw::read_embedding_model_epoch(&self.store, txn)? == epoch)
    }

    /// Exact index revision currently available, including unedited births.
    pub fn indexed_revision(&self, id: &EntityId) -> Result<Option<super::RevisionRef>> {
        let txn = self.store.env.read_txn()?;
        self.indexed_revision_in_txn(&txn, id)
    }

    pub(crate) fn indexed_revision_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<super::RevisionRef>> {
        let Some(raw) = read_entity_revision_in_txn(self, txn, id, ReadMode::Indexed)? else {
            return Ok(None);
        };
        Ok(Some(state(&self.store, txn, id)?.map_or_else(
            || super::storage::reference(id, &raw),
            |value| value.indexed,
        )))
    }
}

/// Drops what a revision with nothing to embed must not keep: its vector and
/// graph node, and the pending marker, job and lease a worker would lease it
/// by. A turn left with no text drops the same state.
pub(crate) fn drop_vector_state(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let had_node = vault
        .store
        .hnsw_neighbors
        .get(txn, id.as_bytes())?
        .is_some();
    let had_vector = vault.store.vectors.delete(txn, id.as_bytes())?;
    if had_vector || had_node {
        crate::hnsw::hnsw_deindex(&vault.store, txn, id)?;
        crate::hnsw::increment_vector_version(&vault.store, txn)?;
    }
    crate::embed::clear_embedding_locality_in_txn(&vault.store, txn, id)?;
    vault.store.clear_pending_embedding(txn, id)?;
    #[cfg(feature = "sync")]
    {
        crate::sync::queue::delete_embed_job_in_txn(&vault.store, txn, id)?;
        crate::embed::clear_pending_embedding_lease_if_any(vault, txn, id)?;
    }
    Ok(())
}
