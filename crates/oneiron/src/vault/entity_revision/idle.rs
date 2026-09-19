//! Idle debounce and atomic BM25/vector/frontier publication.

use super::storage::{STATE, put_state, read_entity_revision_in_txn, state, text_fields};
use super::{IndexedRefreshReport, IndexedRevisionEmbedder, IndexedRevisionInput, ReadMode};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, apply_ops};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

const DEBOUNCE: &[u8] = b"manifest:entity_text:indexed_idle_delay_ms";

impl Vault {
    /// Seeds the host's loop policy once; never overwrites a live manifest edit.
    pub fn seed_indexed_idle_delay_ms(&self, delay_ms: u64) -> Result<()> {
        self.with_write_txn(|txn| {
            if self.store.vault_meta.get(txn, DEBOUNCE)?.is_none() {
                self.store
                    .vault_meta
                    .put(txn, DEBOUNCE, &delay_ms.to_be_bytes())?;
            }
            Ok(())
        })
    }

    /// Loop-owned, hot-editable debounce. No compiled-in delay is assumed.
    pub fn set_indexed_idle_delay_ms(&self, delay_ms: u64) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        self.store
            .vault_meta
            .put(&mut txn, DEBOUNCE, &delay_ms.to_be_bytes())?;
        txn.commit()?;
        Ok(())
    }

    /// Re-reads dirty live documents at idle, then embeds that exact revision.
    /// A concurrent edit discards the stale work rather than publishing a
    /// vector for one revision beside the text/frontier of another.
    pub fn refresh_indexed_at_idle(
        &self,
        now_ms: u64,
        embedder: &dyn IndexedRevisionEmbedder,
    ) -> Result<IndexedRefreshReport> {
        self.refresh_indexed(now_ms, Some(embedder))
    }

    /// Publishes caller-staged text/vectors at idle without a model backend.
    /// Configure the loop-owned delay with `set_indexed_idle_delay_ms` first.
    /// A dirty entity with an existing vector needs a newly staged vector;
    /// otherwise this refuses rather than pair old vectors with new content.
    pub fn refresh_staged_indexed_at_idle(&self, now_ms: u64) -> Result<IndexedRefreshReport> {
        self.refresh_indexed(now_ms, None)
    }

    fn refresh_indexed(
        &self,
        now_ms: u64,
        embedder: Option<&dyn IndexedRevisionEmbedder>,
    ) -> Result<IndexedRefreshReport> {
        let candidates = {
            let txn = self.store.env.read_txn()?;
            let raw = self.store.vault_meta.get(&txn, DEBOUNCE)?.ok_or_else(|| {
                Error::InvalidConfig("indexed idle delay manifest row is missing".into())
            })?;
            let delay = u64::from_be_bytes(
                raw.as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("indexed idle delay"))?,
            );
            let mut candidates = Vec::new();
            for row in self.store.vault_meta.prefix_iter(&txn, STATE)? {
                let (key_bytes, _) = row?;
                let bytes: [u8; 16] = key_bytes[STATE.len()..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("entity revision key"))?;
                let id = EntityId::from_bytes(bytes)
                    .map_err(|_| Error::CorruptedIndex("entity revision id"))?;
                let current = state(&self.store, &txn, &id)?
                    .ok_or(Error::CorruptedIndex("entity revision state"))?;
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
                    source_revision_ref: current.live,
                    fields: text_fields(&body),
                    body,
                });
            }
            candidates
        };
        let mut report = IndexedRefreshReport::default();
        for input in candidates {
            let staged = {
                let txn = self.store.env.read_txn()?;
                super::pending_index::load(
                    &self.store,
                    &txn,
                    &input.entity,
                    input.source_revision_ref,
                )?
            };
            let vector = match staged.vector {
                Some(vector) => Some(vector),
                None => match embedder {
                    Some(embedder) => Some(embedder.embed_revision(&input)?),
                    None if self.get_vector(&input.entity)?.is_none() => None,
                    None => {
                        return Err(Error::InvalidConfig(
                            "idle index publication requires a staged vector or embedder".into(),
                        ));
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
            let codes = super::phonetic::take_phonetic(
                &self.store,
                &mut txn,
                &input.entity,
                input.source_revision_ref,
            )?;
            crate::batch::delete_from_phonetic_postings(&self.store, &mut txn, &input.entity)?;
            // Publish the stamp before the batch vector door in this SAME
            // transaction. On any text/vector failure LMDB rolls all back.
            current.indexed = current.live;
            put_state(&self.store, &mut txn, &input.entity, &current)?;
            let generated_vector = staged.vector.is_none() && embedder.is_some();
            let vector = staged.vector.or(vector);
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
            apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                &mut txn,
                ops,
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                false,
            )?;
            if wrote_vector && generated_vector {
                self.store
                    .clear_pending_embedding(&mut txn, &input.entity)?;
            }
            super::pending_index::clear(&self.store, &mut txn, &input.entity)?;
            txn.commit()?;
            report
                .refreshed
                .push((input.entity, input.source_revision_ref));
        }
        Ok(report)
    }

    /// Exact index revision currently available, including unedited births.
    pub fn indexed_revision(&self, id: &EntityId) -> Result<Option<super::RevisionRef>> {
        let txn = self.store.env.read_txn()?;
        let Some(raw) = read_entity_revision_in_txn(self, &txn, id, ReadMode::Indexed)? else {
            return Ok(None);
        };
        Ok(Some(
            state(&self.store, &txn, id)?
                .map(|value| value.indexed)
                .unwrap_or_else(|| super::storage::reference(id, &raw)),
        ))
    }
}
