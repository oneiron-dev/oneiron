//! Receiving-vault feedback archive, T2 vector dedup, and propose-only digest input.
use crate::{EntityId, Error, Result, TimeRange, Vault};
use serde::{Deserialize, Serialize};
mod refs;
use super::{FeedbackCategory, decode_feedback_bundle, feedback_bundle_digest};
const QUEUE: &[u8] = b"feedback:queue:v1:";
const DIGEST: &[u8] = b"feedback:received:v1:";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FeedbackReviewItem {
    #[serde(with = "refs::one")]
    pub id: EntityId,
    pub category: FeedbackCategory,
    #[serde(with = "refs::many")]
    pub bundles: Vec<EntityId>,
    pub received_at: u64,
    pub open: bool,
    centroid: Vec<f32>,
}
#[derive(Clone, Copy, Debug)]
pub struct FeedbackDedup {
    min_similarity: f32,
}
impl FeedbackDedup {
    pub fn new(min_similarity: f32) -> Result<Self> {
        if !min_similarity.is_finite() || !(0.0..=1.0).contains(&min_similarity) {
            return Err(Error::InvalidConfig(
                "invalid feedback dedup similarity".into(),
            ));
        }
        Ok(Self { min_similarity })
    }
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| Error::CorruptedIndex("feedback intake"))
}
fn decode(key: &[u8], bytes: &[u8]) -> Result<FeedbackReviewItem> {
    let item: FeedbackReviewItem =
        rmp_serde::from_slice(bytes).map_err(|_| Error::CorruptedIndex("feedback intake"))?;
    if key.strip_prefix(QUEUE) != Some(item.id.as_bytes().as_slice()) {
        return Err(Error::CorruptedIndex("feedback review identity"));
    }
    Ok(item)
}
fn normalized(vector: &[f32]) -> Result<Vec<f32>> {
    let norm = vector
        .iter()
        .map(|v| f64::from(*v).powi(2))
        .sum::<f64>()
        .sqrt();
    if vector.is_empty() || !norm.is_finite() || norm == 0.0 {
        return Err(Error::InvalidConfig("invalid feedback embedding".into()));
    }
    Ok(vector
        .iter()
        .map(|v| (f64::from(*v) / norm) as f32)
        .collect())
}
impl Vault {
    /// The embedding is supplied by the receiving host. No model runs in this
    /// transaction. Identical bundles are idempotent; T2 keeps one review item
    /// while preserving every distinct source bundle as an ASSET entity.
    pub fn ingest_feedback(
        &self,
        bytes: &[u8],
        embedding: &[f32],
        dedup: FeedbackDedup,
        now: u64,
    ) -> Result<FeedbackReviewItem> {
        let bundle = decode_feedback_bundle(bytes)
            .map_err(|_| Error::InvalidConfig("invalid feedback bundle".into()))?;
        let vector = normalized(embedding)?;
        if vector.len() != self.config.dimensions {
            return Err(Error::InvalidConfig("feedback embedding dimensions".into()));
        }
        let digest = feedback_bundle_digest(bytes);
        let digest_key = [DIGEST, digest.as_bytes()].concat();
        let id = EntityId::from_bytes(
            blake3::hash(digest.as_bytes()).as_bytes()[..16]
                .try_into()
                .expect("digest prefix"),
        )?;
        self.with_write_txn(|txn| {
            if let Some(review_id) = self.store.vault_meta.get(txn, &digest_key)? {
                let raw = crate::vault::entity_revision::read_entity_revision_in_txn(
                    self,
                    txn,
                    &id,
                    crate::vault::entity_revision::ReadMode::Live,
                )?
                .ok_or(Error::CorruptedIndex("feedback evidence missing"))?;
                let header = crate::batch::EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("feedback evidence header"))?;
                if header.entity_type != crate::registry::ENTITY_TYPE_ASSET
                    || raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) != Some(bytes)
                {
                    return Err(Error::CorruptedIndex("feedback evidence mismatch"));
                }
                let key = [QUEUE, review_id.as_ref()].concat();
                return decode(
                    &key,
                    &self
                        .store
                        .vault_meta
                        .get(txn, &key)?
                        .ok_or(Error::CorruptedIndex("feedback queue reference"))?,
                );
            }
            let mut best: Option<(f32, FeedbackReviewItem)> = None;
            for row in self.store.vault_meta.prefix_iter(txn, QUEUE)? {
                let (key, bytes) = row?;
                let item = decode(&key, &bytes)?;
                if !item.open
                    || item.category != bundle.category
                    || item.centroid.len() != vector.len()
                {
                    continue;
                }
                let center = normalized(&item.centroid)?;
                let similarity = vector.iter().zip(&center).map(|(a, b)| a * b).sum::<f32>();
                if similarity >= dedup.min_similarity
                    && best.as_ref().is_none_or(|(score, _)| similarity > *score)
                {
                    best = Some((similarity, item));
                }
            }
            let mut item = best.map_or_else(
                || FeedbackReviewItem {
                    id,
                    category: bundle.category,
                    bundles: vec![],
                    received_at: now,
                    open: true,
                    centroid: vector.clone(),
                },
                |(_, item)| item,
            );
            let n = item.bundles.len() as f32;
            item.centroid = item
                .centroid
                .iter()
                .zip(&vector)
                .map(|(a, b)| (a * n + b) / (n + 1.0))
                .collect();
            item.bundles.push(id);
            self.batch_in()
                .put(
                    &id,
                    crate::registry::ENTITY_TYPE_ASSET,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    bytes,
                )
                .vector(&id, &vector)
                .apply(txn)?;
            self.store.vault_meta.put(
                txn,
                &[QUEUE, item.id.as_bytes()].concat(),
                &encode(&item)?,
            )?;
            self.store
                .vault_meta
                .put(txn, &digest_key, item.id.as_bytes())?;
            Ok(item)
        })
    }
    /// Open proposals only, in stable arrival order. Agent policy receives this
    /// view; the engine contains no triage prompt or issue-closing policy.
    pub fn feedback_digest(&self) -> Result<Vec<FeedbackReviewItem>> {
        let txn = self.store.env.read_txn()?;
        let mut items = Vec::new();
        for row in self.store.vault_meta.prefix_iter(&txn, QUEUE)? {
            let (key, bytes) = row?;
            let item = decode(&key, &bytes)?;
            if item.open {
                items.push(item);
            }
        }
        items.sort_by_key(|item| (item.received_at, item.id));
        Ok(items)
    }
    /// Host-authorized review changes queue state, never deletes evidence.
    pub fn close_feedback_review(&self, id: &EntityId) -> Result<()> {
        self.with_write_txn(|txn| {
            let key = [QUEUE, id.as_bytes()].concat();
            let mut item = decode(
                &key,
                &self
                    .store
                    .vault_meta
                    .get(txn, &key)?
                    .ok_or(Error::EntityNotFound)?,
            )?;
            item.open = false;
            self.store.vault_meta.put(txn, &key, &encode(&item)?)?;
            Ok(())
        })
    }
}
#[cfg(test)]
mod tests;
