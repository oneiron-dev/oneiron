//! Content-addressed persona/user evidence prefix. Retrieval remains the read-time delta.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::Vault;
use crate::claim::ScopedRead;
use crate::disclosure::DisclosureContext;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::PipelineBuilder;
use crate::ppr::PprNodeVisibility;

#[cfg(test)]
mod tests;

const MAX_CACHE_ENTRIES: usize = 32;
const MAX_CACHE_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVIDENCE_BYTES: usize = 256 * 1024;

/// A score-free JSON prefix, ordered by full claim id, with its evidence digest.
/// The shared body allocation is reused on a cache hit. It never contains query
/// scores, relative time, or read-time delta items.
#[derive(Debug, Clone)]
pub struct L2BaseSummary {
    pub content_hash: [u8; 32],
    pub body: Arc<str>,
    evidence_ids: Vec<EntityId>,
    subjects: Vec<EntityId>,
    max_field_chars: usize,
}

impl L2BaseSummary {
    /// The exact claims used to render the prefix, in canonical order.
    pub fn evidence_ids(&self) -> &[EntityId] {
        &self.evidence_ids
    }

    pub(crate) fn fits_field_budget(&self, max: usize) -> bool {
        max == 0 || self.max_field_chars <= max
    }
}

impl serde::Serialize for L2BaseSummary {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("L2BaseSummary", 2)?;
        state.serialize_field(
            "content_hash",
            &crate::entity_id::bytes_to_hex_lower(&self.content_hash),
        )?;
        state.serialize_field("body", self.body.as_ref())?;
        state.end()
    }
}

/// Vault-owned, bounded, rebuildable memory. No named database or global state.
#[derive(Default)]
pub(crate) struct L2BaseCache {
    entries: BTreeMap<[u8; 32], L2BaseSummary>,
    bytes: usize,
    erased_at_revision: Option<usize>,
}

impl L2BaseCache {
    /// Clear before a destructive write and bar pre-commit snapshots from
    /// repopulating the cache. An aborted erase only delays caching until the
    /// next commit; it cannot retain erased content or widen a read.
    pub(crate) fn erase(&mut self, id: &EntityId, committed_revision: usize) {
        self.entries.retain(|_, summary| {
            summary.evidence_ids.binary_search(id).is_err()
                && summary.subjects.binary_search(id).is_err()
        });
        self.bytes = self.entries.values().map(summary_bytes).sum();
        self.erased_at_revision = Some(committed_revision);
    }

    fn insert(&mut self, summary: L2BaseSummary) {
        let bytes = summary_bytes(&summary);
        if bytes > MAX_CACHE_BYTES {
            return;
        }
        while self.entries.len() >= MAX_CACHE_ENTRIES || self.bytes + bytes > MAX_CACHE_BYTES {
            let Some((_, evicted)) = self.entries.pop_first() else {
                break;
            };
            self.bytes -= summary_bytes(&evicted);
        }
        self.bytes += bytes;
        self.entries.insert(summary.content_hash, summary);
    }
}

pub(super) fn produce_l2_base(
    vault: &Vault,
    pipeline: &PipelineBuilder<'_>,
    subjects: &[EntityId],
    clamp: Option<&DisclosureContext>,
    reader: Option<&ScopedRead<'_>>,
    cache_enabled: bool,
) -> Result<Option<L2BaseSummary>> {
    if subjects.is_empty() {
        return Ok(None);
    }
    if subjects.len() > 8 {
        return Err(Error::InvalidConfig(
            "L2 summaries allow at most eight explicit subjects".into(),
        ));
    }
    if reader.is_some_and(|reader| !std::ptr::eq(reader.vault(), vault)) {
        return Err(Error::InvalidConfig(
            "L2 reader belongs to another vault".into(),
        ));
    }
    // Capture before opening the snapshot. A later erasure invalidates any
    // producer with this revision, even if it finishes after that write.
    let revision = vault.store.env.info().last_txn_id;
    let txn = vault.store.env.read_txn()?;
    let visibility = reader
        .map(|reader| reader.retrieval_visibility_in(&txn, None))
        .transpose()?;
    let mut evidence = pipeline.l2_evidence_in(&txn, subjects)?;
    let quarantine = super::quarantine::load_pack_quarantine_index(&vault.store, &txn)?;
    let mut bodies = std::collections::HashMap::new();
    let mut admitted = Vec::new();
    for (id, body) in evidence.drain(..) {
        if let Some(visibility) = &visibility
            && !visibility.ppr_node_visible(&txn, &id)?
        {
            continue;
        }
        if let Some(clamp) = clamp
            && !clamp.admits(
                &vault.store,
                &txn,
                &id,
                crate::registry::ENTITY_TYPE_CLAIM,
                Some(&body),
            )?
        {
            continue;
        }
        bodies.insert(id, body.clone());
        super::validation::validate_pack_entity_reference(
            &vault.store,
            &txn,
            &id,
            &mut bodies,
            &quarantine,
        )?;
        admitted.push((id, body));
    }
    if admitted.is_empty() {
        return Ok(None);
    }
    admitted.sort_unstable_by_key(|(id, _)| *id);
    let mut digest = blake3::Hasher::new();
    digest.update(b"oneiron:l2-base:v1");
    let subjects: BTreeSet<_> = subjects.iter().copied().collect();
    digest.update(&(subjects.len() as u64).to_be_bytes());
    for subject in &subjects {
        digest.update(subject.as_bytes());
    }
    let mut evidence_bytes = 0usize;
    for (id, body) in &admitted {
        let raw = crate::claim::encode_claim_body(body)?;
        evidence_bytes = evidence_bytes.saturating_add(raw.len());
        if evidence_bytes > MAX_EVIDENCE_BYTES {
            return Err(Error::IndexOverflow("L2 evidence bytes"));
        }
        digest.update(id.as_bytes());
        digest.update(&(raw.len() as u64).to_be_bytes());
        digest.update(&raw);
    }
    let content_hash = *digest.finalize().as_bytes();
    if cache_enabled {
        let cache = vault
            .store
            .l2_base_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(summary) = cache.entries.get(&content_hash) {
            return Ok(Some(summary.clone()));
        }
    }
    let rows: Vec<_> = admitted
        .iter()
        .map(|(id, body)| {
            let crate::claim::ClaimSubject::Entity(subject) = body.subject else {
                return Err(Error::InvariantViolation("L2 non-entity subject"));
            };
            Ok(serde_json::json!({
                "id": id.to_hex(), "subj": subject.to_hex(),
                "pred": body.predicate, "val": super::hydration::rmpv_to_json(&body.value),
                "world": body.world.map(|world| world.to_hex()),
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let max_field_chars = rows.iter().map(max_string_chars).max().unwrap_or(0);
    let body =
        serde_json::to_string(&rows).map_err(|_| Error::InvariantViolation("L2 JSON render"))?;
    let summary = L2BaseSummary {
        content_hash,
        body: Arc::from(body),
        evidence_ids: admitted.into_iter().map(|(id, _)| id).collect(),
        subjects: subjects.into_iter().collect(),
        max_field_chars,
    };
    if cache_enabled {
        let mut cache = vault
            .store
            .l2_base_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache
            .erased_at_revision
            .is_none_or(|erased| revision > erased)
        {
            // A concurrent producer may already have rendered this content.
            if let Some(existing) = cache.entries.get(&content_hash) {
                return Ok(Some(existing.clone()));
            }
            cache.insert(summary.clone());
        }
    }
    Ok(Some(summary))
}

/// Re-admit the immutable prefix on the hydration snapshot. Any changed body,
/// erased row, new clamp or denied read drops the entire optional prefix.
pub(super) fn revalidate_l2_base(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    summary: &L2BaseSummary,
    clamp: Option<&DisclosureContext>,
    reader: Option<&ScopedRead<'_>>,
) -> Result<bool> {
    let visibility = reader
        .map(|reader| reader.retrieval_visibility_in(txn, None))
        .transpose()?;
    let quarantine = super::quarantine::load_pack_quarantine_index(&vault.store, txn)?;
    let mut digest = blake3::Hasher::new();
    digest.update(b"oneiron:l2-base:v1");
    digest.update(&(summary.subjects.len() as u64).to_be_bytes());
    for subject in &summary.subjects {
        digest.update(subject.as_bytes());
    }
    let mut bodies = std::collections::HashMap::new();
    for id in &summary.evidence_ids {
        let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
            return Ok(false);
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
            return Ok(false);
        };
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Ok(false);
        }
        let body = crate::claim::decode_claim_body(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            true,
        )?;
        if !crate::claim::claim_surfaceable(&body) {
            return Ok(false);
        }
        if let Some(visibility) = &visibility
            && !visibility.ppr_node_visible(txn, id)?
        {
            return Ok(false);
        }
        if let Some(clamp) = clamp
            && !clamp.admits(
                &vault.store,
                txn,
                id,
                crate::registry::ENTITY_TYPE_CLAIM,
                Some(&body),
            )?
        {
            return Ok(false);
        }
        let canonical = crate::claim::encode_claim_body(&body)?;
        digest.update(id.as_bytes());
        digest.update(&(canonical.len() as u64).to_be_bytes());
        digest.update(&canonical);
        bodies.insert(*id, body);
        super::validation::validate_pack_entity_reference(
            &vault.store,
            txn,
            id,
            &mut bodies,
            &quarantine,
        )?;
    }
    Ok(digest.finalize().as_bytes() == &summary.content_hash)
}

fn summary_bytes(summary: &L2BaseSummary) -> usize {
    summary.body.len() + (summary.evidence_ids.len() + summary.subjects.len()) * 16
}

fn max_string_chars(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::String(text) => text.chars().count(),
        serde_json::Value::Array(values) => values.iter().map(max_string_chars).max().unwrap_or(0),
        serde_json::Value::Object(values) => {
            values.values().map(max_string_chars).max().unwrap_or(0)
        }
        _ => 0,
    }
}
