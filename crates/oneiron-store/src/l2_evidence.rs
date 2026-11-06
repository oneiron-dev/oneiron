//! Bounded, vault-owned cache of score-free context evidence.

use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeMap;
use std::sync::Arc;

const MAX_CACHE_ENTRIES: usize = 32;
const MAX_CACHE_BYTES: usize = 2 * 1024 * 1024;

/// A score-free JSON prefix, ordered by full claim id, with its evidence and
/// resolved-handle digest. The shared body allocation is reused on a cache hit.
/// It never contains query scores, relative time, or read-time delta items.
#[derive(Debug, Clone)]
pub struct L2BaseSummary {
    pub content_hash: [u8; 32],
    pub body: Arc<str>,
    pub evidence_ids: Vec<EntityId>,
    pub subjects: Vec<EntityId>,
    pub max_field_chars: usize,
}

impl L2BaseSummary {
    /// The exact claims used to render the prefix, in canonical order.
    pub fn evidence_ids(&self) -> &[EntityId] {
        &self.evidence_ids
    }

    pub fn fits_field_budget(&self, max: usize) -> bool {
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
            &oneiron_contracts::entity_id::bytes_to_hex_lower(&self.content_hash),
        )?;
        state.serialize_field("body", self.body.as_ref())?;
        state.end()
    }
}

/// Vault-owned, bounded, rebuildable memory. No named database or global state.
#[derive(Default)]
pub struct L2BaseCache {
    pub entries: BTreeMap<[u8; 32], L2BaseSummary>,
    bytes: usize,
    pub erased_at_revision: Option<usize>,
}

impl L2BaseCache {
    /// Clear before a destructive write and bar pre-commit snapshots from
    /// repopulating the cache. An aborted erase only delays caching until the
    /// next commit; it cannot retain erased content or widen a read.
    pub fn erase(&mut self, id: &EntityId, committed_revision: usize) {
        self.entries.retain(|_, summary| {
            summary.evidence_ids.binary_search(id).is_err()
                && summary.subjects.binary_search(id).is_err()
        });
        self.bytes = self.entries.values().map(summary_bytes).sum();
        self.erased_at_revision = Some(committed_revision);
    }

    pub fn insert(&mut self, summary: L2BaseSummary) {
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

fn summary_bytes(summary: &L2BaseSummary) -> usize {
    summary.body.len() + (summary.evidence_ids.len() + summary.subjects.len()) * 16
}
