//! Summary-first rank fusion. Hits expose refs; detail requires explicit expansion.
use crate::claim::{ScopedRead, ScopedReadResult};
use crate::gate::RetrievalFilter;
use crate::registry::{ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_SUMMARY};
use crate::{EntityId, Result};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct DocsSummaryHit {
    pub reference: String,
    pub entity_type: u8,
    pub rank_score: f32,
}
impl ScopedRead<'_> {
    pub fn search_docs_summaries(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<ScopedReadResult<Vec<DocsSummaryHit>>> {
        let mut ranks = BTreeMap::<EntityId, (u8, f32)>::new();
        let mut suppressed = 0;
        for kind in [ENTITY_TYPE_SUMMARY, ENTITY_TYPE_ASSET_TEXT] {
            let requested = RetrievalFilter {
                entity_types: Some(BTreeSet::from([kind])),
                ..Default::default()
            };
            let results = self.search_text(query, limit, Some(&requested))?;
            suppressed += results.receipt.suppressed_count;
            for (rank, row) in results.value.into_iter().enumerate() {
                ranks.entry(row.id).or_insert((kind, 0.0)).1 += 1.0 / (60.0 + rank as f32 + 1.0);
            }
        }
        let requested = RetrievalFilter {
            entity_types: Some(BTreeSet::from([
                ENTITY_TYPE_SUMMARY,
                ENTITY_TYPE_ASSET_TEXT,
            ])),
            ..Default::default()
        };
        let candidates = ranks
            .iter()
            .map(|(id, (_, score))| crate::ScoredEntity {
                id: *id,
                score: *score,
            })
            .collect();
        let filtered = self.filter_scored_entities_requested(candidates, Some(&requested))?;
        let mut receipt = filtered.receipt;
        receipt.add_suppressed(suppressed);
        let mut value = filtered
            .value
            .into_iter()
            .map(|row| DocsSummaryHit {
                reference: row.id.to_hex(),
                entity_type: ranks[&row.id].0,
                rank_score: row.score,
            })
            .collect::<Vec<_>>();
        value.sort_by(|a, b| {
            (a.entity_type != ENTITY_TYPE_SUMMARY)
                .cmp(&(b.entity_type != ENTITY_TYPE_SUMMARY))
                .then_with(|| b.rank_score.total_cmp(&a.rank_score))
                .then_with(|| a.reference.cmp(&b.reference))
        });
        value.truncate(limit);
        Ok(ScopedReadResult { value, receipt })
    }
    /// Explicitly expand an authorized docs asset and run its opt-in NER on read.
    /// A search hit alone never performs model work or writes claims.
    pub fn expand_doc_ref_deep(
        &self,
        reference: &str,
        owner: &crate::consent::AuthenticatedOwner,
        extractor: &dyn super::DocsDeepExtractor,
        now: u64,
    ) -> Result<(
        ScopedReadResult<Option<serde_json::Value>>,
        Option<super::DocsDeepReceipt>,
    )> {
        if self.actor_key().actor_ref() != owner.principal_ref() {
            return Err(crate::Error::InvalidConfig(
                "docs read principal differs from owner".into(),
            ));
        }
        let expanded = self.expand_doc_ref(reference)?;
        let deep = if expanded.value.is_some()
            && expanded
                .value
                .as_ref()
                .is_some_and(|body| body.get("page_id").is_some())
        {
            Some(self.vault().deep_ingest_docs_asset(
                owner,
                EntityId::from_hex(reference)?,
                super::DocsDeepTrigger::OnRead,
                extractor,
                now,
            )?)
        } else {
            None
        };
        Ok((expanded, deep))
    }

    /// Engine-issued references use the same live read authority as ordinary hydrate.
    pub fn expand_doc_ref(
        &self,
        reference: &str,
    ) -> Result<ScopedReadResult<Option<serde_json::Value>>> {
        let id = EntityId::from_hex(reference)?;
        let result = self.get_entity_parts_with_receipt(&id, None)?;
        let value = result
            .value
            .map(|(_, _, body)| crate::batch::export::redacted_memory_body(&body));
        Ok(ScopedReadResult {
            receipt: result.receipt,
            value,
        })
    }
}
