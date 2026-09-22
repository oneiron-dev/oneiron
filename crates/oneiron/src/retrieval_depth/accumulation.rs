use crate::claim::decode_claim_body;
use crate::retrieval_quality::classify_retrieval_quality;
use std::collections::HashMap;

use super::*;

/// Ordered, deduplicated merge of every channel a read ran.
#[derive(Default)]
pub(super) struct DepthAccumulator {
    pub(super) narrowing: Vec<crate::claim::ScopedReadReceipt>,
    /// Entity ids in first-seen order; the read's ranking before any rerank.
    pub(super) order: Vec<EntityId>,
    /// Best engine score seen for each id, across channels.
    scores: HashMap<EntityId, f32>,
    revisions: HashMap<EntityId, crate::vault::RevisionRef>,
    signals: Vec<String>,
    pub(super) queries_run: Vec<String>,
    candidates_scanned: u64,
    pub(super) tokens_used: u64,
    backend_used: bool,
    pub(super) partial: bool,
    pub(super) retrieval_diagnostics: RetrievalDiagnostics,
}

impl DepthAccumulator {
    pub(super) fn attempt(&mut self, signal: RetrievalSignal) {
        if !self.retrieval_diagnostics.attempted.contains(&signal) {
            self.retrieval_diagnostics.attempted.push(signal);
        }
    }

    pub(super) fn complete(&mut self, signal: RetrievalSignal) {
        if !self.retrieval_diagnostics.succeeded.contains(&signal) {
            self.retrieval_diagnostics.succeeded.push(signal);
        }
    }

    pub(super) fn merge_revisioned(
        &mut self,
        hits: Vec<ScoredEntity>,
        revisions: HashMap<EntityId, crate::vault::RevisionRef>,
    ) {
        let admitted = hits
            .into_iter()
            .filter(|hit| {
                let Some(revision) = revisions.get(&hit.id) else {
                    return false;
                };
                // Never combine a newer frontier's score with an earlier body.
                *self.revisions.entry(hit.id).or_insert(*revision) == *revision
            })
            .collect();
        self.merge(admitted);
    }

    pub(super) fn merge(&mut self, hits: Vec<ScoredEntity>) {
        self.candidates_scanned = self.candidates_scanned.saturating_add(hits.len() as u64);
        for hit in hits {
            match self.scores.get_mut(&hit.id) {
                Some(existing) => *existing = existing.max(hit.score),
                None => {
                    self.scores.insert(hit.id, hit.score);
                    self.order.push(hit.id);
                }
            }
        }
    }

    /// Fuse channel scores before truncation; stable ties keep first-seen order.
    pub(super) fn fuse(&mut self) {
        self.order
            .sort_by(|left, right| self.scores[right].total_cmp(&self.scores[left]));
    }

    pub(super) fn mark(&mut self, signal: &str) {
        if !self.signals.iter().any(|seen| seen == signal) {
            self.signals.push(signal.to_owned());
        }
    }

    pub(super) fn record_query(&mut self, query: String) {
        self.queries_run.push(query);
    }

    pub(super) fn already_ran(&self, query: &str) -> bool {
        self.queries_run.iter().any(|seen| seen == query)
    }

    pub(super) fn charge_backend(&mut self, signal: &str, tokens_used: u64) {
        self.backend_used = true;
        self.mark(signal);
        self.tokens_used = self.tokens_used.saturating_add(tokens_used);
    }

    /// The engine's own cap on a backend round: blank and repeated queries
    /// drop out, and at most [`DEEP_QUERIES_PER_ROUND`] survive.
    pub(super) fn admissible_round_queries(&self, proposed: Vec<String>) -> Vec<String> {
        let mut round: Vec<String> = Vec::new();
        for candidate in proposed {
            if round.len() == DEEP_QUERIES_PER_ROUND {
                break;
            }
            let candidate = candidate.trim().to_owned();
            if candidate.is_empty() || self.already_ran(&candidate) || round.contains(&candidate) {
                continue;
            }
            round.push(candidate);
        }
        round
    }

    /// Decoded claim bodies for the candidate set, read through the same
    /// actor-keyed door the hits came from, so a rerank cannot see a body the
    /// ranking itself was not allowed to.
    pub(super) fn candidate_claim_bodies(
        &mut self,
        scoped: &ScopedRead<'_>,
    ) -> Result<Vec<Option<crate::claim::ClaimBody>>> {
        let refs: Vec<_> = self
            .order
            .iter()
            .filter_map(|id| {
                self.revisions
                    .get(id)
                    .map(|revision| (*id, crate::vault::ReadMode::Pinned(*revision)))
            })
            .collect();
        let requested = self.applied_filter();
        let read = scoped.get_entities_parts_with_modes_with_receipt(&refs, requested.as_ref())?;
        self.narrowing.push(read.receipt);
        let mut projected = read.value.into_iter();
        let mut bodies = Vec::with_capacity(self.order.len());
        for id in &self.order {
            if !self.revisions.contains_key(id) {
                bodies.push(None);
                continue;
            }
            bodies.push(match projected.next().flatten() {
                Some((ENTITY_TYPE_CLAIM, _, body)) => Some(decode_claim_body(&body, true)?),
                _ => None,
            });
        }
        Ok(bodies)
    }

    /// Later snapshots can tighten, but cannot widen any executed channel's floor.
    fn applied_filter(&self) -> Option<crate::gate::RetrievalFilter> {
        let mut receipts = self.narrowing.iter();
        let mut combined = receipts.next()?.clone();
        for receipt in receipts {
            combined.restrict_with(receipt);
        }
        Some(combined.applied.as_filter())
    }

    pub(super) fn rerank_candidates<'a>(
        &self,
        bodies: &'a [Option<crate::claim::ClaimBody>],
    ) -> Vec<RerankCandidate<'a>> {
        self.order
            .iter()
            .zip(bodies)
            .enumerate()
            .map(|(index, (id, claim))| RerankCandidate {
                id: *id,
                score: self.scores.get(id).copied().unwrap_or_default(),
                rank: u32::try_from(index + 1).unwrap_or(u32::MAX),
                claim: claim.as_ref(),
            })
            .collect()
    }

    /// Reorders the ranking by backend score, highest first, keeping the
    /// engine's own order among ties. Engine scores are untouched.
    pub(super) fn reorder_by(&mut self, backend_scores: &[f32]) {
        let mut ranked: Vec<(usize, EntityId)> = self.order[..backend_scores.len()]
            .iter()
            .copied()
            .enumerate()
            .collect();
        ranked.sort_by(|left, right| {
            backend_scores[right.0]
                .total_cmp(&backend_scores[left.0])
                .then_with(|| left.0.cmp(&right.0))
        });
        // Keep entity-bound engine scores: this lane has no pre-decay ladder.
        // Moving a neighbor's already-decayed score would resurrect expired claims.
        for (position, (_, id)) in ranked.into_iter().enumerate() {
            self.order[position] = id;
        }
    }

    pub(super) fn finish_scoped(
        self,
        scoped: &ScopedRead<'_>,
        limit: usize,
    ) -> Result<DepthSearchResult> {
        let requested = self.applied_filter();
        let mut result = self.finish(limit);
        // Preserve the captured frontier and all channel receipts. Final admission
        // reads pinned bodies and current authority together, never a live replacement.
        let refs: Vec<_> = result
            .hits
            .iter()
            .filter_map(|hit| {
                result
                    .revisions
                    .get(&hit.id)
                    .map(|revision| (hit.id, crate::vault::ReadMode::Pinned(*revision)))
            })
            .collect();
        let filtered =
            scoped.get_entities_parts_with_modes_with_receipt(&refs, requested.as_ref())?;
        let admitted: std::collections::HashSet<_> = refs
            .into_iter()
            .zip(filtered.value)
            .filter_map(|((id, _), parts)| parts.map(|_| id))
            .collect();
        result.narrowing.push(filtered.receipt);
        result.hits.retain(|hit| admitted.contains(&hit.id));
        result.revisions.retain(|id, _| admitted.contains(id));
        Ok(result)
    }

    pub(super) fn finish(self, limit: usize) -> DepthSearchResult {
        let hits: Vec<_> = self
            .order
            .iter()
            .take(limit)
            .map(|id| ScoredEntity {
                id: *id,
                score: self.scores.get(id).copied().unwrap_or_default(),
            })
            .collect();
        let retrieval_quality = classify_retrieval_quality(&self.retrieval_diagnostics);
        let revisions = hits
            .iter()
            .filter_map(|hit| {
                self.revisions
                    .get(&hit.id)
                    .map(|revision| (hit.id, *revision))
            })
            .collect();
        DepthSearchResult {
            narrowing: self.narrowing,
            hits,
            revisions,
            partial: self.partial,
            queries_run: self.queries_run,
            signals_used: self.signals,
            candidates_scanned: self.candidates_scanned,
            backend_used: self.backend_used,
            tokens_used: self.tokens_used,
            retrieval_diagnostics: self.retrieval_diagnostics,
            retrieval_quality,
        }
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;
    use crate::claim::ScopedReadActorKey;

    #[test]
    fn finish_scoped_keeps_channel_receipts_on_an_empty_result() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
        let scoped = vault.scoped_read(ScopedReadActorKey::new("receipt-reader").unwrap());
        let channel = scoped.read_receipt(None, 3)?;
        let mut acc = DepthAccumulator::default();
        acc.narrowing.push(channel.clone());
        let result = acc.finish_scoped(&scoped, 10)?;
        assert!(result.hits.is_empty());
        assert_eq!(result.narrowing.len(), 2);
        assert_eq!(result.narrowing[0], channel);
        assert_eq!(result.narrowing[1].suppressed_count, 0);
        Ok(())
    }

    #[test]
    fn finish_scoped_preserves_a_receipted_channel_revision_after_an_edit() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
        let id = EntityId::now();
        let range = crate::TimeRange { start: 1, end: 1 };
        vault
            .batch()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                range,
                1,
                b"original",
            )
            .text(&id, &[("body", "original")])
            .commit()?;
        let scoped = vault.scoped_read(ScopedReadActorKey::new("receipt-reader").unwrap());
        let channel = scoped.search_text_revisioned("original", 10, None)?;
        assert_eq!(channel.hits.len(), 1);
        let revision = channel.revisions[&id];
        let receipt = channel.receipt.clone();
        let mut acc = DepthAccumulator::default();
        acc.narrowing.push(channel.receipt);
        acc.merge_revisioned(channel.hits, channel.revisions);
        vault
            .batch()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                range,
                1,
                b"replacement",
            )
            .text(&id, &[("body", "replacement")])
            .commit()?;
        vault.refresh_staged_indexed_at_idle(u64::MAX)?;
        let result = acc.finish_scoped(&scoped, 10)?;
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.revisions[&id], revision);
        assert_eq!(result.narrowing.len(), 2);
        assert_eq!(result.narrowing[0], receipt);
        let crate::claim::ScopedReadResult {
            value,
            receipt: _receipt,
        } = scoped.get_entity_parts_with_mode_with_receipt(
            &id,
            crate::vault::ReadMode::Pinned(revision),
            None,
        )?;
        assert_eq!(value.map(|(_, _, body)| body), Some(b"original".to_vec()));
        Ok(())
    }
}
