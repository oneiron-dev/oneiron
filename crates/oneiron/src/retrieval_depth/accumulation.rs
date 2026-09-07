use std::collections::HashMap;

use super::*;

/// Ordered, deduplicated merge of every channel a read ran.
#[derive(Default)]
pub(super) struct DepthAccumulator {
    /// Entity ids in first-seen order; the read's ranking before any rerank.
    pub(super) order: Vec<EntityId>,
    /// Best engine score seen for each id, across channels.
    scores: HashMap<EntityId, f32>,
    signals: Vec<String>,
    pub(super) queries_run: Vec<String>,
    candidates_scanned: u64,
    tokens_used: u64,
    backend_used: bool,
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
        &self,
        scoped: &ScopedRead<'_>,
    ) -> Result<Vec<Option<crate::claim::ClaimBody>>> {
        let mut bodies = Vec::with_capacity(self.order.len());
        for id in &self.order {
            let decoded = match scoped.get_entity_parts(id)? {
                Some((ENTITY_TYPE_CLAIM, _, body)) => Some(decode_claim_body(&body, true)?),
                _ => None,
            };
            bodies.push(decoded);
        }
        Ok(bodies)
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
        let mut ranked: Vec<(usize, EntityId)> = self.order.iter().copied().enumerate().collect();
        ranked.sort_by(|left, right| {
            backend_scores[right.0]
                .total_cmp(&backend_scores[left.0])
                .then_with(|| left.0.cmp(&right.0))
        });
        self.order = ranked.into_iter().map(|(_, id)| id).collect();
    }

    pub(super) fn finish(self, limit: usize) -> DepthSearchResult {
        let hits = self
            .order
            .iter()
            .take(limit)
            .map(|id| ScoredEntity {
                id: *id,
                score: self.scores.get(id).copied().unwrap_or_default(),
            })
            .collect();
        let retrieval_quality = classify_retrieval_quality(&self.retrieval_diagnostics);
        DepthSearchResult {
            hits,
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
