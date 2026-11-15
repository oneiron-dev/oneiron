//! Bound extraction observation reads in the caller transaction.
//!
//! The bound verdict rebuilds its queued branch projection once, then reads
//! mechanical selection, graph and replay facts for each verified candidate
//! in the same live transaction. Every read here reuses the native factored
//! helpers, so bound facts match native facts exactly.

use std::collections::{BTreeMap, BTreeSet};

use super::super::super::assembly::{SelectionEvidenceFacts, selection_evidence_facts};
use super::super::super::conflict::{candidate_facts, candidate_probe_body};
use super::super::super::evidence::VerifiedCandidate;
use super::super::super::routing::CandidateKeys;
use super::super::super::support::invalid_consolidation;
use super::super::super::watermark::decode_turn_body;
use super::super::super::{PriorHead, PromotionCandidate};
use super::super::document_version;
use super::super::prior::{Standing, prior_keys, standing};
use super::super::restated::{
    provisional_heads_from_parts, restates_head_in_slice, unlisted_cohort_ids_in_txn,
};
use super::super::signals::{
    candidate_vector_in_txn, claim_graph_source_in_slice, count_graph_signals, facet,
    last_reviewed_in_txn, project_slice_admits, relationship_slice_admits,
    session_graph_axes_in_slice, turn_graph_axes_in_slice,
};
use super::BoundBranchRead;
use crate::claim::{ClaimSource, ScopedRead, decode_claim_body};
use crate::edge::EdgeKind;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_SESSION,
    ENTITY_TYPE_TURN,
};
use crate::{ClaimSubject, EntityId, Result, Vault};
use rmpv::Value;

impl BoundBranchRead {
    /// The bound candidate selection evidence facts in the caller transaction.
    /// The verified signal sources, speaker fold, stored times and candidate-time fallback match native selection exactly.
    pub(crate) fn selection_facts_in_txn(
        &self,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        candidate: &VerifiedCandidate,
    ) -> Result<SelectionEvidenceFacts> {
        let signal_sources: Vec<(EntityId, bool)> = candidate
            .evidence
            .signal_sources()
            .into_iter()
            .map(|(id, _hash, claim)| (id, claim))
            .collect();
        let distinct: Vec<EntityId> = signal_sources
            .iter()
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let rows = read.get_entities_parts_in_txn(txn, &distinct)?;
        let mut times = BTreeMap::new();
        let mut speakers: BTreeMap<EntityId, Option<String>> = BTreeMap::new();
        for (id, row) in distinct.iter().zip(rows) {
            let Some((kind, learned_at, body)) = row else {
                return Err(invalid_consolidation("bound evidence is not readable"));
            };
            let pin = self
                .sources
                .get(id)
                .ok_or_else(|| invalid_consolidation("unlisted bound evidence"))?;
            if !self.scope.allows_read(&pin.resource) {
                return Err(invalid_consolidation("bound evidence read refused"));
            }
            if pin.entity_type != kind
                || pin.learned_at != learned_at
                || document_version(*id, &body) != pin.resource
            {
                return Err(invalid_consolidation("bound evidence revision changed"));
            }
            times.insert(*id, learned_at.saturating_mul(1_000));
            if kind == ENTITY_TYPE_TURN {
                speakers.insert(*id, decode_turn_body(&body).speaker);
            }
        }
        let count = candidate.evidence.count();
        // A candidate's learned_at is Unix seconds (FIX 8695).
        selection_evidence_facts(
            &signal_sources,
            count,
            candidate.learned_at.saturating_mul(1_000),
            |id| {
                times
                    .get(id)
                    .copied()
                    .ok_or_else(|| invalid_consolidation("missing bound evidence time"))
            },
            |id| {
                let Some(speaker) = speakers.get(id) else {
                    return Err(invalid_consolidation("bound turn evidence type changed"));
                };
                Ok(speaker.clone())
            },
        )
    }

    /// The bound candidate graph and vector signals in the caller transaction.
    /// The fan-in, fresh-reference and stored-vector reads match native candidate signals exactly.
    pub(crate) fn candidate_signals_in_txn(
        &self,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        candidate: &PromotionCandidate,
    ) -> Result<(u64, u64, Option<Vec<f32>>)> {
        if !self.scope.allows_read(&self.signals) {
            return Err(invalid_consolidation(
                "branch signals projection read refused",
            ));
        }
        let facts = candidate_facts(&candidate.candidate)?;
        let vault = read.vault();
        // The target must itself be actor-readable. A genuinely new subject has
        // no stored graph yet; that is absence of data, not absence of rights.
        let (fan_in, new_refs) = if read.is_entity_readable_in(txn, &facts.subject)? {
            // A reference is fresh when it came after the subject's last
            // completed consolidation review (FIX 8699); a subject never
            // reviewed counts from this candidate's own time, as before.
            let since = last_reviewed_in_txn(vault, txn, read, &facts.subject)?
                .unwrap_or(candidate.learned_at);
            let edges = crate::ports::EdgeStore::port_edge_neighbors(
                vault,
                txn,
                &facts.subject,
                crate::ports::EdgeDirection::In,
                None,
                usize::MAX,
            )?;
            count_graph_signals(&edges, since, |id| {
                self.graph_source_in_slice_in_txn(read, txn, id)
            })?
        } else {
            (0, 0)
        };
        let vector = candidate_vector_in_txn(
            read,
            txn,
            &self.scope,
            &self.signals,
            self.attempt,
            candidate.claim_id,
            &candidate.candidate,
        )?;
        Ok((fan_in, new_refs, vector))
    }

    /// The bound replay cohort in the caller transaction, in native subject-claims order.
    /// All reachable unlisted provisional eligible own subject and predicate heads, with no value matching and no write rights.
    pub(crate) fn replay_heads_in_txn(
        &self,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        candidate: &PromotionCandidate,
    ) -> Result<Vec<PriorHead>> {
        let fresh = candidate_probe_body(&candidate.candidate)?;
        let ClaimSubject::Entity(subject) = fresh.subject else {
            return Ok(Vec::new());
        };
        let vault = read.vault();
        let ids = unlisted_cohort_ids_in_txn(vault, txn, subject, &fresh.predicate, &self.priors)?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = read.get_entities_parts_in_txn(txn, &ids)?;
        let parts: Vec<Option<(u8, Vec<u8>)>> = rows
            .into_iter()
            .map(|row| row.map(|(kind, _, bytes)| (kind, bytes)))
            .collect();
        provisional_heads_from_parts(&ids, parts, &self.scope, |id| {
            crate::gate::claim_consolidation_eligible_in_txn(
                &vault.store,
                txn,
                id,
                crate::gate::ConsolidationReader::ExplicitPrior,
            )
        })
    }

    /// Whether `candidate`, which matched no admitted prior, restates an
    /// unlisted provisional eligible own head of its subject and predicate:
    /// the replay cohort in the caller's transaction with native's
    /// comparison. `meet` is the candidate's evidence meet; an imported
    /// restatement is never judged here. The default facet reads through
    /// the caller's transaction.
    pub(crate) fn restates_unlisted_candidate_in_txn(
        &self,
        vault: &Vault,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        candidate: &PromotionCandidate,
        meet: ClaimSource,
    ) -> Result<bool> {
        if meet == ClaimSource::Imported {
            return Ok(false);
        }
        let heads = self.replay_heads_in_txn(read, txn, candidate)?;
        if heads.is_empty() {
            return Ok(false);
        }
        restates_head_in_slice(candidate, self.key_rules(), meet, &heads, || {
            vault.default_facet_in_txn(txn)
        })
    }

    /// The native routing keys for `head` under the bound key rules.
    /// The bound read owns no key derivation and calls the native function.
    pub(crate) fn observation_prior_keys(&self, head: &PriorHead) -> Result<CandidateKeys> {
        prior_keys(head, self.key_rules())
    }

    /// Whether `head` stands only provisionally on the bound scope.
    /// A vetted prior returns false here.
    pub(crate) fn observation_prior_provisional(&self, head: &PriorHead) -> Result<bool> {
        Ok(standing(head, self.scope())? == Some(Standing::Provisional))
    }

    /// The facet the scope map names, when it names one valid facet.
    /// An absent entry reads as none, exactly as the native facet reader does.
    pub(crate) fn observation_named_facet(scope: Option<&Value>) -> Result<Option<EntityId>> {
        facet(scope)
    }

    /// Whether graph source `id` stands in the bound scope slice in the caller transaction.
    /// Private and other-slice rows never count.
    fn graph_source_in_slice_in_txn(
        &self,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let vault = read.vault();
        // Type check avoids asking the generic byte door for custody records.
        let Some(kind) = vault.get_entity_type_in_txn(txn, id)? else {
            return Ok(false);
        };
        if kind == ENTITY_TYPE_SECRET_CUSTODY {
            return Ok(false);
        }
        let mut rows = read.get_entities_parts_in_txn(txn, &[*id])?;
        let Some((row_kind, learned_at, bytes)) = rows.pop().flatten() else {
            return Ok(false);
        };
        let pinned = self.scope.allows_read(&document_version(*id, &bytes));
        if !project_slice_admits(&self.scope, pinned) {
            return Ok(false);
        }
        match kind {
            ENTITY_TYPE_CLAIM => {
                let body = decode_claim_body(&bytes, true)?;
                claim_graph_source_in_slice(&body, &self.scope, || {
                    crate::gate::claim_consolidation_eligible_in_txn(
                        &vault.store,
                        txn,
                        id,
                        crate::gate::ConsolidationReader::GraphSignal,
                    )
                })
            }
            ENTITY_TYPE_TURN => {
                if !relationship_slice_admits(&self.scope, pinned) {
                    return Ok(false);
                }
                // The native scoped ChildOf projection (signals.rs): the TURN
                // counts only as a retrievable graph center, every MESSAGE readable.
                let edges = read.edges_out_of_in_txn(txn, id, Some(EdgeKind::ChildOf))?;
                if edges.receipt.suppressed_count != 0 {
                    return Ok(false);
                }
                let Some(parents) = edges.value else {
                    return Ok(false);
                };
                if parents.len() != 1 || !self.parents.contains(&parents[0].target) {
                    return Ok(false);
                }
                let parent = parents[0].target;
                let pin = self
                    .sources
                    .get(&parent)
                    .ok_or_else(|| invalid_consolidation("unlisted branch document"))?;
                if !self.scope.allows_read(&pin.resource) {
                    return Err(invalid_consolidation("branch document read refused"));
                }
                let mut parent_rows = read.get_entities_parts_in_txn(txn, &[parent])?;
                let Some((parent_kind, parent_learned, parent_bytes)) = parent_rows.pop().flatten()
                else {
                    return Err(invalid_consolidation("branch source is not readable"));
                };
                if parent_kind != pin.entity_type
                    || parent_learned != pin.learned_at
                    || document_version(parent, &parent_bytes) != pin.resource
                {
                    return Err(invalid_consolidation("branch source revision changed"));
                }
                turn_graph_axes_in_slice(&bytes, &parent_bytes, &self.scope)
            }
            ENTITY_TYPE_SESSION | ENTITY_TYPE_CONVERSATION => {
                if !self.parents.contains(id) {
                    return Ok(false);
                }
                let pin = self
                    .sources
                    .get(id)
                    .ok_or_else(|| invalid_consolidation("unlisted branch document"))?;
                if !self.scope.allows_read(&pin.resource) {
                    return Err(invalid_consolidation("branch document read refused"));
                }
                if row_kind != pin.entity_type
                    || learned_at != pin.learned_at
                    || document_version(*id, &bytes) != pin.resource
                {
                    return Err(invalid_consolidation("branch source revision changed"));
                }
                session_graph_axes_in_slice(&bytes, &self.scope)
            }
            _ => Ok(pinned),
        }
    }
}
