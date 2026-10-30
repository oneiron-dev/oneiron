//! Actor- and branch-filtered graph/vector inputs for mechanical selection.
//! A projection grant is mandatory. Model-selected ids never grant vector access.

use super::{BranchResources, document_version};
use crate::claim::{PointRead, ReadRow, decode_claim_body};
use crate::dreamer_consolidation::conflict::candidate_facts;
use crate::dreamer_consolidation::provenance::PromotionCandidate;
use crate::dreamer_consolidation::reviewed::{names, reviewed_output};
use crate::dreamer_consolidation::support::{
    TURN_BODY_FACET_REF_KEY, TURN_BODY_WORLD_REF_KEY, invalid_consolidation,
};
use crate::dreamer_consolidation::watermark::entity_ref_from_value;
use crate::edge::EdgeKind;
use crate::llm::Scope;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN,
};
use crate::{EntityId, Result};
use rmpv::Value;

/// The door a consolidation's promotion stamps its claims' births with:
/// a claim born there is a review the Dreamer completed about its subject.
const PROMOTION_DOOR: &str = "dreamer.promotion";

impl BranchResources<'_> {
    pub(in crate::dreamer_consolidation) fn require_signals(&self, scope: &Scope) -> Result<()> {
        self.check_axes(scope)?;
        if !scope.allows_read(&self.signals) {
            return Err(invalid_consolidation(
                "branch signals projection read refused",
            ));
        }
        Ok(())
    }

    pub(in crate::dreamer_consolidation) fn candidate_signals(
        &self,
        scope: &Scope,
        candidate: &PromotionCandidate,
    ) -> Result<(u64, u64, Option<Vec<f32>>)> {
        self.require_signals(scope)?;
        // Recompute the output id from this attempt and the semantic identity.
        // An arbitrary model-supplied claim id cannot select a stored vector.
        self.validate_candidates(scope, std::slice::from_ref(candidate))?;
        let facts = candidate_facts(&candidate.candidate)?;
        let mut fan_in = 0;
        let mut new_refs = 0;
        // The target must itself be actor-readable. A genuinely new subject has
        // no stored graph yet; that is absence of data, not absence of rights.
        if self.read.is_entity_readable(&facts.subject)? {
            // A reference is fresh when it came after the subject's last
            // completed consolidation review (FIX 8699); a subject never
            // reviewed counts from this candidate's own time, as before.
            let since = self
                .last_reviewed(&facts.subject)?
                .unwrap_or(candidate.learned_at);
            for edge in self.read.vault().edges_in(&facts.subject)? {
                // edges_in uses `target` for the incoming source. Do not expose
                // a raw count first: private and other-slice rows never count.
                if self.graph_source_in_slice(scope, &edge.target)? {
                    fan_in += 1;
                    new_refs += u64::from(edge.created_at > since);
                }
            }
        }
        // The candidate projection also permits host-materialized vector-only
        // rows under engine-derived output ids. If an entity exists at that id,
        // it must be an actor-readable matching claim, never another resource;
        // or this attempt's own output, which an earlier pass committed into
        // the owner's review and `reviewed_output` matched to this candidate.
        // The ordinary lane serves surfaceable claims only, so it cannot read
        // one the review holds or the owner declined.
        if self
            .read
            .vault()
            .get_entity_type(&candidate.claim_id)?
            .is_some()
            && !reviewed_output(self.read.vault(), candidate)?
        {
            let stored = self
                .read
                .read(&[PointRead::id(candidate.claim_id)], None)?
                .single();
            self.fold_read_receipt(&stored.receipt)?;
            let Some(ReadRow {
                entity_type: kind,
                body: Some(bytes),
                ..
            }) = stored.value
            else {
                return Err(invalid_consolidation(
                    "candidate vector entity is not readable",
                ));
            };
            if kind != ENTITY_TYPE_CLAIM {
                return Err(invalid_consolidation(
                    "candidate vector identity is not a claim",
                ));
            }
            let body = decode_claim_body(&bytes, true)?;
            if !names(&facts, &body)? {
                return Err(invalid_consolidation("candidate vector identity changed"));
            }
        }
        let vector = self.read.vault().get_vector(&candidate.claim_id)?;
        Ok((fan_in, new_refs, vector))
    }

    /// When consolidation last completed a review of `subject`, in Unix
    /// seconds: the newest birth among the claims about it the promotion
    /// door wrote that this branch's reader may read. `None` when there is
    /// none.
    fn last_reviewed(&self, subject: &EntityId) -> Result<Option<u64>> {
        let vault = self.read.vault();
        let txn = vault.store.env.read_txn()?;
        let mut newest = None;
        for id in vault.claims_for_subject_in_txn(&txn, subject)? {
            let Some(birth) = crate::provenance::birth::row_birth_in_txn(&vault.store, &txn, &id)?
            else {
                continue;
            };
            if birth.made_by.process.identity == PROMOTION_DOOR
                && self.read.is_entity_readable_in(&txn, &id)?
            {
                newest = newest.max(Some(birth.made_by.at));
            }
        }
        Ok(newest)
    }

    fn graph_source_in_slice(&self, scope: &Scope, id: &EntityId) -> Result<bool> {
        // Type check avoids asking the generic byte door for custody records.
        let Some(kind) = self.read.vault().get_entity_type(id)? else {
            return Ok(false);
        };
        if kind == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
            return Ok(false);
        }
        let source = self.read.read(&[PointRead::id(*id)], None)?.single();
        self.fold_read_receipt(&source.receipt)?;
        let Some(ReadRow {
            body: Some(bytes), ..
        }) = source.value
        else {
            return Ok(false);
        };
        let pinned = scope.allows_read(&document_version(*id, &bytes));
        // Project is a caller-defined exact document slice. It is NOT a claim
        // identity coordinate or a fictitious project column on a TURN.
        if scope.project.is_some() && !pinned {
            return Ok(false);
        }
        match kind {
            ENTITY_TYPE_CLAIM => {
                let body = decode_claim_body(&bytes, true)?;
                Ok(body.world == scope.world
                    && facet(body.scope.as_ref())? == scope.facet
                    && (scope.relationship.is_none() || body.rel == scope.relationship)
                    // A claim awaiting its owner's confirmation ranks nothing.
                    && self.read.vault().claim_consolidation_eligible(
                        id,
                        crate::gate::ConsolidationReader::GraphSignal,
                    )?)
            }
            ENTITY_TYPE_TURN => {
                // TURNs have no relationship column. An explicit relationship
                // scope binds them only via its real document-version grants.
                if scope.relationship.is_some() && !pinned {
                    return Ok(false);
                }
                // Membership is the ChildOf edge alone, as for a branch turn:
                // a neighbour counts only under a declared part's parent, at
                // that parent's pin and axes (FIX 7524).
                let edges = self.read.edges_out_of_kind(id, EdgeKind::ChildOf)?;
                self.fold_read_receipt(&edges.receipt)?;
                if edges.receipt.suppressed_count != 0 {
                    return Ok(false);
                }
                let Some(edges) = edges.value else {
                    return Ok(false);
                };
                let parents: Vec<_> = edges
                    .iter()
                    .filter(|e| e.kind == EdgeKind::ChildOf)
                    .collect();
                if parents.len() != 1 || !self.is_part_parent(&parents[0].target) {
                    return Ok(false);
                }
                let (_, parent) = self.source(scope, &parents[0].target)?;
                let (world, facet) = turn_axes(&bytes)?;
                let (parent_world, parent_facet) = turn_axes(&parent)?;
                Ok(world.or(parent_world) == scope.world && facet.or(parent_facet) == scope.facet)
            }
            ENTITY_TYPE_SESSION | ENTITY_TYPE_CONVERSATION => {
                if !self.is_part_parent(id) {
                    return Ok(false);
                }
                self.source(scope, id)?;
                let (world, facet) = turn_axes(&bytes)?;
                Ok(world == scope.world && facet == scope.facet)
            }
            // Non-claim/non-turn rows carry no common world/facet/rel columns.
            // Only a caller's exact grant can place one in this slice. ScopedRead
            // above still refuses actor-private NOTE rows even with such a grant.
            _ => Ok(pinned),
        }
    }
}

pub(crate) fn facet(scope: Option<&Value>) -> Result<Option<EntityId>> {
    let Some(Value::Map(entries)) = scope else {
        return Ok(None);
    };
    axis(entries, TURN_BODY_FACET_REF_KEY)
}

fn turn_axes(bytes: &[u8]) -> Result<(Option<EntityId>, Option<EntityId>)> {
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)) else {
        return Ok((None, None));
    };
    Ok((
        axis(&entries, TURN_BODY_WORLD_REF_KEY)?,
        axis(&entries, TURN_BODY_FACET_REF_KEY)?,
    ))
}

fn axis(entries: &[(Value, Value)], name: &str) -> Result<Option<EntityId>> {
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() == Some(name) {
            if found.is_some() {
                return Err(invalid_consolidation("duplicate graph source axis"));
            }
            found = Some(
                entity_ref_from_value(value)
                    .ok_or_else(|| invalid_consolidation("invalid graph source axis"))?,
            );
        }
    }
    Ok(found)
}

impl crate::Vault {
    #[cfg(test)]
    pub(crate) fn graph_source_in_slice_for_test(
        &self,
        actor: crate::WriteActor,
        conversation: EntityId,
        source: &EntityId,
    ) -> Result<bool> {
        let resources = BranchResources::open(
            self,
            actor,
            crate::dreamer_consolidation::ConsolidationPartitionKey {
                conversation_ref: conversation,
                world_ref: None,
                facet_ref: None,
            },
            &[],
            crate::attempt_queue::AttemptId::now(),
            None,
        )?;
        resources.graph_source_in_slice(resources.scope(), source)
    }
}
