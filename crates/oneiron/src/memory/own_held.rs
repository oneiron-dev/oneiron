//! The writer's pending claims, admitted separately from normal retrieval.

use super::claims::claim_envelope_actor;
use super::recall::bar::query_terms;
use super::{ClaimView, HeldMark, Memory, MemoryResult};
use crate::analyzer::AnalyzerContext;
use crate::claim::{
    CallerLocality, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimReadStatus,
    PointRead, claim_index_text, decode_claim_body,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::registry::ENTITY_TYPE_CLAIM;

/// The most recent tray entries an own-held read considers.
const OWN_HELD_TRAY_SCAN: usize = 2048;

/// The most held claims shown beside a search or recall result.
const OWN_HELD_SEARCH_LIMIT: usize = 5;

impl Memory<'_> {
    /// The caller's own held claims that `keep` accepts, newest tray entry
    /// first, at most `limit`, each with its [`HeldMark`]. Own means the
    /// claim's write-envelope actor is this handle's actor. Each claim is
    /// admitted through the caller's Recorded lane (the lane hydrate reads),
    /// so this returns only rows the caller could already hydrate. A System
    /// caller gets none.
    pub(crate) fn own_held_claims(
        &self,
        keep: impl Fn(&EntityId, &ClaimBody) -> bool,
        limit: usize,
    ) -> MemoryResult<Vec<ClaimView>> {
        if limit == 0
            || self.actor_class == EdgeActorClass::System
            || EntityId::from_bytes(*self.actor.as_bytes()).is_err()
        {
            return Ok(Vec::new());
        }
        let keep = |id: &EntityId, body: &ClaimBody| {
            body.approval == ClaimApprovalStatus::Proposed
                && body.lifecycle == ClaimLifecycleStatus::Active
                && claim_envelope_actor(body) == Some(self.actor)
                && keep(id, body)
        };
        let mut reads = Vec::new();
        {
            let store = &self.vault.store;
            let txn = store.env.read_txn().map_err(Error::from)?;
            for record in store.newest_pending_gate_consents_in_txn(&txn, OWN_HELD_TRAY_SCAN)? {
                let id = EntityId::from_bytes(record.claim_id)?;
                if self.vault.entity_type_in_txn(&txn, &id)? != Some(ENTITY_TYPE_CLAIM) {
                    continue;
                }
                if self
                    .vault
                    .get_claim_in_txn(&txn, &id)?
                    .is_some_and(|body| keep(&id, &body))
                {
                    reads.push(PointRead::id(id));
                }
            }
        }
        if reads.is_empty() {
            return Ok(Vec::new());
        }
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let admitted = lane.read(&reads, None)?;
        let mut views = Vec::new();
        for row in admitted.value.into_iter().flatten() {
            if row.entity_type != ENTITY_TYPE_CLAIM {
                continue;
            }
            let Some(bytes) = row.body.as_deref() else {
                continue;
            };
            let body = decode_claim_body(bytes, true)?;
            // Check the admitted revision, not the one used to select the id.
            if !keep(&row.id, &body)
                || (self.locality == CallerLocality::OffDevice
                    && self
                        .vault
                        .device_local_keeps_for(&row.id, &self.destination)?)
            {
                continue;
            }
            let view = self.served_claim_view(&row.id, &body)?;
            if view.held.is_some() {
                views.push(view);
                if views.len() == limit {
                    break;
                }
            }
        }
        Ok(views)
    }

    /// [`Self::own_held_claims`] whose index text holds at least one of
    /// `query`'s terms (the text index's analyzer), inside `project_refs`
    /// and every project below them when any are named. Empty for a query
    /// with no terms.
    pub(crate) fn own_held_for_query(
        &self,
        query: &str,
        project_refs: &[String],
    ) -> MemoryResult<Vec<ClaimView>> {
        let terms = query_terms(self.vault, query);
        if terms.is_empty() {
            return Ok(Vec::new());
        }
        let projects = self.projects_at_or_below(project_refs)?;
        self.own_held_claims(
            |_, body| {
                if !projects.matches(body.scope_project) {
                    return false;
                }
                let text = claim_index_text(&body.predicate, &body.value);
                let mut tokens = Vec::new();
                self.vault
                    .analyzer
                    .analyze(&text, &AnalyzerContext::for_index(), &mut tokens);
                tokens.iter().any(|token| {
                    terms
                        .binary_search_by(|term| term.as_str().cmp(token.term.as_ref()))
                        .is_ok()
                })
            },
            OWN_HELD_SEARCH_LIMIT,
        )
    }

    /// The tray row's mark for a held claim; `None` when the tray holds none
    /// or holds a row that does not decode, so a tray fault never fails a
    /// read of the claim itself.
    pub(super) fn held_mark(&self, id: &EntityId) -> MemoryResult<Option<HeldMark>> {
        let store = &self.vault.store;
        let txn = store.env.read_txn().map_err(Error::from)?;
        Ok(store.lenient_tray_in_txn(&txn, id)?.map(|row| HeldMark {
            reason_codes: row.reason_codes,
            decision_ref: format!("gate:{}", row.decision_id.to_hex()),
        }))
    }
}
