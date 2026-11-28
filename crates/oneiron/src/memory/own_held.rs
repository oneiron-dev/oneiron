//! The writer's pending claims, admitted separately from normal retrieval.

use super::claims::claim_envelope_actor;
use super::recall::bar::query_terms;
use super::structural::type_byte_for_kind;
use super::{ClaimView, HeldMark, Memory, MemoryResult, RecallScope};
use crate::analyzer::AnalyzerContext;
use crate::claim::{
    CallerLocality, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimReadStatus,
    PointRead, decode_claim_body,
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
    /// Whether `body` is this handle's own write: its write-envelope actor is
    /// this handle's actor, and the handle is no System caller.
    pub(super) fn is_own_write(&self, body: &ClaimBody) -> bool {
        self.actor_class != EdgeActorClass::System && claim_envelope_actor(body) == Some(self.actor)
    }

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
        self.own_held_claims_shown(keep, |_| true, limit)
    }

    /// [`Self::own_held_claims`] whose served view `shown` also accepts. The
    /// lane admits the candidates uncharged, and `shown` tests each one's
    /// view without its birth ([`Self::claim_view_without_birth`]), whose
    /// scoped read would charge it; only the claims returned are charged to
    /// the caller's read exposure (L8-65) and listed as producers of the
    /// answer, so a kept reply is checked against each of them
    /// ([`crate::vault::Vault::own_held_claim_readable`]).
    fn own_held_claims_shown(
        &self,
        keep: impl Fn(&EntityId, &ClaimBody) -> bool,
        shown: impl Fn(&ClaimView) -> bool,
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
                && self.is_own_write(body)
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
        let admitted = lane.read_uncharged(&reads)?;
        let (mut served, mut views) = (Vec::new(), Vec::new());
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
            let candidate = self.claim_view_without_birth(&row.id, &body)?;
            if candidate.held.is_some() && shown(&candidate) {
                served.push(row.id);
                views.push(self.served_claim_view(&row.id, &body)?);
                if views.len() == limit {
                    break;
                }
            }
        }
        lane.charge_served(served.iter().copied());
        self.produced_from(served);
        Ok(views)
    }

    /// The caller's own held claims that `keep` accepts and whose served
    /// value holds at least one of `query`'s terms (the text index's
    /// analyzer, over the value text as the index reads a claim's value).
    /// Only the value the view serves is matched, never stored words it
    /// redacts or masks. A stale claim only when `include_stale`, the stale
    /// selector the read beside it applied under the actor ceiling. At most
    /// [`OWN_HELD_SEARCH_LIMIT`]; none for a query with no terms.
    fn own_held_matching(
        &self,
        query: &str,
        include_stale: bool,
        keep: impl Fn(&EntityId, &ClaimBody) -> bool,
    ) -> MemoryResult<Vec<ClaimView>> {
        let terms = query_terms(self.vault, query);
        if terms.is_empty() {
            return Ok(Vec::new());
        }
        self.own_held_claims_shown(
            |id, body| (include_stale || !body.stale) && keep(id, body),
            |view| {
                let text = match &view.value {
                    serde_json::Value::String(text) => text.clone(),
                    other => other.to_string(),
                };
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

    /// `vault.search.bm25`'s held list: [`Self::own_held_matching`] over
    /// every held claim of the caller, stale ones only when the search's
    /// applied selector `include_stale` takes them.
    pub(crate) fn own_held_for_search(
        &self,
        query: &str,
        include_stale: bool,
    ) -> MemoryResult<Vec<ClaimView>> {
        self.own_held_matching(query, include_stale, |_, _| true)
    }

    /// A recall's held list: [`Self::own_held_matching`] under the recall's
    /// own selection from `scope`: its worlds (as recall reads them, the
    /// actor's default when none is named), its projects and every project
    /// below them, and its kinds, which must name CLAIM when set. A scope
    /// that selects by conversation, person or facet names nothing this
    /// list can test a claim against, so it gets none. Stale claims only
    /// when the recall's applied selector `include_stale` takes them.
    pub(crate) fn own_held_for_recall(
        &self,
        query: &str,
        scope: &RecallScope,
        include_stale: bool,
    ) -> MemoryResult<Vec<ClaimView>> {
        let claims_asked = scope.kinds.as_ref().is_none_or(|kinds| {
            kinds
                .iter()
                .any(|kind| type_byte_for_kind(kind).is_ok_and(|kind| kind == ENTITY_TYPE_CLAIM))
        });
        if !claims_asked
            || !scope.conversation_refs.is_empty()
            || scope.person_ref.is_some()
            || scope.facet.is_some()
        {
            return Ok(Vec::new());
        }
        let worlds = self.recall_worlds(scope)?;
        let projects = self.selected_projects(scope)?;
        self.own_held_matching(query, include_stale, |_, body| {
            worlds
                .as_ref()
                .is_none_or(|worlds| worlds.admits(body.world))
                && projects.matches(body.scope_project)
        })
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

impl crate::vault::Vault {
    /// Whether `id` is the own held claim of `key`'s reader that an own held
    /// list serves it now: a Proposed, Active claim whose write-envelope
    /// actor is that reader (no System caller), with its tray row, that the
    /// key's record lane admits and no world keeps from the key's
    /// destination, the checks [`Memory::own_held_claims`] served it under.
    /// A kept reply's producer recheck takes it beside
    /// [`crate::claim::ScopedRead::is_entity_readable`], whose Surfaceable
    /// lane refuses every held claim, so a held claim served to its writer
    /// reads again for that writer alone; every other row is judged as
    /// before.
    ///
    /// # Errors
    ///
    /// Storage errors, or a claim row that does not decode.
    pub fn own_held_claim_readable(
        &self,
        key: crate::claim::ScopedReadActorKey,
        id: &EntityId,
    ) -> crate::error::Result<bool> {
        if key.actor_class() == Some(EdgeActorClass::System.gate_actor_class()) {
            return Ok(false);
        }
        let Ok(reader) = EntityId::from_hex(key.actor_ref()) else {
            return Ok(false);
        };
        {
            let txn = self.store.env.read_txn()?;
            if self.entity_type_in_txn(&txn, id)? != Some(ENTITY_TYPE_CLAIM)
                || self.store.lenient_tray_in_txn(&txn, id)?.is_none()
            {
                return Ok(false);
            }
            let Some(body) = self.get_claim_in_txn(&txn, id)? else {
                return Ok(false);
            };
            if body.approval != ClaimApprovalStatus::Proposed
                || body.lifecycle != ClaimLifecycleStatus::Active
                || claim_envelope_actor(&body) != Some(reader)
            {
                return Ok(false);
            }
        }
        if self.device_local_keeps_for(id, key.destination())? {
            return Ok(false);
        }
        self.scoped_read(key)
            .recorded_lane()?
            .is_entity_readable(id)
    }
}
