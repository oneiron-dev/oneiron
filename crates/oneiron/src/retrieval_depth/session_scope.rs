use crate::claim::{ScopedRead, decode_claim_body};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::pipeline::ScoredEntity;
use crate::registry::ENTITY_TYPE_CLAIM;

use super::{DepthSearchRequest, short_ref_or_hex};

/// Session scope for a depth read: NARROWING ONLY.
///
/// Every field can drop hits and none can add one. That direction is the whole
/// point — a session context is a caller-supplied hint, and a hint that could
/// widen an actor-keyed read would be a way to ask for someone else's memory
/// by naming their world.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionScope {
    /// Keep only claims scoped to this WORLD.
    pub world_ref: Option<EntityId>,
    /// Keep only entities carrying a `facet_of` edge to this facet.
    pub facet_ref: Option<EntityId>,
    /// Keep only these short ids (`short_id` or `short_id:hash`). Empty means
    /// "no document narrowing", not "narrow to nothing".
    pub document_short_ids: Vec<String>,
}

impl SessionScope {
    /// Whether this scope narrows anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.world_ref.is_none() && self.facet_ref.is_none() && self.document_short_ids.is_empty()
    }
}

/// Narrows `hits` to a session scope. See [`SessionScope`]: this can only
/// remove hits.
pub fn narrow_to_session_scope(
    scoped: &ScopedRead<'_>,
    hits: Vec<ScoredEntity>,
    scope: &SessionScope,
) -> Result<Vec<ScoredEntity>> {
    if scope.is_empty() {
        return Ok(hits);
    }
    let mut kept = Vec::with_capacity(hits.len());
    for hit in hits {
        if hit_in_session_scope(scoped, &hit.id, scope)? {
            kept.push(hit);
        }
    }
    Ok(kept)
}

fn hit_in_session_scope(
    scoped: &ScopedRead<'_>,
    id: &EntityId,
    scope: &SessionScope,
) -> Result<bool> {
    if let Some(world) = &scope.world_ref
        && claim_world(scoped, id)? != Some(*world)
    {
        return Ok(false);
    }
    if let Some(facet) = &scope.facet_ref
        && !carries_facet(scoped, id, facet)?
    {
        return Ok(false);
    }
    if !scope.document_short_ids.is_empty() {
        let short_ref = short_ref_or_hex(scoped.vault(), id)?;
        if !scope
            .document_short_ids
            .iter()
            .any(|requested| short_ref_matches(&short_ref, requested))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Compares a stored `short_id:hash` ref against a caller-supplied one,
/// accepting either form on either side. The hash suffix is a content stamp,
/// not part of the identity being narrowed to.
fn short_ref_matches(stored: &str, requested: &str) -> bool {
    let stored_id = stored.split(':').next().unwrap_or(stored);
    let requested_id = requested.trim();
    let requested_id = requested_id.split(':').next().unwrap_or(requested_id);
    !requested_id.is_empty() && stored_id == requested_id
}

/// The claim's world, read through the actor-keyed door. A non-CLAIM entity,
/// or one this actor cannot read, has no world and therefore never satisfies
/// a world narrowing.
fn claim_world(scoped: &ScopedRead<'_>, id: &EntityId) -> Result<Option<EntityId>> {
    let Some((entity_type, _, body)) = scoped.get_entity_parts(id)? else {
        return Ok(None);
    };
    if entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    Ok(decode_claim_body(&body, true)?.world)
}

fn carries_facet(scoped: &ScopedRead<'_>, id: &EntityId, facet: &EntityId) -> Result<bool> {
    let Some(edges) = scoped.edges_out(id)? else {
        return Ok(false);
    };
    Ok(edges
        .iter()
        .any(|edge| edge.kind == EdgeKind::FacetOf && edge.target == *facet))
}

impl DepthSearchRequest<'_> {
    /// Fetch the indexed candidate set before session narrowing, just as the
    /// actor-keyed door does for policy filters. A global page is not a scoped page.
    pub(super) fn channel_limit(&self, scoped: &ScopedRead<'_>, text: bool) -> Result<usize> {
        if self.session_scope.is_none_or(SessionScope::is_empty) {
            return Ok(self.limit);
        }
        scoped
            .vault()
            .scoped_read_search_candidate_limit(self.limit, text, !text)
    }

    pub(super) fn narrow_hits(
        &self,
        scoped: &ScopedRead<'_>,
        hits: Vec<ScoredEntity>,
    ) -> Result<Vec<ScoredEntity>> {
        let mut hits = match self.session_scope {
            Some(scope) => narrow_to_session_scope(scoped, hits, scope)?,
            None => hits,
        };
        hits.truncate(self.limit);
        Ok(hits)
    }
}
