use heed::RoTxn;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::claim_surfaceable;
use crate::codebase::codebase_candidate_matches_scope_key;
use crate::edge::{EDGE_KEY_LEN, EdgeKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_RELATIONSHIP};
use crate::store::Store;

use super::support::intervals_overlap;
use super::types::{
    ClaimStatusGateCache, EntityMetadataCache, FacetMode, PipelineFilterConfig, RelMode,
    ScoredEntity, WorldScope,
};

/// D19 read-path status gate (its own pipeline stage; ARCH-0003 retrieval
/// rule, ARCH-0004 §H items 1/2/4).
///
/// Removes from `scores` every type-0 (CLAIM) record that fails
/// [`claim_surfaceable`] — and, fail-closed, every type-0 record whose body
/// is missing or does not decode as the pinned CLAIM ABI (a raw-written
/// non-map body, missing `appr`/`life`, …) — so excluded claims never
/// consume `result_limit` slots (the gate runs before sort/truncate).
/// Exclusion is silent: no error, the claim is dropped and memoized as
/// suppressed in `gate` (surfaced to callers as
/// `PackStats::claims_suppressed`). Entities of every OTHER type byte pass
/// through untouched — their bodies are opaque at the storage layer. The
/// body is decoded at most ONCE per entity per run; passing bodies are kept
/// in `gate` for context-pack field projection.
pub(super) fn apply_claim_status_gate(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
    gate: &mut ClaimStatusGateCache,
) -> Result<()> {
    let mut kept = Vec::with_capacity(scores.len());

    for scored in scores.iter().copied() {
        if claim_status_gate_allows(store, rtxn, &scored.id, metadata_cache, gate)? {
            kept.push(scored);
        }
    }

    *scores = kept;
    Ok(())
}

pub(super) fn claim_status_gate_allows(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    metadata_cache: &mut EntityMetadataCache,
    gate: &mut ClaimStatusGateCache,
) -> Result<bool> {
    // Entities without a parseable envelope are not a claim-status
    // decision; `apply_filters` drops them downstream exactly as before.
    let Some(meta) = metadata_cache.get(store, rtxn, id)? else {
        return Ok(true);
    };
    if meta.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(true);
    }

    if let Some(decision) = gate.decisions.get(id) {
        return Ok(decision.is_some());
    }

    // Read path allows reserved `edge.*` predicates so stored provenance
    // Claims gate on their own appr/life/stale like any other claim instead
    // of failing the decode.
    let decision = store
        .entities
        .get(rtxn, id.as_bytes())?
        .and_then(|raw| {
            raw.get(ENTITY_METADATA_HEADER_LEN..)
                .and_then(|body| crate::claim::decode_claim_body(body, true).ok())
        })
        .filter(|body| {
            claim_surfaceable(body)
                || (gate.include_stale
                    && matches!(
                        body.approval,
                        crate::claim::ClaimApprovalStatus::Auto
                            | crate::claim::ClaimApprovalStatus::Approved
                    )
                    && body.lifecycle == crate::claim::ClaimLifecycleStatus::Active)
        });
    let allowed = decision.is_some();
    gate.decisions.insert(*id, decision);
    Ok(allowed)
}

pub(super) fn import_claim_gate_decisions_for_scores(
    claim_gate: &mut ClaimStatusGateCache,
    probe_gate: &mut ClaimStatusGateCache,
    scores: &[ScoredEntity],
) {
    for scored in scores {
        let Some(decision) = probe_gate.decisions.remove(&scored.id) else {
            continue;
        };
        claim_gate.decisions.entry(scored.id).or_insert(decision);
    }
}

/// ARCH-0039 facet filter (its own pipeline stage, ONE-1117): the
/// post-fusion claim filter for the `strict` / `prefer` facet modes.
///
/// Operates on type-0 (CLAIM) records only — entities of every other type
/// byte pass through untouched, even when they carry `FacetOf` edges. A
/// claim's facet scope is its outgoing `FacetOf` (`CLAIM → FACET`, u8 17)
/// adjacency; no other edge kind participates and claim bodies are never
/// decoded (so this stage shares nothing with the claim-status decode path
/// beyond the entity-metadata cache).
///
/// * [`FacetMode::Strict`] — claims scoped exclusively to other facets are
///   removed; core/unfaceted and active-facet claims pass with their score
///   untouched. Removal is silent (no error) and happens before the
///   `result_limit` truncation, so excluded claims free their slots.
/// * [`FacetMode::Prefer`] — nothing is removed; active-facet claims have
///   their score multiplied by the caller-supplied boost exactly once.
///
/// Fail-closed: a malformed `edges_out` key under the scanned
/// `(claim, FacetOf)` prefix is a typed [`Error::CorruptedIndex`], never a
/// skip.
///
/// Disclosure contract (ONE-1645): this is the ARCH-0039 RELEVANCE stage, not
/// an exposure boundary. Keeping an unfaceted claim here says nothing about
/// whether it may be disclosed — stamp-absence is never invariant evidence.
/// The exposure decision lives on the disclosure axis: the unstamped
/// sensitivity floor (`claim_sensitivity_band` reads band 2 on a missing
/// stamp) today, and the ONE-1646 `disclosable_set` conjunct inside
/// `admits()` next. Relevance never bypasses that conjunct (P7).
///
/// Scope of the CLAIM-only reading: this stage is the LOCAL QUERY door, and a
/// non-CLAIM `FacetOf` stamp being inert HERE is not a statement about the
/// entity's exposure anywhere else. `crate::sync::selector` is a second door
/// that scopes by every source type the ONE-1645 table admits, so a TURN- or
/// EVENT-sourced stamp is disclosure-effective there. "Inert on this door"
/// never generalizes to "disclosure-inert".
pub(super) fn apply_facet_filter(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
    active_facet: &EntityId,
    mode: FacetMode,
) -> Result<()> {
    // Fail-closed: the active facet MUST resolve to an existing FACET entity
    // (type byte 13, per contracts.ts §1 / ARCH-0022 `facet_of` is CLAIM →
    // FACET). A bogus id or a wrong-type id is rejected with a typed error —
    // otherwise strict mode would silently treat every scoped claim as
    // belonging to another facet and drop them all.
    let active_facet_type = metadata_cache
        .get(store, rtxn, active_facet)?
        .map(|meta| meta.entity_type);
    if active_facet_type != Some(ENTITY_TYPE_FACET) {
        return Err(Error::InvalidFacet {
            facet: *active_facet,
            found: active_facet_type,
        });
    }

    let mut kept = Vec::with_capacity(scores.len());

    for mut scored in scores.iter().copied() {
        // Entities without a parseable envelope are not a facet decision;
        // `apply_filters` handles them downstream exactly as before.
        let Some(meta) = metadata_cache.get(store, rtxn, &scored.id)? else {
            kept.push(scored);
            continue;
        };
        if meta.entity_type != ENTITY_TYPE_CLAIM {
            kept.push(scored);
            continue;
        }

        match claim_facet_scope(store, rtxn, &scored.id, active_facet)? {
            ClaimFacetScope::Unfaceted => kept.push(scored),
            ClaimFacetScope::ActiveFacet => {
                if let FacetMode::Prefer { boost } = mode {
                    scored.score *= boost;
                }
                kept.push(scored);
            }
            ClaimFacetScope::OtherFacetsOnly => {
                if let FacetMode::Prefer { .. } = mode {
                    kept.push(scored);
                }
                // Strict: removed — never leak another facet's claims.
            }
        }
    }

    *scores = kept;
    Ok(())
}

/// Resolves a claim's [`ClaimFacetScope`] by prefix-scanning `edges_out`
/// over the 17-byte `(claim_id ‖ FacetOf)` prefix. Only the edge KEY is
/// read — `(source, kind, target)` carries the whole facet-scope signal.
fn claim_facet_scope(
    store: &Store,
    rtxn: &RoTxn<'_>,
    claim_id: &EntityId,
    active_facet: &EntityId,
) -> Result<ClaimFacetScope> {
    let mut prefix = [0_u8; ENTITY_ID_LEN + 1];
    prefix[..ENTITY_ID_LEN].copy_from_slice(claim_id.as_bytes());
    prefix[ENTITY_ID_LEN] = EdgeKind::FacetOf as u8;

    let mut any_facet_edge = false;
    for row in store.edges_out.prefix_iter(rtxn, prefix.as_slice())? {
        let (key, _value) = row?;
        if key.len() != EDGE_KEY_LEN {
            return Err(Error::CorruptedIndex("edge record"));
        }
        any_facet_edge = true;
        if &key[ENTITY_ID_LEN + 1..] == active_facet.as_bytes() {
            return Ok(ClaimFacetScope::ActiveFacet);
        }
    }

    if any_facet_edge {
        Ok(ClaimFacetScope::OtherFacetsOnly)
    } else {
        Ok(ClaimFacetScope::Unfaceted)
    }
}

/// A claim's facet scope relative to the query's active facet, derived from
/// its outgoing `FacetOf` (`CLAIM → FACET`, u8 17) adjacency.
///
/// CLAIM-sourced adjacency only — this is the local query door. The write
/// table also admits `TURN | EVENT → FACET`, and those stamps carry disclosure
/// weight on the federation selector door even though they never reach this
/// enum (see [`crate::batch::validate_facet_of_edge`]).
enum ClaimFacetScope {
    /// No `FacetOf` edge — a relevance-neutral claim. Passes every mode.
    ///
    /// NOT invariant evidence: absence of a facet stamp never widens
    /// disclosure (ONE-1645, P3/V2). The disclosure conjunct (ONE-1646) must
    /// derive invariant admission from POSITIVE evidence only — a stored
    /// public stamp or a promotion record — never from this variant. The
    /// live disclosure floor for unstamped provenance is
    /// `claim_sensitivity_band`, which reads band 2 on a missing stamp.
    Unfaceted,
    /// At least one `FacetOf` edge targets the active facet.
    ActiveFacet,
    /// Has `FacetOf` edges, none targeting the active facet.
    OtherFacetsOnly,
}

/// ARCH-0004 world filter (ONE-1117): the post-fusion claim world filter for
/// the `Base` / `World(id)` scopes. A pure removal filter — scores are never
/// rewritten, mirroring the facet filter's `strict` removal.
///
/// * [`WorldScope::All`] — passes every candidate EXCEPT claims of a
///   stale-stamped federated world (ONE-1411); the context pack groups the rest
///   by world downstream.
/// * [`WorldScope::Base`] — only base-reality claims (no `world` key) survive;
///   every world-scoped claim is removed, stale-stamped ones included by
///   construction.
/// * [`WorldScope::World`] — claims scoped to the target world plus base
///   claims survive; claims scoped to any other world are removed. A STAMPED
///   target is kept: naming a dead world is an explicit request to read it,
///   and the context pack marks what it returns rather than hiding it.
///
/// Non-claim entities have no world and are treated as base, so they pass
/// every scope untouched. Removal happens before the `result_limit`
/// truncation, so excluded claims free their slots.
pub(super) fn apply_relationship_filter(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
    active_relationship: &EntityId,
    mode: RelMode,
) -> Result<()> {
    let found = metadata_cache
        .get(store, rtxn, active_relationship)?
        .map(|meta| meta.entity_type);
    if found != Some(ENTITY_TYPE_RELATIONSHIP) {
        return Err(Error::InvalidRelationship {
            relationship: *active_relationship,
            found,
        });
    }
    let mut in_scope = Vec::with_capacity(scores.len());
    let mut other = Vec::new();
    for scored in scores.iter().copied() {
        let is_other = claim_rel(store, rtxn, &scored.id)?
            .is_some_and(|relationship| relationship != *active_relationship);
        if is_other {
            other.push(scored);
        } else {
            in_scope.push(scored);
        }
    }
    match mode {
        RelMode::Filter => *scores = in_scope,
        RelMode::Demote => {
            in_scope.extend(other);
            *scores = in_scope;
        }
    }
    Ok(())
}

fn claim_rel(store: &Store, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<EntityId>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    Ok(body.rel)
}

pub(super) fn apply_world_filter(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    scope: WorldScope,
) -> Result<()> {
    let target = match scope {
        WorldScope::All => return drop_stale_federated_claims(scores, store, rtxn),
        WorldScope::Base => None,
        WorldScope::World(id) => Some(id),
        WorldScope::WorldSet(scope_key) => {
            let mut kept = Vec::with_capacity(scores.len());
            for scored in scores.iter().copied() {
                if codebase_candidate_matches_scope_key(store, rtxn, &scored.id, &scope_key)? {
                    kept.push(scored);
                }
            }
            *scores = kept;
            return Ok(());
        }
    };

    let mut kept = Vec::with_capacity(scores.len());
    for scored in scores.iter().copied() {
        let keep = match claim_world(store, rtxn, &scored.id)? {
            // Base reality (no world key, or a non-claim entity) always passes.
            None => true,
            // A world-scoped claim passes only for its own world.
            Some(world) => target == Some(world),
        };
        if keep {
            kept.push(scored);
        }
    }

    *scores = kept;
    Ok(())
}

/// ONE-1411 stale-federation exclusion for the UNSCOPED default.
///
/// `WorldScope::All` is the scope a caller lands in without asking for
/// anything, so content from a world whose pact went terminal must not ride it:
/// it no longer refreshes, and nothing in an unscoped result set says so.
/// Naming that world explicitly still returns it — this drops it only from the
/// scope that never asked.
///
/// The stamp set is read ONCE per retrieval run. This is the single call site
/// of the world filter, and the map is probed per candidate rather than
/// re-scanned, so the cost is one prefix scan regardless of candidate count.
fn drop_stale_federated_claims(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<()> {
    let stale = crate::federation::stale_stamped_worlds(store, rtxn)?;
    if stale.is_empty() {
        return Ok(());
    }

    let mut kept = Vec::with_capacity(scores.len());
    for scored in scores.iter().copied() {
        let stale_world =
            claim_world(store, rtxn, &scored.id)?.is_some_and(|world| stale.contains_key(&world));
        if !stale_world {
            kept.push(scored);
        }
    }

    *scores = kept;
    Ok(())
}

/// Reads a candidate's world for the post-fusion world filter (ARCH-0004 /
/// ARCH-0022). Returns `None` for base reality — a non-claim entity, a claim
/// with no `world` key, or an entity with no parseable envelope — and
/// `Some(world_id)` for a world-scoped claim. The claim body is decoded once
/// through the pinned claim validator (the world key was structurally
/// validated to 16 bytes at write time).
fn claim_world(store: &Store, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<EntityId>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    Ok(body.world)
}

pub(super) fn apply_filters(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    filters: PipelineFilterConfig<'_>,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<()> {
    let mut filtered = Vec::with_capacity(scores.len());

    for scored in scores.iter().copied() {
        let Some(meta) = metadata_cache.get(store, rtxn, &scored.id)? else {
            continue;
        };

        if !super::authority::type_allowed(filters.authority_filter, store, meta.entity_type) {
            continue;
        }
        if let Some(types) = filters.type_filter
            && !types.contains(&meta.entity_type)
        {
            continue;
        }

        if let Some(timestamp) = filters.since_filter
            && meta.learned_at < timestamp
        {
            continue;
        }

        if let Some((start, end)) = filters.occurred_range
            && !intervals_overlap(meta.occurred_start, meta.occurred_end, start, end)
        {
            continue;
        }

        if let Some((start, end)) = filters.learned_range
            && (meta.learned_at < start || meta.learned_at > end)
        {
            continue;
        }

        if !crate::codebase::codebase_candidate_matches_filters(
            store,
            rtxn,
            &scored.id,
            filters.repo_ref_filter,
            filters.project_id_filter,
        )? {
            continue;
        }

        filtered.push(scored);
    }

    *scores = filtered;
    Ok(())
}

pub(super) fn pipeline_candidate_matches_filters_and_gate(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    filters: PipelineFilterConfig<'_>,
    metadata_cache: &mut EntityMetadataCache,
    claim_gate: &mut ClaimStatusGateCache,
) -> Result<bool> {
    let Some(meta) = metadata_cache.get(store, rtxn, id)? else {
        return Ok(false);
    };

    if !super::authority::type_allowed(filters.authority_filter, store, meta.entity_type) {
        return Ok(false);
    }
    if let Some(types) = filters.type_filter
        && !types.contains(&meta.entity_type)
    {
        return Ok(false);
    }

    if let Some(timestamp) = filters.since_filter
        && meta.learned_at < timestamp
    {
        return Ok(false);
    }

    if let Some((start, end)) = filters.occurred_range
        && !intervals_overlap(meta.occurred_start, meta.occurred_end, start, end)
    {
        return Ok(false);
    }

    if let Some((start, end)) = filters.learned_range
        && (meta.learned_at < start || meta.learned_at > end)
    {
        return Ok(false);
    }

    if !crate::codebase::codebase_candidate_matches_filters(
        store,
        rtxn,
        id,
        filters.repo_ref_filter,
        filters.project_id_filter,
    )? {
        return Ok(false);
    }

    if !claim_status_gate_allows(store, rtxn, id, metadata_cache, claim_gate)? {
        return Ok(false);
    }

    if !pipeline_candidate_matches_facet_filter(
        store,
        rtxn,
        id,
        meta.entity_type,
        filters.facet_filter,
        metadata_cache,
    )? {
        return Ok(false);
    }

    if !pipeline_candidate_matches_world_filter(store, rtxn, id, filters.world_scope)? {
        return Ok(false);
    }

    pipeline_candidate_matches_relationship_filter(
        store,
        rtxn,
        id,
        meta.entity_type,
        filters.relationship_filter,
        metadata_cache,
    )
}

/// The candidate-scan twin of [`apply_facet_filter`], with the same
/// disclosure contract (ONE-1645): this is a RELEVANCE decision. Admitting an
/// unfaceted claim here is not evidence that it is invariant or publicly
/// disclosable — the unstamped sensitivity floor and the ONE-1646
/// `disclosable_set` conjunct own that axis.
fn pipeline_candidate_matches_facet_filter(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    facet_filter: Option<(EntityId, FacetMode)>,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<bool> {
    let Some((active_facet, mode)) = facet_filter else {
        return Ok(true);
    };

    let active_facet_type = metadata_cache
        .get(store, rtxn, &active_facet)?
        .map(|meta| meta.entity_type);
    if active_facet_type != Some(ENTITY_TYPE_FACET) {
        return Err(Error::InvalidFacet {
            facet: active_facet,
            found: active_facet_type,
        });
    }

    if entity_type != ENTITY_TYPE_CLAIM {
        return Ok(true);
    }

    match claim_facet_scope(store, rtxn, id, &active_facet)? {
        ClaimFacetScope::OtherFacetsOnly => Ok(matches!(mode, FacetMode::Prefer { .. })),
        ClaimFacetScope::Unfaceted | ClaimFacetScope::ActiveFacet => Ok(true),
    }
}

fn pipeline_candidate_matches_relationship_filter(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    relationship_filter: Option<(EntityId, RelMode)>,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<bool> {
    let Some((active_relationship, mode)) = relationship_filter else {
        return Ok(true);
    };
    let found = metadata_cache
        .get(store, rtxn, &active_relationship)?
        .map(|meta| meta.entity_type);
    if found != Some(ENTITY_TYPE_RELATIONSHIP) {
        return Err(Error::InvalidRelationship {
            relationship: active_relationship,
            found,
        });
    }
    if entity_type != ENTITY_TYPE_CLAIM {
        return Ok(true);
    }
    Ok(match claim_rel(store, rtxn, id)? {
        Some(relationship) if relationship != active_relationship => {
            matches!(mode, RelMode::Demote)
        }
        _ => true,
    })
}

fn pipeline_candidate_matches_world_filter(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    scope: WorldScope,
) -> Result<bool> {
    let target = match scope {
        WorldScope::All => return Ok(true),
        WorldScope::Base => None,
        WorldScope::World(id) => Some(id),
        WorldScope::WorldSet(scope_key) => {
            return codebase_candidate_matches_scope_key(store, rtxn, id, &scope_key);
        }
    };

    Ok(match claim_world(store, rtxn, id)? {
        None => true,
        Some(world) => target == Some(world),
    })
}
