use heed::RoTxn;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, claim_surfaceable};
use crate::codebase::codebase_candidate_matches_scope_key;
use crate::edge::{EDGE_KEY_LEN, EdgeKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_RELATIONSHIP};
use crate::store::Store;
use crate::vault::{MAX_EDGE_QUERY_RESULTS, edge_kind_prefix, parse_edge_record};

use super::support::intervals_overlap;
use super::types::{
    ActiveWorldSelection, ClaimStatusGateCache, EntityMetadataCache, FacetMode,
    PREDICATE_WORLD_ACCESS_ALLOWED_SET, PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
    PipelineFilterConfig, RelMode, ResolvedWorldAuthority, ScoredEntity, WorldAuthoritySet,
    WorldScope, decode_world_access_claim_value,
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
        .filter(claim_surfaceable);
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
    active_selection: Option<&ActiveWorldSelection>,
    at: u64,
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
        // ONE-1420: the authority resolves under THIS read transaction, at the
        // run's clock, and a resolution failure (no selection, a selection
        // outside the owner grant, a malformed authority row) propagates as the
        // whole query's error. There is no arm here that admits a candidate the
        // owner never granted.
        WorldScope::ActiveSet => {
            let selection = require_active_world_selection(active_selection)?;
            let resolved = resolve_world_authority(store, rtxn, selection, at)?;
            let mut kept = Vec::with_capacity(scores.len());
            for scored in scores.iter().copied() {
                if active_set_admits(store, rtxn, &scored.id, &resolved.active_set)? {
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

/// Whether one candidate survives a resolved per-turn ActiveSet (ONE-1420).
///
/// Base handling is EXPLICIT: base-reality claims and non-claim entities — the
/// two things [`claim_world`] reports as `None` — survive only when the active
/// set includes base. A world-scoped claim survives only when its own world is
/// a selected member; no other world is reachable, and nothing here consults
/// the codebase scope key.
fn active_set_admits(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    active_set: &WorldAuthoritySet,
) -> Result<bool> {
    Ok(match claim_world(store, rtxn, id)? {
        None => active_set.include_base,
        Some(world) => active_set.worlds.contains(&world),
    })
}

/// The typed refusal for `.world(WorldScope::ActiveSet)` with no selection.
///
/// A scope that names an authority tier but carries no selection is a caller
/// bug, and the only safe answer is to fail the run: silently reading it as
/// [`WorldScope::All`] would hand the agent every world the vault holds.
fn require_active_world_selection(
    selection: Option<&ActiveWorldSelection>,
) -> Result<&ActiveWorldSelection> {
    selection.ok_or_else(|| {
        Error::InvalidConfig(
            "WorldScope::ActiveSet requires PipelineBuilder::active_worlds or \
             PipelineBuilder::default_active_worlds"
                .to_owned(),
        )
    })
}

/// Resolves the run's world authority once, for the scopes that have one.
///
/// `Ok(None)` for every scope except [`WorldScope::ActiveSet`], so the ordinary
/// scopes pay nothing for this stage. The resolution runs ONCE per retrieval
/// run and its `active_set` is then borrowed by every per-candidate check.
pub(super) fn resolve_active_world_authority(
    store: &Store,
    rtxn: &RoTxn<'_>,
    scope: WorldScope,
    selection: Option<&ActiveWorldSelection>,
    at: u64,
) -> Result<Option<ResolvedWorldAuthority>> {
    if !matches!(scope, WorldScope::ActiveSet) {
        return Ok(None);
    }
    let selection = require_active_world_selection(selection)?;
    resolve_world_authority(store, rtxn, selection, at).map(Some)
}

/// Folds the stored authority tiers into the set this turn may read
/// (ONE-1420).
///
/// The pinned rules, in order:
///
/// ```text
/// allowed = intersection(all in-force, active, approved, user-stated ALLOWED-SET rows)
/// default = newest in-force active DEFAULT-SUBSET by (valid_from, learned_at, entity_id)
/// active  = explicit per-turn selection if present, else default
/// require default ⊆ allowed
/// require active  ⊆ allowed
/// no allowed row => allowed/default/active are empty
/// ```
///
/// Bitemporal precedence runs BEFORE the fold: rows closed at `at` (by
/// `valid_from` / `valid_to`) and rows closed by lifecycle, approval or the
/// staleness marker are ignored entirely, so a superseded grant neither
/// narrows nor widens. Intersection is what makes the owner tier monotone —
/// writing another ALLOWED-SET row can only remove members — and an agent
/// cannot reach a wider read by adding rows of its own, because only
/// user-stated approved rows are folded at all. A malformed value on a row
/// that DID qualify fails the read closed rather than being skipped.
pub(super) fn resolve_world_authority(
    store: &Store,
    rtxn: &RoTxn<'_>,
    selection: &ActiveWorldSelection,
    at: u64,
) -> Result<ResolvedWorldAuthority> {
    let rows = world_access_rows(store, rtxn, &selection.agent_ref, at)?;

    let mut folded_allowed: Option<WorldAuthoritySet> = None;
    let mut allowed_claim_ids = Vec::new();
    for row in &rows {
        if row.body.predicate != PREDICATE_WORLD_ACCESS_ALLOWED_SET
            || !owner_granted_allowed_row(&row.body)
        {
            continue;
        }
        let granted = decode_world_access_claim_value(&row.body)?;
        folded_allowed = Some(match folded_allowed {
            None => granted,
            Some(folded) => folded.intersect(&granted),
        });
        allowed_claim_ids.push(row.id);
    }
    // No qualifying owner row is the EMPTY authority, never `All`.
    let allowed_set = folded_allowed.unwrap_or_default();

    let mut newest_default: Option<(&WorldAccessRow, WorldAuthoritySet)> = None;
    for row in &rows {
        if row.body.predicate != PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET {
            continue;
        }
        // Closed rows were removed before this loop. Every remaining default
        // must decode, even when a newer active row wins precedence.
        let subset = decode_world_access_claim_value(&row.body)?;
        if newest_default.as_ref().is_none_or(|(current, _)| {
            default_row_precedence(row) > default_row_precedence(current)
        }) {
            newest_default = Some((row, subset));
        }
    }
    let (default_subset, default_claim_id) = match newest_default {
        Some((row, subset)) => (subset, Some(row.id)),
        None => (WorldAuthoritySet::default(), None),
    };
    if !default_subset.is_subset_of(&allowed_set) {
        return Err(Error::InvalidConfig(format!(
            "stored {PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET} row exceeds the owner-granted \
             {PREDICATE_WORLD_ACCESS_ALLOWED_SET}"
        )));
    }

    let active_set = match selection.selected.as_ref() {
        Some(selected) => selected.clone(),
        None => default_subset.clone(),
    };
    if !active_set.is_subset_of(&allowed_set) {
        return Err(Error::InvalidConfig(format!(
            "requested world selection is outside the owner-granted \
             {PREDICATE_WORLD_ACCESS_ALLOWED_SET}"
        )));
    }

    Ok(ResolvedWorldAuthority {
        allowed_set,
        default_subset,
        active_set,
        allowed_claim_ids,
        default_claim_id,
    })
}

/// One world-access authority CLAIM row that is in force for this resolution.
struct WorldAccessRow {
    id: EntityId,
    body: ClaimBody,
    learned_at: u64,
}

/// Bitemporal precedence key for DEFAULT-SUBSET rows: valid-time first, then
/// the learned-at envelope, then the entity id as the total-order tiebreak, so
/// two rows can never tie and the winner does not depend on scan order.
fn default_row_precedence(row: &WorldAccessRow) -> (u64, u64, EntityId) {
    (row.body.valid_from.unwrap_or(0), row.learned_at, row.id)
}

/// The owner tier's extra bar on top of [`claim_surfaceable`]: a grant counts
/// only when the OWNER stated it and it carries explicit approval. An
/// agent-authored `auto` row under the same predicate is ignored, so authoring
/// one is not a self-widen path.
fn owner_granted_allowed_row(body: &ClaimBody) -> bool {
    body.approval == ClaimApprovalStatus::Approved && body.source == Some(ClaimSource::UserStated)
}

/// Whether a row's valid-time window contains `at`. Half-open `[from, to)`:
/// an absent bound is unbounded on that side.
fn world_access_row_in_force(body: &ClaimBody, at: u64) -> bool {
    body.valid_from.is_none_or(|from| from <= at) && body.valid_to.is_none_or(|to| at < to)
}

/// Reads the agent's in-force world-access rows through its inbound `claim_of`
/// adjacency — the same edge the claim door writes, so authority rows are
/// ordinary claims about the agent and nothing else.
///
/// Rows that are closed (lifecycle, approval, staleness, or valid-time at
/// `at`), rows about another subject, and rows under any other predicate are
/// skipped here, BEFORE any value decode: the resolver only ever decodes rows
/// it would honour.
fn world_access_rows(
    store: &Store,
    rtxn: &RoTxn<'_>,
    agent_ref: &EntityId,
    at: u64,
) -> Result<Vec<WorldAccessRow>> {
    let prefix = edge_kind_prefix(agent_ref, EdgeKind::ClaimOf);
    let mut rows = Vec::new();
    for (scanned, entry) in store
        .edges_in
        .prefix_iter(rtxn, prefix.as_slice())?
        .enumerate()
    {
        if scanned >= MAX_EDGE_QUERY_RESULTS {
            return Err(Error::IndexOverflow("world access authority claims"));
        }
        let (key, value) = entry?;
        let claim_id = parse_edge_record(&key, &value)?.target;
        let Some(raw) = store.entities.get(rtxn, claim_id.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if body.predicate != PREDICATE_WORLD_ACCESS_ALLOWED_SET
            && body.predicate != PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET
        {
            continue;
        }
        if body.subject != ClaimSubject::Entity(*agent_ref)
            || !claim_surfaceable(&body)
            || !world_access_row_in_force(&body, at)
        {
            continue;
        }
        rows.push(WorldAccessRow {
            id: claim_id,
            body,
            learned_at: header.learned_at,
        });
    }
    Ok(rows)
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

    if !pipeline_candidate_matches_world_filter(
        store,
        rtxn,
        id,
        filters.world_scope,
        filters.world_active_set,
    )? {
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
    active_set: Option<&WorldAuthoritySet>,
) -> Result<bool> {
    let target = match scope {
        WorldScope::All => return Ok(true),
        WorldScope::Base => None,
        WorldScope::World(id) => Some(id),
        WorldScope::WorldSet(scope_key) => {
            return codebase_candidate_matches_scope_key(store, rtxn, id, &scope_key);
        }
        // Same admission as the post-fusion arm, against the authority the run
        // resolved once. A missing set means the run reached a per-candidate
        // check under `ActiveSet` with nothing resolved, which is refused
        // rather than treated as "no restriction".
        WorldScope::ActiveSet => {
            let active_set = active_set.ok_or_else(|| {
                Error::InvalidConfig(
                    "WorldScope::ActiveSet candidate check has no resolved world authority"
                        .to_owned(),
                )
            })?;
            return active_set_admits(store, rtxn, id, active_set);
        }
    };

    Ok(match claim_world(store, rtxn, id)? {
        None => true,
        Some(world) => target == Some(world),
    })
}
