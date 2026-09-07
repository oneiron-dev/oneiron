//! Per-turn world authority, bound to the host's executing principal.

use heed::RoTxn;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, claim_surfaceable,
    session_claim_producer,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::vault::{MAX_EDGE_QUERY_RESULTS, edge_kind_prefix, parse_edge_record};
use crate::write_envelope::WriteActor;

use super::types::{
    ActiveWorldSelection, PREDICATE_WORLD_ACCESS_ALLOWED_SET,
    PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET, ResolvedWorldAuthority, WorldAuthoritySet, WorldScope,
    decode_world_access_claim_value,
};

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
    execution_actor: Option<WriteActor>,
    at: u64,
) -> Result<Option<ResolvedWorldAuthority>> {
    if !matches!(scope, WorldScope::ActiveSet) {
        return Ok(None);
    }
    let selection = require_active_world_selection(selection)?;
    let actor = execution_actor.ok_or_else(|| {
        Error::InvalidConfig("WorldScope::ActiveSet requires a host-bound execution".to_owned())
    })?;
    if selection.agent_ref != actor.entity_ref() {
        return Err(Error::InvalidConfig(
            "world selection agent does not match the executing principal".to_owned(),
        ));
    }
    let raw = store
        .entities
        .get(rtxn, actor.entity_ref().as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("executing actor entity header"))?;
    crate::provenance::validate_actor_class(header.entity_type, actor.actor_class())?;
    resolve_world_authority(store, rtxn, selection, at).map(Some)
}

/// Folds the stored authority tiers into the set this turn may read
/// (ONE-1420).
///
/// The pinned rules, in order:
///
/// ```text
/// allowed = intersection(all in-force, active, approved, user-stated ALLOWED-SET rows)
/// default = newest in-force active self-authored DEFAULT-SUBSET by (valid_from, learned_at, entity_id)
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
/// it would honour. Defaults also require the subject's envelope-stamped writer
/// identity. Another writer's row cannot win precedence or cause a value-decode
/// refusal, even when its value is malformed.
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
        if body.predicate == PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET
            && session_claim_producer(&body) != Some(*agent_ref)
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
