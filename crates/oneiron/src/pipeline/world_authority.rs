//! Per-turn world authority, bound to the host's executing principal.

use crate::ports::EdgeStoreRead;
use crate::ports::EntityStoreRead;
use heed::RoTxn;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, claim_surfaceable,
    session_claim_producer,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::vault::MAX_EDGE_QUERY_RESULTS;
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
    scope: &WorldScope,
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
        .port_entity_record(rtxn, &actor.entity_ref())?
        .ok_or(Error::EntityNotFound)?;
    crate::provenance::validate_actor_class(raw.entity_type, actor.actor_class())?;
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
pub(crate) fn resolve_world_authority(
    store: &Store,
    rtxn: &RoTxn<'_>,
    selection: &ActiveWorldSelection,
    at: u64,
) -> Result<ResolvedWorldAuthority> {
    resolve_world_authority_admitting(store, rtxn, selection, at, &|_, _| Ok(true))
}

/// [`resolve_world_authority`] over only the rows `admit` keeps, so a caller
/// holding the authority fold can drop causally quarantined grants.
fn resolve_world_authority_admitting(
    store: &Store,
    rtxn: &RoTxn<'_>,
    selection: &ActiveWorldSelection,
    at: u64,
    admit: &RowAdmission<'_>,
) -> Result<ResolvedWorldAuthority> {
    let rows = world_access_rows(store, rtxn, &selection.agent_ref, at, admit)?;

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

/// A row filter for the authority resolver; `Ok(false)` drops the row.
pub(crate) type RowAdmission<'a> = dyn Fn(&EntityId, &ClaimBody) -> Result<bool> + 'a;

/// Grant postings read in one pass before an actor-local scan takes over.
const GRANT_POSTING_SCAN: usize = 10_000;

/// Which actors world-access law governs. Any ALLOWED-SET row ever written
/// about an actor puts it under that law, and the actor stays under it after
/// its last grant closes: losing a grant never falls back to base reality.
pub(crate) struct WorldGrantIndex {
    /// `None` when the vault holds more grant rows than one pass reads.
    governed: Option<std::collections::BTreeSet<EntityId>>,
}

impl WorldGrantIndex {
    /// One pass over the grant predicate's postings.
    pub(crate) fn read(store: &Store, rtxn: &RoTxn<'_>) -> Result<Self> {
        let ids = match crate::claim::claim_ids_for_predicate_bounded_in_txn(
            store,
            rtxn,
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            GRANT_POSTING_SCAN,
        ) {
            Ok(ids) => ids,
            Err(Error::IndexOverflow(_)) => return Ok(Self { governed: None }),
            Err(error) => return Err(error),
        };
        let mut governed = std::collections::BTreeSet::new();
        for id in ids {
            if let Some(subject) = grant_subject(store, rtxn, &id)? {
                governed.insert(subject);
            }
        }
        Ok(Self {
            governed: Some(governed),
        })
    }

    fn governs(&self, store: &Store, rtxn: &RoTxn<'_>, actor: EntityId) -> Result<bool> {
        if let Some(governed) = &self.governed {
            return Ok(governed.contains(&actor));
        }
        for (scanned, entry) in store
            .port_edges(
                rtxn,
                &actor,
                crate::ports::EdgeDirection::In,
                Some(EdgeKind::ClaimOf),
                None,
            )?
            .enumerate()
        {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("world access authority claims"));
            }
            if grant_subject(store, rtxn, &entry?.target)? == Some(actor) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// The subject of an ALLOWED-SET row, whatever its state.
fn grant_subject(store: &Store, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<EntityId>> {
    let Some(raw) = store.port_entity_record(rtxn, id)? else {
        return Ok(None);
    };
    if raw.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let body = crate::claim::decode_claim_body(&raw.body, true)?;
    Ok(match body.subject {
        ClaimSubject::Entity(subject) if body.predicate == PREDICATE_WORLD_ACCESS_ALLOWED_SET => {
            Some(subject)
        }
        _ => None,
    })
}

/// The worlds `actor` reads when a request names none (ARCH-0022): base plus
/// the active world. An actor under world-access law reads its resolved
/// DEFAULT-SUBSET, which a guest may write without base, or with no default,
/// base reality only while an in-force grant holds base. An actor no grant
/// was ever written about reads base reality. `admit` drops rows the caller's
/// authority snapshot quarantines.
pub(crate) fn reading_default(
    store: &Store,
    rtxn: &RoTxn<'_>,
    grants: &WorldGrantIndex,
    admit: &RowAdmission<'_>,
    actor: EntityId,
    at: u64,
) -> Result<WorldAuthoritySet> {
    if !grants.governs(store, rtxn, actor)? {
        return WorldAuthoritySet::new(true, []);
    }
    let selection = ActiveWorldSelection {
        agent_ref: actor,
        selected: None,
    };
    let resolved = resolve_world_authority_admitting(store, rtxn, &selection, at, admit)?;
    if resolved.default_claim_id.is_some() {
        return Ok(resolved.default_subset);
    }
    WorldAuthoritySet::new(resolved.allowed_set.include_base(), [])
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
    admit: &RowAdmission<'_>,
) -> Result<Vec<WorldAccessRow>> {
    let mut rows = Vec::new();
    for (scanned, entry) in store
        .port_edges(
            rtxn,
            agent_ref,
            crate::ports::EdgeDirection::In,
            Some(EdgeKind::ClaimOf),
            None,
        )?
        .enumerate()
    {
        if scanned >= MAX_EDGE_QUERY_RESULTS {
            return Err(Error::IndexOverflow("world access authority claims"));
        }
        let edge_row = entry?;
        let claim_id = edge_row.target;
        let Some(raw) = store.port_entity_record(rtxn, &claim_id)? else {
            continue;
        };

        if raw.entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        let body = crate::claim::decode_claim_body(&raw.body, true)?;
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
        if !admit(&claim_id, &body)? {
            continue;
        }
        rows.push(WorldAccessRow {
            id: claim_id,
            body,
            learned_at: raw.learned_at,
        });
    }
    Ok(rows)
}
