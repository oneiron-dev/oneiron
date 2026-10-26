//! Per-turn world authority, bound to the host's executing principal.

use crate::ports::EntityStoreRead;
use heed::RoTxn;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, claim_surfaceable,
    session_claim_producer,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
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
    let mut held_allowed: Option<WorldAuthoritySet> = None;
    let mut allowed_claim_ids = Vec::new();
    for row in &rows {
        if row.body.predicate != PREDICATE_WORLD_ACCESS_ALLOWED_SET
            || !owner_granted_allowed_row(&row.body)
        {
            continue;
        }
        let granted = decode_world_access_claim_value(&row.body)?;
        let fold = if row.held {
            &mut held_allowed
        } else {
            &mut folded_allowed
        };
        *fold = Some(match fold.take() {
            None => granted,
            Some(folded) => folded.meet(&granted),
        });
        allowed_claim_ids.push(row.id);
    }
    // No qualifying owner row is the EMPTY authority, never `All`. A held
    // grant only narrows a settled one; alone it grants nothing.
    let allowed_set = match (folded_allowed, held_allowed) {
        (Some(settled), Some(held)) => settled.meet(&held),
        (Some(settled), None) => settled,
        (None, _) => {
            allowed_claim_ids.clear();
            WorldAuthoritySet::default()
        }
    };

    let mut newest_default: Option<(&WorldAccessRow, WorldAuthoritySet)> = None;
    let mut newest_settled_default: Option<(&WorldAccessRow, WorldAuthoritySet)> = None;
    for row in &rows {
        if row.body.predicate != PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET {
            continue;
        }
        // Closed rows were removed before this loop. Every remaining default
        // must decode, even when a newer active row wins precedence.
        let subset = decode_world_access_claim_value(&row.body)?;
        if !row.held && newer_default(row, newest_settled_default.as_ref()) {
            newest_settled_default = Some((row, subset.clone()));
        }
        if newer_default(row, newest_default.as_ref()) {
            newest_default = Some((row, subset));
        }
    }
    // A held newest default only narrows the settled one, and with no settled
    // default it leaves nothing to read.
    let (default_subset, default_claim_id) = match newest_default {
        Some((row, held)) if row.held => (
            newest_settled_default.map_or_else(WorldAuthoritySet::default, |(_, settled)| {
                settled.meet(&held)
            }),
            Some(row.id),
        ),
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

/// Grant rows whose subjects one pass decodes up front; past it, each actor
/// walks the rows for itself.
#[cfg(not(test))]
const GRANT_POSTING_SCAN: usize = 10_000;
#[cfg(test)]
const GRANT_POSTING_SCAN: usize = 2;

/// Which actors world-access law governs. An owner's ALLOWED-SET grant about
/// an actor puts it under that law, and the actor stays under it after the
/// grant closes or loses its authority: losing a grant never falls back to
/// base reality. A row the owner never granted governs nobody.
///
/// Read from the grant predicate's postings, which co-commit with the grant
/// rows, never from `claim_of` edges: an edge can go while its row stays, and
/// a missing edge is not permission to read base. Every posting is read,
/// however many (FIX 8659).
pub(crate) struct WorldGrantIndex {
    /// Every grant row under the predicate.
    rows: Vec<EntityId>,
    /// The rows' subjects, decoded up front while one pass covers them.
    governed: Option<std::collections::BTreeSet<EntityId>>,
}

impl WorldGrantIndex {
    pub(crate) fn read(store: &Store, rtxn: &RoTxn<'_>) -> Result<Self> {
        let rows = crate::claim::claim_ids_for_predicate_in_txn(
            store,
            rtxn,
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        )?;
        if rows.len() > GRANT_POSTING_SCAN {
            return Ok(Self {
                rows,
                governed: None,
            });
        }
        let mut governed = std::collections::BTreeSet::new();
        for id in &rows {
            if let Some(subject) = grant_subject(store, rtxn, id)? {
                governed.insert(subject);
            }
        }
        Ok(Self {
            rows,
            governed: Some(governed),
        })
    }

    fn governs(&self, store: &Store, rtxn: &RoTxn<'_>, actor: EntityId) -> Result<bool> {
        if let Some(governed) = &self.governed {
            return Ok(governed.contains(&actor));
        }
        for id in &self.rows {
            if grant_subject(store, rtxn, id)? == Some(actor) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// The subject of an owner's ALLOWED-SET grant, open, closed or since
/// stripped of its authority.
fn grant_subject(store: &Store, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<EntityId>> {
    let Some(raw) = store.port_entity_record(rtxn, id)? else {
        return Ok(None);
    };
    if raw.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let body = crate::claim::decode_claim_body(&raw.body, true)?;
    let ClaimSubject::Entity(subject) = body.subject else {
        return Ok(None);
    };
    if body.predicate != PREDICATE_WORLD_ACCESS_ALLOWED_SET || !owner_granted_allowed_row(&body) {
        return Ok(None);
    }
    Ok(Some(subject))
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

impl crate::Vault {
    /// The three world tiers a board shows for `actor`, folded now with no
    /// retrieval run. The tiers are the ones its planner reads: an actor no
    /// owner grant ever governed, or a caller with no entity principal, reads
    /// base reality only (ARCH-0022), so its allowed, default and active tiers
    /// are base. A governed actor folds its owner grants and its own default,
    /// over the rows its authority snapshot admits; with no selection and no
    /// stored default it reads base only while its grant holds base. A
    /// `selected` set outside the allowed tier is refused, never widened.
    pub fn board_world_authority(
        &self,
        actor: Option<EntityId>,
        selected: Option<WorldAuthoritySet>,
    ) -> Result<ResolvedWorldAuthority> {
        let rtxn = self.store.env.read_txn()?;
        let at = self.store.clock.now_recorded_at();
        let grants = WorldGrantIndex::read(&self.store, &rtxn)?;
        let governed = match actor {
            Some(actor) => grants.governs(&self.store, &rtxn, actor)?.then_some(actor),
            None => None,
        };
        let Some(actor) = governed else {
            let base = WorldAuthoritySet::new(true, [])?;
            let active_set = selected.unwrap_or_else(|| base.clone());
            if !active_set.is_subset_of(&base) {
                return Err(Error::InvalidConfig(
                    "requested world selection is outside base reality, the only world an \
                     ungoverned actor reads"
                        .to_owned(),
                ));
            }
            return Ok(ResolvedWorldAuthority {
                allowed_set: base.clone(),
                default_subset: base,
                active_set,
                allowed_claim_ids: Vec::new(),
                default_claim_id: None,
            });
        };
        // Folded once, and only for a governed actor: a grant row the
        // authority fold quarantines never counts.
        let fold = std::cell::OnceCell::new();
        let admit = |id: &EntityId, body: &ClaimBody| -> Result<bool> {
            if fold.get().is_none() {
                let _ = fold.set(self.authority_fold_readonly_in_txn(&rtxn)?);
            }
            let fold = fold.get().expect("authority fold was just set");
            crate::authority::claim_causal_admitted(&self.store, &rtxn, fold, id, body)
        };
        let explicit = selected.is_some();
        let selection = ActiveWorldSelection {
            agent_ref: actor,
            selected,
        };
        let mut resolved =
            resolve_world_authority_admitting(&self.store, &rtxn, &selection, at, &admit)?;
        if !explicit && resolved.default_claim_id.is_none() {
            resolved.active_set = WorldAuthoritySet::new(resolved.allowed_set.include_base(), [])?;
        }
        Ok(resolved)
    }
}

/// One world-access authority CLAIM row that is in force for this resolution.
struct WorldAccessRow {
    id: EntityId,
    body: ClaimBody,
    learned_at: u64,
    /// Awaiting its owner's critical confirm: it may narrow, never widen.
    held: bool,
}

/// Bitemporal precedence key for DEFAULT-SUBSET rows: valid-time first, then
/// the learned-at envelope, then the entity id as the total-order tiebreak, so
/// two rows can never tie and the winner does not depend on scan order.
fn default_row_precedence(row: &WorldAccessRow) -> (u64, u64, EntityId) {
    (row.body.valid_from.unwrap_or(0), row.learned_at, row.id)
}

/// Whether `row` wins DEFAULT-SUBSET precedence over `current`.
fn newer_default(
    row: &WorldAccessRow,
    current: Option<&(&WorldAccessRow, WorldAuthoritySet)>,
) -> bool {
    current.is_none_or(|(prior, _)| default_row_precedence(row) > default_row_precedence(prior))
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

/// Reads the agent's in-force world-access rows from the two grant
/// predicates' postings, which co-commit with the rows, never from `claim_of`
/// adjacency: an edge can go while its row stays, and dropping one narrowing
/// row's edge must not widen the fold. A deleted row grants nothing, even
/// while an unapplied delete leaves its body stored.
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
    for predicate in [
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
    ] {
        crate::claim::for_each_claim_id_for_predicate_in_txn(store, rtxn, predicate, |claim_id| {
            let Some(raw) = store.port_entity_record(rtxn, &claim_id)? else {
                return Ok(());
            };
            if raw.entity_type != ENTITY_TYPE_CLAIM
                || !crate::vault::live_entity_row_in_txn(store, rtxn, &claim_id)?.is_live()
            {
                return Ok(());
            }
            let body = crate::claim::decode_claim_body(&raw.body, true)?;
            if body.predicate != predicate {
                return Ok(());
            }
            if body.subject != ClaimSubject::Entity(*agent_ref)
                || !claim_surfaceable(&body)
                || !world_access_row_in_force(&body, at)
            {
                return Ok(());
            }
            if body.predicate == PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET
                && session_claim_producer(&body) != Some(*agent_ref)
            {
                return Ok(());
            }
            if !admit(&claim_id, &body)? {
                return Ok(());
            }
            let held = !crate::gate::claim_critical_confirm_settled_in_txn(store, rtxn, &claim_id)?;
            rows.push(WorldAccessRow {
                id: claim_id,
                body,
                learned_at: raw.learned_at,
                held,
            });
            Ok(())
        })?;
    }
    Ok(rows)
}
