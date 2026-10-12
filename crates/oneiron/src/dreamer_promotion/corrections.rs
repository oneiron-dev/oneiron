//! A correction the Dreamer stages, settled in the pass that staged it.
//!
//! A replacement takes its Auto grant through the deferred door when the
//! vault's policy allows it; the grant closes its named prior in the same
//! transaction. One the policy protects (critical or attributed truth, a Gate
//! that pends, the Generated-over-UserStated guard) is never applied here: it
//! stays Proposed in the owner's run review. Once the prior is closed, each
//! open conflict that named it closes through the conflict-close door.
use std::collections::BTreeSet;

use super::*;
use crate::claim::{ClaimLifecycleStatus, PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED};
use crate::dreamer_consolidation::close_persistent_conflict;
use crate::dreamer_consolidation::resources::ConsolidationFence;
use crate::edge::EdgeKind;

/// Grants `replacement` when the policy allows it, returning the prior the
/// grant closed. Anything else leaves it Proposed for the owner.
pub(super) fn grant_allowed_replacement(
    vault: &Vault,
    run: &DreamerRunContext,
    fence: &ConsolidationFence,
    replacement: EntityId,
    checker: Option<&BoundedAutoChecker>,
) -> Option<EntityId> {
    let prior = match vault.pending_claim_supersession(&replacement) {
        Ok(prior) => prior?,
        Err(error) => {
            tracing::warn!(%error, replacement = %replacement.to_hex(), "a staged replacement could not be read");
            return None;
        }
    };
    match vault.grant_deferred_claim_auto_after(&replacement, run.now_ms, checker, |txn| {
        fence.validate_in_txn(vault, txn)
    }) {
        Ok(()) => {
            fence.closed_by_this_write(prior);
            Some(prior)
        }
        // The policy protects it; the owner's run review holds it.
        Err(Error::Gate(error)) => {
            tracing::info!(target: "oneiron::dreamer", %error, replacement = %replacement.to_hex(), "a staged replacement is held for the owner");
            None
        }
        Err(error) => {
            tracing::warn!(%error, replacement = %replacement.to_hex(), "a staged replacement was not granted; it stays in the owner's review");
            None
        }
    }
}

/// The prior this attempt's own correction closed, when an earlier pass
/// already landed it with its grant and died before the attempt completed:
/// the claim at the candidate's id says what the candidate says, is Auto,
/// and supersedes a prior. A replay meets it again with no prior left to
/// route to, so it is not written twice.
pub(super) fn granted_correction(
    vault: &Vault,
    candidate: &PromotionCandidate,
) -> Result<Option<EntityId>> {
    if vault.get_entity_type(&candidate.claim_id)? != Some(ENTITY_TYPE_CLAIM) {
        return Ok(None);
    }
    let Some(stored) = vault.get_claim(&candidate.claim_id)? else {
        return Ok(None);
    };
    if stored.approval != ClaimApprovalStatus::Auto
        || !crate::dreamer_consolidation::reviewed::names_candidate(candidate, &stored)?
    {
        return Ok(None);
    }
    superseded_prior(vault, candidate.claim_id)
}

/// The prior `head` closed, when `head` is a granted replacement.
pub(super) fn superseded_prior(vault: &Vault, head: EntityId) -> Result<Option<EntityId>> {
    Ok(vault
        .edges_out(&head)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Supersedes)
        .map(|edge| edge.target))
}

/// Closes each open conflict on `replacement`'s subject that named `prior`
/// on `replacement`'s own world, facet, relationship and project, citing
/// `evidence` and recording `replacement` as its resolution. A marker a
/// standing resolution already answers is left as it is, so a replay closes
/// nothing twice; a proposed, refused, closed or stale one answers nothing.
pub(super) fn close_conflicts_naming(
    vault: &Vault,
    run: &DreamerRunContext,
    replacement: EntityId,
    prior: EntityId,
    evidence: &[EntityId],
) -> Result<()> {
    let Some(body) = vault.get_claim(&replacement)? else {
        return Ok(());
    };
    let crate::claim::ClaimSubject::Entity(subject) = body.subject else {
        return Ok(());
    };
    let mut open = Vec::new();
    let mut resolved = BTreeSet::new();
    for id in vault.claims_for_subject(&subject)? {
        let Some(claim) = vault.get_claim(&id)? else {
            continue;
        };
        if claim.predicate == PREDICATE_CONFLICT_RESOLVED {
            if crate::claim::claim_surfaceable(&claim) {
                resolved.extend(ids_at(&claim.value, "open_marker"));
            }
        } else if claim.predicate == PREDICATE_CONFLICT_OPEN
            && claim.lifecycle == ClaimLifecycleStatus::Active
            && same_axes(&claim, &body)
            && ids_at(&claim.value, "prior_head")
                .chain(ids_at(&claim.value, "prior_heads"))
                .any(|named| named == prior)
        {
            open.push(id);
        }
    }
    let resolution = Value::Map(vec![(
        Value::from("superseded_by"),
        Value::Binary(replacement.as_bytes().to_vec()),
    )]);
    for marker in open.into_iter().filter(|marker| !resolved.contains(marker)) {
        // A marker this close cannot land stays open, and in the owner's
        // view; the correction itself has landed.
        let reason = match close_persistent_conflict(
            vault,
            run,
            marker,
            resolution.clone(),
            evidence.to_vec(),
        ) {
            Ok(closed) => closed.rejected.into_iter().next().map(|(_, reason)| reason),
            Err(error) => Some(error.to_string()),
        };
        if let Some(reason) = reason {
            tracing::warn!(%reason, marker = %marker.to_hex(), "an open conflict the correction answered stayed open");
        }
    }
    Ok(())
}

/// Whether `marker` asks its question on `replacement`'s axes. A marker in
/// another world, facet, relationship or project is another branch's, and a
/// facet that does not read is no match.
fn same_axes(marker: &crate::ClaimBody, replacement: &crate::ClaimBody) -> bool {
    let facet = |body: &crate::ClaimBody| {
        crate::dreamer_consolidation::resources::claim_facet(body.scope.as_ref())
    };
    marker.world == replacement.world
        && marker.rel == replacement.rel
        && marker.scope_project == replacement.scope_project
        && matches!((facet(marker), facet(replacement)), (Ok(a), Ok(b)) if a == b)
}

/// The ids under `key` in a claim value map: one binary id, or an array.
fn ids_at<'v>(value: &'v Value, key: &str) -> impl Iterator<Item = EntityId> + 'v {
    let found = match value {
        Value::Map(rows) => rows
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, value)| value),
        _ => None,
    };
    let values: &'v [Value] = match found {
        Some(Value::Array(values)) => values,
        Some(value) => std::slice::from_ref(value),
        None => &[],
    };
    values.iter().filter_map(|value| match value {
        Value::Binary(bytes) => <[u8; 16]>::try_from(bytes.as_slice())
            .ok()
            .and_then(|bytes| EntityId::from_bytes(bytes).ok()),
        _ => None,
    })
}
