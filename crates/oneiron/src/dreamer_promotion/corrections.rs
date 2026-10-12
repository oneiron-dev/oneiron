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
        Ok(()) => Some(prior),
        // The policy protects it; the owner's run review holds it.
        Err(Error::Gate(_)) => None,
        Err(error) => {
            tracing::warn!(%error, replacement = %replacement.to_hex(), "a staged replacement was not granted; it stays in the owner's review");
            None
        }
    }
}

/// The prior `head` closed, when `head` is a granted replacement.
pub(super) fn superseded_prior(vault: &Vault, head: EntityId) -> Result<Option<EntityId>> {
    Ok(vault
        .edges_out(&head)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Supersedes)
        .map(|edge| edge.target))
}

/// Closes each open conflict on `replacement`'s subject that named `prior`,
/// citing `evidence` and recording `replacement` as its resolution. A marker
/// already resolved is left as it is, so a replay closes nothing twice.
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
            resolved.extend(ids_at(&claim.value, "open_marker"));
        } else if claim.predicate == PREDICATE_CONFLICT_OPEN
            && claim.lifecycle == ClaimLifecycleStatus::Active
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
