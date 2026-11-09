//! The head an approved proposal supersedes (e2e MEMORY-01; ARCH-0040
//! `mcp:5`, ARCH-0003 conflictSet): the newest standing claim on the
//! proposal's conflict set.
//!
//! The set is the key an Auto write replaces on: subject, predicate, world,
//! relationship and exact scope, with `value.question_id` for the declared
//! multi-cardinality predicates. Scopes compare by their canonical bytes, so
//! two binary facet or project ids never read as one. A set-cardinality
//! predicate keys on the question its scoped `topic_key` names, never on its
//! answer, so a changed answer to the same question replaces the old one and
//! an answer to another question stands beside it. Without a `topic_key` it
//! has no conflict set.
//!
//! A proposal whose lifecycle a feature owns proposes no supersession of a
//! memory head: an engine-generated claim (a plugin install, a consolidation
//! finding, which vetting and their own doors settle), a reserved predicate,
//! and a task proposal, whose approval lands its TASK.

use super::*;

/// The scope field that names a set-cardinality claim's question, as the
/// extractor supplies it (`dreamer_consolidation::conflict::topic_key`).
const TOPIC_KEY_SCOPE_FIELD: &str = "topic_key";

/// The predicate namespace of task proposals (`tasks.create`, `tasks.cancel`,
/// `tasks.brief`), which `task_verb` settles into TASK rows.
const TASK_PROPOSAL_NAMESPACE: &str = "tasks";

/// A standing claim an approval closes, as its review read it.
pub(super) struct ConflictHead {
    pub(super) id: EntityId,
    pub(super) body: ClaimBody,
}

/// The newest standing claim other than `id` on the conflict set of
/// `proposal`, the body stored at `id`, in `txn`. A head the proposal may not
/// close is passed over: a stated one beside an observed preference (OF-023),
/// and user-stated truth beside a generated claim.
pub(super) fn conflict_head_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    proposal: &ClaimBody,
) -> crate::Result<Option<ConflictHead>> {
    let ClaimSubject::Entity(subject) = proposal.subject else {
        return Ok(None);
    };
    if crate::claim::claim_generated_origin(proposal)
        || crate::claim::is_reserved_predicate(&proposal.predicate)
        || proposal.predicate.split('.').next() == Some(TASK_PROPOSAL_NAMESPACE)
        || (SET_CARDINALITY_PREDICATES.contains(&proposal.predicate.as_str())
            && !has_topic_key(proposal.scope.as_ref()))
    {
        return Ok(None);
    }
    let scope = canonical_scope(proposal.scope.as_ref())?;
    let question = MULTI_CARDINALITY_PREDICATES
        .contains(&proposal.predicate.as_str())
        .then(|| question_id(&proposal.value));
    let beside_stated = crate::claim::is_observed_preference(proposal.source, &proposal.predicate);
    let mut head: Option<ConflictHead> = None;
    for candidate in vault.claims_for_subject_in_txn(txn, &subject)? {
        // The newest id (UUIDv7 order) is the head, as for an Auto write.
        if candidate == *id || head.as_ref().is_some_and(|head| head.id >= candidate) {
            continue;
        }
        let Some(body) = vault.get_claim_in_txn(txn, &candidate)? else {
            continue;
        };
        if body.lifecycle != ClaimLifecycleStatus::Active
            || !matches!(
                body.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
            || body.predicate != proposal.predicate
            || body.world != proposal.world
            || body.rel != proposal.rel
            || canonical_scope(body.scope.as_ref())? != scope
            || question
                .as_ref()
                .is_some_and(|question| *question != question_id(&body.value))
            || (beside_stated && body.source == Some(ClaimSource::UserStated))
            || crate::Vault::require_source_trust_supersession_rights(proposal, &body).is_err()
        {
            continue;
        }
        head = Some(ConflictHead {
            id: candidate,
            body,
        });
    }
    Ok(head)
}

/// `scope`'s canonical bytes: map order does not count, and every value,
/// binary ones included, keeps its identity.
fn canonical_scope(scope: Option<&Value>) -> crate::Result<Option<Vec<u8>>> {
    scope
        .map(crate::dreamer_consolidation::topic_key_canonical_bytes)
        .transpose()
}

/// Whether `scope` names a question: a `topic_key` that is not nil.
fn has_topic_key(scope: Option<&Value>) -> bool {
    let Some(Value::Map(fields)) = scope else {
        return false;
    };
    fields
        .iter()
        .any(|(key, value)| key.as_str() == Some(TOPIC_KEY_SCOPE_FIELD) && !value.is_nil())
}

/// The `question_id` of a multi-cardinality claim's value.
fn question_id(value: &Value) -> Option<serde_json::Value> {
    msgpack_value_to_json(value)
        .get(MULTI_CARDINALITY_VALUE_KEY)
        .cloned()
}
