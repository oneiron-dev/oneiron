//! The head an approved proposal supersedes (e2e MEMORY-01; ARCH-0040
//! `mcp:5`, ARCH-0003 conflictSet): the newest standing claim on the
//! proposal's conflict set.
//!
//! The set is the key an Auto write replaces on: subject, predicate, world,
//! relationship and exact scope, with `value.question_id` for the declared
//! multi-cardinality predicates. Scopes compare by their canonical bytes, so
//! two binary facet or project ids never read as one. The head must also
//! carry the proposal's scope stamps, the facet and project each was born
//! in, as an OF-023 conflict marker's peer must: a head in another facet is
//! another audience's, and an approval here never closes it. A set-cardinality
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
pub(super) const TASK_PROPOSAL_NAMESPACE: &str = "tasks";

/// A standing claim an approval closes, as its review read it.
pub(super) struct ConflictHead {
    pub(super) id: EntityId,
    pub(super) body: ClaimBody,
}

/// The conflict set a proposal keys on when it proposes to supersede a memory
/// head: the one filter `conflict_head_in_txn` and `ConflictHeadIndex` both
/// apply, so both name the same head.
struct ProposalConflictSet<'a> {
    subject: EntityId,
    proposal: &'a ClaimBody,
    scope: Option<Vec<u8>>,
    question: Option<Option<serde_json::Value>>,
    beside_stated: bool,
}

/// The conflict set of `proposal`; `None` when it proposes no supersession.
fn proposal_conflict_set(proposal: &ClaimBody) -> crate::Result<Option<ProposalConflictSet<'_>>> {
    let ClaimSubject::Entity(subject) = proposal.subject else {
        return Ok(None);
    };
    if crate::claim::claim_generated_origin(proposal)
        || crate::claim::is_reserved_predicate(&proposal.predicate)
        || proposal.predicate.split('.').next() == Some(TASK_PROPOSAL_NAMESPACE)
        || (declared_cardinality(&proposal.predicate) == ClaimCardinality::Set
            && !has_topic_key(proposal.scope.as_ref()))
    {
        return Ok(None);
    }
    Ok(Some(ProposalConflictSet {
        subject,
        proposal,
        scope: canonical_scope(proposal.scope.as_ref())?,
        question: MULTI_CARDINALITY_PREDICATES
            .contains(&proposal.predicate.as_str())
            .then(|| question_id(&proposal.value)),
        beside_stated: crate::claim::is_observed_preference(proposal.source, &proposal.predicate),
    }))
}

impl ProposalConflictSet<'_> {
    /// Whether `body`, a claim about the set's subject, is a standing claim on
    /// this conflict set that the proposal may close.
    fn admits(&self, body: &ClaimBody) -> crate::Result<bool> {
        let proposal = self.proposal;
        Ok(body.lifecycle == ClaimLifecycleStatus::Active
            && matches!(
                body.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
            && body.predicate == proposal.predicate
            && body.world == proposal.world
            && body.rel == proposal.rel
            && canonical_scope(body.scope.as_ref())? == self.scope
            && body.scope_facet == proposal.scope_facet
            && body.scope_project == proposal.scope_project
            && self
                .question
                .as_ref()
                .is_none_or(|question| *question == question_id(&body.value))
            && (!self.beside_stated || body.source != Some(ClaimSource::UserStated))
            && crate::Vault::require_source_trust_supersession_rights(proposal, body).is_ok())
    }
}

/// The newest standing claim other than `id` on the conflict set of
/// `proposal`, the body stored at `id`, in `txn`, born in the proposal's facet
/// and project. A head the proposal may not
/// close is passed over: a stated one beside an observed preference (OF-023),
/// and user-stated truth beside a generated claim.
pub(super) fn conflict_head_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    proposal: &ClaimBody,
) -> crate::Result<Option<ConflictHead>> {
    let Some(set) = proposal_conflict_set(proposal)? else {
        return Ok(None);
    };
    let mut head: Option<ConflictHead> = None;
    for candidate in vault.claims_for_subject_in_txn(txn, &set.subject)? {
        // The newest id (UUIDv7 order) is the head, as for an Auto write.
        if candidate == *id || head.as_ref().is_some_and(|head| head.id >= candidate) {
            continue;
        }
        let Some(body) = vault.get_claim_in_txn(txn, &candidate)? else {
            continue;
        };
        if set.admits(&body)? {
            head = Some(ConflictHead {
                id: candidate,
                body,
            });
        }
    }
    Ok(head)
}

/// The conflict heads of many proposals read in one txn: each subject's
/// standing claims are read once, by predicate, newest first, so a restore
/// group of N claims about one person costs one read of that person's claims,
/// not N (R6, RULING 02:26 13 Nov). `head` names the head
/// `conflict_head_in_txn` names in the same txn. A write between two calls
/// could add or close a head, so a txn that writes passes each claim it
/// settled to `record_settled`, and calls `clear` after a write that may
/// change any other claim.
#[derive(Default)]
pub(in crate::memory) struct ConflictHeadIndex {
    subjects: std::collections::HashMap<EntityId, StandingClaims>,
}

/// One subject's standing claims, by predicate, newest first.
type StandingClaims = std::collections::HashMap<String, Vec<(EntityId, ClaimBody)>>;

impl ConflictHeadIndex {
    /// The head `conflict_head_in_txn(vault, txn, id, proposal)` returns,
    /// reading the proposal's subject at its first use.
    pub(super) fn head(
        &mut self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        proposal: &ClaimBody,
    ) -> crate::Result<Option<ConflictHead>> {
        let Some(set) = proposal_conflict_set(proposal)? else {
            return Ok(None);
        };
        let standing = match self.subjects.entry(set.subject) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(standing_claims_in_txn(vault, txn, &set.subject)?)
            }
        };
        for (candidate, body) in standing.get(&proposal.predicate).into_iter().flatten() {
            if candidate != id && set.admits(body)? {
                return Ok(Some(ConflictHead {
                    id: *candidate,
                    body: body.clone(),
                }));
            }
        }
        Ok(None)
    }

    /// The id of the head `head` returns.
    pub(super) fn head_id(
        &mut self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        proposal: &ClaimBody,
    ) -> crate::Result<Option<EntityId>> {
        Ok(self.head(vault, txn, id, proposal)?.map(|head| head.id))
    }

    /// Takes in the claim `id` as `txn` stores it after a write in `txn`
    /// settled it: it joins its subject's standing claims or leaves them. A
    /// settlement keeps the claim's subject and predicate. A subject this
    /// index has not read yet is read at its first use, so it needs nothing.
    /// The claims about `id` itself change with it (an approval of a MACHINE
    /// claim writes its history claims, and a claim Put deletes its lexical
    /// query hints), so `id` read as a subject is read again at its next use.
    pub(super) fn record_settled(
        &mut self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> crate::Result<()> {
        self.subjects.remove(id);
        let Some(body) = vault.get_claim_in_txn(txn, id)? else {
            for standing in self.subjects.values_mut() {
                for claims in standing.values_mut() {
                    claims.retain(|(candidate, _)| candidate != id);
                }
            }
            return Ok(());
        };
        let ClaimSubject::Entity(subject) = body.subject else {
            return Ok(());
        };
        let Some(standing) = self.subjects.get_mut(&subject) else {
            return Ok(());
        };
        let claims = standing.entry(body.predicate.clone()).or_default();
        claims.retain(|(candidate, _)| candidate != id);
        if is_standing(&body) {
            // Newest first, as `standing_claims_in_txn` orders them.
            let at = claims.partition_point(|(candidate, _)| candidate > id);
            claims.insert(at, (*id, body));
        }
        Ok(())
    }

    /// Forgets every subject read, after a write that may have changed a
    /// claim other than the one it settled.
    pub(super) fn clear(&mut self) {
        self.subjects.clear();
    }
}

/// Whether `body` is a standing claim: Active, and Auto or Approved.
fn is_standing(body: &ClaimBody) -> bool {
    body.lifecycle == ClaimLifecycleStatus::Active
        && matches!(
            body.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
}

/// The Active, Auto or Approved claims about `subject` in `txn`, by
/// predicate, newest first.
fn standing_claims_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> crate::Result<StandingClaims> {
    let mut standing = StandingClaims::new();
    for candidate in vault.claims_for_subject_in_txn(txn, subject)? {
        let Some(body) = vault.get_claim_in_txn(txn, &candidate)? else {
            continue;
        };
        if is_standing(&body) {
            standing
                .entry(body.predicate.clone())
                .or_default()
                .push((candidate, body));
        }
    }
    for claims in standing.values_mut() {
        claims.sort_unstable_by_key(|claim| std::cmp::Reverse(claim.0));
    }
    Ok(standing)
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
