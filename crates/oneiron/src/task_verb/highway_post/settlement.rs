//! Approved post and brief proposal settlement.
//! Entry: `settle_task_proposal_in_txn`.
//! Post vocabulary stays in `highway_post`.

use super::*;

/// The settlement continuation of the two approval doors (OF-220).
///
/// Called in the transaction that set a claim's approval, after it did. A
/// claim that is not an approved `tasks.create` post, `tasks.brief`
/// revision or `tasks.cancel` proposal is left alone. An approved post
/// lands its TASK under the id the claim derives, so a second settlement
/// finds it and changes nothing; an approved revision lands as the TASK's
/// next brief revision; an approved cancel stops its target (FIX 8946).
/// Approval is the door's, never the body's: the body's own approval
/// decides nothing, and the opener never settles its own proposal
/// (DEC-0006).
///
/// A post or revision refusal fails the approving transaction, so the
/// proposal stays pending and the approver is told why. A cancel that does
/// not land is logged and fails nothing.
pub(crate) fn settle_task_proposal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: EntityId,
    approver: Option<WriteActor>,
    now: u64,
) -> Result<()> {
    let Some(claim) = vault.get_claim_in_txn(wtxn, &claim_id)? else {
        return Ok(());
    };
    if claim.approval != ClaimApprovalStatus::Approved {
        return Ok(());
    }
    // FIX 5993: an approved commitment series projects from here.
    vault.index_consented_commitment_series_in_txn(wtxn, &claim, &claim_id, now)?;
    if claim.predicate == TASK_CREATE_PROPOSAL_PREDICATE {
        settle_post(vault, wtxn, claim_id, &claim, approver, now)
    } else if claim.predicate == TASK_BRIEF_PROPOSAL_PREDICATE {
        settle_brief(vault, wtxn, &claim, approver, now)
    } else if claim.predicate == TASK_CANCEL_PROPOSAL_PREDICATE {
        crate::task_verb::cancel_settlement::settle_cancel_in_txn(
            vault, wtxn, &claim, approver, now,
        );
        Ok(())
    } else {
        Ok(())
    }
}

/// The proposer of a settled claim, refused when it is the approver.
pub(in crate::task_verb) fn proposer_of(
    claim: &ClaimBody,
    approver: Option<WriteActor>,
) -> Result<EntityId> {
    let proposer = crate::claim::session_claim_producer(claim)
        .ok_or(Error::InvariantViolation("task proposal names no producer"))?;
    if approver.is_some_and(|approver| approver.entity_ref() == proposer) {
        return Err(Error::InvariantViolation(
            "a proposal's opener never settles its own proposal",
        ));
    }
    Ok(proposer)
}

/// The actor class a claim's write envelope stamped into its evidence:
/// immutable, unlike its subject or any approver.
pub(in crate::task_verb) fn envelope_actor_class(claim: &ClaimBody) -> Option<EdgeActorClass> {
    let Value::Map(entries) = claim.evidence.as_ref()? else {
        return None;
    };
    let mut classes = entries.iter().filter(|(key, _)| {
        key.as_str() == Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY)
    });
    let (_, class) = classes.next()?;
    if classes.next().is_some() {
        return None;
    }
    EdgeActorClass::try_from_u8(u8::try_from(class.as_u64()?).ok()?)
}

pub(super) fn class_of(byte: u8) -> Result<EdgeActorClass> {
    EdgeActorClass::try_from_u8(byte).ok_or(Error::Record(
        crate::error::RecordError::InvalidTaskBody("tasks.proposal.actor_class"),
    ))
}

pub(super) fn settle_post(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: EntityId,
    claim: &ClaimBody,
    approver: Option<WriteActor>,
    now: u64,
) -> Result<()> {
    let Value::Map(entries) = &claim.value else {
        return Ok(());
    };
    // A brief-less create proposal carries no post stamp: it lands from
    // its stored create fields.
    let Some(stamp_value) = task_body_optional(entries, TASK_POST_STAMP_KEY)? else {
        return super::proposal_create::settle_create_in_txn(
            vault, wtxn, claim_id, claim, approver, now,
        );
    };
    let stamp: PostStamp = from_value(stamp_value).ok_or(Error::Record(
        crate::error::RecordError::InvalidTaskBody("tasks.proposal.post"),
    ))?;
    let proposer = proposer_of(claim, approver)?;
    let class = class_of(stamp.actor_class)?;
    let task_ref = EntityId::derive(TASK_SETTLE_ID_DOMAIN, &[claim_id.as_bytes()])?;
    if vault.get_raw_in(wtxn, &task_ref)?.is_some() {
        return Ok(());
    }
    // The approved value is what lands: an approver's amendment to the
    // assignee, spec, label, TTL or parent rides through the same keys it was
    // parked under, and the brief through the stamp.
    let assignee = match task_body_optional(entries, "assignee")? {
        Some(value) => decode_task_assignee(value)?,
        None => TaskAssignee::Dreamer,
    };
    let label = task_body_optional(entries, "label")?
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or(Error::Record(
                crate::error::RecordError::InvalidTaskBody("tasks.proposal.label"),
            ))
        })
        .transpose()?;
    let ttl = task_body_optional(entries, "ttl")?
        .map(|value| {
            value
                .as_map()
                .and_then(|ttl| task_body_field(ttl, "deadline_at").ok())
                .and_then(Value::as_u64)
                .map(TaskTtl::at)
                .ok_or(Error::Record(crate::error::RecordError::InvalidTaskBody(
                    "tasks.proposal.ttl",
                )))
        })
        .transpose()?;
    let parent_ref = task_body_optional(entries, "parent_ref")?
        .map(|value| decode_entity_ref(value, "tasks.proposal.parent_ref"))
        .transpose()?;
    let spec = task_body_field(entries, "spec")?.clone();
    let copied = stamp.redo_of.is_some();
    let post = TaskPost {
        intent_key: stamp.intent_key.clone(),
        brief: stamp.brief,
        assignee,
        spec: (spec != Value::Nil).then_some(spec),
        ttl,
        label,
        parent_ref,
    };
    let memory = vault
        .memory(proposer, class)
        .with_birth_position(BirthPosition {
            world: stamp.birth_world,
            facet: stamp.birth_facet,
        });
    // The creator the proposal witnessed, never its approver: approval may
    // outlive the worker's lease, so the route rechecks the stored creator.
    let origin = proposal_origin_in(vault, wtxn, claim_id).map_err(settle_refusal)?;
    memory
        .land_settled_post_in_txn(
            wtxn,
            task_ref,
            &post,
            &post_provenance(&stamp.intent_key, &stamp.request_digest, Some(claim_id)),
            origin.as_ref(),
            now,
            copied,
        )
        .map_err(settle_refusal)?;
    Ok(())
}

pub(super) fn settle_brief(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &ClaimBody,
    approver: Option<WriteActor>,
    now: u64,
) -> Result<()> {
    let revision: BriefRevision = from_value(&claim.value).ok_or(Error::Record(
        crate::error::RecordError::InvalidTaskBody("tasks.proposal.brief"),
    ))?;
    let proposer = proposer_of(claim, approver)?;
    let class = class_of(revision.actor_class)?;
    let mut body =
        task_verb_body_in(vault, wtxn, revision.task_ref)?.ok_or(Error::EntityNotFound)?;
    let held = body.brief.as_ref().map_or(0, |brief| brief.rev);
    if held != revision.base_rev {
        // Another revision landed since this one was proposed: approving it
        // would overwrite one the approver never saw.
        return Err(Error::InvalidConfig(format!(
            "task brief revision is stale: proposed against rev {}, the task holds rev {held}",
            revision.base_rev
        )));
    }
    let memory = vault.memory(proposer, class);
    revision
        .brief
        .validate_in(vault, wtxn, body.assignee)
        .map_err(settle_refusal)?;
    body.brief = Some(StoredBrief {
        rev: held.saturating_add(1),
        digest: brief_digest(&revision.brief),
        brief: revision.brief,
    });
    memory
        .rewrite_task_in_txn(wtxn, revision.task_ref, body, now)
        .map_err(settle_refusal)
}
