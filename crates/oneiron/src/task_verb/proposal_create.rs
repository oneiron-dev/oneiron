//! Brief-less `tasks.create` proposals land on approval (OF-220).
//!
//! A create the gate does not answer Auto parks the ordinary `tasks.create`
//! Proposed CLAIM carrying the create's own fields and no post stamp. Its
//! approval lands the TASK it describes inside the approving transaction,
//! exactly once, under the id the claim derives, the way a stamped post
//! settles: the approved (amended) value is what lands, the proposer is the
//! envelope's immutable producer, and the birth world and facet are the
//! proposal's own. A refusal fails the approval, so the proposal stays
//! pending.

use rmpv::Value;

use crate::Vault;
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::federation::record_scope::BirthPosition;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::write_envelope::WriteActor;

use super::consts::{TASK_CREATE_PROPOSAL_PREDICATE, TASK_SETTLE_ID_DOMAIN};
use super::create_spec::TaskCreateSpec;
use super::create_validation::validate_task_create_in;
use super::highway_post::{
    envelope_actor_class, proposer_of, put_assignment_fact_in_txn, settle_refusal,
};
use super::verb_kind::{TaskKind, TaskTtl};
use super::wire_decode::{
    decode_consult_payload, decode_task_assignee, task_body_field, task_body_optional,
};

fn invalid(field: &'static str) -> MemoryError {
    MemoryError::from(Error::Record(RecordError::InvalidTaskBody(field)))
}

/// Decodes the stored value of one brief-less `tasks.create` proposal:
/// every field `task_create_proposal_value` writes, `Nil` meaning absent.
/// The kind and a consult's payload ride through, so an approved consult
/// lands as a consult, never silently as a standard task. `created_at` is
/// the proposal's own time and comes back as the spec's `now`.
pub(super) fn decode_task_create_proposal(value: &Value) -> MemoryResult<TaskCreateSpec> {
    let Value::Map(entries) = value else {
        return Err(invalid("tasks.proposal"));
    };
    let created_at = task_body_field(entries, "created_at")?
        .as_u64()
        .ok_or_else(|| invalid("tasks.proposal.created_at"))?;
    let label = task_body_optional(entries, "label")?
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("tasks.proposal.label"))
        })
        .transpose()?;
    let owner_ref = task_body_optional(entries, "owner_ref")?
        .map(|value| {
            value
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or_else(|| invalid("tasks.proposal.owner_ref"))
        })
        .transpose()?;
    let mut spec = TaskCreateSpec::new(
        task_body_field(entries, "spec")?.clone(),
        label,
        owner_ref,
        Some(created_at),
    );
    spec.kind = task_body_optional(entries, "kind")?
        .map(|value| {
            value
                .as_str()
                .ok_or(Error::Record(RecordError::InvalidTaskBody(
                    "tasks.proposal.kind",
                )))
                .and_then(TaskKind::from_token)
        })
        .transpose()?;
    spec.assignee = task_body_optional(entries, "assignee")?
        .map(decode_task_assignee)
        .transpose()?;
    spec.consult = task_body_optional(entries, "consult")?
        .map(decode_consult_payload)
        .transpose()?;
    spec.ttl = task_body_optional(entries, "ttl")?
        .map(|value| {
            value
                .as_map()
                .and_then(|ttl| task_body_field(ttl, "deadline_at").ok())
                .and_then(Value::as_u64)
                .map(TaskTtl::at)
                .ok_or_else(|| invalid("tasks.proposal.ttl"))
        })
        .transpose()?;
    spec.type_ref = task_body_optional(entries, "type_ref")?
        .map(|value| {
            value
                .as_str()
                .and_then(|wire| crate::task_type::TaskTypeRef::parse_wire(wire).ok())
                .ok_or_else(|| invalid("tasks.proposal.type_ref"))
        })
        .transpose()?;
    Ok(spec)
}

/// Lands one approved brief-less create proposal inside the approving
/// transaction: the TASK at the id the claim derives, its route, and the
/// assignment fact a stamped post writes. An id already landed changes
/// nothing; a spec that no longer validates (expired, amended into an
/// invalid shape) fails the approval. The opener never settles its own.
pub(super) fn settle_create_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: EntityId,
    claim: &ClaimBody,
    approver: Option<WriteActor>,
    now: u64,
) -> Result<()> {
    let proposer = proposer_of(claim, approver)?;
    let task_ref = EntityId::derive(TASK_SETTLE_ID_DOMAIN, &[claim_id.as_bytes()])?;
    if vault.get_raw_in(wtxn, &task_ref)?.is_some() {
        return Ok(());
    }
    let class = envelope_actor_class(claim).ok_or(Error::Record(RecordError::InvalidTaskBody(
        "tasks.proposal.actor_class",
    )))?;
    let spec = decode_task_create_proposal(&claim.value).map_err(settle_refusal)?;
    // A parked proposal was born where its writer's TASK would be; the TASK
    // is born there too.
    let facet =
        (claim.scope_facet != vault.default_facet_in_txn(wtxn)?).then_some(claim.scope_facet);
    vault
        .memory(proposer, class)
        .with_birth_position(BirthPosition {
            world: claim.world,
            facet,
        })
        .land_settled_create_in_txn(wtxn, task_ref, claim_id, &spec, now)
        .map_err(settle_refusal)
}

impl Memory<'_> {
    /// The landing half of [`settle_create_in_txn`], as the proposer: the
    /// spec validated at approval time, the TASK minted with the stored
    /// owner or else the proposer, routed in the same transaction, and an
    /// addressed standard task's Assigned fact.
    fn land_settled_create_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        claim_id: EntityId,
        spec: &TaskCreateSpec,
        now: u64,
    ) -> MemoryResult<()> {
        let validated = validate_task_create_in(self.vault(), &*wtxn, spec, now)?;
        let owner = spec.owner_ref.unwrap_or_else(|| self.actor());
        let provenance = Value::Map(vec![
            (Value::from("surface"), Value::from("facade")),
            (
                Value::from("verb"),
                Value::from(TASK_CREATE_PROPOSAL_PREDICATE),
            ),
            (Value::from("proposal_ref"), Value::from(claim_id.to_hex())),
        ]);
        self.mint_task_at_in_txn(
            wtxn,
            (task_ref, owner),
            &validated,
            spec.label.clone(),
            &provenance,
            now,
        )?;
        self.route_created_task_in_txn(wtxn, task_ref, &validated, now)?;
        if validated.kind == TaskKind::Standard
            && let Some(assignee) = validated.assignee
        {
            put_assignment_fact_in_txn(self.vault(), wtxn, task_ref, self.actor(), assignee, now)?;
        }
        Ok(())
    }
}
