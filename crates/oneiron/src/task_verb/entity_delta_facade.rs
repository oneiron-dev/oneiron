use rmpv::Value;

use crate::Vault;
use crate::claim::ClaimBody;
use crate::consult_ladder::{
    EntityDeltaArtifact, GraduationLookup, GraduationScope, NoveltyDecision, novelty_guard,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::facade::{
    FACADE_CODE_FORBIDDEN, FACADE_CODE_INVALID_STATE, FacadeError, FacadeResult, MemoryFacade,
    verify_actor_binding,
};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};

use super::consult_ladder_facade::CrossActorRoute;
use super::consult_payload::{ConsultPayload, ConsultPayloadRef};
use super::create_spec::TaskCreateSpec;
use super::create_validation::{consult_refusal, require_resolved_entity};
use super::rate_limit::task_create_owner;
use super::verb_kind::{TaskAssignee, TaskKind, TaskTtl};
use super::wire_encode::entity_ref_value;

impl MemoryFacade<'_> {
    /// Routes one cross-actor entity-delta write.
    ///
    /// Ownership is RESOLVED from durable state, never asserted by the caller:
    /// a delta naming an owning actor the vault disagrees with is refused
    /// outright. "Auto" never means bypassing the write gate, the actor
    /// ceiling, or the standing-grant scope — it means the existing typed
    /// write path may proceed without a NEW owner-agent consult, because
    /// ownership or an already-receipted narrow grant already permits it.
    ///
    /// This function writes no target state on any branch. The consult branch
    /// writes exactly one TASK.
    pub fn route_entity_delta(
        &self,
        delta: EntityDeltaArtifact,
        graduation: Option<(&dyn GraduationLookup, &GraduationScope)>,
        deadline_at: u64,
        now: u64,
    ) -> FacadeResult<CrossActorRoute> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let owning_actor_ref = self.resolve_cross_actor_owner(&delta)?;
        if owning_actor_ref == self.actor() {
            return Ok(CrossActorRoute::AutoOwn);
        }
        if let Some((lookup, scope)) = graduation
            && scope.proposer_actor_ref == delta.proposer_actor_ref
            && scope.owning_actor_ref == owning_actor_ref
            && let NoveltyDecision::AutoKnownShape { standing_grant_ref } =
                novelty_guard(lookup, scope, &delta.shape)
        {
            return Ok(CrossActorRoute::AutoViaStandingGrant { standing_grant_ref });
        }
        let payload = self.entity_delta_payload(delta)?;
        let receipt = self.tasks_create(
            &TaskCreateSpec::new(Value::Nil, None, None, Some(now))
                .with_kind(TaskKind::Consult)
                .with_consult(payload)
                .with_assignee(TaskAssignee::Peer {
                    actor_ref: owning_actor_ref,
                })
                .with_ttl(TaskTtl::at(deadline_at)),
        )?;
        Ok(CrossActorRoute::ConsultOwner { receipt })
    }

    /// The two attribution laws every cross-actor delta answers to, and the
    /// owning actor they resolve.
    ///
    /// The proposer must BE the acting actor — a delta proposed "on behalf of"
    /// a third actor is an unattributed write — and the owning actor must be
    /// the one the target's own provenance names (ARCH-0043: actor = WHO, and
    /// WHO is read, never claimed).
    pub(super) fn resolve_cross_actor_owner(
        &self,
        delta: &EntityDeltaArtifact,
    ) -> FacadeResult<EntityId> {
        if delta.proposer_actor_ref != self.actor() {
            return Err(consult_refusal(
                FACADE_CODE_FORBIDDEN,
                "the proposer of an entity delta must be the acting actor",
                "Route the delta as the actor that authored it.",
            ));
        }
        let owning_actor_ref = resolve_owning_actor(self.vault(), delta.target_ref)?.ok_or_else(
            || {
                consult_refusal(
                    FACADE_CODE_INVALID_STATE,
                    "the target's owning actor does not resolve from durable state",
                    "Record the target's ownership provenance, or route the case as a pathology consult.",
                )
            },
        )?;
        if owning_actor_ref == delta.owning_actor_ref {
            Ok(owning_actor_ref)
        } else {
            Err(consult_refusal(
                FACADE_CODE_FORBIDDEN,
                "the delta names an owning actor the target's provenance contradicts",
                "Resolve the owning actor from the target's provenance before proposing.",
            ))
        }
    }

    /// Builds the consult payload for one entity-delta ask, binding every
    /// carried ref to a live entity of its declared kind first.
    pub(super) fn entity_delta_payload(
        &self,
        delta: EntityDeltaArtifact,
    ) -> FacadeResult<ConsultPayload> {
        let vault = self.vault();
        require_resolved_entity(vault, delta.target_ref)?;
        require_resolved_entity(vault, delta.proposer_actor_ref)?;
        require_resolved_entity(vault, delta.owning_actor_ref)?;
        let question_ref = consult_payload_ref_for(vault, delta.delta_ref)?;
        let mut context_refs = Vec::new();
        for optional in [delta.base_state_ref, delta.message_thread_ref] {
            let Some(entity_ref) = optional else { continue };
            let carried = consult_payload_ref_for(vault, entity_ref)?;
            if carried != question_ref && !context_refs.contains(&carried) {
                context_refs.push(carried);
            }
        }
        Ok(
            ConsultPayload::question(question_ref, context_refs, EntityId::now())
                .with_entity_delta(delta),
        )
    }
}

/// Binds one durable ref to the typed consult-ref kind it actually is.
fn consult_payload_ref_for(vault: &Vault, entity_ref: EntityId) -> FacadeResult<ConsultPayloadRef> {
    match vault.get_entity_type(&entity_ref)? {
        Some(ENTITY_TYPE_CLAIM) => Ok(ConsultPayloadRef::Claim(entity_ref)),
        Some(ENTITY_TYPE_TURN) => Ok(ConsultPayloadRef::Turn(entity_ref)),
        _ => Err(FacadeError::bad_request(
            "a consult ref must resolve to a stored CLAIM or TURN entity",
        )),
    }
}

/// Resolves the AUTHORITATIVE owning actor of one target from durable state.
///
/// A TASK's owner is the record stamped atomically by the verified
/// `tasks.create` path; a CLAIM's owner is the actor its write envelope
/// recorded. Anything else has no recorded owner, and an unresolvable owner is
/// a pathology, not a licence to trust the caller (ARCH-0043: actor = WHO).
fn resolve_owning_actor(vault: &Vault, target_ref: EntityId) -> Result<Option<EntityId>> {
    match vault.get_entity_type(&target_ref)? {
        Some(ENTITY_TYPE_TASK) => task_create_owner(vault, target_ref),
        Some(ENTITY_TYPE_CLAIM) => {
            Ok(claim_envelope_actor(vault, target_ref)?.map(|env| env.actor))
        }
        _ => Ok(None),
    }
}

/// The durable counter-lineage artifact one countered TASK keeps as its
/// `result_ref`. Typed refs only.
pub(super) fn counter_lineage_artifact_value(
    parent_task_ref: EntityId,
    counter_task_ref: EntityId,
    occurred_at: u64,
) -> Value {
    Value::Map(vec![
        (Value::from("kind"), Value::from("consult.counter")),
        (
            Value::from("parent_task_ref"),
            entity_ref_value(parent_task_ref),
        ),
        (
            Value::from("counter_task_ref"),
            entity_ref_value(counter_task_ref),
        ),
        (Value::from("occurred_at"), Value::from(occurred_at)),
    ])
}

/// The write-envelope provenance keys that mark a Dreamer-run write. They
/// mirror `gate.rs`'s private reader over the SAME wire map that
/// `dreamer_promotion` stamps; the gate owns its copy and this module owns
/// this one, because 1888 consumes gate.rs read-only.
pub(super) const DREAMER_PROVENANCE_SURFACE_KEYS: [&str; 2] = ["surface", "runner"];

/// The write actor and provenance one stored claim recorded.
pub(super) struct ClaimEnvelopeAttribution {
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
    pub(super) provenance: Value,
}

/// Recovers the write-envelope attribution stamped on one stored claim.
pub(super) fn claim_envelope_actor(
    vault: &Vault,
    claim_ref: EntityId,
) -> Result<Option<ClaimEnvelopeAttribution>> {
    let Some(body) = vault.get_claim(&claim_ref)? else {
        return Ok(None);
    };
    Ok(claim_envelope_attribution(&body))
}

fn claim_envelope_attribution(body: &ClaimBody) -> Option<ClaimEnvelopeAttribution> {
    let Some(Value::Map(entries)) = &body.evidence else {
        return None;
    };
    let mut actor = None;
    let mut actor_class = None;
    let mut provenance = None;
    for (key, value) in entries {
        match key.as_str() {
            Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) => {
                if let Value::Binary(bytes) = value
                    && let Ok(raw) = <[u8; 16]>::try_from(bytes.as_slice())
                {
                    actor = EntityId::from_bytes(raw).ok();
                }
            }
            Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY) => {
                actor_class = value
                    .as_u64()
                    .and_then(|raw| u8::try_from(raw).ok())
                    .and_then(EdgeActorClass::try_from_u8);
            }
            Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY) => {
                provenance = Some(value.clone());
            }
            _ => {}
        }
    }
    Some(ClaimEnvelopeAttribution {
        actor: actor?,
        actor_class: actor_class?,
        provenance: provenance?,
    })
}
