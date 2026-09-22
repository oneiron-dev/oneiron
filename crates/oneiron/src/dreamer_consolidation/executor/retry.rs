//! Fresh source reads for scheduled selection retries, within the original partition.
use super::super::partition::{
    ConsolidationPartitionPlan, decode_partition_payload, encode_partition_payload,
};
use super::super::watermark::{WorkingSetTurn, decode_turn_body};
use crate::dreamer_runner::{
    DreamerAttemptStatus, dreamer_extraction_role_admissible, dreamer_turn_role,
};
use crate::llm::Scope;
use crate::{EntityId, Result, Vault, WriteActor};
use std::collections::BTreeSet;

pub(super) fn refreshed_input(
    vault: &Vault,
    actor: WriteActor,
    status: &DreamerAttemptStatus,
    scope: Option<&Scope>,
) -> Result<rmpv::Value> {
    // Exact queued/caller grants are never widened by retry scheduling. They
    // can release by age or policy, but cannot read newly unlisted documents.
    if status.attempt.retry_of.is_none() || scope.is_some() {
        return Ok(status.payload.input.clone());
    }
    let (partition, original, watermark) = decode_partition_payload(&status.payload.input)?;
    let read = vault.scoped_read(
        crate::claim::ScopedReadActorKey::with_actor_class(
            actor.entity_ref().to_hex(),
            actor.actor_class().gate_actor_class(),
        )
        .ok_or_else(|| super::invalid_consolidation("invalid retry actor"))?,
    );
    let parent = read
        .get(&partition.conversation_ref)?
        .value
        .ok_or(crate::Error::EntityNotFound)?;
    let parent = decode_turn_body(&parent);
    let original: BTreeSet<EntityId> = original.into_iter().collect();
    let mut turns = Vec::new();
    for id in vault.sources(
        &partition.conversation_ref,
        crate::EdgeKind::ChildOf,
        Some(crate::registry::ENTITY_TYPE_TURN),
    )? {
        let crate::claim::ScopedReadResult {
            value,
            receipt: _receipt,
        } = read.get_entity_parts_with_receipt(&id, None)?;
        let Some((_, learned_at, bytes)) = value else {
            continue;
        };
        let facts = decode_turn_body(&bytes);
        let role = dreamer_turn_role(
            facts.speaker.as_deref(),
            &vault.config.assistant_display_names,
        );
        if dreamer_extraction_role_admissible(role)
            && facts.world_ref.or(parent.world_ref) == partition.world_ref
            && facts.facet_ref.or(parent.facet_ref) == partition.facet_ref
            && (original.contains(&id) || learned_at >= watermark)
        {
            turns.push(WorkingSetTurn {
                turn_id: id,
                role,
                learned_at,
                conversation: Some(partition.conversation_ref),
            });
        }
    }
    turns.sort_by_key(|turn| (turn.learned_at, turn.turn_id));
    // Keep all original evidence plus bounded recent additions. A new try has
    // a new durable-step identity and can extract the now-expanded evidence.
    if turns.len() > 1_024 {
        return Err(super::invalid_consolidation(
            "selection retry source limit exceeded",
        ));
    }
    if !original
        .iter()
        .all(|id| turns.iter().any(|turn| turn.turn_id == *id))
    {
        return Err(super::invalid_consolidation(
            "selection retry source no longer admitted",
        ));
    }
    Ok(encode_partition_payload(&ConsolidationPartitionPlan {
        key: partition,
        turns,
        watermark_last_learned_at: watermark,
    }))
}
