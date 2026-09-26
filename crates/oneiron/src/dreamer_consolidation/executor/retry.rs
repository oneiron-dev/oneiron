//! Fresh source reads for scheduled selection retries, within the original partition.
use super::super::partition::{
    ConsolidationPartitionPlan, decode_partition_payload, encode_partition_payload,
};
use super::super::watermark::{WorkingSetTurn, decode_turn_body};
use crate::claim::{PointRead, ReadRow, ScopedReadReceipt};
use crate::dreamer_runner::{
    DreamerAttemptStatus, dreamer_extraction_role_admissible, dreamer_turn_role,
};
use crate::llm::Scope;
use crate::{EntityId, Result, Vault, WriteActor};
use std::collections::BTreeSet;

/// The attempt input, refreshed for a selection retry. A refresh reads the
/// partition again as the Dreamer actor and returns that read's receipt; an
/// input that is not refreshed reads nothing and returns `None`.
pub(super) fn refreshed_input(
    vault: &Vault,
    actor: WriteActor,
    status: &DreamerAttemptStatus,
    scope: Option<&Scope>,
) -> Result<(rmpv::Value, Option<ScopedReadReceipt>)> {
    // Exact queued/caller grants are never widened by retry scheduling. They
    // can release by age or policy, but cannot read newly unlisted documents.
    if status.attempt.retry_of.is_none() || scope.is_some() {
        return Ok((status.payload.input.clone(), None));
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
        .read(&[PointRead::id(partition.conversation_ref)], None)?
        .single();
    let mut receipt = parent.receipt;
    let parent = parent
        .value
        .and_then(|row| row.body)
        .ok_or(crate::Error::EntityNotFound)?;
    let parent = decode_turn_body(&parent);
    let original: BTreeSet<EntityId> = original.into_iter().collect();
    let mut turns = Vec::new();
    let children: Vec<_> = vault
        .sources(
            &partition.conversation_ref,
            crate::EdgeKind::ChildOf,
            Some(crate::registry::ENTITY_TYPE_TURN),
        )?
        .into_iter()
        .map(PointRead::id)
        .collect();
    let children = read.read(&children, None)?;
    receipt.restrict_with(&children.receipt);
    for row in children.value.into_iter().flatten() {
        let ReadRow {
            id,
            learned_at,
            body: Some(bytes),
            ..
        } = row
        else {
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
    Ok((
        encode_partition_payload(&ConsolidationPartitionPlan {
            key: partition,
            turns,
            watermark_last_learned_at: watermark,
        }),
        Some(receipt),
    ))
}
