//! A resident binding's validation: the rows it names, its inbox's actor,
//! its home message's conversation and each goal reference.

use super::{ResidentAgentSpec, invalid};
use crate::Vault;
use crate::error::Result;
use crate::task_verb::ConsultPayloadRef;

pub(super) fn validate(vault: &Vault, spec: &ResidentAgentSpec) -> Result<()> {
    if vault.get_entity_type(&spec.agent_def_ref)? != Some(crate::registry::ENTITY_TYPE_AGENT_DEF)
        || vault.get_entity_type(&spec.home_conversation_ref)?
            != Some(crate::registry::ENTITY_TYPE_CONVERSATION)
        || vault.get_entity_type(&spec.home_message_ref)?
            != Some(crate::registry::ENTITY_TYPE_MESSAGE)
        || spec.goal.axes.len() > 32
    {
        return Err(invalid());
    }
    let facts = vault
        .channel_identity_facts(&spec.inbox_identity_ref)?
        .ok_or_else(invalid)?;
    if facts.binding.actor_ref() != Some(spec.agent_def_ref) {
        return Err(invalid());
    }
    let parents: Vec<_> = vault
        .edges_out(&spec.home_message_ref)?
        .into_iter()
        .filter(|edge| edge.kind == crate::edge::EdgeKind::BelongsTo)
        .collect();
    if parents.len() != 1 || parents[0].target != spec.home_conversation_ref {
        return Err(invalid());
    }
    for reference in std::iter::once(spec.goal.goal)
        .chain(std::iter::once(spec.goal.why))
        .chain(spec.goal.axes.iter().copied())
    {
        ConsultPayloadRef::parse(vault, &reference.short_ref())?;
    }
    Ok(())
}
