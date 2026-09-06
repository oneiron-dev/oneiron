//! Read-only integrity checks for surfaced failure cards.

use crate::{
    Error, Result, Vault,
    attempt_queue::AttemptId,
    batch::EntityMetadataHeader,
    edge::EdgeKind,
    entity_id::EntityId,
    failure_ladder::HealerRepairRoute,
    memory::sole_edge_target,
    registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN},
};

use super::parse_card_ref;

/// Validate reference spellings, then bind the selected repair to its context.
/// Artifact kinds and skill-manifest relations have no validation substrate
/// here. These strings remain references, not executable authority.
pub(super) fn require_diagnosed_route(
    vault: &Vault,
    failing_attempt_id: AttemptId,
    pre_fail_checkpoint_ref: EntityId,
    route: &HealerRepairRoute,
) -> Result<()> {
    let agent_ref = match route {
        HealerRepairRoute::SkillEdit {
            agent_ref,
            skill_ref,
            patch_ref,
            diagnosis_ref,
        } => {
            parse_repair_ref("skill_ref", skill_ref)?;
            parse_repair_ref("patch_ref", patch_ref)?;
            parse_repair_ref("diagnosis_ref", diagnosis_ref)?;
            agent_ref
        }
        HealerRepairRoute::PromptInjectAndForkResume {
            agent_ref,
            prompt_ref,
            checkpoint_ref,
            diagnosis_ref,
        } => {
            parse_repair_ref("prompt_ref", prompt_ref)?;
            let checkpoint = parse_repair_ref("checkpoint_ref", checkpoint_ref)?;
            if checkpoint != pre_fail_checkpoint_ref
                || checkpoint.as_bytes() == failing_attempt_id.as_bytes()
            {
                return Err(Error::InvalidConfig(
                    "healer fork checkpoint must match pre-fail context, never the failing attempt"
                        .to_owned(),
                ));
            }
            parse_repair_ref("diagnosis_ref", diagnosis_ref)?;
            agent_ref
        }
        HealerRepairRoute::Environment {
            agent_ref,
            environment_ref,
            repair_ref,
            diagnosis_ref,
        } => {
            parse_repair_ref("environment_ref", environment_ref)?;
            parse_repair_ref("repair_ref", repair_ref)?;
            parse_repair_ref("diagnosis_ref", diagnosis_ref)?;
            agent_ref
        }
        HealerRepairRoute::EscalateWithDiagnosis {
            agent_ref,
            diagnosis_ref,
        } => {
            parse_repair_ref("diagnosis_ref", diagnosis_ref)?;
            agent_ref
        }
    };
    let expected = parse_repair_ref("agent_ref", agent_ref)?;
    let record = crate::AttemptQueue::new(vault)
        .get(failing_attempt_id)?
        .ok_or_else(|| {
            Error::InvalidConfig("healer diagnosis requires a stored failing attempt".to_owned())
        })?;
    if crate::failure_ladder::dispatched_target_ref(&record) != Some(expected) {
        return Err(Error::InvalidConfig(
            "healer diagnosis agent must match the failing attempt's dispatched agent".to_owned(),
        ));
    }
    Ok(())
}

fn parse_repair_ref(field: &str, value: &str) -> Result<EntityId> {
    let context = format!("healer diagnosis {field}");
    let id = parse_card_ref(&context, value)?;
    if id.to_hex() != value {
        return Err(Error::InvalidConfig(format!(
            "{context} must be a canonical lowercase-hex EntityId string"
        )));
    }
    Ok(id)
}

/// Read sole canonical bindings in one snapshot before accepting any match.
/// A TURN's ChildOf and a MESSAGE's BelongsTo must agree when both exist.
/// Either conversation binding can stand alone, as can direct PartOf membership.
/// Only a TURN is the intermediate container in the two-hop path.
pub(super) fn require_thread_membership(
    vault: &Vault,
    message_ref: EntityId,
    thread_ref: EntityId,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    let sole = |source: &EntityId, kind, label| {
        sole_edge_target(&vault.store, &txn, source, kind, label)
            .map_err(|error| Error::InvalidConfig(error.to_string()))
    };
    let part_of = sole(&message_ref, EdgeKind::PartOf, "message")?;
    let belongs_to = sole(&message_ref, EdgeKind::BelongsTo, "message")?;
    let container_kind = |id: EntityId| -> Result<u8> {
        let raw = vault
            .store
            .entities
            .get(&txn, id.as_bytes())?
            .ok_or_else(|| {
                Error::InvalidConfig("healer qa membership container is missing".to_owned())
            })?;
        Ok(EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity header"))?
            .entity_type)
    };
    if let Some(conversation) = belongs_to
        && container_kind(conversation)? != ENTITY_TYPE_CONVERSATION
    {
        return Err(Error::InvalidConfig(
            "healer qa BelongsTo must name a CONVERSATION".to_owned(),
        ));
    }
    let outer = match part_of {
        Some(container) => match container_kind(container)? {
            ENTITY_TYPE_TURN => sole(&container, EdgeKind::ChildOf, "turn")?,
            ENTITY_TYPE_CONVERSATION => {
                if belongs_to.is_some_and(|conversation| conversation != container) {
                    return Err(Error::InvalidConfig(
                        "healer qa PartOf and BelongsTo name conflicting conversations".to_owned(),
                    ));
                }
                None
            }
            _ => {
                return Err(Error::InvalidConfig(
                    "healer qa PartOf must name a TURN or CONVERSATION".to_owned(),
                ));
            }
        },
        None => None,
    };
    if let Some(conversation) = outer {
        if container_kind(conversation)? != ENTITY_TYPE_CONVERSATION {
            return Err(Error::InvalidConfig(
                "healer qa TURN ChildOf must name a CONVERSATION".to_owned(),
            ));
        }
        if belongs_to.is_some_and(|direct| direct != conversation) {
            return Err(Error::InvalidConfig(
                "healer qa BelongsTo and TURN ChildOf name conflicting conversations".to_owned(),
            ));
        }
    }
    if [part_of, belongs_to, outer].contains(&Some(thread_ref)) {
        return Ok(());
    }
    Err(Error::InvalidConfig(
        "healer qa message_ref is not part of the named thread".to_owned(),
    ))
}
