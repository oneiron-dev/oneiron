//! The owner's per-agent model list (FIX 4472): the models an agent may run
//! on, each with the owner's own words on when, and the model that compacts
//! its window. A wake's seat is picked among the agent's own list by those
//! words; the engine only holds the run to a listed model. With no list the
//! agent runs on its one house-routed model, and with no compaction model on
//! the house's. The agent's home (self-model, voice, diary, lessons) is keyed
//! to the agent, never to a model, so it carries across them.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::decode::{text_value, validate_text_field};
use super::types::{
    AGENT_DESC_MAX_BYTES, AGENT_MAX_LIST_ENTRIES, AGENT_MODEL_TIER_MAX_BYTES, AgentDefinition,
    KEY_MODEL_REF, KEY_MODEL_WHEN,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, ClaimError, Error, Result};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::llm::ModelId;
use crate::llm::registry::ModelRegistryRow;
use crate::side_table::{self, Named, SideTable};
use crate::{Vault, WriteActor};

/// The model an agent's last wake ran on. Key: id16(agent).
const WAKE_MODEL: SideTable<EntityId, ModelId, Named> =
    SideTable::new(&side_table::AGENT_DEF_WAKE_MODEL);

/// Producer of the owner's note that a model on an agent's list is retired.
const NOTIFICATION_PRODUCER_RETIRED_MODEL: &str = "agent_def.model_retired";

const MODEL_REF_TEXT: &str =
    "model entry model_ref must be a provider/name@revision model id at most 256 bytes";
const WHEN_TEXT: &str = "model entry when must be a non-empty UTF-8 string at most 4096 bytes";
const COMPACTION_MODEL_TEXT: &str =
    "compaction_model must be a provider/name@revision model id at most 256 bytes";

/// One model on an agent's list: a revision-pinned model and the owner's
/// description of when the agent should run on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentModel {
    pub model_ref: ModelId,
    /// When the agent takes this model, in the owner's words. A wake's seat
    /// pick reads it first among the model's description lines.
    pub when: String,
}

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDefBody(reason))
}

/// The `models` value: each entry the [`super::AGENT_MODEL_KEYS`] in pinned
/// order, in the owner's list order.
pub(super) fn encode_agent_models(models: &[AgentModel]) -> Value {
    Value::Array(
        models
            .iter()
            .map(|model| {
                Value::Map(vec![
                    (
                        Value::from(KEY_MODEL_REF),
                        Value::from(model.model_ref.as_str()),
                    ),
                    (
                        Value::from(KEY_MODEL_WHEN),
                        Value::from(model.when.as_str()),
                    ),
                ])
            })
            .collect(),
    )
}

/// Strict `models` decode: an array of at most 64 maps, each holding both
/// pinned keys once and nothing else.
pub(super) fn decode_agent_models(value: &Value) -> Result<Vec<AgentModel>> {
    let Value::Array(values) = value else {
        return Err(invalid("models must be a MessagePack array"));
    };
    if values.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(invalid("models must contain at most 64 entries"));
    }
    values.iter().map(decode_agent_model).collect()
}

fn decode_agent_model(value: &Value) -> Result<AgentModel> {
    let Value::Map(entries) = value else {
        return Err(invalid("model entry must be a MessagePack map"));
    };
    let (mut model_ref, mut when) = (None, None);
    for (key, value) in entries {
        match key.as_str() {
            Some(KEY_MODEL_REF) if model_ref.is_none() => {
                model_ref = Some(decode_model_id(value, MODEL_REF_TEXT)?);
            }
            Some(KEY_MODEL_WHEN) if when.is_none() => {
                when = Some(text_value(value, AGENT_DESC_MAX_BYTES, WHEN_TEXT)?);
            }
            _ => return Err(invalid("unknown or duplicate model entry key")),
        }
    }
    Ok(AgentModel {
        model_ref: model_ref
            .ok_or_else(|| invalid("missing required model entry key model_ref"))?,
        when: when.ok_or_else(|| invalid("missing required model entry key when"))?,
    })
}

/// Strict `compaction_model` decode: one revision-pinned model id.
pub(super) fn decode_compaction_model(value: &Value) -> Result<ModelId> {
    decode_model_id(value, COMPACTION_MODEL_TEXT)
}

fn decode_model_id(value: &Value, context: &'static str) -> Result<ModelId> {
    ModelId::new(text_value(value, AGENT_MODEL_TIER_MAX_BYTES, context)?)
        .map_err(|_| invalid(context))
}

/// The list rules every encode and decode holds: at most 64 entries, each a
/// model id at most 256 bytes listed once, with a non-blank `when` at most
/// 4096 bytes. The compaction model need not be listed: it compacts the
/// agent's window and runs none of its wakes.
pub(super) fn validate_agent_models(def: &AgentDefinition) -> Result<()> {
    if def.models.len() > AGENT_MAX_LIST_ENTRIES {
        return Err(invalid("models must contain at most 64 entries"));
    }
    for (index, model) in def.models.iter().enumerate() {
        validate_text_field(
            model.model_ref.as_str(),
            AGENT_MODEL_TIER_MAX_BYTES,
            MODEL_REF_TEXT,
        )?;
        validate_text_field(&model.when, AGENT_DESC_MAX_BYTES, WHEN_TEXT)?;
        if def.models[..index]
            .iter()
            .any(|listed| listed.model_ref == model.model_ref)
        {
            return Err(invalid("models must not list a model twice"));
        }
    }
    if let Some(model) = &def.compaction_model {
        validate_text_field(
            model.as_str(),
            AGENT_MODEL_TIER_MAX_BYTES,
            COMPACTION_MODEL_TEXT,
        )?;
    }
    Ok(())
}

/// The model that compacts `agent`'s window: its own when it names one, else
/// `house`, the host's concrete compaction model. It need not be on the
/// agent's list.
#[must_use]
pub fn resolve_compaction_model<'a>(agent: &'a AgentDefinition, house: &'a ModelId) -> &'a ModelId {
    agent.compaction_model.as_ref().unwrap_or(house)
}

/// Holds a run to `agent`'s list: any model when the agent lists none (its
/// one house-routed model), else only a listed one.
///
/// # Errors
///
/// [`Error::InvalidConfig`] naming the agent and the model when the agent
/// lists models and `model` is not one of them.
pub fn ensure_listed(agent: &AgentDefinition, model: &ModelId) -> Result<()> {
    if list_admits(&agent.models, model) {
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "model {model} is not in agent {}'s model list",
        agent.agent_id
    )))
}

/// The entry `model` holds on `listed`, an agent's list.
pub(crate) fn listed_entry<'a>(
    listed: &'a [AgentModel],
    model: &ModelId,
) -> Option<&'a AgentModel> {
    listed.iter().find(|entry| &entry.model_ref == model)
}

/// Whether a seat on `model` keeps to `listed`: any model when it is empty.
pub(crate) fn list_admits(listed: &[AgentModel], model: &ModelId) -> bool {
    listed.is_empty() || listed_entry(listed, model).is_some()
}

/// A seat birth that found no listed model it could seat refuses, naming the
/// models it skipped: the wake holds rather than run on an unlisted one.
pub(crate) fn no_listed_model(listed: &[AgentModel]) -> Error {
    let skipped: Vec<&str> = listed
        .iter()
        .map(|entry| entry.model_ref.as_str())
        .collect();
    Error::InvalidConfig(format!(
        "no listed model is eligible: {}",
        skipped.join(", ")
    ))
}

/// Tells the vault's owners, once per agent and model, that a model on
/// `def`'s list is retired: its registry row is stale (its provider retired
/// it) or gone. The agent keeps running on the rest of its list; the note asks
/// for a replacement. `agent_def_id` is the definition's row, the note's
/// subject.
///
/// # Errors
///
/// Registry reads and the notification write. A wake logs them and runs.
pub fn note_stale_listed_models(
    vault: &Vault,
    agent_def_id: EntityId,
    def: &AgentDefinition,
) -> Result<()> {
    let mut retired = Vec::new();
    for listed in &def.models {
        if vault
            .model_registry_row(&listed.model_ref)?
            .as_ref()
            .is_none_or(ModelRegistryRow::is_stale)
        {
            retired.push(&listed.model_ref);
        }
    }
    if retired.is_empty() {
        return Ok(());
    }
    let agent = agent_def_id.to_hex();
    let name = def.display_name.as_deref().unwrap_or(&def.agent_id);
    vault.with_write_txn(|txn| {
        let created_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        for owner in crate::policy_model::owners_in_txn(vault, txn)? {
            for model in &retired {
                // A replay finds the row it wrote first: one note per agent
                // and model, whichever wake sees it.
                vault.record_notification_in_txn(
                    txn,
                    &NotificationEvent {
                        kind: NotificationKind::Finding,
                        source: NotificationSource {
                            producer: NOTIFICATION_PRODUCER_RETIRED_MODEL.to_owned(),
                            event: format!("{agent}:{model}:{}", owner.to_hex()),
                            detail: Some(format!(
                                "model {model} on agent {name}'s list is retired; the agent runs on the rest of its list; add a replacement"
                            )),
                            ..NotificationSource::default()
                        },
                        subject_refs: vec![agent_def_id],
                        recipient: Some(owner),
                        created_at,
                        origin_conversation: None,
                    },
                )?;
            }
        }
        Ok(())
    })
}

impl Vault {
    /// Notes in `agent`'s own diary, as the agent, that this wake ran on
    /// `model` for `why` (its seat receipt's words), when that is not the
    /// model its last wake ran on; its first wake notes it too. Returns
    /// whether a note was written.
    ///
    /// # Errors
    ///
    /// Storage errors; a diary write that fails other than by the agent's
    /// standing.
    pub fn note_wake_model(&self, agent: EntityId, model: &ModelId, why: &str) -> Result<bool> {
        {
            let txn = self.store.env.read_txn()?;
            if WAKE_MODEL.get(&self.store, &txn, &agent)?.as_ref() == Some(model) {
                return Ok(false);
            }
        }
        // The seen model and the note commit in one write, as the refusal
        // dial's change note does (OF-533): two wakes racing over one change
        // write one note. A note the agent's standing refuses rolls back
        // alone: the model is seen and the wake writes no note.
        self.with_write_txn(|txn| {
            if WAKE_MODEL.get(&self.store, txn, &agent)?.as_ref() == Some(model) {
                return Ok(false);
            }
            WAKE_MODEL.put(&self.store, txn, &agent, model)?;
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut savepoint = self.store.env.nested_write_txn(txn)?;
            match crate::memory::append_agent_diary_in_txn(
                self,
                &mut savepoint,
                WriteActor::new(agent, EdgeActorClass::Agent),
                format!("This wake ran on {model} ({why})."),
                at,
            ) {
                Ok(_) => {
                    savepoint.commit()?;
                    Ok(true)
                }
                Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { .. })) => {
                    drop(savepoint);
                    Ok(false)
                }
                Err(error) => Err(error),
            }
        })
    }
}
