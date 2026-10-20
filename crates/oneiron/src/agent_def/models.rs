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
use crate::side_table::{self, Named, SideTable};
use crate::{Vault, WriteActor};

/// The model an agent's last wake ran on. Key: id16(agent).
const WAKE_MODEL: SideTable<EntityId, ModelId, Named> =
    SideTable::new(&side_table::AGENT_DEF_WAKE_MODEL);

/// Producer of the owner's note that a model on an agent's list is retired.
const NOTIFICATION_PRODUCER_RETIRED_MODEL: &str = "agent_def.model_retired";

/// Producer of the owner's note that no registry row names a model on an
/// agent's list.
const NOTIFICATION_PRODUCER_UNAVAILABLE_MODEL: &str = "agent_def.model_unavailable";

/// Producer of the owner's note that an agent's list bound none of its runs.
const NOTIFICATION_PRODUCER_LIST_UNBOUND: &str = "agent_def.model_list_unbound";

/// What [`no_listed_model`]'s refusal says first.
const NO_LISTED_MODEL_TEXT: &str = "no listed model is eligible";

/// The one policy hook for a run of an agent with a model list that its list
/// does not bind (FIX 4544, FIX 4539). `false`, the owner's ruling (FIX
/// 6030): the engine enforces only the list, so a reader or summary job its
/// inherited list admits no eligible model for refuses its seat birth
/// ([`no_listed_model`]), and an agent run no seat binds (no model manifest
/// and no seat receipt) whose configured route is not on the list refuses
/// ([`ensure_listed`]); both name the list. `true` is the old path: the job
/// runs on any eligible model ([`birth_under_inherited_list`]) and the
/// seatless run on its configured route, the owner told
/// ([`note_unbound_listed_run`]).
pub const UNBOUND_LIST_KEEPS_ROUTE: bool = false;

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
/// `fallback`, the default its host supplies (for a `self` writer, the
/// self-compaction row's cheap model, FIX 6029). It need not be on the
/// agent's list.
#[must_use]
pub fn resolve_compaction_model<'a>(
    agent: &'a AgentDefinition,
    fallback: &'a ModelId,
) -> &'a ModelId {
    agent.compaction_model.as_ref().unwrap_or(fallback)
}

/// Holds a run to `agent`'s list: any model when the agent lists none (its
/// one house-routed model), else only a listed one.
///
/// # Errors
///
/// [`Error::InvalidConfig`] naming the agent, the model and the list when
/// the agent lists models and `model` is not one of them.
pub fn ensure_listed(agent: &AgentDefinition, model: &ModelId) -> Result<()> {
    if list_admits(&agent.models, model) {
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "model {model} is not in agent {}'s model list: {}",
        agent.agent_id,
        list_text(&agent.models)
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
    Error::InvalidConfig(format!("{NO_LISTED_MODEL_TEXT}: {}", list_text(listed)))
}

/// `listed`'s model ids, comma-separated.
fn list_text(listed: &[AgentModel]) -> String {
    let models: Vec<&str> = listed
        .iter()
        .map(|entry| entry.model_ref.as_str())
        .collect();
    models.join(", ")
}

/// Births a reader or summary job's seat through `birth`, which holds it to
/// the list it is passed (FIX 4539): `inherited`, the list the job's
/// originating run froze. Under [`UNBOUND_LIST_KEEPS_ROUTE`] a job that list
/// admits no eligible model for is born on an empty one, any eligible model,
/// as before lists, and logged; so is one whose stored seat was born that
/// way, its model (`prior`) unlisted. `run` is the job's run, for the log.
///
/// # Errors
///
/// `birth`'s.
pub fn birth_under_inherited_list<T, E: std::fmt::Display>(
    run: EntityId,
    inherited: &[AgentModel],
    prior: Option<&ModelId>,
    birth: impl Fn(Vec<AgentModel>) -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    if inherited.is_empty() || !UNBOUND_LIST_KEEPS_ROUTE {
        return birth(inherited.to_vec());
    }
    if prior.is_some_and(|model| !list_admits(inherited, model)) {
        return birth(Vec::new());
    }
    match birth(inherited.to_vec()) {
        Err(error) if error.to_string().contains(NO_LISTED_MODEL_TEXT) => {
            tracing::info!(%error, run = %run.to_hex(), "a job's inherited model list admits no eligible model; it runs on any eligible one");
            birth(Vec::new())
        }
        born => born,
    }
}

/// Tells the vault's owners, once per agent and model, that a model on
/// `def`'s list is retired, its registry row stale (its provider retired it),
/// or unavailable, no row naming it (never registered, or removed). The agent
/// keeps running on the rest of its list; the note asks for a replacement.
/// `agent_def_id` is the definition's row, the note's subject.
///
/// # Errors
///
/// Registry reads and the notification write. A wake logs them and runs.
pub fn note_stale_listed_models(
    vault: &Vault,
    agent_def_id: EntityId,
    def: &AgentDefinition,
) -> Result<()> {
    let name = def.display_name.as_deref().unwrap_or(&def.agent_id);
    let mut notes = Vec::new();
    for listed in &def.models {
        let model = &listed.model_ref;
        // Only a stale row is its provider's retirement: a missing one says
        // no more than that this vault knows no such model.
        match vault.model_registry_row(model)? {
            Some(row) if row.is_stale() => notes.push((
                NOTIFICATION_PRODUCER_RETIRED_MODEL,
                model,
                format!(
                    "model {model} on agent {name}'s list is retired; the agent runs on the rest \
                     of its list; add a replacement"
                ),
            )),
            None => notes.push((
                NOTIFICATION_PRODUCER_UNAVAILABLE_MODEL,
                model,
                format!(
                    "model {model} on agent {name}'s list is unavailable: no registry row names \
                     it (it may never have been registered, or was removed); register it, or \
                     list an available model on the agent"
                ),
            )),
            Some(_) => {}
        }
    }
    if notes.is_empty() {
        return Ok(());
    }
    note_owners(vault, agent_def_id, &notes)
}

/// Tells the vault's owners, once per agent and model used, that a run of
/// `def`, which lists models, ran on `used`, the model its host configured,
/// as the vault has no model manifest to bear it a seat (FIX 4544): under
/// [`UNBOUND_LIST_KEEPS_ROUTE`] such a run keeps that route. `agent_def_id`
/// is the definition's row, the note's subject.
///
/// # Errors
///
/// The notification write. A wake logs it and runs.
pub fn note_unbound_listed_run(
    vault: &Vault,
    agent_def_id: EntityId,
    def: &AgentDefinition,
    used: &ModelId,
) -> Result<()> {
    let name = def.display_name.as_deref().unwrap_or(&def.agent_id);
    let detail = format!(
        "agent {name} lists {} but this vault has no model manifest, so its run used {used}; \
         configure the vault's model manifest to bind the list",
        list_text(&def.models)
    );
    let notes = [(NOTIFICATION_PRODUCER_LIST_UNBOUND, used, detail)];
    note_owners(vault, agent_def_id, &notes)
}

/// Writes each of `notes`, its producer, the model it is about and its text,
/// to every owner of the vault, about `agent_def_id`'s row, in one write.
fn note_owners(
    vault: &Vault,
    agent_def_id: EntityId,
    notes: &[(&str, &ModelId, String)],
) -> Result<()> {
    let agent = agent_def_id.to_hex();
    vault.with_write_txn(|txn| {
        let created_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        for owner in crate::policy_model::owners_in_txn(vault, txn)? {
            for (producer, model, detail) in notes {
                // A replay finds the row it wrote first: one note per
                // producer, agent and model, whichever wake sees it.
                vault.record_notification_in_txn(
                    txn,
                    &NotificationEvent {
                        kind: NotificationKind::Finding,
                        source: NotificationSource {
                            producer: (*producer).to_owned(),
                            event: format!("{agent}:{model}:{}", owner.to_hex()),
                            detail: Some(detail.clone()),
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
