//! The owner's per-agent model list (FIX 4472): the models an agent may run
//! on, each with the owner's own words on when, and the model that compacts
//! its window. A wake's seat is picked among the agent's own list by those
//! words; the engine only holds the run to a listed model. With no list the
//! agent runs on its one house-routed model, and with no compaction model on
//! the house's. The agent's home (self-model, voice, diary, lessons) is keyed
//! to the agent, never to a model, so it carries across them.

use super::types::AgentDefinition;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::llm::ModelId;
use crate::side_table::{self, Named, SideTable};
use crate::{Vault, WriteActor};

pub use crate::store::agent_model::AgentModel;

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

/// Holds a seatless job to `listed`, the list its spawning run froze (FIX
/// 5070, FIX 6030): an empty list keeps today's path (any eligible or
/// configured model), and a non-empty one admits only a listed `model`. The
/// engine enforces only the list; a model outside it refuses, naming the list.
///
/// # Errors
///
/// [`no_listed_model`]'s refusal, naming `listed`, when it holds models and
/// `model` is not one of them.
pub fn ensure_inherited_model_list(listed: &[AgentModel], model: &ModelId) -> Result<()> {
    if list_admits(listed, model) {
        return Ok(());
    }
    Err(no_listed_model(listed))
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
