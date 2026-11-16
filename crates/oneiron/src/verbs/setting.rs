//! The Setting primitive's verbs (DESIGN 15-setting-primitive, stage 0.1): `vault.settings.get`,
//! `vault.settings.list` and `vault.settings.set`, one each for every catalogue key.
//!
//! The caller is the vault owner, on the owner's own proof, or an agent on its verified
//! binding. Reads follow each key's `read_by`; a change goes through [`Vault::set_setting`],
//! which checks the power live in its write.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::federation::EngineControlClass;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult,
};
use crate::setting::{
    SetSetting, SetSettingOutcome, SettingCaller, SettingCatalogueEntry, SettingListFilter,
    SettingMode, SettingReader, SettingScope, SettingView,
};

const GET: &str = "vault.settings.get";
const LIST: &str = "vault.settings.list";
const SET: &str = "vault.settings.set";

/// `vault.settings.get` input: one key, at the places the caller knows.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SettingGetRequest {
    /// The key's dotted name.
    pub key: String,
    /// For a family key, the item.
    #[serde(default)]
    pub item: Option<String>,
    /// The places the value is read at (a world, a project, an agent ...); the vault is always
    /// last and is never named.
    #[serde(default)]
    pub at: Vec<SettingScope>,
}

/// `vault.settings.list` input: what to narrow the catalogue to.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SettingListRequest {
    /// Keys whose name starts with it.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Keys a holder of this `engine.controls` class sets.
    #[serde(default)]
    pub class: Option<EngineControlClass>,
    /// The places each value in force is read at.
    #[serde(default)]
    pub at: Vec<SettingScope>,
}

/// What `vault.settings.list` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettingCatalogue {
    /// The keys the caller may read, in name order.
    pub keys: Vec<SettingCatalogueEntry>,
}

/// `vault.settings.set` input: one row's change.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SettingSetRequest {
    /// The key's dotted name.
    pub key: String,
    /// For a family key, the item.
    #[serde(default)]
    pub item: Option<String>,
    /// Where the row applies.
    pub scope: SettingScope,
    /// Whether the row is the owner's pin; a value row when absent.
    #[serde(default)]
    pub pin: bool,
    /// The new value; absent or null clears the row.
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    /// The row's revision the caller read; the change is refused when the row has moved.
    #[serde(default)]
    pub expected_revision: Option<u64>,
    /// Why, in the setter's words.
    #[serde(default)]
    pub why: Option<String>,
    /// The approved check-in this change waited on, 32 hex.
    #[serde(default)]
    pub check_in_ref: Option<String>,
}

fn bad_request(message: String) -> MemoryError {
    MemoryError::new(MEMORY_CODE_BAD_REQUEST, message, &[])
}

fn forbidden(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb} takes the vault owner or an agent"),
        &["Call as the owner, or as an agent the owner granted."],
    )
}

/// The verified agent behind `memory`, or a refusal.
fn agent_of(memory: &Memory<'_>, verb: &str) -> MemoryResult<EntityId> {
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(forbidden(verb));
    }
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    crate::memory::verify_actor_binding_in_txn(vault, &txn, memory.actor(), memory.actor_class())?;
    Ok(memory.actor())
}

/// Who reads, through `memory`: the owner when its proof holds, else its verified agent.
fn reader_of(memory: &Memory<'_>, verb: &str) -> MemoryResult<SettingReader> {
    if let Ok(owner) = memory.embedded_owner(verb) {
        owner.revalidate(memory.vault())?;
        return Ok(SettingReader::Owner);
    }
    agent_of(memory, verb).map(SettingReader::Actor)
}

/// `vault.settings.get`: the value in force for one key, which row decided it, and its revision.
///
/// # Errors
///
/// BAD_REQUEST for an unknown key, an item or place it does not admit, or a reader who may not
/// read it; FORBIDDEN for a caller that is neither the owner nor an agent; storage errors.
pub fn setting_get_embedded(
    memory: &Memory<'_>,
    input: SettingGetRequest,
) -> MemoryResult<SettingView> {
    let reader = reader_of(memory, GET)?;
    Ok(memory
        .vault()
        .setting_view_for(reader, &input.key, input.item.as_deref(), &input.at)?)
}

/// `vault.settings.list`: every catalogue key the caller may read, with its schema, default,
/// value in force and stored rows.
///
/// # Errors
///
/// FORBIDDEN for a caller that is neither the owner nor an agent; storage errors.
pub fn setting_list_embedded(
    memory: &Memory<'_>,
    input: SettingListRequest,
) -> MemoryResult<SettingCatalogue> {
    let reader = reader_of(memory, LIST)?;
    let filter = SettingListFilter {
        prefix: input.prefix,
        class: input.class,
        at: input.at,
    };
    Ok(SettingCatalogue {
        keys: memory.vault().setting_catalogue_for(reader, &filter)?,
    })
}

/// `vault.settings.set`: one row's change through [`Vault::set_setting`]: `applied`, or
/// `pending` with the check-in it waits on.
///
/// # Errors
///
/// BAD_REQUEST for a `check_in_ref` that is not 32 hex, and as [`Vault::set_setting`];
/// FORBIDDEN for a caller that is neither the owner nor an agent; storage errors.
pub fn setting_set_embedded(
    memory: &Memory<'_>,
    input: SettingSetRequest,
) -> MemoryResult<SetSettingOutcome> {
    let request = set_request(input)?;
    let vault: &Vault = memory.vault();
    if let Ok(owner) = memory.embedded_owner(SET) {
        return Ok(vault.set_setting(SettingCaller::Owner(&owner), request)?);
    }
    let agent = agent_of(memory, SET)?;
    Ok(vault.set_setting(SettingCaller::Agent(agent), request)?)
}

fn set_request(input: SettingSetRequest) -> MemoryResult<SetSetting> {
    let check_in_ref = input
        .check_in_ref
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| bad_request("check_in_ref is a check-in's 32 hex id".to_owned()))?;
    Ok(SetSetting {
        key: input.key,
        item: input.item,
        scope: input.scope,
        mode: if input.pin {
            SettingMode::Pin
        } else {
            SettingMode::Value
        },
        value: input.value.filter(|value| !value.is_null()),
        expected_revision: input.expected_revision,
        why: input.why,
        check_in_ref,
    })
}
