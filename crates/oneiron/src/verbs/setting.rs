//! The Setting primitive's verbs (DESIGN 15-setting-primitive, stage 0.1): `vault.settings.get`,
//! `vault.settings.list` and `vault.settings.set`, one each for every catalogue key; and, from
//! stage 6.0, `vault.settings.accept_defaults`, the owner's yes to a pack's waiting defaults.
//!
//! The caller is the vault owner, on the owner's own proof, or an agent on its verified
//! binding. Reads follow each key's `read_by`; a change goes through [`Vault::set_setting`],
//! which checks the power live in its write. A host door also takes a live owner it proved from
//! the request itself, a co-owner included (each `*_with_request_owner` form; FIX
//! SETTINGS-SET-DOOR-CO-OWNER).

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::federation::EngineControlClass;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult,
};
use crate::setting::{
    SetSetting, SetSettingOutcome, SettingCaller, SettingCatalogueEntry, SettingListFilter,
    SettingMode, SettingReadCaller, SettingScope, SettingView,
};

const GET: &str = "vault.settings.get";
const LIST: &str = "vault.settings.list";
const SET: &str = "vault.settings.set";
const ACCEPT_DEFAULTS: &str = "vault.settings.accept_defaults";

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
    /// Whether the row is the one a move carried onto a project (stage 6.0): only a clear, which
    /// releases it as a loose move. Never with `pin`.
    #[serde(default)]
    pub carried: bool,
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
    /// A learned key's seed: its weight in runs, finite and above zero. Only a value row of a
    /// learned key carries one, and it must.
    #[serde(default)]
    pub weight_runs: Option<f64>,
}

/// `vault.settings.accept_defaults` input: the waiting proposal the owner says yes to.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SettingAcceptDefaultsRequest {
    /// The pack that proposes the defaults (`engine` for this build's own).
    pub pack: String,
    /// The proposal's digest, as `vault.settings.list` shows it in `proposed_default`.
    pub proposal: String,
}

/// What `vault.settings.accept_defaults` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettingAcceptedDefaults {
    /// The keys whose default the vault now accepts from the pack, in name order.
    pub keys: Vec<String>,
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

/// The `request_owner` of an embedded call, which has no request: none.
fn no_request_owner() -> Option<AuthenticatedOwner> {
    None
}

/// The owner behind `memory`: the handle's own owner proof ([`Memory::embedded_owner`]), else,
/// for a human caller that one refuses, the live owner the host proved from the request
/// (`request_owner`, as the host's owner doors prove one: a co-owner on their own full slip
/// included) when that proof belongs to this vault and names the handle's own actor. `None` for
/// any other caller, who then acts as its verified agent or is refused, as before. Each door
/// still revalidates the proof it is given inside its own transaction: a read in the snapshot it
/// reads ([`SettingReadCaller::Owner`]), a change in its write.
fn owner_of(
    memory: &Memory<'_>,
    verb: &str,
    request_owner: impl FnOnce() -> Option<AuthenticatedOwner>,
) -> Option<AuthenticatedOwner> {
    if let Ok(owner) = memory.embedded_owner(verb) {
        return Some(owner);
    }
    if memory.actor_class() != EdgeActorClass::Human {
        return None;
    }
    request_owner()
        .filter(|owner| owner.actor_for_read(memory.vault()).ok() == Some(memory.actor()))
}

/// Who reads, through `memory`: the owner ([`owner_of`]), whose proof the read revalidates in
/// the snapshot it reads, else its verified agent.
fn reader_of(
    memory: &Memory<'_>,
    verb: &str,
    request_owner: impl FnOnce() -> Option<AuthenticatedOwner>,
) -> MemoryResult<SettingReadCaller> {
    if let Some(owner) = owner_of(memory, verb, request_owner) {
        return Ok(SettingReadCaller::Owner(owner));
    }
    agent_of(memory, verb).map(SettingReadCaller::Agent)
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
    setting_get_with_request_owner(memory, no_request_owner, input)
}

/// [`setting_get_embedded`] on a host door: `request_owner` is the live owner the host proves
/// from the request, asked only when the handle's own owner proof refuses a human caller.
///
/// # Errors
///
/// As [`setting_get_embedded`].
pub fn setting_get_with_request_owner(
    memory: &Memory<'_>,
    request_owner: impl FnOnce() -> Option<AuthenticatedOwner>,
    input: SettingGetRequest,
) -> MemoryResult<SettingView> {
    let reader = reader_of(memory, GET, request_owner)?;
    Ok(memory
        .vault()
        .setting_view_for(&reader, &input.key, input.item.as_deref(), &input.at)?)
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
    setting_list_with_request_owner(memory, no_request_owner, input)
}

/// [`setting_list_embedded`] on a host door, with the owner the host proves from the request as
/// [`setting_get_with_request_owner`] takes it.
///
/// # Errors
///
/// As [`setting_list_embedded`].
pub fn setting_list_with_request_owner(
    memory: &Memory<'_>,
    request_owner: impl FnOnce() -> Option<AuthenticatedOwner>,
    input: SettingListRequest,
) -> MemoryResult<SettingCatalogue> {
    let reader = reader_of(memory, LIST, request_owner)?;
    let filter = SettingListFilter {
        prefix: input.prefix,
        class: input.class,
        at: input.at,
    };
    Ok(SettingCatalogue {
        keys: memory.vault().setting_catalogue_for(&reader, &filter)?,
    })
}

/// `vault.settings.set`: one row's change through [`Vault::set_setting`]: `applied`, or
/// `pending` with the check-in it waits on. The owner's applied change is signed on the main log
/// from the handle's act surface (stage 7a-1).
///
/// # Errors
///
/// BAD_REQUEST for a `check_in_ref` that is not 32 hex, and as [`Vault::set_setting`];
/// FORBIDDEN for a caller that is neither the owner nor an agent; storage errors.
pub fn setting_set_embedded(
    memory: &Memory<'_>,
    input: SettingSetRequest,
) -> MemoryResult<SetSettingOutcome> {
    setting_set_with_request_owner(memory, no_request_owner, input)
}

/// [`setting_set_embedded`] on a host door, with the owner the host proves from the request as
/// [`setting_get_with_request_owner`] takes it: that owner's change is the owner's, signed from
/// the handle's act surface like the embedded owner's.
///
/// # Errors
///
/// As [`setting_set_embedded`].
pub fn setting_set_with_request_owner(
    memory: &Memory<'_>,
    request_owner: impl FnOnce() -> Option<AuthenticatedOwner>,
    input: SettingSetRequest,
) -> MemoryResult<SetSettingOutcome> {
    let request = set_request(input)?;
    let vault: &Vault = memory.vault();
    if let Some(owner) = owner_of(memory, SET, request_owner) {
        // The owner's change is signed from where the owner's request reached this install, as
        // the host bound it on the handle (an embedded handle's own call names this install).
        let request = SetSetting {
            surface: Some(memory.owner_surface()),
            ..request
        };
        return Ok(vault.set_setting(SettingCaller::Owner(&owner), request)?);
    }
    let agent = agent_of(memory, SET)?;
    Ok(vault.set_setting(SettingCaller::Agent(agent), request)?)
}

/// `vault.settings.accept_defaults`: the owner's yes to a pack's waiting proposal, through
/// [`Vault::accept_pack_defaults`]. An owner act: a pack holds no widening power, and no agent
/// accepts a default for the owner.
///
/// # Errors
///
/// FORBIDDEN for a caller that is not the owner; BAD_REQUEST as [`Vault::accept_pack_defaults`]
/// (no such proposal, or a default that moved since); storage errors.
pub fn setting_accept_defaults_embedded(
    memory: &Memory<'_>,
    input: SettingAcceptDefaultsRequest,
) -> MemoryResult<SettingAcceptedDefaults> {
    setting_accept_defaults_with_request_owner(memory, no_request_owner, input)
}

/// [`setting_accept_defaults_embedded`] on a host door, with the owner the host proves from the
/// request as [`setting_get_with_request_owner`] takes it.
///
/// # Errors
///
/// As [`setting_accept_defaults_embedded`].
pub fn setting_accept_defaults_with_request_owner(
    memory: &Memory<'_>,
    request_owner: impl FnOnce() -> Option<AuthenticatedOwner>,
    input: SettingAcceptDefaultsRequest,
) -> MemoryResult<SettingAcceptedDefaults> {
    let owner = owner_of(memory, ACCEPT_DEFAULTS, request_owner).ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{ACCEPT_DEFAULTS} takes the vault owner"),
            &["Call as the owner: a pack's looser default waits for the owner's yes."],
        )
    })?;
    let mut keys = memory
        .vault()
        .accept_pack_defaults(&owner, &input.pack, &input.proposal)?;
    keys.sort();
    Ok(SettingAcceptedDefaults { keys })
}

fn set_request(input: SettingSetRequest) -> MemoryResult<SetSetting> {
    let check_in_ref = input
        .check_in_ref
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| bad_request("check_in_ref is a check-in's 32 hex id".to_owned()))?;
    let mode = match (input.pin, input.carried) {
        (true, true) => {
            return Err(bad_request(
                "a row is a pin or a carried row, not both".to_owned(),
            ));
        }
        (true, false) => SettingMode::Pin,
        (false, true) => SettingMode::Carried,
        (false, false) => SettingMode::Value,
    };
    Ok(SetSetting {
        key: input.key,
        item: input.item,
        scope: input.scope,
        mode,
        value: input.value.filter(|value| !value.is_null()),
        expected_revision: input.expected_revision,
        why: input.why,
        check_in_ref,
        weight_runs: input.weight_runs,
        surface: None,
    })
}
