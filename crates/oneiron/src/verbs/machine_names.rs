//! The owner's machine list and his name for each machine as typed rows
//! (FIX [DEVICE-DISPLAY-NAME]): `vault.machines.list` and
//! `vault.machines.name.set`. Each runs the engine read or door its `GET
//! /v1/owner/machines` or `POST /v1/owner/machines/name` route runs
//! ([`Vault::machine_list`], [`Vault::set_machine_owner_name`]) under the
//! owner's proof, with the same reply fields.
//!
//! A machine is named by 32 hex, as `/v1/owner/machines/answer` names it.
//! Display only: a name moves no machine's profile, revision, role or reach,
//! and no authority, policy or routing decision reads it.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::{MachineOwnership, MachineRole};
use crate::consent::AuthenticatedOwner;
use crate::machine_names::{MachineListing, MachineNameSource};
use crate::memory::MemoryResult;
use oneiron_verb_wire::verbs::secret_custody::entity_id;

/// `vault.machines.list`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineListReply {
    /// Every machine the vault's authority names, this install's first.
    pub machines: Vec<MachineListItem>,
}

/// One machine of the owner's list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineListItem {
    /// The MACHINE row, 32 hex.
    pub machine: String,
    /// `phone` or `computer`.
    pub class: String,
    /// The owner's answer for it, as `GET /v1/owner/machines/answer` names
    /// it: `yours`, `work_school`, `rented`, `hosted_node`,
    /// `execution_node`, `removed` or `unanswered`; null with no roster
    /// chain.
    pub role: Option<String>,
    /// Whether it stands live here.
    pub live: bool,
    /// The name it is shown by.
    pub name: String,
    /// Where `name` comes from: `owner`, `reported`, `model` or `class`.
    pub name_source: MachineNameSource,
    /// The owner's own name for it.
    pub owner_name: Option<String>,
    /// The name it reports for itself.
    pub reported_name: Option<String>,
    /// The model it reports for itself.
    pub reported_model: Option<String>,
    /// Whether it is this install's own machine.
    pub this_install: bool,
    /// Its answer revision, 64 hex: what `POST /v1/owner/machines/answer`
    /// and `/machines/remove` take as `seen`. A name never moves it.
    pub revision: String,
}

/// `vault.machines.name.set`'s input: the body `POST
/// /v1/owner/machines/name` takes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineNameSetRequest {
    /// The MACHINE row, 32 hex.
    pub machine: String,
    /// The owner's one-line name for it; `null` or blank clears it, and the
    /// machine is shown by its own report or its class again.
    #[serde(default)]
    pub name: Option<String>,
}

/// Where a machine's name stands after the act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineNameSetReply {
    /// The machine as the list shows it now.
    pub machine: MachineListItem,
    /// The act's Gate receipt.
    pub receipt: String,
}

/// `vault.machines.list`: every machine the vault's authority names, with
/// the name each is shown by.
///
/// # Errors
/// Every refusal of [`Vault::machine_list`].
pub fn list_machines_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<MachineListReply> {
    Ok(MachineListReply {
        machines: vault
            .machine_list(owner)?
            .into_iter()
            .map(MachineListItem::from)
            .collect(),
    })
}

/// `vault.machines.name.set`: sets or clears the owner's name for one of his
/// machines.
///
/// # Errors
/// A `machine` that is not 32 hex; every refusal of
/// [`Vault::set_machine_owner_name`].
pub fn set_machine_name_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: MachineNameSetRequest,
) -> MemoryResult<MachineNameSetReply> {
    let machine = entity_id("machine", &input.machine)?;
    let set = vault.set_machine_owner_name(owner, machine, input.name.as_deref())?;
    Ok(MachineNameSetReply {
        machine: set.machine.into(),
        receipt: set.receipt,
    })
}

impl From<MachineListing> for MachineListItem {
    fn from(listing: MachineListing) -> Self {
        Self {
            machine: listing.machine.to_hex(),
            class: listing.class.wire().to_owned(),
            role: listing.role.map(|role| role_wire(role).to_owned()),
            live: listing.live,
            name: listing.name,
            name_source: listing.name_source,
            owner_name: listing.owner_name,
            reported_name: listing.reported_name,
            reported_model: listing.reported_model,
            this_install: listing.this_install,
            revision: oneiron_hex::encode(&listing.revision),
        }
    }
}

/// A role as the wire names it, as `/v1/owner/machines/answer` does.
fn role_wire(role: MachineRole) -> &'static str {
    match role {
        MachineRole::Owned(MachineOwnership::Yours) => "yours",
        MachineRole::Owned(MachineOwnership::WorkSchool) => "work_school",
        MachineRole::Owned(MachineOwnership::Rented) => "rented",
        MachineRole::HostedNode => "hosted_node",
        MachineRole::ExecutionNode => "execution_node",
        MachineRole::Removed => "removed",
        MachineRole::Unanswered => "unanswered",
    }
}
