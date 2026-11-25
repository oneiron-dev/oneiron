//! Door 12, `vault.machines.execution.clear_drain` (pass 33 row R4, 7.9; pass 34, 2.4): clears
//! the issuer's drain of one machine, so it takes new jobs again. Who may is the owner's setting
//! `machines.drain.clear_by` for that machine (declared in `machine_policy`), judged at each
//! call:
//! - `after_readiness_check` (the default): the owner, and the machine's readiness check of row
//!   Q4 clears it by itself;
//! - `owner`: the vault owner under their own proof;
//! - `grants [...]`: the owner, or an agent whose own live Grant is listed there and names the
//!   verb;
//! - `person_at_box`: nobody through a verb.
//!
//! It clears the issuer's half. The owner's call under `owner` or `grants` also writes the
//! owner's setting `machines.drain.cleared_at` for the machine, in the same write: a signed act
//! that reaches the machine with the vault's history, whose execution node then clears its own
//! drain at its next readiness tick ([`NodeDrainClear::OwnerClearSent`]). An agent's call clears
//! the issuer's half only. No request on the wire clears the node's drain. Each call clears the
//! issuer's drain it read, never one set again since.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use super::{ClearDrainRefusal, MachineDrain};
use crate::machine_policy::setting_keys::{DRAIN_CLEAR_BY, DRAIN_CLEARED_AT};
use crate::machine_policy::{DrainClearBy, machine_item};
use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError,
    MemoryResult,
};
use crate::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use crate::{EntityId, Vault};

/// The verb's name, as its row and the Grants name it.
pub const CLEAR_DRAIN_VERB: &str = "vault.machines.execution.clear_drain";

/// `vault.machines.execution.clear_drain`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineDrainClearRequest {
    /// The machine's id, lower hex.
    pub machine: String,
}

/// What the door cleared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MachineDrainCleared {
    pub machine: String,
    /// Why the issuer had drained it.
    pub was_drained_because: String,
    pub cleared_at_ms: u64,
    /// What becomes of the machine's own drain.
    pub node_drain: NodeDrainClear,
}

/// What door 12's call does for the machine's own drain, which its execution node keeps beside
/// the issuer's (pass 34, 2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeDrainClear {
    /// The owner's clear is written as the owner's `machines.drain.cleared_at` for the machine.
    /// Once the machine has the vault's history, its next readiness tick clears a drain that
    /// began before `cleared_at_ms`. A machine whose last readiness check failed keeps its drain
    /// until a check passes, and a box whose file keeps the clear for the person at the box keeps
    /// it.
    OwnerClearSent,
    /// Under `after_readiness_check` the machine clears its own drain when a readiness check
    /// passes, or a person clears it at the box (`oneiron execution-node resume`).
    AfterReadinessCheck,
    /// An agent's call clears the issuer's drain only: the machine's own drain waits for the
    /// owner's clear or a person at the box. A later build carries a listed Grant's clear to the
    /// machine.
    OwnerOrBox,
}

fn forbidden(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{CLEAR_DRAIN_VERB}: {why}"),
        &["The machine's setting machines.drain.clear_by names who may clear its drain."],
    )
}

/// Whether `caller` may clear a drain under `clear_by`.
fn admits(clear_by: &DrainClearBy, caller: &VerbGrantCaller) -> Result<(), &'static str> {
    match (clear_by, caller) {
        (DrainClearBy::PersonAtBox, _) => Err("clear_by_person_at_box"),
        (_, VerbGrantCaller::Owner) => Ok(()),
        (DrainClearBy::Grants { grants }, VerbGrantCaller::Agent { grant, .. })
            if grants.contains(grant) =>
        {
            Ok(())
        }
        (DrainClearBy::Grants { .. }, VerbGrantCaller::Agent { .. }) => Err("grant_not_listed"),
        (
            DrainClearBy::Owner | DrainClearBy::AfterReadinessCheck,
            VerbGrantCaller::Agent { .. },
        ) => Err("owner_only"),
    }
}

fn not_drained(refusal: ClearDrainRefusal) -> MemoryError {
    let hints: &[&str] = match refusal {
        ClearDrainRefusal::NotDrained => &[
            "Only a machine the issuer drained has a drain to clear.",
            "A drain the machine keeps by itself clears through the owner's setting machines.drain.cleared_at for the machine.",
        ],
        ClearDrainRefusal::DrainedAgain => &[
            "The issuer drained the machine again after this call read its drain: call again to clear the drain as it stands now.",
        ],
    };
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{CLEAR_DRAIN_VERB}: {refusal}"),
        hints,
    )
}

/// The issuer's half alone: clears `was`, the drain the door read.
///
/// # Errors
///
/// `invalid_state` for a drain cleared or set again since the door read it; a store failure.
fn clear_issuer_drain(
    vault: &Vault,
    machine: EntityId,
    was: &MachineDrain,
    now_ms: u64,
) -> MemoryResult<()> {
    vault
        .clear_machine_job_drain(machine, was, now_ms)?
        .map(drop)
        .map_err(not_drained)
}

/// The owner's clear of both halves in one write, so neither applies without the other: the
/// owner's `machines.drain.cleared_at` for `machine` at `now_ms`, written under the owner's proof
/// as every owner change of a setting is (signed, so it travels to the machine), and the
/// issuer's clear of `was`. The owner's presence is asked before the write opens. Inside it the
/// door reads again what the ask may have outlived: the machine's `machines.drain.clear_by`, and
/// the issuer's drain, which must still be `was`.
///
/// # Errors
///
/// As [`Vault::set_setting`]; `forbidden` for a `clear_by` that became `person_at_box`;
/// `invalid_state` for a drain cleared or set again meanwhile, or an owner's change that did not
/// apply. Each leaves both halves as they were.
fn clear_both_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    machine: EntityId,
    was: &MachineDrain,
    now_ms: u64,
) -> MemoryResult<()> {
    let item = machine_item(machine);
    let request = SetSetting {
        item: Some(item.clone()),
        why: Some(format!("{CLEAR_DRAIN_VERB}: the owner cleared the drain")),
        ..SetSetting::vault_value(DRAIN_CLEARED_AT.spec.name, serde_json::json!(now_ms))
    };
    vault.set_setting_with(
        SettingCaller::Owner(owner),
        request,
        || {},
        |txn, outcome| {
            if let SetSettingOutcome::Pending { check_in } = outcome {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    format!("{CLEAR_DRAIN_VERB}: the owner's clear waits on check-in {check_in}"),
                    &[],
                ));
            }
            let clear_by = DRAIN_CLEAR_BY.read_in_txn(vault, txn, &[], Some(&item))?.value;
            admits(&clear_by, &VerbGrantCaller::Owner).map_err(forbidden)?;
            vault
                .clear_machine_job_drain_in_txn(txn, machine, was, now_ms)?
                .map_err(not_drained)
        },
    )?;
    Ok(())
}

/// Door 12 for this handle's caller: the owner under `owner`, or an agent under its own Grant,
/// as `machines.drain.clear_by` allows for the machine. The owner's call under `owner` or
/// `grants` writes the owner's clear for the machine's own drain and clears the issuer's in one
/// write, so a refused call clears neither.
///
/// # Errors
///
/// `forbidden` for a caller the verb or the setting does not admit; `bad_request` for a
/// machine id that is not lower hex; `invalid_state` for a machine the issuer has not drained,
/// a drain cleared or set again since the call read it, or an owner's clear that did not apply;
/// the owner's setting write's refusal (a proof that no longer holds, or presence the owner did
/// not give); a store failure.
pub fn clear_drain_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &MachineDrainClearRequest,
) -> MemoryResult<MachineDrainCleared> {
    let caller = memory.verb_grant_caller_admits(owner, CLEAR_DRAIN_VERB)?;
    let machine = EntityId::from_hex(&input.machine)
        .ok()
        .filter(|machine| machine.to_hex() == input.machine)
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_BAD_REQUEST,
                format!("{CLEAR_DRAIN_VERB}: machine must be a machine id in lower hex"),
                &[],
            )
        })?;
    let vault = memory.vault();
    let settings = vault.machine_job_settings(machine)?;
    admits(&settings.clear_by, &caller).map_err(forbidden)?;
    let Some(was) = vault.machine_job_drained(machine)? else {
        return Err(not_drained(ClearDrainRefusal::NotDrained));
    };
    let now_ms = crate::unix_millis_now();
    let node_drain = match (&settings.clear_by, caller, owner) {
        (DrainClearBy::AfterReadinessCheck, ..) => {
            clear_issuer_drain(vault, machine, &was, now_ms)?;
            NodeDrainClear::AfterReadinessCheck
        }
        (_, VerbGrantCaller::Owner, Some(owner)) => {
            clear_both_as_owner(vault, owner, machine, &was, now_ms)?;
            NodeDrainClear::OwnerClearSent
        }
        _ => {
            clear_issuer_drain(vault, machine, &was, now_ms)?;
            NodeDrainClear::OwnerOrBox
        }
    };
    Ok(MachineDrainCleared {
        machine: input.machine.clone(),
        was_drained_because: was.why,
        cleared_at_ms: now_ms,
        node_drain,
    })
}

/// Door 12 on a bound handle: the embedded owner under its own proof, any other caller under
/// its own Grant.
///
/// # Errors
///
/// As [`clear_drain_as`].
pub fn clear_drain_embedded(
    memory: &Memory<'_>,
    input: &MachineDrainClearRequest,
) -> MemoryResult<MachineDrainCleared> {
    let owner = memory.embedded_owner(CLEAR_DRAIN_VERB).ok();
    clear_drain_as(memory, owner.as_ref(), input)
}
