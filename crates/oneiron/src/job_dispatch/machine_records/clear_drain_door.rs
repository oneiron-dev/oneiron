//! Door 12, `vault.machines.execution.clear_drain` (pass 33 row R4, 7.9; pass 34, 2.4): clears
//! the issuer's drain of one machine, so it takes new jobs again. Who may is the owner's setting
//! `machines.drain.clear_by` for that machine (declared in `machine_policy`), judged at each
//! call:
//! - `after_readiness_check` (the default): the owner. A passed readiness check of row Q4 also
//!   clears the drain by itself, when the node ran it after the issuer read the drain; the
//!   issuer's job worker sees it in the machine's `Node` answer on a work-order pass
//!   (`Vault::clear_machine_job_drain_after_check`);
//! - `owner`: the vault owner under their own proof;
//! - `grants [...]`: the owner, or an agent whose own live Grant is listed there and names the
//!   verb;
//! - `person_at_box`: nobody through a verb.
//!
//! It clears only the issuer's half. The node's own drain is cleared at the box, whatever this
//! says, and no request on the wire clears it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::machine_policy::DrainClearBy;
use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError,
    MemoryResult,
};

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

/// Door 12 for this handle's caller: the owner under `owner`, or an agent under its own Grant,
/// as `machines.drain.clear_by` allows for the machine.
///
/// # Errors
///
/// `forbidden` for a caller the verb or the setting does not admit; `bad_request` for a
/// machine id that is not lower hex; `invalid_state` for a machine the issuer has not drained;
/// a store failure.
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
    let was = vault
        .machine_job_drained(machine)?
        .map(|drain| drain.why)
        .unwrap_or_default();
    let now_ms = crate::unix_millis_now();
    match vault.clear_machine_job_drain(machine, now_ms)? {
        Ok(_) => Ok(MachineDrainCleared {
            machine: input.machine.clone(),
            was_drained_because: was,
            cleared_at_ms: now_ms,
        }),
        Err(refusal) => Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!("{CLEAR_DRAIN_VERB}: {refusal}"),
            &["Only a machine the issuer drained has a drain to clear."],
        )),
    }
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
