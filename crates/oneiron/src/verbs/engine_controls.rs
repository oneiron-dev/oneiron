//! The engine-control knob verbs (untangle 6.6d; Engine S66-CALLS, 9 Nov
//! 23:59; owner 9 Nov 22:47, "every substrate read and control is a public
//! verb behind a grant"). One verb per knob a holder of `engine.controls`
//! may change (6.6b's holder doors), each a host door:
//! `vault.stewardship.rules.period.set`, `vault.free_time.schedule.set`, and
//! (6.6f) `vault.settings.snapshot_read.lower`. The projector policy, the
//! sieve's budgets, the wake policy, the consolidation selection's timing,
//! the consolidation strength policy, the curator's cadence and the retune
//! thresholds are settings: a holder moves them through `vault.settings.set`.
//!
//! Each runs as the vault owner under its proof, or as a holder of
//! `engine.controls`; the knob's writer checks which in the write itself
//! ([`crate::Vault::apply_engine_control`]), so a narrowed or revoked grant
//! changes nothing from its next call on. Every change writes the
//! engine-control receipt, which each verb answers with and
//! `vault.engine.controls.changes` lists for the owner. Owner pins and the
//! owner's caps stand: `vault.free_time.schedule.set` moves only the
//! schedule of a policy that stands (S66B-BUDGETS B2 = A). The snapshot
//! bounds only go down through `vault.settings.snapshot_read.lower`
//! (SNAPSHOT-SETTINGS-IN-6.6). The owner keeps `vault.free_time.policy.set`
//! and `vault.settings.snapshot_read.replace` for the whole rows.

use super::EngineControlChangeEntry;
use crate::federation::EngineControlActor;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::settings::snapshot_read::SnapshotReadSettings;
use crate::{EntityId, Error, Result, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::engine_controls::{
    FreeTimeScheduleSetRequest, StewardshipRulePeriodSetRequest,
};

/// The receipt the engine-control door wrote under `id`.
fn receipt(vault: &Vault, id: EntityId) -> Result<EngineControlChangeEntry> {
    Ok(EngineControlChangeEntry {
        id,
        change: vault.engine_control_change(id)?,
    })
}

/// Runs `act` as `memory`'s caller: the embedded owner under its own proof,
/// any other caller as a holder of `engine.controls`, which the knob's
/// writer checks.
fn as_controller<T>(
    memory: &Memory<'_>,
    verb: &str,
    act: impl FnOnce(&Vault, EngineControlActor<'_>) -> Result<T>,
) -> MemoryResult<T> {
    let vault = memory.vault();
    match memory.embedded_owner(verb) {
        Ok(owner) => act(vault, EngineControlActor::Owner(&owner)),
        Err(_) => act(vault, EngineControlActor::Holder(memory.actor())),
    }
    .map_err(MemoryError::from)
}

/// `vault.stewardship.rules.period.set` as `actor`.
///
/// # Errors
///
/// An actor that is neither the owner nor a live holder; an unknown rule or
/// a period the rule refuses; store failures.
pub fn set_stewardship_rule_period_as(
    vault: &Vault,
    actor: EngineControlActor<'_>,
    input: StewardshipRulePeriodSetRequest,
) -> Result<EngineControlChangeEntry> {
    let id = vault.set_stewardship_rule_period_by(actor, &input.rule, input.every_secs)?;
    receipt(vault, id)
}

/// `vault.stewardship.rules.period.set` on a bound handle.
///
/// # Errors
///
/// As [`set_stewardship_rule_period_as`].
pub fn set_stewardship_rule_period_embedded(
    memory: &Memory<'_>,
    input: StewardshipRulePeriodSetRequest,
) -> MemoryResult<EngineControlChangeEntry> {
    as_controller(
        memory,
        "vault.stewardship.rules.period.set",
        |vault, actor| set_stewardship_rule_period_as(vault, actor, input),
    )
}

/// `vault.settings.snapshot_read.lower` as `actor`: the six snapshot
/// bounds, each at or below its value in force (SNAPSHOT-SETTINGS-IN-6.6,
/// in the shape of S66B-BUDGETS B1 = A). The input is the whole row, as the
/// owner's `vault.settings.snapshot_read.replace` takes it.
///
/// # Errors
///
/// An actor that is neither the owner nor a live holder of
/// `engine.controls.work_budget`; a bound above its value in force, or
/// bounds the row refuses; store failures.
pub fn lower_snapshot_read_bounds_as(
    vault: &Vault,
    actor: EngineControlActor<'_>,
    input: SnapshotReadSettings,
) -> Result<EngineControlChangeEntry> {
    let id = vault.lower_snapshot_read_bounds_by(actor, input)?;
    receipt(vault, id)
}

/// `vault.settings.snapshot_read.lower` on a bound handle.
///
/// # Errors
///
/// As [`lower_snapshot_read_bounds_as`].
pub fn lower_snapshot_read_bounds_embedded(
    memory: &Memory<'_>,
    input: SnapshotReadSettings,
) -> MemoryResult<EngineControlChangeEntry> {
    as_controller(
        memory,
        "vault.settings.snapshot_read.lower",
        |vault, actor| lower_snapshot_read_bounds_as(vault, actor, input),
    )
}

/// `vault.free_time.schedule.set` as `actor`: a holder of
/// `engine.controls` moves the schedule of a standing policy, recorded as
/// the holder's act through its grant (S66B-BUDGETS B2 = A). The owner sets
/// and clears whole policies at `vault.free_time.policy.set`, so this verb
/// refuses the owner.
///
/// # Errors
///
/// The owner; an agent id that is not 32 hex; the holder door's refusals
/// (no live `engine.controls`, no standing policy, an invalid schedule, an
/// unknown agent, a stale revision); store failures.
pub fn set_free_time_schedule_as(
    vault: &Vault,
    actor: EngineControlActor<'_>,
    input: FreeTimeScheduleSetRequest,
) -> Result<EngineControlChangeEntry> {
    let EngineControlActor::Holder(holder) = actor else {
        return Err(Error::InvalidConfig(
            "the owner sets free time at vault.free_time.policy.set".into(),
        ));
    };
    let agent = EntityId::from_hex(&input.agent)
        .map_err(|_| Error::InvalidConfig("an agent id is 32 hex".into()))?;
    let (id, _) = vault.set_free_time_schedule_as_holder(
        holder,
        agent,
        input.expected_revision,
        input.schedule,
    )?;
    receipt(vault, id)
}

/// `vault.free_time.schedule.set` on a bound handle.
///
/// # Errors
///
/// As [`set_free_time_schedule_as`].
pub fn set_free_time_schedule_embedded(
    memory: &Memory<'_>,
    input: FreeTimeScheduleSetRequest,
) -> MemoryResult<EngineControlChangeEntry> {
    as_controller(memory, "vault.free_time.schedule.set", |vault, actor| {
        set_free_time_schedule_as(vault, actor, input)
    })
}
