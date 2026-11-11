//! The engine-control knob verbs (untangle 6.6d; Engine S66-CALLS, 9 Nov
//! 23:59; owner 9 Nov 22:47, "every substrate read and control is a public
//! verb behind a grant"). One verb per knob a holder of `engine.controls`
//! may change (6.6b's holder doors), each a host door:
//! `vault.consolidation.selection_timing.set`,
//! `vault.consolidation.strength.set`, `vault.curator.cadence.set`,
//! `vault.proactivity.period.set`, `vault.evaluation.retune_thresholds.set`,
//! `vault.stewardship.rules.period.set`, `vault.dreamer.projector.set`,
//! `vault.sieve.budgets.lower` and `vault.free_time.schedule.set`.
//!
//! Each runs as the vault owner under its proof, or as a holder of
//! `engine.controls`; the knob's writer checks which in the write itself
//! ([`crate::Vault::apply_engine_control`]), so a narrowed or revoked grant
//! changes nothing from its next call on. Every change writes the
//! engine-control receipt, which each verb answers with and
//! `vault.engine.controls.changes` lists for the owner. Owner pins and the
//! owner's caps stand: the sieve's budgets only go down through
//! `vault.sieve.budgets.lower`, and `vault.free_time.schedule.set` moves
//! only the schedule of a policy that stands (S66B-BUDGETS B1 = A, B2 = A).
//! The owner keeps `vault.sieve.policy.set` and `vault.free_time.policy.set`
//! for the whole rows.
use serde::{Deserialize, Serialize};

use super::EngineControlChangeEntry;
use crate::dreamer_consolidation::strength::ConsolidationStrengthPolicy;
use crate::dreamer_runner::FreeTimeSchedule;
use crate::dreamer_runner::maintenance::RetuneThresholds;
use crate::dreamer_wake::{ProjectorPolicy, SievePassBudgets};
use crate::federation::EngineControlActor;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EntityId, Error, Result, Vault};

/// `vault.consolidation.selection_timing.set`'s input: how long a claim
/// soaks before consolidation selects it, and the recency window, in
/// milliseconds. Every other selection field stays as it stands.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationSelectionTimingSetRequest {
    pub soak_ms: u64,
    pub recency_window_ms: u64,
}

/// `vault.consolidation.strength.set`'s input: the strength under which a
/// quiet claim is archived (0 to 1), and how long a claim stays quiet before
/// it may be, in milliseconds (above 0).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationStrengthSetRequest {
    pub archive_below: f64,
    pub quiet_ms: u64,
}

/// `vault.curator.cadence.set`'s input: the minimum age of what the curator
/// reviews and the period between its passes, in seconds. The factors and
/// the questions stay as the owner set them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CuratorCadenceSetRequest {
    pub minimum_age_secs: u64,
    pub cadence_secs: u64,
}

/// `vault.proactivity.period.set`'s input: the proactivity digest's period,
/// in seconds (above 0). Its grouping, its urgent flags and the
/// presentation stay as the owner set them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProactivityPeriodSetRequest {
    pub period_secs: u64,
}

/// `vault.evaluation.retune_thresholds.set`'s input: the score regression
/// (0 to 1) past which each tuned artifact is retuned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetuneThresholdsSetRequest {
    pub prompts_score_regression: f64,
    pub weights_score_regression: f64,
    pub manifest_thresholds_score_regression: f64,
}

/// `vault.stewardship.rules.period.set`'s input: how often the standing
/// rule `rule` falls due, in seconds. The rule's person, draft route and
/// `since` stay as the owner set them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StewardshipRulePeriodSetRequest {
    /// The rule's id, as the rule set names it.
    pub rule: String,
    pub every_secs: u64,
}

/// `vault.dreamer.projector.set`'s input: how many new statements the wake
/// projector waits for before it projects a turn.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerProjectorSetRequest {
    pub min_new_statements: u32,
}

/// `vault.sieve.budgets.lower`'s input: the sieve's three per-pass work
/// budgets, each at or below its value in force.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SieveBudgetsLowerRequest {
    /// Turns one pass reads.
    pub max_turns_per_pass: u32,
    /// Timeline rows one pass's forward scan steps over.
    pub max_scan_per_pass: u32,
    /// Bytes of turn text one pass reads.
    pub max_text_bytes_per_pass: u32,
}

/// `vault.free_time.schedule.set`'s input: the agent (32 hex) whose standing
/// free-time policy moves, the revision the caller read, and the new
/// schedule. The policy's units, split and shown cap stay the owner's.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeScheduleSetRequest {
    pub agent: String,
    pub expected_revision: u64,
    pub schedule: FreeTimeSchedule,
}

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

/// `vault.consolidation.selection_timing.set` as `actor`.
///
/// # Errors
///
/// An actor that is neither the owner nor a live holder; a timing the
/// selection row refuses; store failures.
pub fn set_consolidation_selection_timing_as(
    vault: &Vault,
    actor: EngineControlActor<'_>,
    input: ConsolidationSelectionTimingSetRequest,
) -> Result<EngineControlChangeEntry> {
    let id =
        vault.set_consolidation_selection_timing_by(actor, input.soak_ms, input.recency_window_ms)?;
    receipt(vault, id)
}

/// `vault.consolidation.selection_timing.set` on a bound handle.
///
/// # Errors
///
/// As [`set_consolidation_selection_timing_as`].
pub fn set_consolidation_selection_timing_embedded(
    memory: &Memory<'_>,
    input: ConsolidationSelectionTimingSetRequest,
) -> MemoryResult<EngineControlChangeEntry> {
    as_controller(
        memory,
        "vault.consolidation.selection_timing.set",
        |vault, actor| set_consolidation_selection_timing_as(vault, actor, input),
    )
}

/// `vault.consolidation.strength.set` as `actor`.
///
/// # Errors
///
/// An actor that is neither the owner nor a live holder; a strength outside
/// 0 to 1 or a quiet time of 0; store failures.
pub fn set_consolidation_strength_as(
    vault: &Vault,
    actor: EngineControlActor<'_>,
    input: ConsolidationStrengthSetRequest,
) -> Result<EngineControlChangeEntry> {
    let id = vault.set_consolidation_strength_policy_by(
        actor,
        &ConsolidationStrengthPolicy {
            archive_below: input.archive_below,
            quiet_ms: input.quiet_ms,
        },
    )?;
    receipt(vault, id)
}

/// `vault.consolidation.strength.set` on a bound handle.
///
/// # Errors
///
/// As [`set_consolidation_strength_as`].
pub fn set_consolidation_strength_embedded(
    memory: &Memory<'_>,
    input: ConsolidationStrengthSetRequest,
) -> MemoryResult<EngineControlChangeEntry> {
    as_controller(memory, "vault.consolidation.strength.set", |vault, actor| {
        set_consolidation_strength_as(vault, actor, input)
    })
}

/// `vault.curator.cadence.set` as `actor`.
///
/// # Errors
///
/// An actor that is neither the owner nor a live holder; a cadence the
/// rubric refuses; store failures.
pub fn set_curator_cadence_as(
    vault: &Vault,
    actor: EngineControlActor<'_>,
    input: CuratorCadenceSetRequest,
) -> Result<EngineControlChangeEntry> {
    let id = vault.set_curator_cadence_by(actor, input.minimum_age_secs, input.cadence_secs)?;
    receipt(vault, id)
}

/// `vault.curator.cadence.set` on a bound handle.
///
/// # Errors
///
/// As [`set_curator_cadence_as`].
pub fn set_curator_cadence_embedded(
    memory: &Memory<'_>,
    input: CuratorCadenceSetRequest,
) -> MemoryResult<EngineControlChangeEntry> {
    as_controller(memory, "vault.curator.cadence.set", |vault, actor| {
        set_curator_cadence_as(vault, actor, input)
    })
}

/// `vault.proactivity.period.set` as `actor`.
///
/// # Errors
///
/// An actor that is neither the owner nor a live holder; a period of 0;
/// store failures.
pub fn set_proactivity_period_as(
    vault: &Vault,
    actor: EngineControlActor<'_>,
    input: ProactivityPeriodSetRequest,
) -> Result<EngineControlChangeEntry> {
    let id = vault.set_proactivity_period_by(actor, input.period_secs)?;
    receipt(vault, id)
}

/// `vault.proactivity.period.set` on a bound handle.
///
/// # Errors
///
/// As [`set_proactivity_period_as`].
pub fn set_proactivity_period_embedded(
    memory: &Memory<'_>,
    input: ProactivityPeriodSetRequest,
) -> MemoryResult<EngineControlChangeEntry> {
    as_controller(memory, "vault.proactivity.period.set", |vault, actor| {
        set_proactivity_period_as(vault, actor, input)
    })
}

/// `vault.evaluation.retune_thresholds.set` as `actor`.
///
/// # Errors
///
/// An actor that is neither the owner nor a live holder; a threshold
/// outside 0 to 1; store failures.
pub fn set_retune_thresholds_as(
    vault: &Vault,
    actor: EngineControlActor<'_>,
    input: RetuneThresholdsSetRequest,
) -> Result<EngineControlChangeEntry> {
    let id = vault.set_retune_thresholds_by(
        actor,
        &RetuneThresholds {
            prompts_score_regression: input.prompts_score_regression,
            weights_score_regression: input.weights_score_regression,
            manifest_thresholds_score_regression: input.manifest_thresholds_score_regression,
        },
    )?;
    receipt(vault, id)
}

/// `vault.evaluation.retune_thresholds.set` on a bound handle.
///
/// # Errors
///
/// As [`set_retune_thresholds_as`].
pub fn set_retune_thresholds_embedded(
    memory: &Memory<'_>,
    input: RetuneThresholdsSetRequest,
) -> MemoryResult<EngineControlChangeEntry> {
    as_controller(
        memory,
        "vault.evaluation.retune_thresholds.set",
        |vault, actor| set_retune_thresholds_as(vault, actor, input),
    )
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
    as_controller(memory, "vault.stewardship.rules.period.set", |vault, actor| {
        set_stewardship_rule_period_as(vault, actor, input)
    })
}

/// `vault.dreamer.projector.set` as `actor`.
///
/// # Errors
///
/// An actor that is neither the owner nor a live holder; store failures.
pub fn set_dreamer_projector_as(
    vault: &Vault,
    actor: EngineControlActor<'_>,
    input: DreamerProjectorSetRequest,
) -> Result<EngineControlChangeEntry> {
    let id = vault.set_dreamer_projector_policy_by(
        actor,
        ProjectorPolicy {
            min_new_statements: input.min_new_statements,
        },
    )?;
    receipt(vault, id)
}

/// `vault.dreamer.projector.set` on a bound handle.
///
/// # Errors
///
/// As [`set_dreamer_projector_as`].
pub fn set_dreamer_projector_embedded(
    memory: &Memory<'_>,
    input: DreamerProjectorSetRequest,
) -> MemoryResult<EngineControlChangeEntry> {
    as_controller(memory, "vault.dreamer.projector.set", |vault, actor| {
        set_dreamer_projector_as(vault, actor, input)
    })
}

/// `vault.sieve.budgets.lower` as `actor`: each budget at or below its
/// value in force (S66B-BUDGETS B1 = A).
///
/// # Errors
///
/// An actor that is neither the owner nor a live holder; a budget above its
/// value in force, or a row the sieve policy refuses; store failures.
pub fn lower_sieve_budgets_as(
    vault: &Vault,
    actor: EngineControlActor<'_>,
    input: SieveBudgetsLowerRequest,
) -> Result<EngineControlChangeEntry> {
    let id = vault.lower_dreamer_sieve_budgets_by(
        actor,
        SievePassBudgets {
            max_turns_per_pass: input.max_turns_per_pass,
            max_scan_per_pass: input.max_scan_per_pass,
            max_text_bytes_per_pass: input.max_text_bytes_per_pass,
        },
    )?;
    receipt(vault, id)
}

/// `vault.sieve.budgets.lower` on a bound handle.
///
/// # Errors
///
/// As [`lower_sieve_budgets_as`].
pub fn lower_sieve_budgets_embedded(
    memory: &Memory<'_>,
    input: SieveBudgetsLowerRequest,
) -> MemoryResult<EngineControlChangeEntry> {
    as_controller(memory, "vault.sieve.budgets.lower", |vault, actor| {
        lower_sieve_budgets_as(vault, actor, input)
    })
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
