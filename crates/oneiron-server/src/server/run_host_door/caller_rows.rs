//! The lane-economy host-door rows a turn program's run reaches as its own
//! agent ([RSI-PROJECT-WORKFLOW]): `vault.arms.admit`,
//! `vault.arms.forecast`, `vault.arms.get` and `vault.arms.units.reserve`
//! (proof `verb_grant_caller`), and `vault.gpu.jobs.status` (proof
//! `gpu_job_caller`). Exactly these five: every other host-door row stays
//! refused on a program's door, as before.
//!
//! The caller is the program's waking agent on its own handle, with no
//! owner proof and no credential made up for it: no owner fallback. Each
//! call reads the agent's Grant again, never a Grant cached at arm or at an
//! earlier stage. The engine admits the agent before the row's verb hooks
//! fire, as the facade does for a credential, and the row's own act admits
//! it again in its read. `vault.arms.units.reserve` starts the claim's one
//! job through the facade row's own body.

use oneiron::experiment_arm::{
    ARMS_ADMIT_VERB, ARMS_FORECAST_VERB, ARMS_GET_VERB, ARMS_UNITS_RESERVE_VERB, arm_admit_as,
    arm_forecast_as, arm_get_as,
};
use oneiron::gpu_job::GpuJobVerb;
use oneiron::memory::{HostWriteOrigin, Memory, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{self, AgentVerb};
use oneiron::task_verb::verb_hook_boundary;
use oneiron::{EntityId, WriteActor};
use serde_json::Value;

use super::{SyncServer, agent_memory, decode, encode, internal};
use crate::api::{gpu_job_status_for_agent, reserve_and_start_unit};
use crate::gpu_host::now_ms;

/// One of the five rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallerRow {
    ArmsAdmit,
    ArmsForecast,
    ArmsGet,
    ArmsUnitsReserve,
    GpuJobsStatus,
}

impl CallerRow {
    /// The row `verb` is, if it is one of the five.
    fn of(verb: AgentVerb) -> Option<Self> {
        let name = verb.as_str();
        match name {
            ARMS_ADMIT_VERB => Some(Self::ArmsAdmit),
            ARMS_FORECAST_VERB => Some(Self::ArmsForecast),
            ARMS_GET_VERB => Some(Self::ArmsGet),
            ARMS_UNITS_RESERVE_VERB => Some(Self::ArmsUnitsReserve),
            _ if GpuJobVerb::from_name(name) == Some(GpuJobVerb::Status) => {
                Some(Self::GpuJobsStatus)
            }
            _ => None,
        }
    }

    /// The engine's admission of the agent on `memory` to this row, before
    /// its verb hooks fire: its own live Grant listing the verb, read now.
    fn admits(self, memory: &Memory<'_>, verb: &str) -> MemoryResult<()> {
        match self {
            Self::GpuJobsStatus => memory.gpu_job_admits(None, GpuJobVerb::Status),
            _ => memory.verb_grant_caller_admits(None, verb).map(drop),
        }
    }

    /// The row's act for the agent on `memory`, with no owner proof.
    fn act(self, server: &SyncServer, memory: &Memory<'_>, input: Value) -> MemoryResult<Value> {
        match self {
            Self::ArmsAdmit => encode(arm_admit_as(memory, None, &decode(input)?, now_ms())?),
            Self::ArmsForecast => encode(arm_forecast_as(memory, None, &decode(input)?, now_ms())?),
            Self::ArmsGet => encode(arm_get_as(memory, None, &decode(input)?)?),
            Self::ArmsUnitsReserve => encode(reserve_and_start_unit(
                server,
                memory,
                None,
                &decode(input)?,
            )?),
            Self::GpuJobsStatus => {
                encode(gpu_job_status_for_agent(server, memory, &decode(input)?)?)
            }
        }
    }
}

/// Whether `verb` is one of the five rows a program's door serves here.
pub(super) fn is_caller_row(verb: AgentVerb) -> bool {
    CallerRow::of(verb).is_some()
}

/// Answers one of the five rows for the program's agent `actor`, on a fresh
/// surface under the agent that carries `origin` and `invocation`, with its
/// verb hooks once around it. The rows answer with no listed rows: arms and
/// GPU jobs live in side tables. Blocking: call it on a blocking thread of
/// the server's runtime.
pub(super) fn answer(
    server: &SyncServer,
    actor: WriteActor,
    origin: &HostWriteOrigin,
    invocation: InvocationId,
    verb: AgentVerb,
    input: Value,
) -> MemoryResult<(Value, Option<Vec<EntityId>>)> {
    let row = CallerRow::of(verb).ok_or_else(|| internal(verb))?;
    let memory = agent_memory(server, actor, origin, invocation);
    let name = verb.as_str();
    row.admits(&memory, name)?;
    let output =
        verb_hook_boundary::row(&memory, &oneiron::verbs::VERB_TABLE, name, input, |input| {
            sdk::validate_input(name, &input)?;
            row.act(server, &memory, input)
        })?;
    Ok((output, Some(Vec::new())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_five_rows_are_caller_rows() {
        let rows: Vec<&str> = AgentVerb::ALL
            .iter()
            .copied()
            .filter(|verb| is_caller_row(*verb))
            .map(AgentVerb::as_str)
            .collect();
        assert_eq!(
            rows.len(),
            5,
            "exactly the five lane-economy rows: {rows:?}"
        );
        for name in [
            "vault.arms.admit",
            "vault.arms.forecast",
            "vault.arms.get",
            "vault.arms.units.reserve",
            "vault.gpu.jobs.status",
        ] {
            assert!(rows.contains(&name), "{name} is served: {rows:?}");
        }
    }
}
