//! The wave lane's quantum: the vault's operational pump limits, resolved
//! afresh, one bounded pump step, and its log line.
use std::sync::Arc;
use std::time::Duration;

use oneiron::{Vault, WavePlanner, WriteActor};

use super::factory::PassExecutorFactory;
use crate::wave_dispatch::{WaveDispatchLimits, WaveDispatchPass, WaveDispatchPump};

/// Resolve operational pump limits from a fresh vault policy snapshot. A
/// host-supplied selector can NARROW, never widen, the vault-owned ceilings.
pub(super) fn resolved_wave_limits(
    vault: &Vault,
    holder: Option<WaveDispatchLimits>,
) -> oneiron::Result<(WaveDispatchLimits, [u8; 32])> {
    let policy = vault.wave_handoff_policy()?;
    let selected = match holder {
        Some(value) => {
            value.validate()?;
            let mut requested = policy;
            requested.scan_limit = value.page_size;
            requested.retry_floor_ms =
                u64::try_from(value.retry_initial.as_millis()).map_err(|_| {
                    oneiron::Error::InvalidConfig("wave retry floor exceeds u64".into())
                })?;
            requested.retry_cap_ms = u64::try_from(value.retry_max.as_millis())
                .map_err(|_| oneiron::Error::InvalidConfig("wave retry cap exceeds u64".into()))?;
            policy.with_holder(Some(requested))?;
            value
        }
        None => WaveDispatchLimits {
            page_size: policy.scan_limit,
            retry_quantum: policy.scan_limit,
            retry_initial: Duration::from_millis(policy.retry_floor_ms),
            retry_max: Duration::from_millis(policy.retry_cap_ms),
        },
    };
    selected.validate()?;
    Ok((selected, policy.policy_frontier))
}

pub(super) struct WaveQuantum<'a, F> {
    pub(super) vault: &'a Vault,
    pub(super) pump: &'a mut WaveDispatchPump,
    pub(super) factory: &'a mut F,
    pub(super) planner: &'a Arc<dyn WavePlanner + Send + Sync>,
    pub(super) actor: WriteActor,
    pub(super) lease_owner: &'a str,
    pub(super) now: u64,
    pub(super) holder: Option<WaveDispatchLimits>,
    pub(super) frontier: &'a mut Option<[u8; 32]>,
}

pub(super) enum WaveQuantumError {
    Policy(oneiron::Error),
    Pump(oneiron::Error),
}

pub(super) fn run_wave_quantum<F: PassExecutorFactory>(
    input: WaveQuantum<'_, F>,
) -> std::result::Result<WaveDispatchPass, WaveQuantumError> {
    let WaveQuantum {
        vault,
        pump,
        factory,
        planner,
        actor,
        lease_owner,
        now,
        holder,
        frontier,
    } = input;
    let (limits, resolved_frontier) =
        resolved_wave_limits(vault, holder).map_err(WaveQuantumError::Policy)?;
    if *frontier != Some(resolved_frontier) {
        pump.set_limits(limits).map_err(WaveQuantumError::Policy)?;
        *frontier = Some(resolved_frontier);
    }
    pump.work_one(vault, factory, planner, actor, lease_owner, now)
        .map_err(WaveQuantumError::Pump)
}

/// Logs one wave quantum: counts, ids and closed reasons, never TASK text.
pub(super) fn report_wave_pass(pass: WaveDispatchPass) {
    tracing::trace!(progressed = pass.progressed,
        cursor = ?pass.next_cursor, retry = ?pass.earliest_retry,
        "wave dispatch pass");
    if let Some(statement) = &pass.statement {
        tracing::info!(
            tasks = statement.task_count,
            agents = statement.agent_count,
            consults = statement.consult_count,
            over_available = statement.over_available,
            ?statement,
            "wave plan applied"
        );
    }
    for failure in pass.item_failures {
        tracing::warn!(task = ?failure.candidate.task,
            reason = failure.reason, "wave handoff deferred");
    }
}
