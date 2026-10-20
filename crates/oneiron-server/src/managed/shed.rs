//! Mapping the engine's shed transaction, and the supervisor's SLIM status
//! and unslim (FIX 5186), to the managed ctl contract.

use oneiron::slim::supervisor::SupervisorShedOutcome;
use oneiron::{InboundResumeOutcome, ShedBlocker, ShedOutcome, Vault};
use oneiron_vault_contract::slim_control::{
    EligibleWaitWire, SlimResidency, SlimStatusWire, UnslimStatus, UnslimWire,
    WAIT_OBSERVATION_CHANGED,
};
use oneiron_vault_contract::{CtlResponse, ShedBlockerWire, ShedCause, ShedStatus, now_ts};

use super::args::ManagedError;

/// A `wait_id` runs the guarded shed; without one the shed is the one every
/// existing caller gets.
pub(super) fn shed(
    vault: &Vault,
    cause: ShedCause,
    waited_secs: u64,
    wait_id: Option<u64>,
) -> Result<CtlResponse, ManagedError> {
    let cause = match cause {
        ShedCause::LongOutboundWait => oneiron::ShedCause::LongOutboundWait,
        ShedCause::MemoryPressure => oneiron::ShedCause::MemoryPressure,
    };
    let now_ms = now_ts().saturating_mul(1000);
    let outcome = match wait_id {
        None => vault
            .shed_rebuildable_heap(cause, waited_secs, now_ms)
            .map(SupervisorShedOutcome::Shed),
        Some(wait_id) => vault.shed_rebuildable_heap_for_wait(cause, waited_secs, now_ms, wait_id),
    }
    .map_err(refused)?;
    let (status, dropped, blocker) = match outcome {
        SupervisorShedOutcome::Shed(ShedOutcome::Entered { dropped, .. }) => {
            (ShedStatus::Entered, Some(dropped), None)
        }
        SupervisorShedOutcome::Shed(ShedOutcome::AlreadySlim { dropped, .. }) => (
            ShedStatus::AlreadySlim,
            (dropped != oneiron::HeapDropReport::default()).then_some(dropped),
            None,
        ),
        SupervisorShedOutcome::Shed(ShedOutcome::Refused(blocker)) => {
            let kind = match &blocker {
                ShedBlocker::NoPendingOutboundStep => "no_pending_outbound_step",
                ShedBlocker::MultiplePendingOutboundSteps { .. } => {
                    "multiple_pending_outbound_steps"
                }
                ShedBlocker::SyncWindowBusy { .. } => "sync_window_busy",
                ShedBlocker::AlreadySlimForDifferentStep => "already_slim_for_different_step",
            };
            (
                ShedStatus::Refused,
                None,
                Some(ShedBlockerWire {
                    kind: kind.to_owned(),
                    detail: format!("{blocker:?}"),
                }),
            )
        }
        SupervisorShedOutcome::WaitObservationChanged => (
            ShedStatus::Refused,
            None,
            Some(ShedBlockerWire {
                kind: WAIT_OBSERVATION_CHANGED.to_owned(),
                detail: "WaitObservationChanged".to_owned(),
            }),
        ),
    };
    Ok(CtlResponse::Slim {
        slim: vault.residency() == oneiron::VaultResidency::Slim,
        status,
        reclaimed_bytes: dropped.map(|report| report.estimated_reclaimed_bytes),
        dropped_windows: dropped.map(|report| report.sync_windows),
        blocker,
    })
}

/// One atomic read of residency and the eligible live wait. A journal that
/// does not read is an error the listener answers `Ok { ok: false }`.
pub(super) fn slim_status(vault: &Vault) -> Result<CtlResponse, ManagedError> {
    let status = vault.supervisor_slim_status().map_err(refused)?;
    Ok(CtlResponse::SlimStatus {
        slim_status: SlimStatusWire {
            residency: match status.residency {
                oneiron::VaultResidency::Full => SlimResidency::Full,
                oneiron::VaultResidency::Slim => SlimResidency::Slim,
            },
            eligible_wait: status.eligible_wait.map(|wait| EligibleWaitWire {
                wait_id: wait.wait_id,
                waited_secs: wait.waited_secs,
            }),
        },
    })
}

/// Logical FULL through the engine's existing inbound resume: nothing is
/// rebuilt, woken, journaled, cancelled or resent.
pub(super) fn unslim(vault: &Vault) -> Result<CtlResponse, ManagedError> {
    let status = match vault.resume_from_slim_on_inbound().map_err(refused)? {
        InboundResumeOutcome::AlreadyFull => UnslimStatus::AlreadyFull,
        InboundResumeOutcome::Resumed { .. } => UnslimStatus::Resumed,
    };
    Ok(CtlResponse::Unslim {
        unslim: UnslimWire {
            status,
            residency: SlimResidency::Full,
        },
    })
}

/// An engine failure, which the listener answers `Ok { ok: false }`.
fn refused(error: oneiron::Error) -> ManagedError {
    ManagedError::CtlRequestRefused {
        reason: error.to_string(),
    }
}
