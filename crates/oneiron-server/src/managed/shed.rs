//! Mapping the engine's shed transaction to the managed ctl contract.

use oneiron::{ShedBlocker, ShedOutcome, Vault};
use oneiron_vault_contract::{CtlResponse, ShedBlockerWire, ShedCause, ShedStatus, now_ts};

use super::args::ManagedError;

pub(super) fn shed(
    vault: &Vault,
    cause: ShedCause,
    waited_secs: u64,
) -> Result<CtlResponse, ManagedError> {
    let cause = match cause {
        ShedCause::LongOutboundWait => oneiron::ShedCause::LongOutboundWait,
        ShedCause::MemoryPressure => oneiron::ShedCause::MemoryPressure,
    };
    let outcome = vault
        .shed_rebuildable_heap(cause, waited_secs, now_ts().saturating_mul(1000))
        .map_err(|error| ManagedError::CtlRequestRefused {
            reason: error.to_string(),
        })?;
    let (status, dropped, blocker) = match outcome {
        ShedOutcome::Entered { dropped, .. } => (ShedStatus::Entered, Some(dropped), None),
        ShedOutcome::AlreadySlim { dropped, .. } => (
            ShedStatus::AlreadySlim,
            (dropped != oneiron::HeapDropReport::default()).then_some(dropped),
            None,
        ),
        ShedOutcome::Refused(blocker) => {
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
    };
    Ok(CtlResponse::Slim {
        slim: vault.residency() == oneiron::VaultResidency::Slim,
        status,
        reclaimed_bytes: dropped.map(|report| report.estimated_reclaimed_bytes),
        dropped_windows: dropped.map(|report| report.sync_windows),
        blocker,
    })
}
