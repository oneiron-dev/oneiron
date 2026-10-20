//! The host-order legal holds a cold restore installs (FIX 1485, FIX 6598).
//!
//! A host order's holds are runtime rows the image does not carry, so the
//! restored vault lands with none of its source's. The supervisor reads the
//! source's whole family over the source's ctl under its freeze and hands
//! it on the input pipe; `begin` admits it, bound to the plan's attempt and
//! source. `finish` installs one family, whole, in place of the restored
//! vault's, never a union: the pipe's, else the artifact's, else none,
//! which is `host_holds_unknown`: logged, said in the receipt, and never a
//! refusal.

use oneiron::recovery::checkpoint::{
    HostOrderHolds, RestoreAdmissionError, RestoreDestinationState, RestorePhase,
};
use oneiron_vault_contract::restore::{
    ManagedRestoreHostHolds, ManagedRestorePlan, RestoreHostHoldsStatus,
};

use super::receipt;

/// The source's family the input pipe carried, admitted: bound to `plan`'s
/// attempt and source, its bytes its id's, and one family this engine
/// reads. `None` when the supervisor sent none, which is never a refusal.
/// Its rows are checked to be host-order rows when it is installed.
pub(super) fn admit(
    supplied: Option<ManagedRestoreHostHolds>,
    plan: &ManagedRestorePlan,
) -> Result<Option<HostOrderHolds>, &'static str> {
    let Some(supplied) = supplied else {
        return Ok(None);
    };
    supplied.check(plan)?;
    serde_json::from_slice(&supplied.family.0)
        .map(Some)
        .map_err(|_| "its host_holds family is not one host-order family")
}

/// Installs the family the restore carries in place of the restored
/// vault's, whole: `pipe`, the source's, before `artifact`, the image's;
/// with neither, nothing is installed and the restore goes on, not knowing
/// its source's. What it installed from, for the receipt. An install that
/// fails refuses the restore at `finish` under the reason its error's kind
/// names, and the restore removes what it made.
pub(super) fn install(
    vault: &oneiron::Vault,
    pipe: Option<&HostOrderHolds>,
    artifact: Option<&HostOrderHolds>,
) -> Result<RestoreHostHoldsStatus, RestoreAdmissionError> {
    let (family, status) = match (pipe, artifact) {
        (Some(family), _) => (family, RestoreHostHoldsStatus::InstalledFromPipe),
        (None, Some(family)) => (family, RestoreHostHoldsStatus::InstalledFromArtifact),
        (None, None) => {
            tracing::warn!(
                reason = "host_holds_unknown",
                "the cold restore carried no host-order legal holds from its source; it goes on"
            );
            return Ok(RestoreHostHoldsStatus::HostHoldsUnknown);
        }
    };
    vault
        .install_carried_host_order_holds(family)
        .map_err(|error| {
            RestoreAdmissionError::new(
                receipt::by_kind(&error),
                RestorePhase::Finish,
                RestoreDestinationState::Removed,
                error,
            )
        })?;
    Ok(status)
}
