//! The host-order legal holds a cold restore installs (FIX 1485, FIX 6598,
//! FIX 6817).
//!
//! A host order's holds are runtime rows the image's canonical rows do not
//! carry, so the restored vault lands with none of its source's. The
//! supervisor reads the source's whole family over the source's ctl under
//! its freeze, or, where the source cannot answer, its restore worker opens
//! the family the artifact's host-private member holds, and hands it on the
//! input pipe; `begin` admits it, bound to the plan's attempt and source,
//! every row a host-order row. The artifact's family rides the engine's key
//! with its tag, and the restore passes it on only when the tag names the
//! member the artifact it opened carries. `finish` installs one family,
//! whole, in place of the restored vault's, never a union: the pipe's, else
//! the artifact's, else none, which is `host_holds_unknown`: logged, said in
//! the receipt, and never a refusal.

use oneiron::recovery::checkpoint::{
    ArtifactHostOrderHolds, HostOrderHolds, RestoreAdmissionError, RestoreDestinationState,
    RestorePhase,
};
use oneiron_vault_contract::restore::{
    HostHoldsOrigin, ManagedRestoreHostHolds, ManagedRestorePlan, RestoreHostHoldsStatus,
};

use super::receipt;

/// The family the input pipe carried, admitted, by where it came from: the
/// live source's, or the one the artifact's member held with its tag.
#[derive(Default)]
pub(super) struct AdmittedHostOrderHolds {
    pub(super) pipe: Option<HostOrderHolds>,
    pub(super) artifact: Option<ArtifactHostOrderHolds>,
}

/// The family the input pipe carried, admitted: bound to `plan`'s attempt
/// and source, its bytes its id's, one family this engine reads, and every
/// row a host-order row (FIX 6818), all before anything is made. None when
/// the supervisor sent none, which is never a refusal.
pub(super) fn admit(
    supplied: Option<ManagedRestoreHostHolds>,
    plan: &ManagedRestorePlan,
) -> Result<AdmittedHostOrderHolds, &'static str> {
    let Some(supplied) = supplied else {
        return Ok(AdmittedHostOrderHolds::default());
    };
    supplied.check(plan)?;
    let family: HostOrderHolds = serde_json::from_slice(&supplied.family.0)
        .map_err(|_| "its host_holds family is not one host-order family")?;
    family
        .validate()
        .map_err(|_| "its host_holds family carries a row outside the host-order family")?;
    Ok(match supplied.origin {
        HostHoldsOrigin::LiveSource => AdmittedHostOrderHolds {
            pipe: Some(family),
            artifact: None,
        },
        HostHoldsOrigin::CheckpointArtifact {
            snapshot_id,
            recipient_id,
            recipient_epoch,
            member_blake3,
        } => AdmittedHostOrderHolds {
            pipe: None,
            artifact: Some(ArtifactHostOrderHolds::new(
                family,
                snapshot_id,
                recipient_id,
                recipient_epoch,
                member_blake3,
            )),
        },
    })
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
