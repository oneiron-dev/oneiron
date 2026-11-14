//! Doors for the integration tests of the predicted residence level (census
//! L7-46 + L10-14, ARCH-0023b #predicted-residence).

use crate::authority::HostSlipIssuer;
use crate::sync::connection::SyncConnection;
use crate::sync::residence::PredictedResidenceAnswer;
use crate::sync::transport::TransportError;
use crate::{EntityId, Vault};

/// Runs the owner's pending residence directives naming this machine on
/// `connection`, as its residence upkeep does once the authority history is
/// in, without a socket. Answers how many it finished.
///
/// # Errors
///
/// The connection's: a directive that cannot run yet, or storage.
pub async fn apply_residence_directives(
    connection: &SyncConnection,
) -> Result<usize, TransportError> {
    connection.apply_residence_directives().await
}

/// The home's prediction for `machine` through the owner-grade view a home holds of its own
/// linked machine: every node visible except those in a world withheld from it. For integration
/// tests of the predicted level; production predicts through the request's own admission.
///
/// # Errors
///
/// The prediction's: a machine with no standing proof, one not at the predicted level, or
/// storage.
pub fn predict_residence_withholding(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    machine: EntityId,
) -> crate::error::Result<PredictedResidenceAnswer> {
    let visibility = crate::sync::residence::WithholdingNodes::for_machine(vault, machine)?;
    vault.predict_residence_with(issuer, machine, &visibility)
}
