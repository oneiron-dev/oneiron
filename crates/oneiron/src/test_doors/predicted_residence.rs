//! Doors for the integration tests of the predicted residence level (census
//! L7-46 + L10-14, ARCH-0023b #predicted-residence).

use crate::authority::{HostSlipIssuer, PredictedResidenceSet, ResidenceAct, ResidenceDirective};
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

/// Appends a host-signed prediction for `machine` naming `parent`, as the home does: the owner
/// is the parent directive's owner, and the act carries the set's digest and counts. Answers the
/// prediction's id.
///
/// # Errors
///
/// The parent names no directive to the machine, the set fits no counts, or storage.
pub fn append_prediction(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    machine: EntityId,
    parent: EntityId,
    set: &PredictedResidenceSet,
) -> crate::error::Result<EntityId> {
    let owner = SyncConnection::directives_naming_machine(vault, machine)?
        .into_iter()
        .find_map(|directive| (directive.id == parent).then_some(directive.owner))
        .ok_or_else(|| {
            crate::error::Error::InvalidConfig(
                "a prediction names its owner's directive".to_owned(),
            )
        })?;
    let id = EntityId::now();
    let (window_count, document_count) = set.counts().ok_or_else(|| {
        crate::error::Error::InvalidConfig("a prediction fits its counts".to_owned())
    })?;
    let directive = ResidenceDirective {
        id,
        machine,
        owner,
        issued_at: vault.now_recorded_at(),
        act: ResidenceAct::Predicted {
            parent,
            set_digest: set.digest()?,
            window_count,
            document_count,
        },
    };
    let mut txn = vault.store.env.write_txn()?;
    vault.append_residence_directive_in_txn(&mut txn, issuer, directive)?;
    txn.commit()?;
    Ok(id)
}

/// Runs one predicted upkeep pass on `connection`, without waiting for its wake.
///
/// # Errors
///
/// The connection's: a pass the home's outage does not freeze quietly, or storage.
pub async fn run_predicted_pass(connection: &SyncConnection) -> Result<(), TransportError> {
    connection.run_predicted_pass().await
}
