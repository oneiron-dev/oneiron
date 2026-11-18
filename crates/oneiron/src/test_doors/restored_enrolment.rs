//! A root-signed enrolment of an install born of a restore, for the
//! integration tests of the fold's hold and join (row
//! RESTORED-COPIES-ENROL-EACH-OTHER): the bootstrap arm refuses such an
//! install, so no door writes one, and only this door reaches the fold's
//! hold through a store's own writer.

use crate::authority::{AuthorityEntryHash, HostSlipIssuer, MachineEnrolmentRequest, MachineRole};
use crate::error::Result;
use crate::{EntityId, Vault};

/// Signs `request`'s enrolment under `issuer`, the vault's root, for
/// `owner`, as an unanswered install, lands it on `vault` and returns its
/// entry, which the fold holds.
///
/// # Errors
/// A request no restore made, a root that is not `issuer`, and an enrolment
/// the fold did not hold; storage faults.
pub fn file_restored_enrolment(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: EntityId,
    request: &MachineEnrolmentRequest,
) -> Result<AuthorityEntryHash> {
    file_restored_enrolment_in_role(vault, issuer, owner, request, MachineRole::Unanswered)
}

/// [`file_restored_enrolment`] in `role`: the root signs the enrolment as
/// the owner's answer in that role, as a self-host root answers "yours" for
/// its owner. The fold holds it as it holds an unanswered one.
///
/// # Errors
/// As [`file_restored_enrolment`].
pub fn file_restored_enrolment_in_role(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: EntityId,
    request: &MachineEnrolmentRequest,
    role: MachineRole,
) -> Result<AuthorityEntryHash> {
    let mut txn = vault.store.env.write_txn()?;
    let enrolment = vault.file_restored_enrolment_in_txn(&mut txn, issuer, owner, request, role)?;
    txn.commit()?;
    Ok(enrolment)
}
