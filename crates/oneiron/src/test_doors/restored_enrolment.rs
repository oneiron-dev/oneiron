//! A root-signed enrolment of an install born of a restore, for the
//! integration tests of the fold's hold and join (row
//! RESTORED-COPIES-ENROL-EACH-OTHER): the bootstrap arm refuses such an
//! install, so no door writes one, and only this door reaches the fold's
//! hold through a store's own writer. Beside it, a reader of the authority
//! clock floor, so a test can see that a refused join committed no reading
//! (REVIEW-9524 P1).

use crate::authority::{AuthorityEntryHash, HostSlipIssuer, MachineEnrolmentRequest, MachineRole};
use crate::error::Result;
use crate::{EntityId, Vault};

pub mod forged_rows;

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

/// The authority clock floor `vault` holds: the latest reading a committed
/// writer stored, `None` before the first.
///
/// # Errors
/// Storage faults, and a damaged floor.
pub fn authority_clock_floor(vault: &Vault) -> Result<Option<u64>> {
    let txn = vault.store.env.read_txn()?;
    crate::authority::read_authority_clock_floor_in_txn(&vault.store, &txn)
}
