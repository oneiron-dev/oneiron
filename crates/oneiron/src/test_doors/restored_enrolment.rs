//! A root-signed enrolment of an install born of a restore, for the
//! integration tests of the fold's hold and join (row
//! RESTORED-COPIES-ENROL-EACH-OTHER). The red-proof copy: on the base, the
//! root's bootstrap arm enrols any install, so this door is that arm.

use crate::authority::{AuthorityEntryHash, HostSlipIssuer, MachineEnrolmentRequest, MachineRole};
use crate::error::Result;
use crate::{EntityId, Vault};

/// Signs `request`'s enrolment under `issuer`, the vault's root, for
/// `owner`, as an unanswered install, lands it on `vault` and returns its
/// entry.
///
/// # Errors
/// As the bootstrap arm; storage faults.
pub fn file_restored_enrolment(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: EntityId,
    request: &MachineEnrolmentRequest,
) -> Result<AuthorityEntryHash> {
    let mut txn = vault.store.env.write_txn()?;
    let machine =
        vault.enroll_bootstrap_in_txn(&mut txn, issuer, owner, request, MachineRole::Unanswered)?;
    txn.commit()?;
    machine
        .roster
        .map(|roster| roster.entry)
        .ok_or_else(crate::authority::invalid_authority)
}
