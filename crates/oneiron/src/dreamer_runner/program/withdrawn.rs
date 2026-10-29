//! A turn program whose original authorization was positively withdrawn ends,
//! never held (FIX 11593, ruling 4624(a)): the classifier that tells such a
//! withdrawal apart from every other lapse, once the standing came out lapsed.

use crate::authority::{AuthorityFold, CausalWriteDisposition};
use crate::error::{Error, GateError, Result};
use crate::{EntityId, Vault};

use super::authority::TurnProgramAuthority;

/// The slip that authorized the program, or one it was delegated from, was
/// revoked.
pub(super) const SLIP_REVOKED: &str = "the slip that authorized the program was revoked";
/// The Grant that authorized the program was withdrawn.
pub(super) const GRANT_WITHDRAWN: &str = "the Grant that authorized the program was withdrawn";
/// The actor's authority binding was revoked.
pub(super) const BINDING_REVOKED: &str = "the actor's authority binding was revoked";

/// Whether the lapsed `authority` was positively withdrawn: its slip, or one
/// it was delegated from, explicitly revoked; its Grant known withdrawn; or
/// its actor's authority binding recorded revoked. Called only after the
/// standing came out lapsed; every other lapse answers `None`. A read error
/// stays an error, never a withdrawal.
pub(super) fn withdrawn_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authority: &TurnProgramAuthority,
) -> Result<Option<&'static str>> {
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    if let Some(slip) = authority.slip_id()
        && chain_revoked(&fold, &slip)
    {
        return Ok(Some(SLIP_REVOKED));
    }
    if let Some(root) = authority.host_root()
        && chain_revoked(&fold, &root)
    {
        return Ok(Some(SLIP_REVOKED));
    }
    if let Some(grant) = authority.grant()
        && grant_withdrawn_in_txn(vault, txn, grant)?
    {
        return Ok(Some(GRANT_WITHDRAWN));
    }
    if binding_revoked(&fold, authority)? {
        return Ok(Some(BINDING_REVOKED));
    }
    Ok(None)
}

/// Whether `slip` or one it was delegated from is explicitly revoked: only a
/// verified `SlipRevoke` writes the set, so expiry, absence and decode faults
/// never answer here.
fn chain_revoked(fold: &AuthorityFold, slip: &[u8; 32]) -> bool {
    fold.slips
        .delegation_chain(slip)
        .iter()
        .any(|id| fold.slips.explicit_revoked.contains(id))
}

/// Whether `grant` is positively known withdrawn here: the FEDERATION_GRANT
/// marker first, then the guest leg's, whichever the withdrawal wrote.
fn grant_withdrawn_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, grant: EntityId) -> Result<bool> {
    if crate::authority::grant_known_withdrawn_in_txn(&vault.store, txn, grant) {
        return Ok(true);
    }
    vault.guest_grant_withdrawn_in_txn(txn, &grant)
}

/// Whether the vault records `authority`'s actor binding revoked at its
/// class: quarantined by a revocation, never merely unbound.
fn binding_revoked(fold: &AuthorityFold, authority: &TurnProgramAuthority) -> Result<bool> {
    let actor = authority.actor();
    let class = authority.class()?;
    Ok(fold.vault_id.is_some()
        && fold.actor_write_disposition(&actor, class.gate_actor_class(), None)
            == CausalWriteDisposition::Quarantined)
}

/// The reservation refusal a withdrawn authority raises: the withdrawal's own
/// reason, carried as it was raised, as the attested owner's refusal carries
/// his (FIX 11090).
pub(super) fn withdrawn_refusal(reason: &'static str) -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason))
}

/// Whether `error` is a withdrawal refusal [`withdrawn_refusal`] raised, with
/// the withdrawal's reason: an item that met it ends on it.
pub(crate) fn is_withdrawal_refusal(error: &Error) -> Option<&'static str> {
    match error {
        Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason))
            if matches!(*reason, SLIP_REVOKED | GRANT_WITHDRAWN | BINDING_REVOKED) =>
        {
            Some(*reason)
        }
        _ => None,
    }
}
