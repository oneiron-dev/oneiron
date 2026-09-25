//! Checkout redemption rights. Tickets carry only id/epoch, never a secret.

use super::door_types::{CredentialDoorError, DoorResult, log_unreachable, repo_record};
use super::{CredentialDoorService, DoorCredential};
use crate::checkout::lease::{CheckoutId, CheckoutLeaseAct, CheckoutLeaseState, load_act_in_txn};
use crate::codebase::RepoRef;

fn parse_ticket(text: &str) -> DoorResult<(CheckoutId, u64)> {
    let (id, epoch) = text
        .split_once('.')
        .ok_or(CredentialDoorError::AuthorityRejected)?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CredentialDoorError::AuthorityRejected);
    }
    let mut bytes = [0; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&id[2 * i..2 * i + 2], 16)
            .map_err(|_| CredentialDoorError::AuthorityRejected)?;
    }
    let epoch: u64 = epoch
        .parse()
        .map_err(|_| CredentialDoorError::AuthorityRejected)?;
    let id = CheckoutId::from_bytes(bytes).map_err(|_| CredentialDoorError::AuthorityRejected)?;
    if epoch == 0 || format!("{id}.{epoch}") != text {
        return Err(CredentialDoorError::AuthorityRejected);
    }
    Ok((id, epoch))
}

impl CredentialDoorService {
    fn checkout_act(&self, txn: &heed::RoTxn<'_>, ticket: &str) -> DoorResult<CheckoutLeaseAct> {
        let (id, epoch) = parse_ticket(ticket)?;
        let lease = load_act_in_txn(self.vault(), txn, id)
            .map_err(log_unreachable)?
            .ok_or(CredentialDoorError::AuthorityRejected)?;
        let now = self
            .vault()
            .instant_in_txn(txn)
            .map_err(log_unreachable)?
            .secs();
        if lease.epoch != epoch
            || lease.state != CheckoutLeaseState::Active
            || lease.lease_expires_at.is_none_or(|expiry| now >= expiry)
            || now < lease.claimed_at
        {
            return Err(CredentialDoorError::AuthorityRejected);
        }
        Ok(lease)
    }

    pub(crate) fn checkout_credential(
        &self,
        ticket: &str,
        principal: &str,
        repo: &RepoRef,
    ) -> DoorResult<DoorCredential> {
        let txn = self.vault().store.env.read_txn().map_err(log_unreachable)?;
        let lease = self.checkout_act(&txn, ticket)?;
        if lease.holder_ref != principal || repo_record(&lease.repo_ref) != repo_record(repo) {
            return Err(CredentialDoorError::AuthorityRejected);
        }
        Ok(Self::checkout_view(ticket, &lease))
    }

    fn checkout_view(ticket: &str, lease: &CheckoutLeaseAct) -> DoorCredential {
        DoorCredential::from_checkout(ticket, lease)
    }

    pub(super) fn witness_checkout_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        credential: &DoorCredential,
        ticket: &str,
    ) -> DoorResult<()> {
        let lease = self.checkout_act(txn, ticket)?;
        if *credential != Self::checkout_view(ticket, &lease) {
            return Err(CredentialDoorError::AuthorityRejected);
        }
        Ok(())
    }
}
