//! A removed person's own notices of losing a shared vault (OF-158 client
//! leave). Leave and removal revoke the person's slips, so the person-tier
//! outcome read refuses them; this door takes the revoked slip itself,
//! proven by the device that holds its binding key over a fresh request
//! challenge, and answers only that person's loss-of-access notices. It
//! grants no other read: no proof is minted and no scope is consulted.
use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::SharedActOutcome;

impl Vault {
    /// The holder of `slip` proves possession of its binding key over the
    /// request challenge (`request_timestamp`, `request_nonce`, `signature`,
    /// the same proof every slip request carries). The slip must be one this
    /// vault's authority log minted, unchanged, whatever its standing since:
    /// revoked and expired slips pass, as a removed device holds no other.
    /// Answers the slip holder's own MemberLeft, MemberRemoved and
    /// role-losing Owner notices; the nonce is spent once.
    pub fn removed_member_notices(
        &self,
        slip: &CapabilitySlip,
        request_timestamp: u64,
        signature: &[u8],
        request_nonce: &[u8],
    ) -> Result<Vec<SharedActOutcome>> {
        let mut txn = self.store.env.write_txn()?;
        let request_now = super::slip_replay::admission_now_in_txn(self, &mut txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let challenge =
            super::slip_replay::request_challenge(request_timestamp, request_nonce, request_now)?;
        slip.verify_origin(&fold, &challenge, signature)?;
        let person = EntityId::from_hex(&slip.claims.holder_ref)?;
        super::slip_replay::record_nonce(
            self,
            &mut txn,
            &slip.current_binding_key(),
            request_nonce,
            request_timestamp,
            request_now,
        )?;
        let notices = self.removal_outcomes_in_txn(&txn, person)?;
        txn.commit()?;
        Ok(notices)
    }
}
