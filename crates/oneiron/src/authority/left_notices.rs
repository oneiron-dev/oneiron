//! A removed person's own notices of losing a shared vault (OF-158 client
//! leave). Leave and removal revoke the person's slips, so the person-tier
//! outcome read refuses them; this door takes the revoked slip itself,
//! proven by the device that holds its binding key over a fresh request
//! challenge, and answers only that person's loss-of-access notices, and
//! the archive an export-first removal kept for them (OF-150). It grants no
//! other read: no proof is minted and no scope is consulted.
use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{RemovalExportCopy, SharedActOutcome};

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
        let person =
            self.left_person_in_txn(&mut txn, slip, request_timestamp, signature, request_nonce)?;
        let notices = self.removal_outcomes_in_txn(&txn, person)?;
        txn.commit()?;
        Ok(notices)
    }

    /// The archives export-first removals kept for the holder of `slip`
    /// (OF-150), still within their retention, under the same proof as
    /// [`Vault::removed_member_notices`]; the nonce is spent once.
    pub fn removed_owner_exports(
        &self,
        slip: &CapabilitySlip,
        request_timestamp: u64,
        signature: &[u8],
        request_nonce: &[u8],
    ) -> Result<Vec<RemovalExportCopy>> {
        let mut txn = self.store.env.write_txn()?;
        let person =
            self.left_person_in_txn(&mut txn, slip, request_timestamp, signature, request_nonce)?;
        let copies =
            self.removal_exports_in_txn(&txn, person, self.store.clock.now_recorded_at())?;
        txn.commit()?;
        Ok(copies)
    }

    /// The person whose slip, minted here whatever its standing since, the
    /// request proves: its holder signed the request challenge, and the
    /// nonce is spent in the caller's writer.
    fn left_person_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        slip: &CapabilitySlip,
        request_timestamp: u64,
        signature: &[u8],
        request_nonce: &[u8],
    ) -> Result<EntityId> {
        let request_now = super::slip_replay::admission_now_in_txn(self, txn)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let challenge =
            super::slip_replay::request_challenge(request_timestamp, request_nonce, request_now)?;
        slip.verify_origin(&fold, &challenge, signature)?;
        let person = EntityId::from_hex(&slip.claims.holder_ref)?;
        super::slip_replay::record_nonce(
            self,
            txn,
            &slip.current_binding_key(),
            request_nonce,
            request_timestamp,
            request_now,
        )?;
        Ok(person)
    }
}
