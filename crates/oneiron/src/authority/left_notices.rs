//! A removed person's own notices of losing a shared vault (OF-158 client
//! leave). Leave and removal revoke the person's slips, so the person-tier
//! outcome read refuses them; this door takes the revoked slip itself,
//! proven by the device that holds its binding key over a fresh request
//! challenge, and answers only that person's loss-of-access notices, and
//! the archives export-first removals delivered to them (OF-150, FIX 1300),
//! each retrievable for its 90-day term. It grants no other read: no proof
//! is minted and no scope is consulted. Every notice is signed by the host
//! root key (FIX 2053); there is no unsigned answer.
use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{RemovalExportCopy, SignedSharedActOutcome};

impl Vault {
    /// The holder of `slip` proves possession of its binding key over the
    /// request challenge (`request_timestamp`, `request_nonce`, `signature`,
    /// the same proof every slip request carries). The slip must be one this
    /// vault's authority log minted, unchanged, whatever its standing since:
    /// revoked and expired slips pass, as a removed device holds no other.
    /// Answers the slip holder's own MemberLeft, MemberRemoved and
    /// role-losing Owner notices, and the vault's deletion, each signed in
    /// this snapshot by `issuer`, which must stand as this vault's live host
    /// root. The nonce is spent once, only when every notice is signed.
    pub fn removed_member_notices_signed(
        &self,
        issuer: &HostSlipIssuer,
        slip: &CapabilitySlip,
        request_timestamp: u64,
        signature: &[u8],
        request_nonce: &[u8],
    ) -> Result<Vec<SignedSharedActOutcome>> {
        let mut txn = self.store.env.write_txn()?;
        let person =
            self.left_person_in_txn(&mut txn, slip, request_timestamp, signature, request_nonce)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        super::slip_vault::require_host(&fold, issuer)?;
        let authority_vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let notices = self
            .removal_outcomes_in_txn(&txn, person)?
            .iter()
            .map(|outcome| issuer.sign_shared_act_outcome(authority_vault_id, outcome))
            .collect::<Result<Vec<_>>>()?;
        txn.commit()?;
        Ok(notices)
    }

    /// The archives export-first removals delivered to the holder of `slip`
    /// (OF-150, FIX 1300), still within their term, under the same proof as
    /// [`Vault::removed_member_notices_signed`]; the nonce is spent once.
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

    /// The one archive the removal receipt `receipt_id` delivered to the
    /// holder of `slip` (FIX 1300), under the same proof as
    /// [`Vault::removed_member_notices_signed`]: answered while it is within
    /// its term ([`crate::federation::REMOVAL_EXPORT_RETAIN_SECS`] from its
    /// latest delivery), `None` after it or when that removal delivered this
    /// person none. Only the removed person reaches it; the nonce is spent
    /// once, and a malformed `receipt_id` is refused before it is.
    pub fn removed_owner_archive(
        &self,
        slip: &CapabilitySlip,
        request_timestamp: u64,
        signature: &[u8],
        request_nonce: &[u8],
        receipt_id: &str,
    ) -> Result<Option<RemovalExportCopy>> {
        let receipt_id = EntityId::from_hex(receipt_id)?;
        let mut txn = self.store.env.write_txn()?;
        let person =
            self.left_person_in_txn(&mut txn, slip, request_timestamp, signature, request_nonce)?;
        let copy = self.removal_export_in_txn(
            &txn,
            person,
            receipt_id,
            self.store.clock.now_recorded_at(),
        )?;
        txn.commit()?;
        Ok(copy)
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
