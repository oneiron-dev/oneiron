//! The recovery root's authority key R on the owner's roster: its enrolment
//! under its own attestation kind (pass 27 R4 PR 2).

use super::*;

impl Vault {
    /// [`Self::enrol_owner_signing_key_as`] for a key of `kind`, in a write
    /// transaction of its own.
    pub(super) fn enrol_owner_key_of_kind_as<S>(
        &self,
        authority: &ActAuthority,
        input: OwnerKeyEnrollment,
        kind: EnrolledOwnerKeyKind,
        predecessor: AuthorityKey,
        mut sign_predecessor: S,
    ) -> Result<OwnerKeyEnrollmentReceipt>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        if matches!(authority, ActAuthority::Agent(_)) {
            return Err(authority_refused(OWNER_ONLY));
        }
        let mut txn = self.store.env.write_txn()?;
        let receipt = self.enrol_owner_signing_key_in_txn(
            &mut txn,
            authority,
            input,
            kind,
            predecessor,
            &mut sign_predecessor,
        )?;
        txn.commit()?;
        Ok(receipt)
    }

    /// Explicitly enrol the distinct authority key backed by `seed`, before loss.
    /// The seed's source kit does not gain authority by existing or being restored.
    /// This returns the ordinary counted enrollment receipt; it does not publish a
    /// kit or make kit issuance atomic with enrollment. The row carries the
    /// root's own attestation kind ([`EnrolledOwnerKeyKind::RecoveryAuthority`]).
    ///
    /// `machine` and the carrying install must satisfy the existing owner-key
    /// enrollment rules. The predecessor signs inside that door's own writer.
    pub fn enrol_recovery_authority_key_as<S>(
        &self,
        authority: &ActAuthority,
        machine: EntityId,
        seed: &crate::world_keys::RecoveryRootSeed,
        predecessor: AuthorityKey,
        sign_predecessor: S,
    ) -> Result<OwnerKeyEnrollmentReceipt>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        let input = {
            let owner = match authority {
                ActAuthority::Owner(owner, _) => owner,
                ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
            };
            let txn = self.store.env.read_txn()?;
            let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
            let signer = crate::world_keys::RecoveryAuthoritySigner::from_seed(seed, &vault_id)?;
            signer.enrollment(machine, actor)?
        };
        self.enrol_owner_key_of_kind_as(
            authority,
            input,
            EnrolledOwnerKeyKind::RecoveryAuthority,
            predecessor,
            sign_predecessor,
        )
    }

    /// [`Self::enrol_recovery_authority_key_as`] with this host's existing root
    /// as predecessor. The owner's live act and normal carrying install remain
    /// required; possession of a kit alone cannot enrol its derived key.
    pub fn enrol_recovery_authority_key_as_host(
        &self,
        authority: &ActAuthority,
        machine: EntityId,
        seed: &crate::world_keys::RecoveryRootSeed,
        issuer: &HostSlipIssuer,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        self.enrol_recovery_authority_key_as(
            authority,
            machine,
            seed,
            issuer.public_key(),
            |transcript| Ok(issuer.sign_slip(transcript)),
        )
    }
}
