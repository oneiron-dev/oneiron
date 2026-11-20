//! The recovery authority key's generations at a kit change
//! (WAYBACK-KIT-ONLY-AUTHORITY-KEY = B): the generation a kit's activation
//! confirms, and the kit-only switch's rotation to the next one.

use super::*;

impl Vault {
    /// The kit's R that an activation confirms, with its generation: the
    /// live one, which skips the enrol and hands that generation's seed out,
    /// or generation 0 for a kit this vault never enrolled. Old kits read as
    /// generation 0, and after a rotation the same kit confirms on
    /// generation 1. A live generation another owner enrolled is refused at
    /// [`Self::recovery_authority_enrols_in_txn`].
    ///
    /// # Errors
    /// [`REVOKED_AUTHORITY_KEY`] for a spent kit (a generation enrolled, none
    /// live); the enrolled-key read's.
    pub(crate) fn kit_activation_signer_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        seed: &crate::world_keys::RecoveryRootSeed,
        vault_id: &AuthorityVaultId,
    ) -> Result<(u32, crate::world_keys::RecoveryAuthoritySigner)> {
        let found = self.recovery_authority_generations_in_txn(txn, seed, vault_id)?;
        match (found.live, found.enrolled) {
            (Some(live), _) => Ok(live),
            (None, Some(_)) => Err(authority_refused(REVOKED_AUTHORITY_KEY)),
            (None, None) => Ok((
                0,
                crate::world_keys::RecoveryAuthoritySigner::from_seed(seed, vault_id, 0)?,
            )),
        }
    }

    /// Rotates the recovery authority key in the caller's write transaction:
    /// enrols generation `live_generation + 1` with generation
    /// `live_generation` as predecessor (which signs the transcript), then
    /// revokes generation `live_generation` under itself. Enrol first, then
    /// revoke: the self-revoke counts because the new generation is a live
    /// consenting key after the enrol. The holding machine is this install's
    /// machine identity, read in the transaction and never minted; the enrol
    /// door's own carrier check judges it. Then the new generation carries
    /// the approvals the old one signed, chosen before the revoke
    /// ([`Self::recovery_authority_carry_in_txn`],
    /// [`Self::carry_recovery_authority_approvals_in_txn`]), and on a
    /// self-hosted vault binds the owner when the old one held their only
    /// `human` binding ([`Self::bind_unbound_owner_on_self_host_in_txn`]).
    /// Returns the new live generation with its enrol receipt and the old
    /// generation's revocation.
    ///
    /// # Errors
    /// As [`Self::enrol_owner_signing_key_as`], and the revoke's
    /// `REVOKE_NOT_COUNTED`; an agent's act is refused as there.
    pub(crate) fn rotate_recovery_authority_key_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        authority: &ActAuthority,
        seed: &crate::world_keys::RecoveryRootSeed,
        live_generation: u32,
    ) -> Result<(u32, OwnerKeyEnrollmentReceipt, AuthorityEntryHash)> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let next = live_generation
            .checked_add(1)
            .ok_or_else(invalid_authority)?;
        let live_signer = crate::world_keys::RecoveryAuthoritySigner::from_seed(
            seed,
            &vault_id,
            live_generation,
        )?;
        let next_signer =
            crate::world_keys::RecoveryAuthoritySigner::from_seed(seed, &vault_id, next)?;
        let input = next_signer.enrollment(machine, actor)?;
        let live_key = live_signer.authority_key();
        let sign_live = |transcript: &[u8]| live_signer.sign_authority_transcript(transcript);
        let mut sign_enrol = |_: &AuthorityFold, transcript: &[u8]| sign_live(transcript);
        let receipt = self.enrol_owner_signing_key_in_txn(
            txn,
            authority,
            input,
            EnrolledOwnerKeyKind::RecoveryAuthority,
            live_key.clone(),
            &mut sign_enrol,
        )?;
        // The next generation carries what the revoked one approved, chosen
        // before the revocation (an aged approval goes stale at it), so the
        // switch unpairs no machine (WAYBACK-R-REVOCATION-STALES-R-APPROVALS = A).
        let carry = self.recovery_authority_carry_in_txn(txn, std::slice::from_ref(&live_key))?;
        let revoked = self.append_revoke_device_in_txn(
            txn,
            EntrySigner::Key(&live_key, &sign_live),
            live_key.clone(),
        )?;
        self.carry_recovery_authority_approvals_in_txn(txn, carry, &next_signer)?;
        // On a self-hosted vault a revoked generation that held the owner's
        // `human` binding ended it with itself, and the carry never binds a
        // revoked key again: the next generation binds the owner, by the
        // enrolment's rule, under itself (Sol carry-fix D3).
        let next_key = next_signer.authority_key();
        let mut sign_next = |_: &AuthorityFold, transcript: &[u8]| {
            next_signer.sign_authority_transcript(transcript)
        };
        self.bind_unbound_owner_on_self_host_in_txn(
            txn,
            actor,
            next_key.clone(),
            (next_key, &mut sign_next),
        )?;
        Ok((next, receipt, revoked))
    }

    /// Binds `actor` to `key` as `human`, signed by `signer` behind `sign`,
    /// on a self-hosted vault where `actor` holds no active `human` binding
    /// once a kit change revoked the R keys it replaces and carried what
    /// those signed: the enrolment's own rule
    /// ([`Self::enrol_owner_signing_key_in_txn`]), judged after the
    /// revocation. A kit activation signs by its predecessor
    /// ([`Self::bind_owner_to_recovery_authority_key_in_txn`]); the kit-only
    /// rotation by the next generation itself, the one live key of that act
    /// once the revoked generation's binding ended with it (Sol carry-fix D3).
    ///
    /// # Errors
    /// The binding's `BINDING_NOT_COUNTED`, as at the enrolment.
    pub(super) fn bind_unbound_owner_on_self_host_in_txn<S>(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        key: AuthorityKey,
        (signer, sign): (AuthorityKey, &mut S),
    ) -> Result<()>
    where
        S: FnMut(&AuthorityFold, &[u8]) -> Result<Vec<u8>>,
    {
        if self.privacy_posture() != crate::HostingPrivacyPosture::SelfHostLocal {
            return Ok(());
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if actor_binding_is_active(&fold, &actor, ACTOR_CLASS_HUMAN) {
            return Ok(());
        }
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let bind = EnrolledKeyBinding {
            fold: &fold,
            vault_id,
            predecessor: signer,
            key,
            owner: actor,
        };
        self.bind_enrolled_owner_key_in_txn(txn, bind, sign)
    }
}
