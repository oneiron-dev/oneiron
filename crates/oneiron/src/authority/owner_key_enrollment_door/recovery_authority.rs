//! The recovery root's authority key R on the owner's roster: its enrolment
//! under its own attestation kind (pass 27 R4 PR 2).

use super::*;

/// A kit activation's predecessor for the root's authority key enrolment
/// (pass 27 R4 PR 2, WAYBACK-R4-FIRST-KEY = B): this install's live owner
/// key, or this vault's host root on a self-hosted vault. Loaded before the
/// activation's write transaction ([`Vault::load_activation_predecessor`]),
/// used in it ([`Vault::enrol_recovery_authority_key_in_txn`]). The load
/// makes no keystore or store write.
pub(crate) enum ActivationPredecessor {
    /// This install's owner key, held on this handle, an enrolled owner key
    /// of kind [`EnrolledOwnerKeyKind::Device`] live with `ROLE_OWNER`. Signs
    /// through [`CheckpointRootSigner::sign_owner_proof`].
    OwnerKey(Arc<dyn CheckpointRootSigner>),
    /// This vault's host root, from this install's slot, live under
    /// `require_host`. Signs the way
    /// [`Vault::enrol_recovery_authority_key_as_host`] makes its signature.
    HostRoot(HostSlipIssuer),
}

impl ActivationPredecessor {
    /// The roster key the enrolment names as predecessor.
    fn predecessor_key(&self) -> AuthorityKey {
        match self {
            Self::OwnerKey(signer) => signer.root(),
            Self::HostRoot(issuer) => issuer.public_key(),
        }
    }

    /// The predecessor's signature over the enrolment's authority transcript.
    fn sign(&self, transcript: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::OwnerKey(signer) => signer.sign_owner_proof(transcript),
            Self::HostRoot(issuer) => Ok(issuer.sign_slip(transcript)),
        }
    }
}

/// A kit's activation found no predecessor for the root's authority key:
/// this install holds no live owner key, and the vault is not a self-hosted
/// one whose host root this install holds. Authority; nothing was written
/// (WAYBACK-R4-NO-PREDECESSOR = A).
const NO_PREDECESSOR: &str = "this device's owner key is not enrolled; enrol it, then confirm \
                               the kit; nothing was written";

/// R's enrolment input for `machine` and `actor` (the revalidated owner): the
/// one body [`Vault::enrol_recovery_authority_key_as`] and
/// [`Vault::enrol_recovery_authority_key_in_txn`] share, so there are not two
/// copies. The caller supplies `vault_id` from its own snapshot: a read txn
/// for the explicit door, the caller's write txn for the activation.
fn recovery_authority_enrollment(
    seed: &crate::world_keys::RecoveryRootSeed,
    vault_id: &AuthorityVaultId,
    machine: EntityId,
    actor: EntityId,
) -> Result<OwnerKeyEnrollment> {
    let signer = crate::world_keys::RecoveryAuthoritySigner::from_seed(seed, vault_id)?;
    signer.enrollment(machine, actor)
}

/// What ways back the owner has (Engine 22:39 and 22:43; the UI shows "You
/// have no way back yet" and "A passkey in this browser is your only key").
/// Engine read only: no route and no verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaysBack {
    /// Live owner keys of kind [`EnrolledOwnerKeyKind::Device`].
    pub owner_devices: u32,
    /// Live `ROLE_OWNER` P256 keys on the fold roster.
    pub passkeys: u32,
    /// Whether a live owner key of kind
    /// [`EnrolledOwnerKeyKind::RecoveryAuthority`] exists.
    pub kit_root_enrolled: bool,
    /// Whether the box PIN is set. Always false: OPUS-WAYBACK-BOX's R7 is
    /// its producer.
    pub box_pin_set: bool,
}

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
            recovery_authority_enrollment(seed, &vault_id, machine, actor)?
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

    /// A kit activation's predecessor, loaded before its write transaction
    /// opens (pass 27 R4 PR 2): (a) this install's owner key when a signer
    /// this handle holds names an enrolled owner key of kind `Device` live
    /// with `ROLE_OWNER`; else (b) this install's host root when the fold
    /// holds no live host-stamped root and that root is live under
    /// `require_host`; else (c) refused with [`NO_PREDECESSOR`]. Makes no
    /// keystore or store write: one read snapshot for the roster checks, then
    /// the host seed read, which opens its own read txn. Liveness is judged
    /// again in the txn by the enrol door (its `NOT_COUNTED` refusal).
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] with [`NO_PREDECESSOR`] when this
    /// install holds neither; storage and keystore read errors other than
    /// an absent host seed.
    pub(crate) fn load_activation_predecessor(&self) -> Result<ActivationPredecessor> {
        let (enrolled, fold) = {
            let txn = self.store.env.read_txn()?;
            let enrolled = self.enrolled_owner_keys_in_txn(&txn)?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            (enrolled, fold)
        };
        for signer in self.checkpoint_root_signers() {
            let root = signer.root();
            let AuthorityKey::Ed25519(public) = &root else {
                continue;
            };
            let listed = enrolled.iter().find(|key| key.public_key == *public);
            let Some(listed) = listed else {
                continue;
            };
            if listed.kind != EnrolledOwnerKeyKind::Device || !listed.live {
                continue;
            }
            let live_owner = fold
                .roster
                .get(&root)
                .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0);
            if live_owner {
                return Ok(ActivationPredecessor::OwnerKey(signer));
            }
        }
        let hosted = fold.roster.values().any(|device| {
            !device.revoked
                && device.roles & ROLE_OWNER != 0
                && (device.roles & ROLE_CLOUD != 0 || device.tier == AuthorityTier::CloudCustodial)
        });
        if !hosted {
            // An install with no host seed (no keystore, no machine
            // identity, an empty slot) holds no host root: that is the
            // refusal below. Any other failure is the read's own error.
            match self.load_host_slip_issuer() {
                Ok(issuer) => {
                    if super::slip_vault::require_host(&fold, &issuer).is_ok() {
                        return Ok(ActivationPredecessor::HostRoot(issuer));
                    }
                }
                Err(Error::Secret(SecretError::KeystoreUnavailable(_))) => {}
                Err(other) => return Err(other),
            }
        }
        Err(authority_refused(NO_PREDECESSOR))
    }

    /// Enrols the kit's root authority key R in the caller's write
    /// transaction (pass 27 R4 PR 2, WAYBACK-R4-FIRST-KEY = B): the kit's
    /// activation enrols R after its marks and pin move, with `machine` =
    /// this install and `predecessor` from
    /// [`Self::load_activation_predecessor`]. Revalidates the owner, builds
    /// R's enrolment, and calls [`Self::enrol_owner_signing_key_in_txn`]
    /// with kind `RecoveryAuthority`.
    ///
    /// # Errors
    /// As [`Self::enrol_owner_signing_key_as`].
    pub(crate) fn enrol_recovery_authority_key_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        authority: &ActAuthority,
        machine: EntityId,
        seed: &crate::world_keys::RecoveryRootSeed,
        predecessor: &ActivationPredecessor,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let input = recovery_authority_enrollment(seed, &vault_id, machine, actor)?;
        let predecessor_key = predecessor.predecessor_key();
        let mut sign = |transcript: &[u8]| predecessor.sign(transcript);
        self.enrol_owner_signing_key_in_txn(
            txn,
            authority,
            input,
            EnrolledOwnerKeyKind::RecoveryAuthority,
            predecessor_key,
            &mut sign,
        )
    }

    /// Revokes, in a kit activation's write transaction, every live owner
    /// key of kind `RecoveryAuthority` that `actor` enrolled other than
    /// `kept`, the activated kit's R (WAYBACK-SECOND-KIT-OLD-ROOT-KEY = A,
    /// Engine 05:54): a new kit replaces the old one, so a box copy of the
    /// old kit's R, and any recovery hold it signed, no longer act. Each
    /// `RevokeDevice` is signed by `predecessor`, the key that signs the new
    /// R's enrolment, through the one writer
    /// ([`Self::append_revoke_device_in_txn`]). Another owner's R stays: the
    /// filter is the enrolment's owner, as at the membership move.
    ///
    /// # Errors
    /// The writer's: an entry the fold does not count.
    pub(crate) fn revoke_earlier_recovery_authority_keys_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        kept: &AuthorityKey,
        predecessor: &ActivationPredecessor,
    ) -> Result<()> {
        let earlier: Vec<AuthorityKey> = self
            .enrolled_owner_keys_in_txn(txn)?
            .into_iter()
            .filter(|key| {
                key.live
                    && key.owner == actor
                    && key.kind == EnrolledOwnerKeyKind::RecoveryAuthority
            })
            .map(|key| AuthorityKey::Ed25519(key.public_key))
            .filter(|key| key != kept)
            .collect();
        let predecessor_key = predecessor.predecessor_key();
        let sign = |transcript: &[u8]| predecessor.sign(transcript);
        for revoked_key in earlier {
            let signer = match predecessor {
                ActivationPredecessor::OwnerKey(_) => EntrySigner::Key(&predecessor_key, &sign),
                ActivationPredecessor::HostRoot(issuer) => EntrySigner::Host(issuer),
            };
            self.append_revoke_device_in_txn(txn, signer, revoked_key)?;
        }
        Ok(())
    }

    /// What ways back the owner has: live device owner keys, live passkeys,
    /// whether the kit's root is enrolled, and whether the box PIN is set.
    /// Engine read only: no route and no verb.
    pub fn ways_back(&self) -> Result<WaysBack> {
        let txn = self.store.env.read_txn()?;
        let enrolled = self.enrolled_owner_keys_in_txn(&txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let owner_devices = enrolled
            .iter()
            .filter(|key| key.kind == EnrolledOwnerKeyKind::Device && key.live)
            .count() as u32;
        let kit_root_enrolled = enrolled
            .iter()
            .any(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live);
        let passkeys = fold
            .roster
            .iter()
            .filter(|(key, device)| {
                matches!(key, AuthorityKey::P256(_))
                    && !device.revoked
                    && device.roles & ROLE_OWNER != 0
            })
            .count() as u32;
        Ok(WaysBack {
            owner_devices,
            passkeys,
            kit_root_enrolled,
            box_pin_set: false,
        })
    }
}
