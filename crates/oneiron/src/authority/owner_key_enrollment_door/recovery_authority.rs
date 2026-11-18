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
    fn sign(&self, vault: &Vault, fold: &AuthorityFold, transcript: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::OwnerKey(signer) => signer.sign_owner_proof(vault, fold, transcript),
            Self::HostRoot(issuer) => Ok(issuer.sign_slip(transcript)),
        }
    }
}

/// The fold did not count a row by which a kit change's new R carries an
/// approval the revoked R signed. Nothing was written.
const CARRY_NOT_COUNTED: &str = "this install's fold does not count the new kit's carry of an \
                                 approval the old kit signed; nothing was written";

/// What a kit change's new R must carry, chosen before the act revokes the
/// R keys it replaces ([`Vault::recovery_authority_carry_in_txn`]).
#[derive(Debug, Default)]
pub(crate) struct RecoveryAuthorityCarry {
    /// Each roster standing the new R signs again, as the next revision
    /// above its machine's roster head: the head, or the accepted chain's
    /// head when that is another revision (REVIEW-9488 P1 5).
    machines: Vec<MachineProfile>,
    /// Each binding's `RebindActor` one epoch on, which the new R signs.
    rebinds: Vec<AuthorityOp>,
}

/// One standing's or binding's approvals, as the carry's one pass over the
/// history counts them ([`Vault::recovery_authority_carry_in_txn`]).
#[derive(Debug, Default)]
struct CarrySupport {
    /// An approval resting on no key revoked before the act exists.
    open: bool,
    /// An approval resting on no key revoked before the act, nor on a key
    /// the act revokes, exists, or an anchor's row, which never goes stale.
    independent: bool,
}

impl CarrySupport {
    /// The act's revocation would leave no approval that keeps it live.
    fn carried(&self) -> bool {
        self.open && !self.independent
    }
}

/// Whether `entry`'s primary signature or a cosign names a key `revoked`
/// holds: the keys an approval rests on, as the stale-roster window reads
/// them (`stale_roster.rs`).
fn rests_on(entry: &AuthorityLogEntry, revoked: impl Fn(&AuthorityKey) -> bool) -> bool {
    std::iter::once(&entry.signer)
        .chain(&entry.cosigns)
        .any(|signature| revoked(&signature.public_key))
}

/// A kit's activation found no predecessor for the root's authority key:
/// this install holds no live owner key, and the vault is not a self-hosted
/// one whose host root this install holds. Authority; nothing was written
/// (WAYBACK-R4-NO-PREDECESSOR = A).
const NO_PREDECESSOR: &str = "this device's owner key is not enrolled; enrol it, then confirm \
                               the kit; nothing was written";

/// The kit's authority key R is on the roster but revoked: the kit is spent.
/// The owner issues a new kit. Nothing was written.
const REVOKED_AUTHORITY_KEY: &str = "the kit's authority key was revoked; issue a new kit, then \
                                     confirm it; nothing was written";

/// The kit's authority key R is on the roster, but no live enrolment of kind
/// [`EnrolledOwnerKeyKind::RecoveryAuthority`] names the activating owner:
/// another owner's R is never reused as this owner's kit (REVIEW-9488 round 2
/// P1 3). Authority; nothing was written.
const KIT_ROOT_KEY_NOT_THE_OWNERS: &str = "this kit's root authority key is enrolled, but not as \
                                           your recovery key; nothing was written";

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

/// Whether the host root `root` may stand as `actor`'s own predecessor: no
/// live `human` binding gives it to another person, as the vouch door reads
/// a root no enrolment names (REVIEW2 #8798 P2-1). On a shared self-hosted
/// vault the host root bound to the first owner is never a co-owner's.
fn host_root_is_the_owners(fold: &AuthorityFold, root: &AuthorityKey, actor: EntityId) -> bool {
    fold.actor_bindings.get(root).is_none_or(|binding| {
        binding.status != ActorBindingStatus::Active
            || binding.actor_class != ACTOR_CLASS_HUMAN
            || binding.actor_ref == actor
    })
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
        let mut sign_on_fold = |_: &AuthorityFold, transcript: &[u8]| sign_predecessor(transcript);
        let receipt = self.enrol_owner_signing_key_in_txn(
            &mut txn,
            authority,
            input,
            kind,
            predecessor,
            &mut sign_on_fold,
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

    /// A kit activation's predecessor for `owner`, the deciding owner,
    /// loaded before its write transaction opens (pass 27 R4 PR 2): (a) this
    /// install's owner key when a signer this handle holds names an enrolled
    /// owner key of kind `Device`, live with `ROLE_OWNER`, whose enrolment
    /// names `owner`, that the passkey limits do not hold; else (b) this
    /// install's host root when the fold holds no live host-stamped root,
    /// this install is not under the Hosted posture (it never offers a host
    /// root it holds as the owner's proof, Engine ANSWER
    /// HOSTED-REFOLD-SELF-HOST-ROOT-CUSTODY = A), that root is live under
    /// `require_host`, and no live `human` binding gives it to another
    /// person ([`host_root_is_the_owners`]); else (c)
    /// refused with [`NO_PREDECESSOR`]. A co-owner's key this install holds
    /// never signs another owner's R (REVIEW2 #8798 P2-1, the vouch door's
    /// rule). Makes no keystore or store write: one read snapshot for the
    /// owner and the roster checks, then the host seed read, which opens its
    /// own read txn. Liveness is judged again in the txn by the enrol door
    /// (its `NOT_COUNTED` refusal).
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] with [`NO_PREDECESSOR`] when this
    /// install holds neither; an owner refusal when the proof is no longer
    /// the vault's live owner; storage and keystore read errors other than
    /// an absent host seed.
    pub(crate) fn load_activation_predecessor(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> Result<ActivationPredecessor> {
        let (actor, enrolled, fold) = {
            let txn = self.store.env.read_txn()?;
            let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            let enrolled = self.enrolled_owner_keys_in_txn(&txn)?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            (actor, enrolled, fold)
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
            if listed.kind != EnrolledOwnerKeyKind::Device || !listed.live || listed.owner != actor
            {
                continue;
            }
            let live_owner = fold
                .roster
                .get(&root)
                .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0);
            // A key only a passkey vouched for vouches for no further key
            // until it is confirmed (WEBPASSKEY-BLIND-SIGNATURE = B), so it
            // is never R's predecessor: the next key, then the host root,
            // is tried (REVIEW-9488 P1 2).
            if live_owner && !fold.passkey_limited(&root) {
                return Ok(ActivationPredecessor::OwnerKey(signer));
            }
        }
        let hosted = fold.roster.values().any(|device| {
            !device.revoked
                && device.roles & ROLE_OWNER != 0
                && (device.roles & ROLE_CLOUD != 0 || device.tier == AuthorityTier::CloudCustodial)
        });
        // Under the Hosted posture the fold may still trust a self-host root
        // this install holds (a self-hosted vault reopened as Hosted), but a
        // hosted install never signs for the owner with it.
        if !hosted && self.privacy_posture() != crate::HostingPrivacyPosture::Hosted {
            // An install with no host seed (no keystore, no machine
            // identity, an empty slot) holds no host root: that is the
            // refusal below. Any other failure is the read's own error.
            match self.load_host_slip_issuer() {
                Ok(issuer) => {
                    if super::slip_vault::require_host(&fold, &issuer).is_ok()
                        && host_root_is_the_owners(&fold, &issuer.public_key(), actor)
                    {
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
        let mut sign =
            |fold: &AuthorityFold, transcript: &[u8]| predecessor.sign(self, fold, transcript);
        self.enrol_owner_signing_key_in_txn(
            txn,
            authority,
            input,
            EnrolledOwnerKeyKind::RecoveryAuthority,
            predecessor_key,
            &mut sign,
        )
    }

    /// Confirms the kit's root authority key R in the caller's write
    /// transaction when the roster holds R live and only a passkey vouched
    /// for it (lead ruling WEBPASSKEY-BLIND-SIGNATURE = B): `predecessor`,
    /// the activation's, vouches for R again, carried by `machine`, and R
    /// then acts as any owner root, the restored machine's roster row
    /// included (REVIEW-9488 P1 3). Nothing on the roster changes. An R the
    /// passkey limits do not hold needs no row (`None`).
    ///
    /// # Errors
    /// As [`Self::confirm_owner_key_as`].
    pub(crate) fn confirm_recovery_authority_key_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        authority: &ActAuthority,
        machine: EntityId,
        seed: &crate::world_keys::RecoveryRootSeed,
        predecessor: &ActivationPredecessor,
    ) -> Result<Option<OwnerKeyEnrollmentReceipt>> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let input = recovery_authority_enrollment(seed, &vault_id, machine, actor)?;
        if !fold.passkey_limited(&AuthorityKey::Ed25519(input.public_key)) {
            return Ok(None);
        }
        let device = enrolled_device(
            input.public_key,
            input.proof,
            EnrolledOwnerKeyKind::RecoveryAuthority,
        );
        let mut sign =
            |fold: &AuthorityFold, transcript: &[u8]| predecessor.sign(self, fold, transcript);
        let (entry, machine) = self.write_owner_key_enroll_in_txn(
            txn,
            authority,
            Some(input.machine),
            device,
            predecessor.predecessor_key(),
            &mut sign,
            true,
        )?;
        Ok(Some(OwnerKeyEnrollmentReceipt {
            entry,
            machine,
            public_key: input.public_key,
        }))
    }

    /// Whether a kit activation enrols `key`, its R, for `actor`, the
    /// revalidated owner: yes when `fold`'s roster lacks it; no when a live
    /// enrolment of kind `RecoveryAuthority` names `actor` for it, so the
    /// activation confirms that one. Refused when the roster revoked it, and
    /// when it is any other roster key, another owner's R included: that R
    /// would stand for this owner's kit, and a later kit of theirs would not
    /// revoke it (REVIEW-9488 round 2 P1 3).
    ///
    /// # Errors
    /// [`REVOKED_AUTHORITY_KEY`], [`KIT_ROOT_KEY_NOT_THE_OWNERS`]; the
    /// enrolled-key read's.
    pub(crate) fn recovery_authority_enrols_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        actor: EntityId,
        key: &AuthorityKey,
    ) -> Result<bool> {
        match fold.roster.get(key) {
            None => return Ok(true),
            Some(device) if device.revoked => {
                return Err(authority_refused(REVOKED_AUTHORITY_KEY));
            }
            Some(_) => {}
        }
        let owners = self
            .enrolled_owner_keys_in_txn(txn)?
            .into_iter()
            .any(|enrolled| {
                enrolled.live
                    && enrolled.owner == actor
                    && enrolled.kind == EnrolledOwnerKeyKind::RecoveryAuthority
                    && AuthorityKey::Ed25519(enrolled.public_key) == *key
            });
        if owners {
            Ok(false)
        } else {
            Err(authority_refused(KIT_ROOT_KEY_NOT_THE_OWNERS))
        }
    }

    /// Revokes, in a kit activation's write transaction, every live owner
    /// key of kind `RecoveryAuthority` that `actor` enrolled other than
    /// `kept`, the activated kit's R (WAYBACK-SECOND-KIT-OLD-ROOT-KEY = A,
    /// Engine 05:54): a new kit replaces the old one, so a box copy of the
    /// old kit's R, and any recovery hold it signed, no longer act. Each
    /// `RevokeDevice` is signed by `predecessor`, the key that signs the new
    /// R's enrolment, through the one writer
    /// ([`Self::append_revoke_device_in_txn`]). Another owner's R stays: the
    /// filter is the enrolment's owner, as at the membership move. Answers
    /// what the activated R must carry, chosen before the first revocation
    /// ([`Self::recovery_authority_carry_in_txn`]).
    ///
    /// # Errors
    /// The writer's: an entry the fold does not count.
    pub(crate) fn revoke_earlier_recovery_authority_keys_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        kept: &AuthorityKey,
        predecessor: &ActivationPredecessor,
    ) -> Result<RecoveryAuthorityCarry> {
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
        let carry = self.recovery_authority_carry_in_txn(txn, &earlier)?;
        let predecessor_key = predecessor.predecessor_key();
        let signing_fold = self.authority_view_readonly_in_txn(txn)?;
        let sign = |transcript: &[u8]| predecessor.sign(self, &signing_fold, transcript);
        for revoked_key in &earlier {
            let signer = match predecessor {
                ActivationPredecessor::OwnerKey(_) => EntrySigner::Key(&predecessor_key, &sign),
                ActivationPredecessor::HostRoot(issuer) => EntrySigner::Host(issuer),
            };
            self.append_revoke_device_in_txn(txn, signer, revoked_key.clone())?;
        }
        Ok(carry)
    }

    /// Binds `actor` to `key`, the R a kit activation enrolled, as `human`
    /// on a self-hosted vault where `actor` holds no active `human` binding
    /// once the activation revoked their earlier R keys and carried what
    /// those signed: the enrolment's own rule
    /// ([`Self::enrol_owner_signing_key_in_txn`]), judged after the
    /// revocation, because the activation enrols R before it (the
    /// enrolment's carrier may stand on an approval only a revoked R gave,
    /// until the carry signs it again). Signed by `predecessor`, as the
    /// enrolment's binding is.
    ///
    /// # Errors
    /// The binding's `BINDING_NOT_COUNTED`, as at the enrolment.
    pub(crate) fn bind_owner_to_recovery_authority_key_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        key: AuthorityKey,
        predecessor: &ActivationPredecessor,
    ) -> Result<()> {
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
            predecessor: predecessor.predecessor_key(),
            key,
            owner: actor,
        };
        let mut sign =
            |fold: &AuthorityFold, transcript: &[u8]| predecessor.sign(self, fold, transcript);
        self.bind_enrolled_owner_key_in_txn(txn, bind, &mut sign)
    }

    /// Chooses, in the caller's write transaction and BEFORE any key in
    /// `revoking` is revoked, what the R that replaces them must carry
    /// (WAYBACK-R-REVOCATION-STALES-R-APPROVALS = A, Engine 07:13: a kit
    /// change must not unpair the owner's own machines). The choice comes
    /// first because an approval's stale deadline counts from the earlier of
    /// its own first sight and its key's revocation (`stale_roster.rs`): one
    /// older than the window goes stale the moment its key is revoked, so a
    /// fold read after the revocation would miss every aged approval (Sol
    /// carry F1).
    ///
    /// The test is the stale-roster window's own (Sol carry F2): an approval
    /// rests on every key its primary signature or a cosign names. Of the
    /// approvals that rest on no key revoked before this act, when at least
    /// one exists and every one rests on a key in `revoking`, the act would
    /// unpair the standing, so it is carried; one approval resting on none
    /// keeps it live and nothing is carried; and a standing that only rests
    /// on keys revoked before is already going stale (the ruling's guard).
    /// - A machine's live, act-free roster head: its approvals are the valid
    ///   roster rows with the head's exact profile (the rows that renew a
    ///   stale head; an anchor's row renews none). A head an anchor's row
    ///   carried never goes stale and is not carried.
    /// - An active binding: its approvals are the valid `BindActor` and
    ///   `RebindActor` rows of its current tuple (an anchor's row never goes
    ///   stale, so it keeps the binding live). The binding of a key in
    ///   `revoking` ends with that key and is not carried.
    ///
    /// A head at the last revision, or a binding at the last epoch, has no
    /// next row, so it is not carried: no row the revoked key signed can
    /// refuse the kit change that revokes the key (Sol carry F2, F3). Only a
    /// live R's holder can sign such a row, and the standing goes stale as
    /// it did before the carry (FIX [KIT-CHANGE-CARRY-SKIPS-LAST-COUNTER]).
    /// The history is read once (Sol carry F4): the stored rows and the
    /// bodies an adopted checkpoint image carries (Sol carry-fix F2).
    ///
    /// # Errors
    /// A fold or history read's.
    pub(crate) fn recovery_authority_carry_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        revoking: &[AuthorityKey],
    ) -> Result<RecoveryAuthorityCarry> {
        if revoking.is_empty() {
            return Ok(RecoveryAuthorityCarry::default());
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let revoked_before: std::collections::BTreeSet<&AuthorityKey> = fold
            .roster
            .iter()
            .filter(|(_, device)| device.revoked)
            .map(|(key, _)| key)
            .collect();
        // Each machine's roster head and the accepted chain's head (a
        // custodial revision above an owner-held one leaves the accepted
        // chain at the owner-held one), each with its own support: the
        // stale-roster window expires either once the R it rests on is
        // revoked, and renews the accepted chain's only by a mark that chain
        // accepts (REVIEW-9488 round 2 P1 5).
        let mut machines: std::collections::BTreeMap<_, Vec<_>> = fold
            .machines
            .iter()
            .filter_map(|(machine, folded)| {
                let head = folded.roster.as_ref()?;
                if head.profile.revision == u64::MAX {
                    return None;
                }
                let heads: Vec<_> = [(Some(head), false), (folded.roster_trusted.as_ref(), true)]
                    .into_iter()
                    .filter_map(|(head, trusted)| Some((head?, trusted)))
                    .filter(|(head, _)| {
                        head.is_live()
                            && head.profile.act.is_none()
                            && !fold.anchor_entries.contains(&head.entry)
                    })
                    .map(|(head, trusted)| (&head.profile, trusted, CarrySupport::default()))
                    .collect();
                (!heads.is_empty()).then_some((*machine, heads))
            })
            .collect();
        let mut bindings: std::collections::BTreeMap<_, _> = fold
            .actor_bindings
            .iter()
            .filter(|(bound, binding)| {
                matches!(binding.status, ActorBindingStatus::Active)
                    && binding.epoch < u64::MAX
                    && !revoking.contains(bound)
            })
            .map(|(bound, binding)| (bound, (binding, CarrySupport::default())))
            .collect();
        // The approvals the stale-roster window reads: each stored row, and
        // each body an adopted checkpoint image carries that this vault does
        // not store (the adopted fold expires those too), a stored row
        // winning over the image's copy, as the enrolled-key reader reads
        // them (Sol carry-fix F2).
        let history = crate::authority::history_transfer::history_in_txn(self, txn)?;
        let stored: std::collections::BTreeSet<AuthorityEntryHash> =
            history.keys().copied().collect();
        let evidence =
            crate::authority::adopted_evidence::adopted_evidence_in_txn(&self.store, txn)?;
        let stored = &stored;
        let carried_past = evidence
            .iter()
            .flat_map(move |evidence| evidence.carried_past(stored));
        let approvals = history
            .iter()
            .map(|(hash, (_, entry))| (hash, entry))
            .chain(carried_past);
        for (hash, entry) in approvals {
            if !fold.valid_entries.contains(hash) {
                continue;
            }
            let anchor = fold.anchor_entries.contains(hash);
            // The accepted chain's head counts only a mark that chain
            // accepts, as the stale-roster window renews it, never a
            // custodial copy of its profile (`stale_roster.rs`).
            let accepted = fold.accepted_roster_marks.contains(hash);
            let supports: Vec<&mut CarrySupport> = match &entry.op {
                AuthorityOp::MachineProfile(profile) if !anchor => machines
                    .get_mut(&profile.machine)
                    .into_iter()
                    .flatten()
                    .filter(|(head, trusted, _)| *head == profile && (accepted || !*trusted))
                    .map(|(_, _, support)| support)
                    .collect(),
                AuthorityOp::BindActor {
                    authority_key,
                    actor_ref,
                    actor_class,
                    epoch,
                }
                | AuthorityOp::RebindActor {
                    authority_key,
                    actor_ref,
                    actor_class,
                    epoch,
                } => match bindings.get_mut(authority_key) {
                    Some((binding, support))
                        if binding.actor_ref == *actor_ref
                            && binding.actor_class == *actor_class
                            && binding.epoch == *epoch =>
                    {
                        vec![support]
                    }
                    _ => Vec::new(),
                },
                _ => Vec::new(),
            };
            for support in supports {
                if anchor {
                    support.independent = true;
                } else if !rests_on(entry, |key| revoked_before.contains(key)) {
                    support.open = true;
                    if !rests_on(entry, |key| revoking.contains(key)) {
                        support.independent = true;
                    }
                }
            }
        }
        let rebinds = bindings
            .into_iter()
            .filter(|(_, (_, support))| support.carried())
            .map(|(bound, (binding, _))| {
                Ok(AuthorityOp::RebindActor {
                    authority_key: bound.clone(),
                    actor_ref: binding.actor_ref,
                    actor_class: binding.actor_class.clone(),
                    epoch: binding.epoch.checked_add(1).ok_or_else(invalid_authority)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        // One row per machine: the accepted chain's standing when the act
        // would leave it with no approval, else the head's.
        Ok(RecoveryAuthorityCarry {
            machines: machines
                .into_values()
                .filter_map(|heads| {
                    heads
                        .into_iter()
                        .rev()
                        .find(|(_, _, support)| support.carried())
                        .map(|(profile, _, _)| profile.clone())
                })
                .collect(),
            rebinds,
        })
    }

    /// Carries `carry`, chosen before the act revoked the R keys it names
    /// ([`Self::recovery_authority_carry_in_txn`]), under `next`, the R that
    /// replaces them and is live on the roster, as a host re-root carries
    /// its standings ([`Self::carry_machine_standing_in_txn`]): `next` signs
    /// the next revision of each chosen machine's roster head
    /// ([`Self::carry_roster_standing_under_key_in_txn`]), and a
    /// `RebindActor` one epoch on, with the same key, actor and class, for
    /// each chosen binding. Stored change: keep (ordinary rows).
    ///
    /// # Errors
    /// A carried row the fold does not count.
    pub(crate) fn carry_recovery_authority_approvals_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        carry: RecoveryAuthorityCarry,
        next: &crate::world_keys::RecoveryAuthoritySigner,
    ) -> Result<()> {
        let key = next.authority_key();
        let sign = |transcript: &[u8]| next.sign_authority_transcript(transcript);
        for standing in &carry.machines {
            self.carry_roster_standing_under_key_in_txn(txn, (&key, &sign), standing)?;
        }
        for rebind in carry.rebinds {
            self.append_key_signed_op_in_txn(txn, (&key, &sign), rebind, CARRY_NOT_COUNTED)?;
        }
        Ok(())
    }

    /// What ways back `owner` has: their live device owner keys, their live
    /// passkeys, whether their kit's root is enrolled, and whether the box
    /// PIN is set. Each count reads only the keys whose enrolment names the
    /// owner, revalidated in the read's snapshot, so a co-owner's keys on a
    /// shared vault are never theirs (REVIEW-9488 P1 7). Engine read only:
    /// no route and no verb.
    ///
    /// # Errors
    /// An owner refusal when the proof is no longer the vault's live owner;
    /// the store's own.
    pub fn ways_back(&self, owner: &crate::consent::AuthenticatedOwner) -> Result<WaysBack> {
        let txn = self.store.env.read_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let enrolled = self.enrolled_owner_keys_in_txn(&txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let owners = |key: &&EnrolledOwnerKey| key.live && key.owner == actor;
        let owner_devices = enrolled
            .iter()
            .filter(owners)
            .filter(|key| key.kind == EnrolledOwnerKeyKind::Device)
            .count() as u32;
        let kit_root_enrolled = enrolled
            .iter()
            .filter(owners)
            .any(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority);
        let passkeys = self
            .live_owner_keys_enrolled_for_in_txn(&txn, actor)?
            .iter()
            .filter(|key| {
                matches!(key, AuthorityKey::P256(_))
                    && fold
                        .roster
                        .get(key)
                        .is_some_and(|device| device.roles & ROLE_OWNER != 0)
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
