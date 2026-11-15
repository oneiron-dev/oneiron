//! The owner's enrollment of one of his devices' own owner signing keys
//! (FIX 4920 part 2; Engine 10-20 00:5x, ruling D): the public Rust seam
//! L04's keystore (FIX 4921) calls, the writer the owner HTTP routes call,
//! and the listing his surface reads (CALLS "FIX 4920 enrollment API shape",
//! "FIX 4920 enrollment receipt/list").
//!
//! The device signs [`owner_key_enrollment_challenge`] with its new key and
//! hands over an [`OwnerKeyEnrollment`]: the machine that holds the key, the
//! key, and that proof of possession. The writer fixes the rest in one write
//! transaction: the owner, revalidated there from the caller's proof; this
//! install as the carrier of his act, by the one carrier rule; the act's
//! target and zero `seen`; the main-log heads as parents; the predecessor
//! root's next sequence. Both public keys are in the entry before either
//! signs, since the transcript names the cosign keys: the predecessor (an
//! existing live owner root) signs the authority transcript, and the
//! carrier's install key cosigns the same bytes. The entry lands and the
//! fold runs again in that transaction, which commits only when the fold
//! counted the entry, put the key on the roster and held nothing back.
//!
//! An agent never enrols an owner key: no Grant line names the act. The
//! proof of possession authorizes nothing, and the key never signs its own
//! entry. A predecessor this install cannot sign for means this enrollment
//! did not happen; it takes no other owner right away. The operator root
//! alone acts as nobody (FIX 2222): it may be the predecessor, but the
//! carrier is never a roster key.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ed25519_dalek::Signer;

use crate::error::{Error, RecordError, Result, SecretError};
use crate::{EntityId, TimeRange, Vault};

use super::*;

/// An owner signing key is the owner's to enrol: no Grant action names it,
/// so an agent's act never enrols one. Authority; nothing was written.
const OWNER_ONLY: &str = "an owner signing key is the owner's to enrol; no Grant action names it";
/// This install cannot carry the owner's act: it has no machine identity or
/// install key, or no live profile of it stands under that key. Key
/// possession: the act is cosigned by the install that carries it, and no
/// roster key, the host root included, carries an owner act (FIX 2222).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the owner's key enrollment";
/// Integrity: the roster already names the key, live or revoked. A
/// replacement is a fresh key, and the old one's ordinary revoke.
pub(crate) const KEY_ON_ROSTER: &str = "the vault's roster already names this key, live or revoked; enrol a \
                                        fresh key";
/// Integrity: the enrollment's fixed shape does not hold: a weak key, a
/// proof that is not the key's own signature over its challenge, or a key
/// that would sign its own entry.
const NOT_VALID: &str = "the enrollment does not verify: the proof must be the new key's own \
                         signature over its challenge for this vault, machine, key and owner";
/// The fold did not count a key revocation signed by a roster key in this
/// transaction. Nothing was written.
const REVOKE_NOT_COUNTED: &str = "this install's fold does not count the key revocation; nothing \
                                  was written";

/// The signer of one authority entry a door writes in its own write
/// transaction (the one `RevokeDevice` writer, pass 27 R4).
pub(crate) enum EntrySigner<'a> {
    /// This vault's live host root, through its slip issuer.
    Host(&'a HostSlipIssuer),
    /// A live roster key held behind the caller's signing callback, which
    /// signs the entry's authority transcript: the recovery root's
    /// authority key at the root's door.
    Key(&'a AuthorityKey, &'a dyn Fn(&[u8]) -> Result<Vec<u8>>),
}

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

/// The enrollment would name more rows than one authority entry may: the
/// log's encoding bound, never a possession test.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one key enrollment \
                              may name; nothing was written";
/// The fold did not count the signed enrollment here: it never reports
/// success. Nothing was written.
const NOT_COUNTED: &str = "this install's fold does not count the key enrollment: the key is not \
                           fresh, the holding machine is not live, the predecessor is no live \
                           consenting owner root, or the owner is no longer live; nothing was \
                           written";
/// The fold did not count the binding of an Owner's first enrolled key to
/// them: the enrollment does not land without it. Nothing was written.
const BINDING_NOT_COUNTED: &str = "this install's fold does not count the binding of the enrolled \
                                   key to its owner; nothing was written";
/// A membership move no issuer signs would leave owner authority live: the
/// member holds an owner key or a `human` binding the move must revoke, and
/// only the vault's live host root signs that (REVIEW-7931). Authority;
/// nothing moved.
const OWNER_AUTHORITY_NEEDS_HOST: &str = "the member holds an owner key or owner binding that \
                                          this move must revoke, and this install holds no \
                                          live host root to sign it; run the move on the \
                                          vault's host";
/// A membership move gives the embedded owner Owner standing back, and no
/// issuer signs it, so the host root cannot bind them again (REVIEW-7931
/// round 2). Authority; nothing moved.
const OWNER_BINDING_NEEDS_HOST: &str = "the embedded owner regains Owner standing, and this \
                                        install holds no live host root to bind them again; \
                                        run the move on the vault's host";
/// The host root's new binding of the embedded owner did not count.
/// Authority; nothing moved.
const OWNER_BINDING_NOT_RESTORED: &str = "the host root's binding of the embedded owner did not \
                                          count; nothing moved";
/// A kit's activation found no predecessor for the root's authority key:
/// this install holds no live owner key, and the vault is not a self-hosted
/// one whose host root this install holds. Authority; nothing was written
/// (WAYBACK-R4-NO-PREDECESSOR = A).
const NO_PREDECESSOR: &str = "this device's owner key is not enrolled; enrol it, then confirm \
                               the kit; nothing was written";

/// What a device hands its enrollment (CALLS "FIX 4920 enrollment API
/// shape"): the machine that holds the key in its keystore, the key's
/// Ed25519 bytes, and the key's strict signature over
/// [`owner_key_enrollment_challenge`] for this vault, that machine, the key
/// and the enrolling owner ([`OWNER_KEY_POSSESSION_PROOF_LEN`] bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyEnrollment {
    /// The machine that holds the key: a live machine of the vault, in any
    /// role; it may be another machine than the carrying install.
    pub machine: EntityId,
    /// The new key.
    pub public_key: [u8; 32],
    /// The key's proof of possession.
    pub proof: Vec<u8>,
}

/// What a counted enrollment answers (CALLS "FIX 4920 enrollment
/// receipt/list"), only once the fold counted it here and it committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerKeyEnrollmentReceipt {
    /// The enrollment's authority entry.
    pub entry: AuthorityEntryHash,
    /// The machine that holds the key.
    pub machine: EntityId,
    /// The enrolled key.
    pub public_key: [u8; 32],
}

/// One enrolled owner signing key as the owner's surface lists it: a valid
/// retained enrollment body, joined to the roster now (CALLS "FIX 4920
/// enrollment receipt/list").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledOwnerKey {
    /// The enrollment's authority entry.
    pub entry: AuthorityEntryHash,
    /// The machine that holds the key.
    pub machine: EntityId,
    /// The install that carried the owner's act.
    pub carrier: EntityId,
    /// The owner whose act enrolled it.
    pub owner: EntityId,
    /// The enrolled key.
    pub public_key: [u8; 32],
    /// On the roster and not revoked.
    pub live: bool,
    /// A root the owner's checkpoint policy may name now (the selectable
    /// root rule). It promises no signer online and no place among the
    /// roots a policy in force names.
    pub eligible: bool,
    /// When it was signed, advisory unix seconds.
    pub at: u64,
    /// What the key is, as its enrollment's attestation kind says.
    pub kind: EnrolledOwnerKeyKind,
}

/// What an enrolled owner key is, read from its enrollment row alone (pass
/// 27 R4): a device's own key, or the recovery root's authority key. The
/// owner's "last key held on a device" counts the first kind only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrolledOwnerKeyKind {
    /// A device's own owner signing key, held in its keystore
    /// ([`OWNER_KEY_POSSESSION_KIND`]).
    Device,
    /// The recovery root's authority key, derived from the kit's seed
    /// ([`RECOVERY_AUTHORITY_POSSESSION_KIND`]).
    RecoveryAuthority,
}

impl EnrolledOwnerKeyKind {
    /// The attestation kind an enrollment of this kind carries.
    fn attestation_kind(self) -> &'static str {
        match self {
            Self::Device => OWNER_KEY_POSSESSION_KIND,
            Self::RecoveryAuthority => RECOVERY_AUTHORITY_POSSESSION_KIND,
        }
    }

    /// The kind an enrollment row names.
    fn of(enroll: &OwnerKeyEnroll) -> Self {
        if enroll.is_recovery_authority() {
            Self::RecoveryAuthority
        } else {
            Self::Device
        }
    }
}

/// The binding of an owner's first enrolled key to them, as the enrollment's
/// writer hands it on: the fold after the enrollment, the vault, the
/// enrollment's predecessor, the key and the owner.
struct EnrolledKeyBinding<'fold> {
    fold: &'fold AuthorityFold,
    vault_id: AuthorityVaultId,
    predecessor: AuthorityKey,
    key: AuthorityKey,
    owner: EntityId,
}

/// An enrollment that does not verify, as the typed integrity refusal.
pub(crate) fn not_valid(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(reason))
}

/// The one device shape an enrolled owner key has: Ed25519, `ROLE_OWNER`
/// alone, Software tier, no transport binding, its proof as evidence under
/// the attestation kind of `kind`.
fn enrolled_device(
    public_key: [u8; 32],
    proof: Vec<u8>,
    kind: EnrolledOwnerKeyKind,
) -> DeviceAuthority {
    DeviceAuthority {
        key: AuthorityKey::Ed25519(public_key),
        transport_key_binding: [0; 32],
        attestation: AuthorityAttestation {
            kind: kind.attestation_kind().to_owned(),
            evidence: proof,
        },
        tier: AuthorityTier::Software,
        roles: ROLE_OWNER,
    }
}

/// The op's own checks on `entry` before anyone signs it: the fixed shape,
/// the act's kind and target, the one cosign, and the proof of possession.
/// The envelope's signature checks wait for the signatures.
fn verify_unsigned(entry: &AuthorityLogEntry) -> Result<()> {
    let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op else {
        return Err(not_valid(NOT_VALID));
    };
    enroll
        .validate()
        .and_then(|()| enroll.validate_entry(entry))
        .map_err(|_| not_valid(NOT_VALID))
}

/// R's enrolment input for `machine` and `actor` (the revalidated owner): the
/// one body [`Vault::enrol_recovery_authority_key_as`] and
/// [`Vault::enrol_recovery_authority_key_in_txn`] share, so there are not two
/// copies. The caller supplies `vault_id` from its own snapshot: a read txn
/// for the explicit door, the caller's write txn for the activation.
fn recovery_authority_enrollment(
    seed: &crate::world_keys::RecoveryRootSeed,
    vault_id: &AuthorityVaultId,
    generation: u32,
    machine: EntityId,
    actor: EntityId,
) -> Result<OwnerKeyEnrollment> {
    let signer = crate::world_keys::RecoveryAuthoritySigner::from_seed(seed, vault_id, generation)?;
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
    /// The bytes a device's new key signs to enrol on this vault for the
    /// owner `authority` proves: [`owner_key_enrollment_challenge`] over the
    /// vault's id, `machine`, `public_key` and that owner, revalidated now.
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] for an agent's act; an owner
    /// refusal when the proof is no longer the vault's live owner.
    pub fn owner_key_enrollment_challenge_as(
        &self,
        authority: &ActAuthority,
        machine: EntityId,
        public_key: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let txn = self.store.env.read_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        owner_key_enrollment_challenge(&vault_id, machine, public_key, actor)
    }

    /// The owner enrols `input`'s key as an owner root of its own, as
    /// `authority`, carried by this install, with `predecessor` (an existing
    /// live owner root of the roster) as the entry's primary signer.
    /// `sign_predecessor` gets each authority transcript the predecessor
    /// signs and returns its signature over it; it runs while the write
    /// transaction is open, so it must not open another. The entry lands
    /// atomically or not at all, and the receipt comes only once the fold
    /// counted it.
    ///
    /// On a self-hosted vault, the key of an owner whom no live `human`
    /// binding names is bound to them in the same transaction, as the next
    /// entry, which the predecessor signs too (OWNER-ENROL: an added Owner of
    /// a shared vault binds with their first owner key). The host root binds
    /// its embedded owner there already, so that owner's keys bind no one. A
    /// hosted or relay root binds no one (`host_actor`).
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] for an agent's act, an install that
    /// cannot carry it, or an enrollment the fold does not count;
    /// [`RecordError::InvalidAuthorityLogBody`] for a key the roster already
    /// names or a proof that does not verify; an owner refusal when the
    /// proof is no longer the vault's live owner; `sign_predecessor`'s own
    /// error.
    pub fn enrol_owner_signing_key_as<S>(
        &self,
        authority: &ActAuthority,
        input: OwnerKeyEnrollment,
        predecessor: AuthorityKey,
        sign_predecessor: S,
    ) -> Result<OwnerKeyEnrollmentReceipt>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        self.enrol_owner_key_of_kind_as(
            authority,
            input,
            EnrolledOwnerKeyKind::Device,
            predecessor,
            sign_predecessor,
        )
    }

    /// [`Self::enrol_owner_signing_key_as`] for a key of `kind`, in a write
    /// transaction of its own.
    fn enrol_owner_key_of_kind_as<S>(
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

    /// [`Self::enrol_owner_signing_key_as`] for a key of `kind`, in the
    /// caller's write transaction, which commits it or not: the recovery
    /// root's door enrols the new key and revokes the lost ones in one (pass
    /// 27 R4).
    ///
    /// # Errors
    /// As [`Self::enrol_owner_signing_key_as`].
    pub(super) fn enrol_owner_signing_key_in_txn<S>(
        &self,
        txn: &mut heed::RwTxn<'_>,
        authority: &ActAuthority,
        input: OwnerKeyEnrollment,
        kind: EnrolledOwnerKeyKind,
        predecessor: AuthorityKey,
        sign_predecessor: &mut S,
    ) -> Result<OwnerKeyEnrollmentReceipt>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        let (owner, surface) = match authority {
            ActAuthority::Owner(owner, surface) => (owner, *surface),
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        self.enrol_owner_signing_key_for_actor_in_txn(
            txn,
            actor,
            surface,
            input,
            kind,
            predecessor,
            sign_predecessor,
        )
    }

    /// [`Self::enrol_owner_signing_key_in_txn`] for `actor`, an owner the
    /// caller judged live in `txn`, with `surface` as the act's audit-only
    /// surface: the recovery wait's landing seam, which runs with no owner
    /// proof (OPUS-WAYBACK): the hold authorized the act, and the landing
    /// rechecks the owner's liveness itself. Every other caller takes the
    /// authority door above.
    ///
    /// # Errors
    /// As [`Self::enrol_owner_signing_key_as`].
    pub(super) fn enrol_owner_signing_key_for_actor_in_txn<S>(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        surface: ActSurface,
        input: OwnerKeyEnrollment,
        kind: EnrolledOwnerKeyKind,
        predecessor: AuthorityKey,
        sign_predecessor: &mut S,
    ) -> Result<OwnerKeyEnrollmentReceipt>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let (carrier, carrier_key) = self
            .carrier_in_txn(txn, &fold)
            .map_err(authority_refusal_as(NO_CARRIER))?;
        let key = AuthorityKey::Ed25519(input.public_key);
        if fold.roster.contains_key(&key) {
            return Err(not_valid(KEY_ON_ROSTER));
        }
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let joiner = FrontierSigner::Install(carrier, &carrier_key);
        let fold = self
            .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
            .unwrap_or(fold);
        // The main-log heads alone: the carrier's standing rows and the
        // predecessor's roster rows are main-log rows among them or their
        // ancestors, so the fold at the heads carries them.
        let parents = fold.append_heads.clone();
        if parents.is_empty() {
            return Err(invalid_authority());
        }
        if parents.len() > MAX_PARENTS {
            return Err(authority_refused(TOO_MANY_HEADS));
        }
        let act = OwnerAct::by_owner(
            actor,
            OwnerActKind::OwnerKeyEnrollment,
            owner_key_enrollment_target(&vault_id, &input.public_key)?,
            surface,
            OWNER_KEY_ENROLLMENT_SEEN,
        );
        let now = self.instant_in_txn(txn)?.secs();
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: next_sequence(&fold, &predecessor)?,
            parent_hashes: parents.into_iter().collect(),
            op: AuthorityOp::OwnerKeyEnroll(OwnerKeyEnroll {
                act,
                machine: input.machine,
                carrier,
                device: enrolled_device(input.public_key, input.proof, kind),
            }),
            signer: AuthoritySignature {
                suite: predecessor.suite(),
                public_key: predecessor.clone(),
                signature: vec![0; 64],
            },
            cosigns: vec![AuthoritySignature {
                suite: AuthoritySignatureSuite::Ed25519,
                public_key: AuthorityKey::Ed25519(carrier_key.verifying_key().to_bytes()),
                signature: vec![0; 64],
            }],
            ts: now,
        };
        verify_unsigned(&entry)?;
        let transcript = authority_transcript(&entry)?;
        if let Some(cosign) = entry.cosigns.first_mut() {
            cosign.signature = carrier_key.sign(&transcript).to_bytes().to_vec();
        }
        entry.signer.signature = sign_predecessor(&transcript)?;
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !after.valid_entries.contains(&hash)
            || after.install.held_back.contains(&hash)
            || !after.roster.get(&key).is_some_and(|device| !device.revoked)
        {
            return Err(authority_refused(NOT_COUNTED));
        }
        if self.privacy_posture() == crate::HostingPrivacyPosture::SelfHostLocal
            && !actor_binding_is_active(&after, &actor, ACTOR_CLASS_HUMAN)
        {
            let bind = EnrolledKeyBinding {
                fold: &after,
                vault_id,
                predecessor,
                key,
                owner: actor,
            };
            self.bind_enrolled_owner_key_in_txn(txn, bind, sign_predecessor)?;
        }
        Ok(OwnerKeyEnrollmentReceipt {
            entry: hash,
            machine: input.machine,
            public_key: input.public_key,
        })
    }

    /// [`Self::enrol_owner_signing_key_as`] with this host's own root as the
    /// predecessor: `issuer` signs the transcript in process, and no signing
    /// door of it leaves this module.
    ///
    /// # Errors
    /// As [`Self::enrol_owner_signing_key_as`].
    pub fn enrol_owner_signing_key_as_host(
        &self,
        authority: &ActAuthority,
        input: OwnerKeyEnrollment,
        issuer: &HostSlipIssuer,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        self.enrol_owner_signing_key_as(authority, input, issuer.public_key(), |transcript| {
            Ok(issuer.sign_slip(transcript))
        })
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
            recovery_authority_enrollment(seed, &vault_id, 0, machine, actor)?
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
        let input = recovery_authority_enrollment(seed, &vault_id, 0, machine, actor)?;
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

    /// Rotates the recovery authority key in the caller's write transaction:
    /// enrols generation `live_generation + 1` with generation
    /// `live_generation` as predecessor (which signs the transcript), then
    /// revokes generation `live_generation` under itself. Enrol first, then
    /// revoke: the self-revoke counts because the new generation is a live
    /// consenting key after the enrol. The holding machine is this install's
    /// machine identity, read in the transaction and never minted; the enrol
    /// door's own carrier check judges it. Returns the new live generation
    /// with its enrol receipt and the old generation's revocation.
    ///
    /// # Errors
    /// As [`Self::enrol_owner_signing_key_as`], and the revoke's
    /// [`REVOKE_NOT_COUNTED`]; an agent's act is refused as there.
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
        let sign = |transcript: &[u8]| live_signer.sign_authority_transcript(transcript);
        let mut sign_enrol = sign;
        let receipt = self.enrol_owner_signing_key_in_txn(
            txn,
            authority,
            input,
            EnrolledOwnerKeyKind::RecoveryAuthority,
            live_key.clone(),
            &mut sign_enrol,
        )?;
        let revoked = self.append_revoke_device_in_txn(
            txn,
            EntrySigner::Key(&live_key, &sign_enrol),
            live_key,
        )?;
        Ok((next, receipt, revoked))
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

    /// Binds `bind.key`, enrolled in this transaction, to `bind.owner` as
    /// `human`: the next entry after the enrollment, at the first epoch,
    /// signed by the enrollment's predecessor. The fold must count it and the
    /// owner's binding must stand, or the enrollment commits nothing.
    fn bind_enrolled_owner_key_in_txn<S>(
        &self,
        txn: &mut heed::RwTxn<'_>,
        bind: EnrolledKeyBinding<'_>,
        sign_predecessor: &mut S,
    ) -> Result<()>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        let parents = bind.fold.append_heads.clone();
        if parents.is_empty() {
            return Err(invalid_authority());
        }
        if parents.len() > MAX_PARENTS {
            return Err(authority_refused(TOO_MANY_HEADS));
        }
        let now = self.instant_in_txn(txn)?.secs();
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(bind.vault_id),
            seq: next_sequence(bind.fold, &bind.predecessor)?,
            parent_hashes: parents.into_iter().collect(),
            op: AuthorityOp::BindActor {
                authority_key: bind.key,
                actor_ref: bind.owner,
                actor_class: ACTOR_CLASS_HUMAN.into(),
                epoch: 1,
            },
            signer: AuthoritySignature {
                suite: bind.predecessor.suite(),
                public_key: bind.predecessor,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: now,
        };
        let transcript = authority_transcript(&entry)?;
        entry.signer.signature = sign_predecessor(&transcript)?;
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !after.valid_entries.contains(&hash)
            || !actor_binding_is_active(&after, &bind.owner, ACTOR_CLASS_HUMAN)
        {
            return Err(authority_refused(BINDING_NOT_COUNTED));
        }
        Ok(())
    }

    /// Every enrolled owner signing key, ascending by key: each valid
    /// enrollment body this vault keeps (stored, or carried by an adopted
    /// checkpoint image), the smallest entry for a key enrolled on two
    /// branches, joined to the roster now, a revoked or ineligible key
    /// included. Empty before any enrollment.
    pub fn enrolled_owner_keys(&self) -> Result<Vec<EnrolledOwnerKey>> {
        let txn = self.store.env.read_txn()?;
        self.enrolled_owner_keys_in_txn(&txn)
    }

    /// [`Self::enrolled_owner_keys`] in the caller's transaction.
    pub(super) fn enrolled_owner_keys_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<EnrolledOwnerKey>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let managed = CheckpointPosture::from(self.privacy_posture()) == CheckpointPosture::Managed;
        let mut keys = BTreeMap::new();
        let mut stored = BTreeSet::new();
        for (_, body) in super::readonly_fold::authority_log_rows_in_txn(&self.store, txn)? {
            let entry = decode_authority_log_entry_body(&body)?;
            let hash = authority_entry_hash(&entry)?;
            stored.insert(hash);
            keep_enrolled(&mut keys, &fold, managed, hash, &entry);
        }
        if let Some(evidence) = super::adopted_evidence::adopted_evidence_in_txn(&self.store, txn)?
        {
            for (hash, entry) in evidence.carried_past(&stored) {
                keep_enrolled(&mut keys, &fold, managed, *hash, entry);
            }
        }
        Ok(keys.into_values().collect())
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

    /// Ends the owner authority `person` holds on this vault's log, in the
    /// transaction of the membership move that ends their standing
    /// (OWNER-ENROL): under `issuer`, a `RevokeDevice` for each live owner
    /// key whose enrolment names them, which ends any binding on that key,
    /// then a `RevokeActor` for each other live `human` binding that names
    /// them, the host root's binding of its embedded owner among them. The
    /// root key itself stays: only its binding ends. Each entry must count,
    /// or the move commits nothing. A person with neither writes no entry.
    ///
    /// # Errors
    /// The log's: an `issuer` that is not this vault's live host root, or an
    /// entry the fold does not count.
    pub(crate) fn revoke_owner_authority_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        person: EntityId,
    ) -> Result<()> {
        let root = issuer.public_key();
        let keys: Vec<AuthorityKey> = self
            .enrolled_owner_keys_in_txn(txn)?
            .into_iter()
            .filter(|key| key.live && key.owner == person)
            .map(|key| AuthorityKey::Ed25519(key.public_key))
            .filter(|key| *key != root)
            .collect();
        for revoked_key in keys {
            self.append_revoke_device_in_txn(txn, EntrySigner::Host(issuer), revoked_key)?;
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let bindings: Vec<(AuthorityKey, u64)> = fold
            .actor_bindings
            .iter()
            .filter(|(_, binding)| {
                binding.status == ActorBindingStatus::Active
                    && binding.actor_ref == person
                    && binding.actor_class == ACTOR_CLASS_HUMAN
            })
            .map(|(key, binding)| (key.clone(), binding.epoch))
            .collect();
        for (authority_key, epoch) in bindings {
            self.append_slip_op_in_txn(
                txn,
                issuer,
                AuthorityOp::RevokeActor {
                    authority_key,
                    epoch,
                },
            )?;
        }
        Ok(())
    }

    /// One `RevokeDevice` of `revoked_key`, signed by `signer`, in the
    /// caller's write transaction: the one writer of the act (the
    /// membership move signs it with the host root, the recovery root's door
    /// with the root's authority key). It joins a frontier wider than one
    /// entry names, names the main-log heads, takes the signer's next
    /// sequence, and answers the entry's hash only once the fold counts it.
    ///
    /// # Errors
    /// The log's: a signer that is not a live roster key of this vault, or
    /// an entry the fold does not count.
    pub(crate) fn append_revoke_device_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        signer: EntrySigner<'_>,
        revoked_key: AuthorityKey,
    ) -> Result<AuthorityEntryHash> {
        let op = AuthorityOp::RevokeDevice { revoked_key };
        let (key, sign) = match signer {
            EntrySigner::Host(issuer) => return self.append_hashed_slip_op_in_txn(txn, issuer, op),
            EntrySigner::Key(key, sign) => (key, sign),
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let joiner = FrontierSigner::Callback(key, sign);
        let fold = self
            .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
            .unwrap_or(fold);
        let parents = fold.append_heads.clone();
        if parents.is_empty() {
            return Err(invalid_authority());
        }
        if parents.len() > MAX_PARENTS {
            return Err(authority_refused(TOO_MANY_HEADS));
        }
        let now = self.instant_in_txn(txn)?.secs();
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: next_sequence(&fold, key)?,
            parent_hashes: parents.into_iter().collect(),
            op,
            signer: AuthoritySignature {
                suite: key.suite(),
                public_key: key.clone(),
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: now,
        };
        entry.signer.signature = sign(&authority_transcript(&entry)?)?;
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        if !self
            .authority_view_readonly_in_txn(txn)?
            .valid_entries
            .contains(&hash)
        {
            return Err(authority_refused(REVOKE_NOT_COUNTED));
        }
        Ok(hash)
    }

    /// Binds the embedded owner again under the host root, in the
    /// transaction of the membership move that gives them Owner standing
    /// back on a self-hosted vault (REVIEW-7931 round 2). The host root binds
    /// its embedded owner there, as at genesis (`host_actor.rs`), and the
    /// move that ended their standing revoked that binding
    /// ([`Self::revoke_owner_authority_in_txn`]). The new binding is a fresh
    /// epoch above the revoked one, which stays revoked. Nothing for another
    /// person (an added Owner binds through their first owner key's
    /// enrolment), a hosted or relay vault, an unrooted one, an owner a live
    /// `human` binding names or none ever named, or a host key bound to
    /// another actor.
    ///
    /// # Errors
    /// An authority refusal when no issuer signs the move, or when the new
    /// binding does not count; the log's.
    pub(crate) fn restore_embedded_owner_binding_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: Option<&HostSlipIssuer>,
        person: EntityId,
    ) -> Result<()> {
        if person != crate::vault::embedded_owner_actor_id()?
            || self.privacy_posture() != crate::HostingPrivacyPosture::SelfHostLocal
        {
            return Ok(());
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let was_bound = fold
            .actor_bindings
            .values()
            .any(|binding| binding.actor_ref == person && binding.actor_class == ACTOR_CLASS_HUMAN);
        if fold.vault_id.is_none()
            || !was_bound
            || actor_binding_is_active(&fold, &person, ACTOR_CLASS_HUMAN)
        {
            return Ok(());
        }
        let Some(issuer) = issuer else {
            return Err(authority_refused(OWNER_BINDING_NEEDS_HOST));
        };
        let authority_key = issuer.public_key();
        let held = fold.actor_bindings.get(&authority_key);
        if held.is_some_and(|binding| binding.status == ActorBindingStatus::Active) {
            return Ok(());
        }
        let epoch = held.map_or(1, |binding| binding.epoch.saturating_add(1));
        self.append_slip_op_in_txn(
            txn,
            issuer,
            AuthorityOp::BindActor {
                authority_key,
                actor_ref: person,
                actor_class: ACTOR_CLASS_HUMAN.into(),
                epoch,
            },
        )?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !actor_binding_is_active(&after, &person, ACTOR_CLASS_HUMAN) {
            return Err(authority_refused(OWNER_BINDING_NOT_RESTORED));
        }
        Ok(())
    }

    /// Refuses a membership move no issuer signs while `person` holds owner
    /// authority on this vault's log that the move must end: a live owner key
    /// whose enrolment names them, or a live `human` binding that names them.
    /// Only the vault's live host root signs their revocation
    /// ([`Self::revoke_owner_authority_in_txn`]), so such a move runs on the
    /// vault's host; a person with neither moves on any install (REVIEW-7931).
    ///
    /// # Errors
    /// An authority refusal when they hold either; the log's read errors.
    pub(crate) fn refuse_unrevoked_owner_authority_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
    ) -> Result<()> {
        let holds_key = self
            .enrolled_owner_keys_in_txn(txn)?
            .iter()
            .any(|key| key.live && key.owner == person);
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let holds_binding = fold.actor_bindings.values().any(|binding| {
            binding.status == ActorBindingStatus::Active
                && binding.actor_ref == person
                && binding.actor_class == ACTOR_CLASS_HUMAN
        });
        if holds_key || holds_binding {
            return Err(authority_refused(OWNER_AUTHORITY_NEEDS_HOST));
        }
        Ok(())
    }
}

/// Keeps `entry`, at `hash`, in `keys` when it is a valid owner key
/// enrollment on `fold` whose key no smaller entry already stands for.
fn keep_enrolled(
    keys: &mut BTreeMap<[u8; 32], EnrolledOwnerKey>,
    fold: &AuthorityFold,
    managed: bool,
    hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
) {
    let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op else {
        return;
    };
    let Some(public_key) = enroll.public_key() else {
        return;
    };
    if !fold.valid_entries.contains(&hash) {
        return;
    }
    if keys.get(public_key).is_some_and(|kept| kept.entry <= hash) {
        return;
    }
    let device = fold.roster.get(&enroll.device.key);
    keys.insert(
        *public_key,
        EnrolledOwnerKey {
            entry: hash,
            machine: enroll.machine,
            carrier: enroll.carrier,
            owner: enroll.act.owner,
            public_key: *public_key,
            live: device.is_some_and(|device| !device.revoked),
            eligible: device
                .is_some_and(|device| super::checkpoint_policy::selectable_root(device, managed)),
            at: entry.ts,
            kind: EnrolledOwnerKeyKind::of(enroll),
        },
    );
}
