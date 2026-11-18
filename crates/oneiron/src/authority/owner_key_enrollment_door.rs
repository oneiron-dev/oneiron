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

use ed25519_dalek::Signer;

use crate::error::{Error, OwnerKeyMoveStep, RecordError, Result};
use crate::{EntityId, TimeRange, Vault};

use super::*;

/// An owner signing key is the owner's to enrol: no Grant action names it,
/// so an agent's act never enrols one. Authority; nothing was written.
pub(super) const OWNER_ONLY: &str =
    "an owner signing key is the owner's to enrol; no Grant action names it";
/// This install cannot carry the owner's act: it has no machine identity or
/// install key, or no live profile of it stands under that key. Key
/// possession: the act is cosigned by the install that carries it, and no
/// roster key, the host root included, carries an owner act (FIX 2222).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the owner's key enrollment";
/// Integrity: the roster already names the key, live or revoked. A
/// replacement is a fresh key, and the old one's ordinary revoke.
pub(super) const KEY_ON_ROSTER: &str = "the vault's roster already names this key, live or revoked; enrol a \
                             fresh key";
/// Integrity: a confirmation names a key the roster does not: there is
/// nothing to confirm.
const NOT_ON_ROSTER: &str = "the vault's roster does not name this key; a confirmation vouches \
                             for a key a passkey vouched for";
/// Integrity: the enrollment's fixed shape does not hold: a weak key, a
/// proof that is not the key's own signature over its challenge, or a key
/// that would sign its own entry.
const NOT_VALID: &str = "the enrollment does not verify: the proof must be the new key's own \
                         signature over its challenge for this vault, machine, key and owner";
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
}

/// What a passkey hands its enrollment (row WEB-PASSKEY-OWNER-KEY): its
/// credential key and its assertion over
/// [`Vault::owner_passkey_enrollment_challenge_as`], as the browser returns
/// them. No machine holds a passkey, so none is named: the carrier that
/// serves the ceremony stands in its place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerPasskeyEnrollment {
    /// The credential's id (`rawId`), which the enrollment records so a
    /// browser can ask for this passkey by name.
    pub credential_id: Vec<u8>,
    /// The credential's ES256 public key as SEC1 bytes, compressed or not.
    pub public_key: Vec<u8>,
    /// The assertion's authenticator data.
    pub authenticator_data: Vec<u8>,
    /// The assertion's client data JSON.
    pub client_data_json: Vec<u8>,
    /// The assertion's DER signature.
    pub signature: Vec<u8>,
}

/// What a counted passkey enrollment answers, only once the fold counted it
/// here and it committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerPasskeyEnrollmentReceipt {
    /// The enrollment's authority entry.
    pub entry: AuthorityEntryHash,
    /// The carrier that served the ceremony, which the entry names as the
    /// key's machine.
    pub machine: EntityId,
    /// The passkey's key, compressed SEC1.
    pub public_key: Vec<u8>,
    /// The passkey's credential id, as the enrollment records it.
    pub credential_id: Vec<u8>,
}

/// One enrolled passkey as the owner's surface lists it (row
/// WEB-PASSKEY-OWNER-KEY): its valid retained enrollment, joined to the
/// roster now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledOwnerPasskey {
    /// The enrollment's authority entry.
    pub entry: AuthorityEntryHash,
    /// The carrier that served its ceremony, named as its machine.
    pub machine: EntityId,
    /// The owner whose act enrolled it.
    pub owner: EntityId,
    /// The passkey's key, compressed SEC1.
    pub public_key: Vec<u8>,
    /// The passkey's credential id (`rawId`).
    pub credential_id: Vec<u8>,
    /// On the roster and not revoked.
    pub live: bool,
    /// When it was signed, advisory unix seconds.
    pub at: u64,
}

/// An owner key enrollment built for a predecessor that signs elsewhere (a
/// passkey in the owner's browser), waiting for that signature: the entry's
/// canonical encoding with zero signatures, which the client hands back
/// unchanged, and the challenge the passkey's assertion names,
/// [`webauthn_challenge`] of the entry's authority transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedOwnerKeyEnrollment {
    /// The unsigned entry, canonical MessagePack.
    pub entry: Vec<u8>,
    /// The challenge the predecessor's assertion names.
    pub challenge: [u8; 32],
}

/// Integrity: the enrollment handed back is not one this install carries
/// for this owner: another op, owner, vault or carrier, a passkey in place
/// of a device's key, or bytes that are not its one encoding. Land does not
/// prove that prepare answered these exact bytes: a caller that may land
/// may prepare any key too, so the passkey's blind touch bounds it (lead
/// ruling WEBPASSKEY-BLIND-SIGNATURE = B), and the key it lands acts in
/// part until a non-passkey key confirms it (blind review #8539 F1).
const NOT_PREPARED: &str = "the enrollment is not one this install carries for this owner; \
                            prepare it again";

/// Integrity: since the enrollment was prepared, its predecessor left the
/// roster's live owner roots or signed a later entry, or the machine that
/// holds the key is no longer live. The fold would judge the entry at the
/// heads prepare named, where both still stood (blind review #8539 F2).
const PREPARED_ENTRY_STALE: &str = "since this enrollment was prepared, its predecessor key was \
                                    revoked or signed a later entry, or the machine that holds \
                                    the key was removed; prepare it again";

/// Authority: the enrollment would bind its owner to the key (OWNER-ENROL:
/// on a self-hosted vault, an owner whom no live `human` binding names binds
/// with their first owner key), and that binding is a second entry the
/// predecessor signs, which an enrollment prepared for a predecessor that
/// signs elsewhere does not carry. Nothing was written.
const PREPARED_ENTRY_BINDS_OWNER: &str = "this is the owner's first key, and enrolling it also binds \
                                          the owner to it, which a passkey's two-step enrollment \
                                          cannot sign; enrol this first key from a device that \
                                          already holds an owner key, or on the vault's host";

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
pub(super) fn not_valid(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(reason))
}

/// The one device shape an enrolled owner key has: Ed25519, `ROLE_OWNER`
/// alone, Software tier, no transport binding, its proof as evidence.
fn enrolled_device(public_key: [u8; 32], proof: Vec<u8>) -> DeviceAuthority {
    DeviceAuthority {
        key: AuthorityKey::Ed25519(public_key),
        transport_key_binding: [0; 32],
        attestation: AuthorityAttestation {
            kind: OWNER_KEY_POSSESSION_KIND.to_owned(),
            evidence: proof,
        },
        tier: AuthorityTier::Software,
        roles: ROLE_OWNER,
    }
}

/// The passkey shape of an enrolled owner key: its P-256 key, `ROLE_OWNER`
/// alone, Software tier, no transport binding, its credential id and its
/// assertion's envelope as evidence.
fn enrolled_passkey(public_key: Vec<u8>, evidence: Vec<u8>) -> DeviceAuthority {
    DeviceAuthority {
        key: AuthorityKey::P256(public_key),
        transport_key_binding: [0; 32],
        attestation: AuthorityAttestation {
            kind: OWNER_PASSKEY_POSSESSION_KIND.to_owned(),
            evidence,
        },
        tier: AuthorityTier::Software,
        roles: ROLE_OWNER,
    }
}

/// `input`'s passkey as the roster names it (compressed SEC1) and its
/// enrolled shape, its assertion in its envelope as the possession evidence.
fn passkey_enrollment_device(input: &OwnerPasskeyEnrollment) -> Result<(Vec<u8>, DeviceAuthority)> {
    let public_key =
        canonical_p256_key_bytes(&input.public_key).map_err(|_| not_valid(NOT_VALID))?;
    let envelope = webauthn_assertion_envelope(
        &input.authenticator_data,
        &input.client_data_json,
        &input.signature,
    )
    .map_err(|_| not_valid(NOT_VALID))?;
    let evidence = owner_passkey_possession_evidence(&input.credential_id, &envelope)
        .map_err(|_| not_valid(NOT_VALID))?;
    Ok((public_key.clone(), enrolled_passkey(public_key, evidence)))
}

/// An unsigned entry as [`Vault::prepare_owner_key_enrollment_as`] encoded
/// it: one MessagePack value, and exactly its canonical encoding.
fn decode_unsigned_entry(bytes: &[u8]) -> Option<AuthorityLogEntry> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    if usize::try_from(cursor.position()).ok()? != bytes.len() {
        return None;
    }
    let entry = decode_entry_value(&value).ok()?;
    (encode_value(&entry_value(&entry, true)).ok()? == bytes).then_some(entry)
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
        let device = enrolled_device(input.public_key, input.proof);
        let (entry, machine) = self.enrol_owner_device_as(
            authority,
            Some(input.machine),
            device,
            predecessor,
            sign_predecessor,
        )?;
        Ok(OwnerKeyEnrollmentReceipt {
            entry,
            machine,
            public_key: input.public_key,
        })
    }

    /// The one writer of the device door and the passkey door: `device` in
    /// its fixed shape, held by `holder`, or by no machine (a passkey), when
    /// the carrier is named in its place. Answers the counted entry and the
    /// machine it names.
    fn enrol_owner_device_as<S>(
        &self,
        authority: &ActAuthority,
        holder: Option<EntityId>,
        device: DeviceAuthority,
        predecessor: AuthorityKey,
        sign_predecessor: S,
    ) -> Result<(AuthorityEntryHash, EntityId)>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        self.write_owner_key_enroll_as(
            authority,
            holder,
            device,
            predecessor,
            sign_predecessor,
            false,
        )
    }

    /// [`Self::enrol_owner_device_as`], and with `confirming` the second
    /// vouch for a key the roster already names (a key only a passkey
    /// vouched for; lead ruling WEBPASSKEY-BLIND-SIGNATURE = B), which the
    /// fold counts only as that key's confirmation. A new key binds its
    /// owner as [`Self::enrol_owner_signing_key_as`] says (OWNER-ENROL); a
    /// confirmation binds no one.
    fn write_owner_key_enroll_as<S>(
        &self,
        authority: &ActAuthority,
        holder: Option<EntityId>,
        device: DeviceAuthority,
        predecessor: AuthorityKey,
        mut sign_predecessor: S,
        confirming: bool,
    ) -> Result<(AuthorityEntryHash, EntityId)>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        let mut txn = self.store.env.write_txn()?;
        let (mut entry, carrier_key) = self.unsigned_owner_key_enroll_in_txn(
            &mut txn,
            authority,
            holder,
            device,
            predecessor.clone(),
            confirming,
        )?;
        let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op else {
            return Err(invalid_authority());
        };
        let (owner, key) = (enroll.act.owner, enroll.device.key.clone());
        let transcript = authority_transcript(&entry)?;
        entry.signer.signature = sign_predecessor(&transcript)?;
        let (hash, machine) = self.land_owner_key_enroll_in_txn(&mut txn, entry, &carrier_key)?;
        if !confirming {
            self.bind_owner_to_enrolled_key_in_txn(
                &mut txn,
                owner,
                key,
                predecessor,
                &mut sign_predecessor,
            )?;
        }
        txn.commit()?;
        Ok((hash, machine))
    }

    /// OWNER-ENROL for an owner key just enrolled in `txn`: on a self-hosted
    /// vault, `owner`, whom no live `human` binding names, is bound to `key`
    /// as the next entry, which `predecessor` signs as it signed the
    /// enrollment ([`Self::bind_enrolled_owner_key_in_txn`]). Nothing on any
    /// other vault, or for an owner already bound.
    fn bind_owner_to_enrolled_key_in_txn<S>(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        key: AuthorityKey,
        predecessor: AuthorityKey,
        sign_predecessor: &mut S,
    ) -> Result<()>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        if self.privacy_posture() != crate::HostingPrivacyPosture::SelfHostLocal {
            return Ok(());
        }
        let after = self.authority_view_readonly_in_txn(txn)?;
        if actor_binding_is_active(&after, &owner, ACTOR_CLASS_HUMAN) {
            return Ok(());
        }
        let vault_id = after.vault_id.ok_or_else(invalid_authority)?;
        let bind = EnrolledKeyBinding {
            fold: &after,
            vault_id,
            predecessor,
            key,
            owner,
        };
        self.bind_enrolled_owner_key_in_txn(txn, bind, sign_predecessor)
    }

    /// Refuses an enrollment its predecessor signs elsewhere when it would
    /// bind `owner` (OWNER-ENROL: on a self-hosted vault, an owner whom no
    /// live `human` binding names binds with their first owner key): that
    /// binding is a second entry the predecessor signs, and a prepared
    /// enrollment carries one signature.
    fn refuse_prepared_owner_binding_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &EntityId,
    ) -> Result<()> {
        if self.privacy_posture() != crate::HostingPrivacyPosture::SelfHostLocal {
            return Ok(());
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if actor_binding_is_active(&fold, owner, ACTOR_CLASS_HUMAN) {
            return Ok(());
        }
        Err(authority_refused(PREPARED_ENTRY_BINDS_OWNER))
    }

    /// The enrollment of `device` as `authority`, carried by this install,
    /// with `predecessor` as its primary signer (with `confirming`, the
    /// second vouch for a key the roster already names), built in `txn` with
    /// no signature yet (zero placeholders), and the carrier's install key
    /// that cosigns it. A frontier wider than one entry names is joined in
    /// `txn` first (FIX 7908).
    fn unsigned_owner_key_enroll_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        authority: &ActAuthority,
        holder: Option<EntityId>,
        device: DeviceAuthority,
        predecessor: AuthorityKey,
        confirming: bool,
    ) -> Result<(AuthorityLogEntry, ed25519_dalek::SigningKey)> {
        let (owner, surface) = match authority {
            ActAuthority::Owner(owner, surface) => (owner, *surface),
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let (carrier, carrier_key) = self
            .carrier_in_txn(txn, &fold)
            .map_err(authority_refusal_as(NO_CARRIER))?;
        let machine = holder.unwrap_or(carrier);
        if fold.roster.contains_key(&device.key) != confirming {
            return Err(not_valid(if confirming {
                NOT_ON_ROSTER
            } else {
                KEY_ON_ROSTER
            }));
        }
        let target = match &device.key {
            AuthorityKey::Ed25519(bytes) => owner_key_enrollment_target(&vault_id, bytes)?,
            AuthorityKey::P256(bytes) => owner_key_enrollment_target(&vault_id, bytes)?,
        };
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
            target,
            surface,
            OWNER_KEY_ENROLLMENT_SEEN,
        );
        let now = self.instant_in_txn(txn)?.secs();
        let entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: next_sequence(&fold, &predecessor)?,
            parent_hashes: parents.into_iter().collect(),
            op: AuthorityOp::OwnerKeyEnroll(OwnerKeyEnroll {
                act,
                machine,
                carrier,
                device,
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
        Ok((entry, carrier_key))
    }

    /// Lands `entry`, its predecessor's signature in place: the carrier's
    /// install key (`carrier_key`) cosigns its transcript, the entry is
    /// stored in `txn`, and the fold runs again there. Answers the entry and
    /// the machine it names only when the fold counted it, held nothing
    /// back and keeps the key on the roster live; the caller commits.
    fn land_owner_key_enroll_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        mut entry: AuthorityLogEntry,
        carrier_key: &ed25519_dalek::SigningKey,
    ) -> Result<(AuthorityEntryHash, EntityId)> {
        let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op else {
            return Err(not_valid(NOT_VALID));
        };
        let (key, machine) = (enroll.device.key.clone(), enroll.machine);
        let transcript = authority_transcript(&entry)?;
        if let Some(cosign) = entry.cosigns.first_mut() {
            cosign.signature = carrier_key.sign(&transcript).to_bytes().to_vec();
        }
        let hash = authority_entry_hash(&entry)?;
        let now = entry.ts;
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
        Ok((hash, machine))
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

    /// The challenge a passkey's assertion names to enrol on this vault for
    /// the owner `authority` proves (row WEB-PASSKEY-OWNER-KEY):
    /// [`webauthn_challenge`] of [`owner_key_enrollment_challenge`] over the
    /// vault's id, this install as the carrier that names the key's
    /// machine, the passkey's key (`public_key`, SEC1) and that owner,
    /// revalidated now.
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] for an agent's act or an install
    /// that cannot carry it; [`RecordError::InvalidAuthorityLogBody`] for a
    /// key that is no P-256 point; an owner refusal when the proof is no
    /// longer the vault's live owner.
    pub fn owner_passkey_enrollment_challenge_as(
        &self,
        authority: &ActAuthority,
        public_key: &[u8],
    ) -> Result<[u8; 32]> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let key = canonical_p256_key_bytes(public_key).map_err(|_| not_valid(NOT_VALID))?;
        let txn = self.store.env.read_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let (carrier, _) = self
            .carrier_in_txn(&txn, &fold)
            .map_err(authority_refusal_as(NO_CARRIER))?;
        Ok(webauthn_challenge(&owner_key_enrollment_challenge(
            &vault_id, carrier, &key, actor,
        )?))
    }

    /// The owner enrols `input`'s passkey as an owner root of its own, as
    /// `authority`, carried by this install, with `predecessor` (an existing
    /// live owner root of the roster) as the entry's primary signer, as
    /// [`Self::enrol_owner_signing_key_as`] enrols a device's key. Its
    /// machine is this install, the carrier. Once counted, the passkey signs
    /// with its assertions wherever an owner root signs. On a self-hosted vault
    /// it binds an owner whom no live `human` binding names to the passkey, as
    /// the device door binds them to a device key (OWNER-ENROL).
    ///
    /// # Errors
    /// As [`Self::enrol_owner_signing_key_as`]; a key, a credential id or an
    /// assertion that does not decode is
    /// [`RecordError::InvalidAuthorityLogBody`].
    pub fn enrol_owner_passkey_as<S>(
        &self,
        authority: &ActAuthority,
        input: &OwnerPasskeyEnrollment,
        predecessor: AuthorityKey,
        sign_predecessor: S,
    ) -> Result<OwnerPasskeyEnrollmentReceipt>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        let (public_key, device) = passkey_enrollment_device(input)?;
        let (entry, machine) =
            self.enrol_owner_device_as(authority, None, device, predecessor, sign_predecessor)?;
        Ok(OwnerPasskeyEnrollmentReceipt {
            entry,
            machine,
            public_key,
            credential_id: input.credential_id.clone(),
        })
    }

    /// The owner confirms a passkey that only another passkey vouched for
    /// (lead ruling WEBPASSKEY-BLIND-SIGNATURE = B; Sol xhigh stack review
    /// F5), as [`Self::confirm_owner_key_as`] confirms a device's key:
    /// `predecessor`, an owner-held key that is no passkey, vouches for
    /// `input`'s passkey again, carried by this install. `input` is the
    /// passkey's enrollment input again, its assertion over the challenge
    /// [`Self::owner_passkey_enrollment_challenge_as`] answers, and nothing
    /// on the roster changes. After it the passkey vouches for further keys;
    /// its own limits stay (it re-roots nothing and revokes no other owner
    /// key, Engine ruling WEBPASSKEY-PASSKEY-OWN-REVOKE = B).
    ///
    /// # Errors
    /// As [`Self::confirm_owner_key_as`]; a key, a credential id or an
    /// assertion that does not decode is
    /// [`RecordError::InvalidAuthorityLogBody`].
    pub fn confirm_owner_passkey_as<S>(
        &self,
        authority: &ActAuthority,
        input: &OwnerPasskeyEnrollment,
        predecessor: AuthorityKey,
        sign_predecessor: S,
    ) -> Result<OwnerPasskeyEnrollmentReceipt>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        let (public_key, device) = passkey_enrollment_device(input)?;
        let (entry, machine) = self.write_owner_key_enroll_as(
            authority,
            None,
            device,
            predecessor,
            sign_predecessor,
            true,
        )?;
        Ok(OwnerPasskeyEnrollmentReceipt {
            entry,
            machine,
            public_key,
            credential_id: input.credential_id.clone(),
        })
    }

    /// [`Self::enrol_owner_passkey_as`] with this host's own root as the
    /// predecessor: `issuer` signs the transcript in process.
    ///
    /// # Errors
    /// As [`Self::enrol_owner_passkey_as`].
    pub fn enrol_owner_passkey_as_host(
        &self,
        authority: &ActAuthority,
        input: &OwnerPasskeyEnrollment,
        issuer: &HostSlipIssuer,
    ) -> Result<OwnerPasskeyEnrollmentReceipt> {
        self.enrol_owner_passkey_as(authority, input, issuer.public_key(), |transcript| {
            Ok(issuer.sign_slip(transcript))
        })
    }

    /// The owner confirms a key that only a passkey vouched for (lead ruling
    /// WEBPASSKEY-BLIND-SIGNATURE = B): `predecessor`, an owner-held key that
    /// is no passkey (a device key, the recovery kit's authority key),
    /// vouches for `input`'s key again, carried by this install. Until then
    /// the key neither re-roots, nor revokes another owner key, nor vouches
    /// for a further key; after it, it acts as any owner root. `input` is the
    /// key's own enrollment input again (its proof of possession is the
    /// same), and nothing on the roster changes.
    ///
    /// # Errors
    /// As [`Self::enrol_owner_signing_key_as`]; a key the roster does not
    /// name is [`RecordError::InvalidAuthorityLogBody`], and one that is not
    /// passkey-vouched, or a predecessor that may not confirm it (a passkey,
    /// a key in the host's custody), is a confirmation the fold does not
    /// count.
    pub fn confirm_owner_key_as<S>(
        &self,
        authority: &ActAuthority,
        input: OwnerKeyEnrollment,
        predecessor: AuthorityKey,
        sign_predecessor: S,
    ) -> Result<OwnerKeyEnrollmentReceipt>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        let device = enrolled_device(input.public_key, input.proof);
        let (entry, machine) = self.write_owner_key_enroll_as(
            authority,
            Some(input.machine),
            device,
            predecessor,
            sign_predecessor,
            true,
        )?;
        Ok(OwnerKeyEnrollmentReceipt {
            entry,
            machine,
            public_key: input.public_key,
        })
    }

    /// The first step of a device key's enrollment whose predecessor signs
    /// elsewhere (row WEB-PASSKEY-OWNER-KEY: the owner's passkey, in his
    /// browser, vouches for a new device): the enrollment entry
    /// [`Self::enrol_owner_signing_key_as`] would write first, built now with
    /// no signature, and the challenge its predecessor's assertion names. A
    /// frontier join this needs is written and kept; nothing else is.
    ///
    /// # Errors
    /// As [`Self::enrol_owner_signing_key_as`], before any signature; an
    /// authority refusal for an enrollment that would bind its owner to the
    /// key (OWNER-ENROL), whose second entry a prepared enrollment does not
    /// carry.
    pub fn prepare_owner_key_enrollment_as(
        &self,
        authority: &ActAuthority,
        input: OwnerKeyEnrollment,
        predecessor: AuthorityKey,
    ) -> Result<PreparedOwnerKeyEnrollment> {
        let mut txn = self.store.env.write_txn()?;
        let device = enrolled_device(input.public_key, input.proof);
        let (entry, _) = self.unsigned_owner_key_enroll_in_txn(
            &mut txn,
            authority,
            Some(input.machine),
            device,
            predecessor,
            false,
        )?;
        if let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op {
            self.refuse_prepared_owner_binding_in_txn(&txn, &enroll.act.owner)?;
        }
        let challenge = webauthn_challenge(&authority_transcript(&entry)?);
        let body = encode_value(&entry_value(&entry, true))?;
        // A frontier join the entry names must stand for it to land.
        txn.commit()?;
        Ok(PreparedOwnerKeyEnrollment {
            entry: body,
            challenge,
        })
    }

    /// The second step: the owner lands `entry`, as
    /// [`Self::prepare_owner_key_enrollment_as`] answered it, with
    /// `predecessor_signature` (a passkey's assertion envelope over its
    /// challenge) in place. The entry must be an owner key enrollment of a
    /// device's key the roster does not name yet, which this install carries
    /// for the owner `authority` proves now, in its one encoding; this
    /// install cosigns it, and it lands only when the fold counts it, as the
    /// one-step door's does. Its predecessor must still be a live owner
    /// root at its next sequence, and the holding machine still live, at
    /// the heads read here. It never lands a second vouch for a key the
    /// roster names: a confirmation goes through [`Self::confirm_owner_key_as`].
    ///
    /// # Errors
    /// [`RecordError::InvalidAuthorityLogBody`] for an entry this install
    /// does not carry for this owner, for a key the roster names by now, or
    /// for a predecessor revoked or past the entry's sequence or a holding
    /// machine removed since prepare; an authority refusal for an enrollment
    /// that would bind its owner to the key (OWNER-ENROL), judged here again;
    /// then as [`Self::enrol_owner_signing_key_as`].
    pub fn land_owner_key_enrollment_as(
        &self,
        authority: &ActAuthority,
        entry: &[u8],
        predecessor_signature: Vec<u8>,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let mut entry = decode_unsigned_entry(entry).ok_or_else(|| not_valid(NOT_PREPARED))?;
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let (carrier, carrier_key) = self
            .carrier_in_txn(&txn, &fold)
            .map_err(authority_refusal_as(NO_CARRIER))?;
        let carrier_cosign = AuthorityKey::Ed25519(carrier_key.verifying_key().to_bytes());
        let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op else {
            return Err(not_valid(NOT_PREPARED));
        };
        let Some(public_key) = enroll.public_key().copied() else {
            return Err(not_valid(NOT_PREPARED));
        };
        if enroll.act.owner != actor
            || enroll.carrier != carrier
            || entry.vault_id != fold.vault_id
            || !matches!(entry.cosigns.as_slice(), [cosign] if cosign.public_key == carrier_cosign)
        {
            return Err(not_valid(NOT_PREPARED));
        }
        if fold.roster.contains_key(&enroll.device.key) {
            return Err(not_valid(KEY_ON_ROSTER));
        }
        // The fold judges the entry at the heads prepare named; what has
        // ended since is judged again at the heads read here, as the
        // one-step door judges at its own (blind review #8539 F2).
        let predecessor = entry.signer_key();
        if !fold
            .roster
            .get(predecessor)
            .is_some_and(|root| !root.revoked && root.roles & ROLE_OWNER != 0)
            || entry.seq < next_sequence(&fold, predecessor)?
            || !fold
                .machines
                .get(&enroll.machine)
                .is_some_and(super::owner_key_enrollment::machine_is_live)
        {
            return Err(not_valid(PREPARED_ENTRY_STALE));
        }
        self.refuse_prepared_owner_binding_in_txn(&txn, &actor)?;
        verify_unsigned(&entry)?;
        entry.signer.signature = predecessor_signature;
        let (hash, machine) = self.land_owner_key_enroll_in_txn(&mut txn, entry, &carrier_key)?;
        txn.commit()?;
        Ok(OwnerKeyEnrollmentReceipt {
            entry: hash,
            machine,
            public_key,
        })
    }

    /// A revoke of `revoked` signed by `signer` alone at this vault's
    /// main-log heads, stored for the fold to judge; true when it counted.
    /// The integration tests' door to the limits on a key only a passkey
    /// vouched for (lead ruling WEBPASSKEY-BLIND-SIGNATURE = B).
    #[cfg(oneiron_test_support)]
    pub(crate) fn revoke_owner_key_signed_for_test<S>(
        &self,
        signer: AuthorityKey,
        revoked: AuthorityKey,
        sign: S,
    ) -> Result<bool>
    where
        S: FnOnce(&[u8]) -> Vec<u8>,
    {
        let mut sign = Some(sign);
        let counted = self.append_signed_rows_for_test(
            vec![(
                AuthorityOp::RevokeDevice {
                    revoked_key: revoked,
                },
                signer,
                Vec::new(),
            )],
            None,
            |_, transcript| sign.take().map_or_else(Vec::new, |sign| sign(transcript)),
        )?;
        Ok(counted.first().copied().unwrap_or(false))
    }

    /// Signs and stores `rows` in one put, as the signed-row append door
    /// takes a batch: each row is `(op, signer, cosigners)`, the first at
    /// `parents` (this vault's main-log heads when `None`; a sibling branch
    /// of rows stored since when named) and each later one on the row before
    /// it, each signer at its next sequence. `sign` signs an authority
    /// transcript as the key it names. True for each row the fold counted.
    /// The integration tests' door to the limits on a key only a passkey
    /// vouched for (lead ruling WEBPASSKEY-BLIND-SIGNATURE = B; Sol xhigh
    /// stack review F1 and F2; Astra stack review finding 1): a history of
    /// rows no door writes.
    ///
    /// # Errors
    ///
    /// The store's refusal of the rows, or a frontier too wide for one entry.
    #[cfg(oneiron_test_support)]
    pub(crate) fn append_signed_rows_for_test<S>(
        &self,
        rows: Vec<(AuthorityOp, AuthorityKey, Vec<AuthorityKey>)>,
        parents: Option<Vec<AuthorityEntryHash>>,
        mut sign: S,
    ) -> Result<Vec<bool>>
    where
        S: FnMut(&AuthorityKey, &[u8]) -> Vec<u8>,
    {
        let mut txn = self.store.env.write_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        if fold.append_heads.is_empty() || fold.append_heads.len() > MAX_PARENTS {
            return Err(authority_refused(TOO_MANY_HEADS));
        }
        let now = self.instant_in_txn(&txn)?.secs();
        let at = TimeRange {
            start: now,
            end: now,
        };
        let mut parents: Vec<AuthorityEntryHash> =
            parents.unwrap_or_else(|| fold.append_heads.iter().copied().collect());
        let mut seqs: BTreeMap<AuthorityKey, u64> = BTreeMap::new();
        let mut stored = Vec::with_capacity(rows.len());
        let mut hashes = Vec::with_capacity(rows.len());
        for (op, signer, cosigners) in rows {
            let seq = match seqs.get(&signer) {
                Some(prior) => prior.checked_add(1).ok_or_else(invalid_authority)?,
                None => next_sequence(&fold, &signer)?,
            };
            seqs.insert(signer.clone(), seq);
            let unsigned = |key: AuthorityKey| AuthoritySignature {
                suite: key.suite(),
                public_key: key,
                signature: vec![0; 64],
            };
            let mut entry = AuthorityLogEntry {
                schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id: Some(vault_id),
                seq,
                parent_hashes: parents.clone(),
                op,
                signer: unsigned(signer),
                cosigns: cosigners.into_iter().map(unsigned).collect(),
                ts: now,
            };
            let transcript = authority_transcript(&entry)?;
            entry.signer.signature = sign(&entry.signer.public_key, &transcript);
            for cosign in &mut entry.cosigns {
                cosign.signature = sign(&cosign.public_key, &transcript);
            }
            let hash = authority_entry_hash(&entry)?;
            parents = vec![hash];
            hashes.push(hash);
            stored.push((entry, at, now));
        }
        self.put_authority_log_entries_in_txn(&mut txn, &stored)?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let counted = hashes
            .iter()
            .map(|hash| {
                after.valid_entries.contains(hash) && !after.install.held_back.contains(hash)
            })
            .collect();
        txn.commit()?;
        Ok(counted)
    }

    /// The owner key enrollment of `input`'s key on `parents` (a sibling
    /// branch of every row stored since), signed by `predecessor` through
    /// `sign_predecessor` and cosigned by this install as its carrier, as
    /// the one writer builds it but with no roster check of its own; stored
    /// for the fold to judge; true when it counted. The integration tests'
    /// door to two sibling enrolments of one key (Astra delta review
    /// finding 2).
    ///
    /// # Errors
    ///
    /// An agent's act, an install that cannot carry it, an owner proof that
    /// no longer holds, or the store's refusal of the row.
    #[cfg(oneiron_test_support)]
    pub(crate) fn enrol_owner_key_on_parents_for_test<S>(
        &self,
        authority: &ActAuthority,
        input: OwnerKeyEnrollment,
        parents: Vec<AuthorityEntryHash>,
        predecessor: AuthorityKey,
        sign_predecessor: S,
    ) -> Result<bool>
    where
        S: FnOnce(&[u8]) -> Vec<u8>,
    {
        let (owner, surface) = match authority {
            ActAuthority::Owner(owner, surface) => (owner, *surface),
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let (carrier, carrier_key) = self
            .carrier_in_txn(&txn, &fold)
            .map_err(authority_refusal_as(NO_CARRIER))?;
        let act = OwnerAct::by_owner(
            actor,
            OwnerActKind::OwnerKeyEnrollment,
            owner_key_enrollment_target(&vault_id, &input.public_key)?,
            surface,
            OWNER_KEY_ENROLLMENT_SEEN,
        );
        let now = self.instant_in_txn(&txn)?.secs();
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: next_sequence(&fold, &predecessor)?,
            parent_hashes: parents,
            op: AuthorityOp::OwnerKeyEnroll(OwnerKeyEnroll {
                act,
                machine: input.machine,
                carrier,
                device: enrolled_device(input.public_key, input.proof),
            }),
            signer: AuthoritySignature {
                suite: predecessor.suite(),
                public_key: predecessor,
                signature: vec![0; 64],
            },
            cosigns: vec![AuthoritySignature {
                suite: AuthoritySignatureSuite::Ed25519,
                public_key: AuthorityKey::Ed25519(carrier_key.verifying_key().to_bytes()),
                signature: vec![0; 64],
            }],
            ts: now,
        };
        let transcript = authority_transcript(&entry)?;
        if let Some(cosign) = entry.cosigns.first_mut() {
            cosign.signature = carrier_key.sign(&transcript).to_bytes().to_vec();
        }
        entry.signer.signature = sign_predecessor(&transcript);
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(&mut txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let counted =
            after.valid_entries.contains(&hash) && !after.install.held_back.contains(&hash);
        txn.commit()?;
        Ok(counted)
    }

    /// This vault's main-log heads now: the parents a row appended now
    /// names. The integration tests' door to a sibling branch (Astra stack
    /// review finding 1).
    ///
    /// # Errors
    ///
    /// The store's read error.
    #[cfg(oneiron_test_support)]
    pub(crate) fn main_log_heads_for_test(&self) -> Result<Vec<AuthorityEntryHash>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(fold.append_heads.iter().copied().collect())
    }

    /// Explicitly enrol the distinct authority key backed by `seed`, before loss.
    /// The seed's source kit does not gain authority by existing or being restored.
    /// This returns the ordinary counted enrollment receipt; it does not publish a
    /// kit or make kit issuance atomic with enrollment.
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
        self.enrol_owner_signing_key_as(authority, input, predecessor, sign_predecessor)
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
        let managed = CheckpointPosture::from(self.privacy_posture()) == CheckpointPosture::Managed;
        let mut keys = BTreeMap::new();
        self.visit_authority_entries_in_txn(txn, |fold, hash, entry| {
            keep_enrolled(&mut keys, fold, managed, hash, entry);
        })?;
        Ok(keys.into_values().collect())
    }

    /// Every enrolled passkey (row WEB-PASSKEY-OWNER-KEY), ascending by key:
    /// each valid passkey enrollment this vault keeps, stored or carried by
    /// an adopted checkpoint image, the smallest entry for a key enrolled on
    /// two branches, joined to the roster now, a revoked one included. What
    /// a browser needs to ask for a passkey by its credential id and to name
    /// its key as a predecessor. Empty before any passkey enrollment.
    pub fn enrolled_owner_passkeys(&self) -> Result<Vec<EnrolledOwnerPasskey>> {
        let txn = self.store.env.read_txn()?;
        let mut keys = BTreeMap::new();
        self.visit_authority_entries_in_txn(&txn, |fold, hash, entry| {
            keep_enrolled_passkey(&mut keys, fold, hash, entry);
        })?;
        Ok(keys.into_values().collect())
    }

    /// Calls `visit` with the fold in `txn` and each authority entry this
    /// vault keeps there: every stored row, then each body an adopted
    /// checkpoint image carries past them.
    fn visit_authority_entries_in_txn<F>(&self, txn: &heed::RoTxn<'_>, mut visit: F) -> Result<()>
    where
        F: FnMut(&AuthorityFold, AuthorityEntryHash, &AuthorityLogEntry),
    {
        let view = self.authority_view_readonly_in_txn(txn)?;
        let fold: &AuthorityFold = &view;
        let mut stored = BTreeSet::new();
        for (_, body) in super::readonly_fold::authority_log_rows_in_txn(&self.store, txn)? {
            let entry = decode_authority_log_entry_body(&body)?;
            let hash = authority_entry_hash(&entry)?;
            stored.insert(hash);
            visit(fold, hash, &entry);
        }
        if let Some(evidence) = super::adopted_evidence::adopted_evidence_in_txn(&self.store, txn)?
        {
            for (hash, entry) in evidence.carried_past(&stored) {
                visit(fold, *hash, entry);
            }
        }
        Ok(())
    }

    /// Every live owner key whose enrolment names `person`: their device
    /// keys and their passkeys (row WEB-PASSKEY-OWNER-KEY), whose enrolment
    /// names its owner as a device key's does. Each key counts by its
    /// smallest valid enrollment entry, stored or carried by an adopted
    /// checkpoint image, as [`Self::enrolled_owner_keys`] counts a device
    /// key; that listing keeps device keys only (REVIEW-8437 P1).
    pub(super) fn live_owner_keys_enrolled_for_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
    ) -> Result<Vec<AuthorityKey>> {
        let view = self.authority_view_readonly_in_txn(txn)?;
        let fold: &AuthorityFold = &view;
        let mut enrolled: BTreeMap<AuthorityKey, (AuthorityEntryHash, EntityId)> = BTreeMap::new();
        let mut keep = |hash: AuthorityEntryHash, entry: &AuthorityLogEntry| {
            let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op else {
                return;
            };
            if !fold.valid_entries.contains(&hash)
                || enrolled
                    .get(&enroll.device.key)
                    .is_some_and(|(kept, _)| *kept <= hash)
            {
                return;
            }
            enrolled.insert(enroll.device.key.clone(), (hash, enroll.act.owner));
        };
        let mut stored = BTreeSet::new();
        for (_, body) in super::readonly_fold::authority_log_rows_in_txn(&self.store, txn)? {
            let entry = decode_authority_log_entry_body(&body)?;
            let hash = authority_entry_hash(&entry)?;
            stored.insert(hash);
            keep(hash, &entry);
        }
        if let Some(evidence) = super::adopted_evidence::adopted_evidence_in_txn(&self.store, txn)?
        {
            for (hash, entry) in evidence.carried_past(&stored) {
                keep(*hash, entry);
            }
        }
        Ok(enrolled
            .into_iter()
            .filter(|(key, (_, owner))| {
                *owner == person && fold.roster.get(key).is_some_and(|device| !device.revoked)
            })
            .map(|(key, _)| key)
            .collect())
    }

    /// Ends the owner authority `person` holds on this vault's log, in the
    /// transaction of the membership move that ends their standing
    /// (OWNER-ENROL): under `issuer`, a `RevokeDevice` for each live owner
    /// key whose enrolment names them, a passkey among them, which ends any
    /// binding on that key, then a `RevokeActor` for each other live `human`
    /// binding that names them, the host root's binding of its embedded
    /// owner among them. The root key itself stays: only its binding ends.
    /// Each entry must count, or the move commits nothing. A person with
    /// neither writes no entry.
    ///
    /// A revoke of an owner key counts only with an owner key's proof (row
    /// HOSTED-ROOT-REVOKES-OWNER-KEY; the lead, 15 Nov 20:41: "never only the
    /// custodial root"). A self-host server's root proves for the owner
    /// itself. Where `issuer` does not (a managed host's custodial root;
    /// under the Hosted posture no host root this install holds is offered,
    /// [`AuthorityFold::offers_owner_proof`]), each
    /// `RevokeDevice` carries the cosign of an owner key this install holds
    /// ([`Vault::owner_proof_signer`]), and a proof key among the revoked
    /// ends last, after it proved the others. That key is the install's,
    /// not the acting person's: the fold cannot tell who is at the device.
    /// No managed host holds an owner key today (its serving install's
    /// enrolment refuses on a Hosted vault), so there the move refuses until
    /// a device can confirm it (FIX HOSTED-OWNER-MOVE-TWO-PHASE).
    ///
    /// # Errors
    /// An `issuer` that is not this vault's live host root, as the log
    /// refuses it; [`RecordError::OwnerKeyMoveRefused`], before this writes
    /// any authority entry, when the member holds a live owner key and
    /// neither `issuer` nor any key this install holds proves for the owner
    /// (the caller's writer, which holds the move's other changes, drops with
    /// it); an entry the fold does not count.
    pub(crate) fn revoke_owner_authority_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        person: EntityId,
    ) -> Result<()> {
        let root = issuer.public_key();
        let mut keys: Vec<AuthorityKey> = self
            .live_owner_keys_enrolled_for_in_txn(txn, person)?
            .into_iter()
            .filter(|key| *key != root)
            .collect();
        if !keys.is_empty() {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            super::slip_vault::require_host(&fold, issuer)?;
            let hosted = self.privacy_posture() == crate::HostingPrivacyPosture::Hosted;
            // Under the Hosted posture no host root this install holds is
            // offered as the owner's proof, a self-host root a move carried
            // here included (HOSTED-REFOLD-SELF-HOST-ROOT-CUSTODY = A).
            let proof = if fold.offers_owner_proof(issuer, hosted) {
                None
            } else {
                let proof = self.owner_proof_signer(&fold).ok_or(Error::Record(
                    RecordError::OwnerKeyMoveRefused {
                        member: person,
                        step: OwnerKeyMoveStep::Unavailable,
                        act: None,
                    },
                ))?;
                let proof_key = proof.root();
                keys.sort_by_key(|key| *key == proof_key);
                Some(proof)
            };
            for revoked_key in keys {
                let op = AuthorityOp::RevokeDevice { revoked_key };
                match &proof {
                    Some(proof) => self.append_slip_op_with_owner_proof_in_txn(
                        txn,
                        issuer,
                        op,
                        proof.as_ref(),
                    )?,
                    None => self.append_slip_op_in_txn(txn, issuer, op)?,
                }
            }
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
        let holds_key = !self
            .live_owner_keys_enrolled_for_in_txn(txn, person)?
            .is_empty();
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

/// Keeps `entry`, at `hash`, in `keys` when it is a valid passkey
/// enrollment on `fold` whose key no smaller entry already stands for.
fn keep_enrolled_passkey(
    keys: &mut BTreeMap<Vec<u8>, EnrolledOwnerPasskey>,
    fold: &AuthorityFold,
    hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
) {
    let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op else {
        return;
    };
    let Some(credential_id) = enroll.passkey_credential_id() else {
        return;
    };
    if !fold.valid_entries.contains(&hash) {
        return;
    }
    let public_key = enroll.key_bytes().to_vec();
    if keys.get(&public_key).is_some_and(|kept| kept.entry <= hash) {
        return;
    }
    keys.insert(
        public_key.clone(),
        EnrolledOwnerPasskey {
            entry: hash,
            machine: enroll.machine,
            owner: enroll.act.owner,
            credential_id: credential_id.to_vec(),
            live: fold
                .roster
                .get(&enroll.device.key)
                .is_some_and(|device| !device.revoked),
            public_key,
            at: entry.ts,
        },
    );
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
        },
    );
}
