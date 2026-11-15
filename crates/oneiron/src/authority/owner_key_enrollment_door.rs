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

use crate::error::{Error, RecordError, Result};
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
const KEY_ON_ROSTER: &str = "the vault's roster already names this key, live or revoked; enrol a \
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

/// An enrollment that does not verify, as the typed integrity refusal.
fn not_valid(reason: &'static str) -> Error {
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
    /// `sign_predecessor` gets the authority transcript once and returns the
    /// predecessor's signature over it; it runs while the write transaction
    /// is open, so it must not open another. The entry lands atomically or
    /// not at all, and the receipt comes only once the fold counted it.
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
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
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
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
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
    /// fold counts only as that key's confirmation.
    fn write_owner_key_enroll_as<S>(
        &self,
        authority: &ActAuthority,
        holder: Option<EntityId>,
        device: DeviceAuthority,
        predecessor: AuthorityKey,
        sign_predecessor: S,
        confirming: bool,
    ) -> Result<(AuthorityEntryHash, EntityId)>
    where
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
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
        let machine = holder.unwrap_or(carrier);
        let key = device.key.clone();
        if fold.roster.contains_key(&key) != confirming {
            return Err(not_valid(if confirming {
                NOT_ON_ROSTER
            } else {
                KEY_ON_ROSTER
            }));
        }
        let key_bytes: &[u8] = match &key {
            AuthorityKey::Ed25519(bytes) => bytes,
            AuthorityKey::P256(bytes) => bytes,
        };
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let joiner = FrontierSigner::Install(carrier, &carrier_key);
        let fold = self
            .prepare_authority_frontier_in_txn(&mut txn, &fold, joiner, MAX_PARENTS)?
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
            owner_key_enrollment_target(&vault_id, key_bytes)?,
            surface,
            OWNER_KEY_ENROLLMENT_SEEN,
        );
        let now = self.instant_in_txn(&txn)?.secs();
        let mut entry = AuthorityLogEntry {
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
        self.put_authority_log_entries_in_txn(&mut txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        if !after.valid_entries.contains(&hash)
            || after.install.held_back.contains(&hash)
            || !after.roster.get(&key).is_some_and(|device| !device.revoked)
        {
            return Err(authority_refused(NOT_COUNTED));
        }
        txn.commit()?;
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
    /// with its assertions wherever an owner root signs.
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
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
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
        let device = enrolled_passkey(public_key.clone(), evidence);
        let (entry, machine) =
            self.enrol_owner_device_as(authority, None, device, predecessor, sign_predecessor)?;
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
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
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
            |_, transcript| sign.take().map_or_else(Vec::new, |sign| sign(transcript)),
        )?;
        Ok(counted.first().copied().unwrap_or(false))
    }

    /// Signs and stores `rows` in one put, as the signed-row append door
    /// takes a batch: each row is `(op, signer, cosigners)`, the first at
    /// this vault's main-log heads and each later one on the row before it,
    /// each signer at its next sequence. `sign` signs an authority
    /// transcript as the key it names. True for each row the fold counted.
    /// The integration tests' door to the limits on a key only a passkey
    /// vouched for (lead ruling WEBPASSKEY-BLIND-SIGNATURE = B; Sol xhigh
    /// stack review F1 and F2): a history of rows no door writes.
    ///
    /// # Errors
    ///
    /// The store's refusal of the rows, or a frontier too wide for one entry.
    #[cfg(oneiron_test_support)]
    pub(crate) fn append_signed_rows_for_test<S>(
        &self,
        rows: Vec<(AuthorityOp, AuthorityKey, Vec<AuthorityKey>)>,
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
        let mut parents: Vec<AuthorityEntryHash> = fold.append_heads.iter().copied().collect();
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
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
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

    /// Every enrolled owner signing key, ascending by key: each valid
    /// enrollment body this vault keeps (stored, or carried by an adopted
    /// checkpoint image), the smallest entry for a key enrolled on two
    /// branches, joined to the roster now, a revoked or ineligible key
    /// included. Empty before any enrollment.
    pub fn enrolled_owner_keys(&self) -> Result<Vec<EnrolledOwnerKey>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let managed = CheckpointPosture::from(self.privacy_posture()) == CheckpointPosture::Managed;
        let mut keys = BTreeMap::new();
        let mut stored = BTreeSet::new();
        for (_, body) in super::readonly_fold::authority_log_rows_in_txn(&self.store, &txn)? {
            let entry = decode_authority_log_entry_body(&body)?;
            let hash = authority_entry_hash(&entry)?;
            stored.insert(hash);
            keep_enrolled(&mut keys, &fold, managed, hash, &entry);
        }
        if let Some(evidence) = super::adopted_evidence::adopted_evidence_in_txn(&self.store, &txn)?
        {
            for (hash, entry) in evidence.carried_past(&stored) {
                keep_enrolled(&mut keys, &fold, managed, *hash, entry);
            }
        }
        Ok(keys.into_values().collect())
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
        },
    );
}
