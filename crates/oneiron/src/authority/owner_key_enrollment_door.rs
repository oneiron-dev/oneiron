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
        let key = AuthorityKey::Ed25519(input.public_key);
        if fold.roster.contains_key(&key) {
            return Err(not_valid(KEY_ON_ROSTER));
        }
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let fold = self
            .prepare_authority_frontier_in_txn(
                &mut txn,
                &fold,
                FrontierSigner::Install(carrier, &carrier_key),
                MAX_PARENTS,
            )?
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
        let now = self.instant_in_txn(&txn)?.secs();
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: next_sequence(&fold, &predecessor)?,
            parent_hashes: parents.into_iter().collect(),
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
