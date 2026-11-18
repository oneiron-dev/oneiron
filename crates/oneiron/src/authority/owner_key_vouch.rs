//! An owner key vouches for another device's new owner key (pass 27 R2, "an
//! owner key vouches"; MFA-1 A: "vault authority on a new device comes only
//! from an old device (QR approval) or the person's own pieces").
//!
//! The new device makes its key in its keystore slot and signs the key's
//! enrollment challenge ([`Vault::device_owner_key_vouch_request`]); its
//! install key signs the request too, so the machine it names is the one
//! that made it. That is all it can do alone: the challenge binds the vault,
//! the machine that holds the key, the key and the owner, never the key that
//! will vouch for it, so the new device writes no authority row and needs no
//! owner key of its own. It hands
//! the [`OwnerKeyVouchRequest`] to one of the owner's devices: side by side as
//! a QR code ([`OwnerKeyVouchRequest::to_text`]), apart as the act an owner
//! ask carries (OCS-HANDOVER = A), which names it by
//! [`OwnerKeyVouchRequest::digest`].
//!
//! That device's install holds an owner key the vault trusts as the owner's,
//! and the deciding owner's own, and enrols the new key with it
//! ([`Vault::enrol_vouched_owner_signing_key`]): the ordinary `OwnerKeyEnroll`
//! act, whose primary signer is the vouching key and whose carrier is this
//! install. A managed host's custodial root proves nothing on a hosted vault
//! (`AuthorityFold::proves_owner_acts`), so an install holding only that root
//! vouches for nothing, and a co-owner's key never vouches a key into
//! another owner.
//!
//! The request carries no secret: the proof of possession is public, the key
//! never leaves its device. The proof has no nonce and no time, so it never
//! expires; it stops verifying only when the vault's owner changes, and a
//! key already on the roster is never enrolled again. A second answer to the
//! same request answers the first enrollment's receipt, since two owner
//! devices may answer one ask.

use std::sync::Arc;

use base64::Engine as _;
use oneiron_base::msgpack_shape::{ShapeBudget, over_budget};
use oneiron_contracts::fingerprint::ContentHash;
use oneiron_store::diagnostic_record::untrusted_text::is_forbidden_text_scalar;
use rmpv::Value;

use crate::error::{Error, RecordError, Result};
use crate::{EntityId, Vault};

use super::owner_key_enrollment_door::{KEY_ON_ROSTER, OWNER_ONLY, not_valid};
use super::*;

/// The domain the holding machine's install key signs a request under
/// ([`OwnerKeyVouchRequest::machine_transcript`]).
const VOUCH_MACHINE_PROOF_DOMAIN: &[u8] = b"oneiron/owner-key-vouch-machine/v1";
/// What every request's text form starts with: the codec and its version.
pub const OWNER_KEY_VOUCH_TEXT_PREFIX: &str = "oneiron-owner-key-vouch-v1.";
/// The longest device label a request carries, in bytes of UTF-8.
pub const OWNER_KEY_VOUCH_LABEL_MAX: usize = 64;
/// The longest request in bytes. Its six fields take at most 360; nothing
/// longer is decoded.
const OWNER_KEY_VOUCH_REQUEST_MAX_BYTES: usize = 512;
/// The longest text form a request has: its bytes at the bound, in base64.
const REQUEST_TEXT_MAX: usize = OWNER_KEY_VOUCH_REQUEST_MAX_BYTES.div_ceil(3) * 4;
/// What the request's bytes may hold before they are decoded: one flat map
/// of six keys and six values, no string or binary over 64 bytes (the
/// longest are a proof and a label at its bound).
const REQUEST_SHAPE_BUDGET: ShapeBudget = ShapeBudget {
    max_values: 13,
    max_depth: 1,
    max_scalar_bytes: 64,
};
/// The request's map keys, in their one encoded order.
const REQUEST_KEYS: [&str; 6] = [
    "vault_id",
    "machine",
    "public_key",
    "proof",
    "machine_proof",
    "label",
];

/// Integrity: the request names another vault than this one.
const OTHER_VAULT: &str = "the key's request names another vault; make it on the new device for \
                           this vault";
/// Integrity: the request's proof is not the key's own signature over its
/// challenge for this vault, machine, key and owner.
const PROOF_NOT_VALID: &str = "the key's proof of possession does not verify for this vault, its \
                               machine, its key and the owner";
/// Integrity: the request's machine proof is not the install key of a live
/// profile of the machine it names, over the request.
const MACHINE_PROOF_NOT_VALID: &str = "the request is not signed by the install key of the live \
                                       machine it names";
/// Authority: an owner key belongs on a machine the owner holds (ruling
/// CARRIER-HOSTED-SERVER-OWNER-KEY = A), one the owner answered as theirs.
const MACHINE_NOT_THE_OWNERS: &str = "an owner key is held only on a machine the owner answered \
                                      as theirs; this one is a hosted or execution node, or \
                                      unanswered";
/// Integrity: the device label breaks the request's rules.
const LABEL_NOT_VALID: &str = "a device label is at most 64 bytes of text with no control or \
                               invisible format characters";

/// What a new device hands an owner device to have its owner signing key
/// enrolled: everything the answering device needs to run
/// [`Vault::enrol_vouched_owner_signing_key`], and nothing only the asking
/// device holds. It holds no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyVouchRequest {
    /// The authority vault id the key enrols on.
    pub vault_id: [u8; 32],
    /// The machine that holds the key in its keystore: the new device.
    pub machine: EntityId,
    /// The new key's Ed25519 public half.
    pub public_key: [u8; 32],
    /// The key's proof of possession: its signature over
    /// [`owner_key_enrollment_challenge`] for the vault, the machine, the key
    /// and the owner ([`OWNER_KEY_POSSESSION_PROOF_LEN`] bytes).
    pub proof: Vec<u8>,
    /// The holding machine's install key's signature over
    /// [`OwnerKeyVouchRequest::machine_transcript`]: the machine named made
    /// this request, so it holds the key it names.
    pub machine_proof: Vec<u8>,
    /// The device's name as the new device states it, for the owner to
    /// recognise on the answering device. Shown, never trusted:
    /// [`OWNER_KEY_VOUCH_LABEL_MAX`] bytes at most, no control or invisible
    /// format characters (the untrusted-text rule).
    pub label: String,
}

impl OwnerKeyVouchRequest {
    /// The enrollment the vouching device writes for this request.
    #[must_use]
    pub fn enrollment(&self) -> OwnerKeyEnrollment {
        OwnerKeyEnrollment {
            machine: self.machine,
            public_key: self.public_key,
            proof: self.proof.clone(),
        }
    }

    /// The request's one encoding: the canonical MessagePack map of its six
    /// fields, in [`REQUEST_KEYS`] order (ids as lower-case hex, keys and the
    /// proofs as binary, the label as text).
    ///
    /// # Errors
    /// The encoder's own refusal.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_value(&self.fields(Some(&self.machine_proof)))
    }

    /// The bytes the holding machine's install key signs: its own domain,
    /// then the request's fields but that signature, in their one encoding.
    ///
    /// # Errors
    /// The encoder's own refusal.
    pub fn machine_transcript(&self) -> Result<Vec<u8>> {
        let body = encode_value(&self.fields(None))?;
        let mut transcript =
            Vec::with_capacity(VOUCH_MACHINE_PROOF_DOMAIN.len().saturating_add(body.len()));
        transcript.extend_from_slice(VOUCH_MACHINE_PROOF_DOMAIN);
        transcript.extend_from_slice(&body);
        Ok(transcript)
    }

    /// The request's map, with the machine proof when `machine_proof` is
    /// given.
    fn fields(&self, machine_proof: Option<&[u8]>) -> Value {
        let mut entries = vec![
            (Value::from(REQUEST_KEYS[0]), binary_value(self.vault_id)),
            (
                Value::from(REQUEST_KEYS[1]),
                Value::from(self.machine.to_hex()),
            ),
            (Value::from(REQUEST_KEYS[2]), binary_value(self.public_key)),
            (
                Value::from(REQUEST_KEYS[3]),
                Value::Binary(self.proof.clone()),
            ),
        ];
        if let Some(machine_proof) = machine_proof {
            entries.push((
                Value::from(REQUEST_KEYS[4]),
                Value::Binary(machine_proof.to_vec()),
            ));
        }
        entries.push((
            Value::from(REQUEST_KEYS[5]),
            Value::from(self.label.as_str()),
        ));
        Value::Map(entries)
    }

    /// Reads [`Self::to_bytes`] back: at most
    /// `OWNER_KEY_VOUCH_REQUEST_MAX_BYTES` bytes of one flat map, checked
    /// before anything is decoded; exactly the six keys in their order, a
    /// 32-byte vault id and key, a machine id, two proofs of
    /// [`OWNER_KEY_POSSESSION_PROOF_LEN`] bytes, a label within its rules,
    /// and bytes that encode again to themselves, so each request has one
    /// encoding.
    ///
    /// # Errors
    /// The first rule the bytes break, named.
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, &'static str> {
        const SHAPE: &str = "a request is one map of vault_id, machine, public_key, proof, \
                             machine_proof and label, in that order";
        if bytes.len() > OWNER_KEY_VOUCH_REQUEST_MAX_BYTES {
            return Err("a request is at most 512 bytes");
        }
        if over_budget(bytes, REQUEST_SHAPE_BUDGET).is_some() {
            return Err(SHAPE);
        }
        let mut reader = bytes;
        let value = rmpv::decode::read_value(&mut reader).map_err(|_| SHAPE)?;
        if !reader.is_empty() {
            return Err(SHAPE);
        }
        let Value::Map(entries) = value else {
            return Err(SHAPE);
        };
        let [vault_id, machine, public_key, proof, machine_proof, label] = entries.as_slice()
        else {
            return Err(SHAPE);
        };
        for ((key, _), name) in [vault_id, machine, public_key, proof, machine_proof, label]
            .into_iter()
            .zip(REQUEST_KEYS)
        {
            if key.as_str() != Some(name) {
                return Err(SHAPE);
            }
        }
        let bytes_32 = |value: &Value| -> std::result::Result<[u8; 32], &'static str> {
            value
                .as_slice()
                .and_then(|slice| <[u8; 32]>::try_from(slice).ok())
                .ok_or("the vault id and the key are 32 bytes each")
        };
        let signature = |value: &Value| -> std::result::Result<Vec<u8>, &'static str> {
            value
                .as_slice()
                .filter(|slice| slice.len() == OWNER_KEY_POSSESSION_PROOF_LEN)
                .map(<[u8]>::to_vec)
                .ok_or("each proof is one 64-byte Ed25519 signature")
        };
        let request = Self {
            vault_id: bytes_32(&vault_id.1)?,
            machine: machine
                .1
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or("the machine is an entity id in lower-case hex")?,
            public_key: bytes_32(&public_key.1)?,
            proof: signature(&proof.1)?,
            machine_proof: signature(&machine_proof.1)?,
            label: label
                .1
                .as_str()
                .filter(|label| label_is_valid(label))
                .ok_or(LABEL_NOT_VALID)?
                .to_owned(),
        };
        if request.to_bytes().ok().as_deref() != Some(bytes) {
            return Err("the request is not in its one encoding");
        }
        Ok(request)
    }

    /// The request as one line of text, the QR payload a new device shows:
    /// [`OWNER_KEY_VOUCH_TEXT_PREFIX`], then [`Self::to_bytes`] in unpadded
    /// URL-safe base64.
    ///
    /// # Errors
    /// The encoder's own refusal.
    pub fn to_text(&self) -> Result<String> {
        let mut text = String::from(OWNER_KEY_VOUCH_TEXT_PREFIX);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_string(self.to_bytes()?, &mut text);
        Ok(text)
    }

    /// Reads [`Self::to_text`] back, surrounding whitespace ignored; text
    /// longer than a request at its bound is refused before it is decoded.
    ///
    /// # Errors
    /// Another prefix, text that is not unpadded URL-safe base64, or the
    /// first rule of [`Self::from_bytes`] the bytes break.
    pub fn from_text(text: &str) -> std::result::Result<Self, &'static str> {
        let encoded = text
            .trim()
            .strip_prefix(OWNER_KEY_VOUCH_TEXT_PREFIX)
            .ok_or("the text is not an owner key's request")?;
        if encoded.len() > REQUEST_TEXT_MAX {
            return Err("a request is at most 512 bytes");
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "the request's text is not unpadded URL-safe base64")?;
        Self::from_bytes(&bytes)
    }

    /// The request's digest: the [`ContentHash`] of [`Self::to_bytes`], which
    /// names those bytes and nothing else, the same on every device. An ask
    /// names the act by it, so a changed request is another ask.
    ///
    /// # Errors
    /// The encoder's own refusal.
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(ContentHash::of(&self.to_bytes()?).into_bytes())
    }
}

/// A device label within its rules: [`OWNER_KEY_VOUCH_LABEL_MAX`] bytes at
/// most, and none of the characters that make one text render as another
/// (controls, bidirectional overrides and isolates, zero-width and other
/// invisible format characters, line and paragraph separators: the
/// untrusted-text rule, `is_forbidden_text_scalar`).
#[must_use]
pub(crate) fn label_is_valid(label: &str) -> bool {
    label.len() <= OWNER_KEY_VOUCH_LABEL_MAX && !label.chars().any(is_forbidden_text_scalar)
}

/// A device label that breaks its rules, as the typed integrity refusal.
pub(crate) fn label_not_valid() -> Error {
    not_valid(LABEL_NOT_VALID)
}

/// What a new device's request door answers
/// ([`Vault::device_owner_key_vouch_request`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceOwnerKeyVouch {
    /// This install's key is not enrolled yet: the request to hand an owner
    /// device.
    Request(OwnerKeyVouchRequest),
    /// This install's key is live on the roster already, whoever enrolled
    /// it: its enrollment's receipt. The handle now holds the key.
    Enrolled(OwnerKeyEnrollmentReceipt),
}

impl Vault {
    /// The owner `authority` proves, revalidated now: an agent's act is
    /// refused before an owner key door prepares anything for it.
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] for an agent's act; an owner
    /// refusal when the proof is no longer the vault's live owner.
    pub(crate) fn owner_key_act_owner(&self, authority: &ActAuthority) -> Result<EntityId> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)
    }

    /// The owner enrols the new key `request` names, vouched for by an
    /// owner key this install holds that is the deciding owner's own
    /// ([`Self::owner_vouch_signer_in_txn`]): it signs the `OwnerKeyEnroll`
    /// entry as its predecessor, and this install carries it
    /// ([`Vault::enrol_owner_signing_key_as`]). The request is checked and
    /// the roster read once before the write: it names this vault, its key's
    /// proof verifies for this owner, the install key of a live machine the
    /// owner answered as theirs signed it, and its key is fresh. A key
    /// already live on the roster for the request's machine answers its
    /// first enrollment's receipt, and nothing is written; so does a key a
    /// second answer to the same request enrolled while this one ran.
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] for an agent's act, a machine the
    /// owner has not answered as theirs, an install that cannot carry the
    /// act, or an enrollment the fold does not count;
    /// [`RecordError::OwnerKeyRequired`] when this install holds no key the
    /// vault trusts as this owner's (a managed host's custodial root and a
    /// co-owner's key are none, and a key that rests under a device PIN
    /// counts only inside the window a right PIN opened); the signer's
    /// refusal, for a key that stopped after it was picked;
    /// [`RecordError::InvalidAuthorityLogBody`] for
    /// a request that names another vault, a proof that does not verify, a
    /// machine proof that is not the named machine's, or a key the roster
    /// already names otherwise; an owner refusal when the proof is no longer
    /// the vault's live owner.
    pub fn enrol_vouched_owner_signing_key(
        &self,
        authority: &ActAuthority,
        request: &OwnerKeyVouchRequest,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let signer = {
            let txn = self.store.env.read_txn()?;
            let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
            if request.vault_id != vault_id {
                return Err(not_valid(OTHER_VAULT));
            }
            let challenge = owner_key_enrollment_challenge(
                &vault_id,
                request.machine,
                &request.public_key,
                actor,
            )?;
            let proof = ed25519_dalek::Signature::from_slice(&request.proof)
                .map_err(|_| not_valid(PROOF_NOT_VALID))?;
            strong_ed25519_key(&request.public_key)
                .and_then(|key| {
                    key.verify_strict(&challenge, &proof)
                        .map_err(|_| invalid_authority())
                })
                .map_err(|_| not_valid(PROOF_NOT_VALID))?;
            require_holding_machine(&fold, request)?;
            if fold
                .roster
                .contains_key(&AuthorityKey::Ed25519(request.public_key))
            {
                drop(fold);
                drop(txn);
                return self.first_vouched_receipt(request);
            }
            self.owner_vouch_signer_in_txn(&txn, &fold, actor)?
                .ok_or(Error::Record(RecordError::OwnerKeyRequired))?
        };
        // The caller's owner proof was revalidated in the read above; that
        // read's fold picked the key and signs nothing. The key signs inside
        // the enrollment's writer, through its own check, on the fold each
        // entry is signed on (the writer hands it over) and with no
        // transaction of its own: the write is open then. A key that stopped
        // since the pick refuses there: one the roster revoked, one whose
        // seed left its slot, one under a device PIN whose window ended.
        match self.enrol_owner_signing_key_on_entry_fold_as(
            authority,
            request.enrollment(),
            signer.root(),
            |entry_fold, transcript| signer.sign_owner_proof(self, entry_fold, transcript),
        ) {
            // Another answer to the same request enrolled the key after this
            // one read the roster: its receipt answers this one too.
            Err(Error::Record(RecordError::InvalidAuthorityLogBody(reason)))
                if reason == KEY_ON_ROSTER =>
            {
                self.first_vouched_receipt(request)
            }
            landed => landed,
        }
    }

    /// The owner key this install holds that vouches for `actor`'s new key:
    /// a key the fold trusts as the owner's, under this vault's posture
    /// ([`AuthorityFold::proves_owner_acts`], the rule of
    /// `Vault::owner_proof_signer`), that is `actor`'s own
    /// ([`key_is_the_owners`]), and that proves at this moment
    /// ([`CheckpointRootSigner::proves_now`]). A co-owner's key held on this
    /// install never vouches a key into another owner. A key that does not
    /// prove now is passed over as if it were not held: one the roster no
    /// longer lists live, one whose seed left its slot, and one that rests
    /// under a device PIN outside the window a right PIN opened (row
    /// OCS-OWNER-PIN). The door calls this inside its read, so each signer
    /// is asked on `fold` and opens no transaction of the vault.
    ///
    /// # Errors
    /// The store's, reading the enrolled keys.
    fn owner_vouch_signer_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        actor: EntityId,
    ) -> Result<Option<Arc<dyn CheckpointRootSigner>>> {
        let hosted = self.privacy_posture() == crate::HostingPrivacyPosture::Hosted;
        let enrolled = self.enrolled_owner_keys_in_txn(txn)?;
        Ok(self
            .held_checkpoint_root_signers()
            .into_iter()
            .find(|signer| {
                let key = signer.root();
                fold.proves_owner_acts(&key, hosted)
                    && key_is_the_owners(fold, &enrolled, &key, actor)
                    && signer.proves_now(self, fold)
            }))
    }

    /// The receipt of the enrollment that already put `request`'s key on
    /// the roster live for its machine; any other listing of the key is the
    /// roster's refusal. It opens its own read; the caller holds none.
    fn first_vouched_receipt(
        &self,
        request: &OwnerKeyVouchRequest,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        self.enrolled_owner_keys()?
            .into_iter()
            .find(|listed| {
                listed.public_key == request.public_key
                    && listed.machine == request.machine
                    && listed.live
            })
            .map(|listed| OwnerKeyEnrollmentReceipt {
                entry: listed.entry,
                machine: listed.machine,
                public_key: listed.public_key,
            })
            .ok_or_else(|| not_valid(KEY_ON_ROSTER))
    }
}

/// Whether `key` is `actor`'s own owner key: an enrolled key whose
/// enrollment names `actor` as its owner, or a root no enrollment names (a
/// self-host home's host root, an appointed root) that no live `human`
/// binding gives to another person. A key either names for someone else is
/// theirs, not `actor`'s.
fn key_is_the_owners(
    fold: &AuthorityFold,
    enrolled: &[EnrolledOwnerKey],
    key: &AuthorityKey,
    actor: EntityId,
) -> bool {
    let AuthorityKey::Ed25519(public_key) = key else {
        return false;
    };
    match enrolled
        .iter()
        .find(|listed| listed.public_key == *public_key)
    {
        Some(listed) => listed.owner == actor,
        None => fold.actor_bindings.get(key).is_none_or(|binding| {
            binding.status != ActorBindingStatus::Active
                || binding.actor_class != ACTOR_CLASS_HUMAN
                || binding.actor_ref == actor
        }),
    }
}

/// Refuses `request` unless the machine it names made it, as a machine the
/// owner holds: the install key of a live profile of that machine signed
/// [`OwnerKeyVouchRequest::machine_transcript`] (no chain of the machine
/// removed, as the carrier rule reads a profile), and that profile's role is
/// one the owner answered as theirs. Any one such chain of the machine, the
/// roster's or an anchor's, is enough, as one admitting chain admits a
/// machine ([`FoldedMachine::is_admitted`]): a live chain of another role
/// beside it vetoes nothing. A hosted or execution node, or an install the
/// owner has not answered, holds no owner key (ruling
/// CARRIER-HOSTED-SERVER-OWNER-KEY = A).
///
/// # Errors
/// [`RecordError::InvalidAuthorityLogBody`] for a machine proof no live
/// profile of the machine verifies; [`RecordError::AuthorityRefused`] for a
/// machine the owner has not answered as theirs in any live profile whose
/// install key verifies it.
fn require_holding_machine(fold: &AuthorityFold, request: &OwnerKeyVouchRequest) -> Result<()> {
    let transcript = request.machine_transcript()?;
    let proof = ed25519_dalek::Signature::from_slice(&request.machine_proof)
        .map_err(|_| not_valid(MACHINE_PROOF_NOT_VALID))?;
    let folded = fold
        .machine(request.machine)
        .filter(|folded| folded.chains().all(|(_, chain)| !chain.removed))
        .ok_or_else(|| not_valid(MACHINE_PROOF_NOT_VALID))?;
    let mut verified = false;
    for (_, chain) in folded.chains() {
        let signed = chain.is_live()
            && strong_ed25519_key(&chain.profile.machine_key)
                .is_ok_and(|key| key.verify_strict(&transcript, &proof).is_ok());
        if !signed {
            continue;
        }
        if matches!(chain.profile.role, MachineRole::Owned(_)) {
            return Ok(());
        }
        verified = true;
    }
    Err(if verified {
        authority_refused(MACHINE_NOT_THE_OWNERS)
    } else {
        not_valid(MACHINE_PROOF_NOT_VALID)
    })
}
