//! An owner key vouches for another device's new owner key (pass 27 R2, "an
//! owner key vouches"; MFA-1 A: "vault authority on a new device comes only
//! from an old device (QR approval) or the person's own pieces").
//!
//! The new device makes its key in its keystore slot and signs the key's
//! enrollment challenge ([`Vault::device_owner_key_vouch_request`]). That is
//! all it can do alone: the challenge binds the vault, the machine that holds
//! the key, the key and the owner, never the key that will vouch for it, so
//! the new device writes nothing and needs no owner key of its own. It hands
//! the [`OwnerKeyVouchRequest`] to one of the owner's devices: side by side as
//! a QR code ([`OwnerKeyVouchRequest::to_text`]), apart as the act an owner
//! ask carries (OCS-HANDOVER = A), which names it by
//! [`OwnerKeyVouchRequest::digest`].
//!
//! That device's install holds an owner key the vault trusts as the owner's
//! and enrols the new key with it ([`Vault::enrol_vouched_owner_signing_key`]):
//! the ordinary `OwnerKeyEnroll` act, whose primary signer is the vouching
//! key and whose carrier is this install. A managed host's custodial root
//! proves nothing on a hosted vault (`AuthorityFold::proves_owner_acts`), so
//! an install holding only that root vouches for nothing.
//!
//! The request carries no secret: the proof of possession is public, the key
//! never leaves its device. The proof has no nonce and no time, so it never
//! expires; it stops verifying only when the vault's owner changes, and a
//! key already on the roster is never enrolled again. A second answer to the
//! same request answers the first enrollment's receipt, since two owner
//! devices may answer one ask.

use base64::Engine as _;
use rmpv::Value;

use crate::error::{Error, RecordError, Result};
use crate::{EntityId, Vault};

use super::owner_key_enrollment_door::{KEY_ON_ROSTER, OWNER_ONLY, not_valid};
use super::*;

/// The context the request's digest is derived under.
const VOUCH_REQUEST_DIGEST_CONTEXT: &str = "oneiron/owner-key-vouch-request/v1";
/// What every request's text form starts with: the codec and its version.
pub const OWNER_KEY_VOUCH_TEXT_PREFIX: &str = "oneiron-owner-key-vouch-v1.";
/// The longest device label a request carries, in bytes of UTF-8.
pub const OWNER_KEY_VOUCH_LABEL_MAX: usize = 64;
/// The request's map keys, in their one encoded order.
const REQUEST_KEYS: [&str; 5] = ["vault_id", "machine", "public_key", "proof", "label"];

/// Integrity: the request names another vault than this one.
const OTHER_VAULT: &str = "the key's request names another vault; make it on the new device for \
                           this vault";
/// Integrity: the request's proof is not the key's own signature over its
/// challenge for this vault, machine, key and owner.
const PROOF_NOT_VALID: &str = "the key's proof of possession does not verify for this vault, its \
                               machine, its key and the owner";
/// Integrity: the device label breaks the request's rules.
const LABEL_NOT_VALID: &str = "a device label is at most 64 bytes of text with no control \
                               characters";

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
    /// The device's name as the new device states it, for the owner to
    /// recognise on the answering device. Shown, never trusted:
    /// [`OWNER_KEY_VOUCH_LABEL_MAX`] bytes at most, no control characters.
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

    /// The request's one encoding: the canonical MessagePack map of its five
    /// fields, in [`REQUEST_KEYS`] order (ids as lower-case hex, keys and the
    /// proof as binary, the label as text).
    ///
    /// # Errors
    /// The encoder's own refusal.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_value(&Value::Map(vec![
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
            (
                Value::from(REQUEST_KEYS[4]),
                Value::from(self.label.as_str()),
            ),
        ]))
    }

    /// Reads [`Self::to_bytes`] back: exactly the five keys in their order,
    /// a 32-byte vault id and key, a machine id, a proof of
    /// [`OWNER_KEY_POSSESSION_PROOF_LEN`] bytes, a label within its rules,
    /// and bytes that encode again to themselves, so each request has one
    /// encoding.
    ///
    /// # Errors
    /// The first rule the bytes break, named.
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, &'static str> {
        const SHAPE: &str = "a request is one map of vault_id, machine, public_key, proof and \
                             label, in that order";
        let mut reader = bytes;
        let value = rmpv::decode::read_value(&mut reader).map_err(|_| SHAPE)?;
        if !reader.is_empty() {
            return Err(SHAPE);
        }
        let Value::Map(entries) = value else {
            return Err(SHAPE);
        };
        let [vault_id, machine, public_key, proof, label] = entries.as_slice() else {
            return Err(SHAPE);
        };
        for ((key, _), name) in [vault_id, machine, public_key, proof, label]
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
        let request = Self {
            vault_id: bytes_32(&vault_id.1)?,
            machine: machine
                .1
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or("the machine is an entity id in lower-case hex")?,
            public_key: bytes_32(&public_key.1)?,
            proof: proof
                .1
                .as_slice()
                .filter(|slice| slice.len() == OWNER_KEY_POSSESSION_PROOF_LEN)
                .ok_or("the proof is one 64-byte Ed25519 signature")?
                .to_vec(),
            label: label.1.as_str().ok_or(LABEL_NOT_VALID)?.to_owned(),
        };
        if !label_is_valid(&request.label) {
            return Err(LABEL_NOT_VALID);
        }
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

    /// Reads [`Self::to_text`] back, surrounding whitespace ignored.
    ///
    /// # Errors
    /// Another prefix, text that is not unpadded URL-safe base64, or the
    /// first rule of [`Self::from_bytes`] the bytes break.
    pub fn from_text(text: &str) -> std::result::Result<Self, &'static str> {
        let encoded = text
            .trim()
            .strip_prefix(OWNER_KEY_VOUCH_TEXT_PREFIX)
            .ok_or("the text is not an owner key's request")?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "the request's text is not unpadded URL-safe base64")?;
        Self::from_bytes(&bytes)
    }

    /// The request's digest: BLAKE3 derived under its own context over
    /// [`Self::to_bytes`], the same on every device. An ask names the act by
    /// it, so a changed request is another ask.
    ///
    /// # Errors
    /// The encoder's own refusal.
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(blake3::derive_key(
            VOUCH_REQUEST_DIGEST_CONTEXT,
            &self.to_bytes()?,
        ))
    }
}

/// A device label within its rules: [`OWNER_KEY_VOUCH_LABEL_MAX`] bytes at
/// most and no control characters.
#[must_use]
pub(crate) fn label_is_valid(label: &str) -> bool {
    label.len() <= OWNER_KEY_VOUCH_LABEL_MAX && !label.chars().any(char::is_control)
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
    /// The owner enrols the new key `request` names, vouched for by the
    /// owner key this install holds: the key the fold trusts as the owner's
    /// (`Vault::owner_proof_signer`) signs the `OwnerKeyEnroll` entry as
    /// its predecessor, and this install carries it
    /// ([`Vault::enrol_owner_signing_key_as`]). The request is checked and
    /// the roster read once before the write: it names this vault, its
    /// proof verifies for this owner, and its key is fresh. A key already
    /// live on the roster for the request's machine answers its first
    /// enrollment's receipt, and nothing is written.
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] for an agent's act, an install that
    /// cannot carry it, or an enrollment the fold does not count;
    /// [`RecordError::OwnerKeyRequired`] when this install holds no key the
    /// vault trusts as the owner's (a managed host's custodial root is none);
    /// [`RecordError::InvalidAuthorityLogBody`] for a request that names
    /// another vault, a proof that does not verify, or a key the roster
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
            if fold
                .roster
                .contains_key(&AuthorityKey::Ed25519(request.public_key))
            {
                drop(fold);
                drop(txn);
                return self.first_vouched_receipt(request);
            }
            self.owner_proof_signer(&fold)
                .ok_or(Error::Record(RecordError::OwnerKeyRequired))?
        };
        // The owner's presence is asked here, before the write and outside
        // it (OPUS-SPLIT-5 PR 4, D5): everything the proof signs is known.
        self.enrol_owner_signing_key_as(
            authority,
            request.enrollment(),
            signer.root(),
            |transcript| signer.sign_owner_proof(transcript),
        )
    }

    /// The receipt of the enrollment that already put `request`'s key on
    /// the roster live for its machine; any other listing of the key is the
    /// roster's refusal.
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
