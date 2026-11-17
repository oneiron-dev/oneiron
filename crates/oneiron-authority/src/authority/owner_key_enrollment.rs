//! The owner's enrollment of one of his devices' own owner signing keys on
//! the authority roster (FIX 4920; Engine 10-20 00:5x, rulings B and C), and
//! its wire codec.
//!
//! Each of the owner's devices holds its own Ed25519 owner signing key in its
//! keystore (FIX 4921 builds that key, its loader and its signer). He enrols
//! it by an owner act: the record carries his act ([`OwnerAct`], kind
//! `owner_key_enrollment`, target the key itself in this vault:
//! [`owner_key_enrollment_target`], `seen` zero:
//! [`OWNER_KEY_ENROLLMENT_SEEN`]), the machine that holds the key, the carrier
//! that served his say-so, and the key in one fixed device shape: Ed25519,
//! `ROLE_OWNER` alone, Software tier, no transport binding, and an attestation
//! whose evidence is the new key's own proof of possession
//! ([`OWNER_KEY_POSSESSION_KIND`]) over [`owner_key_enrollment_challenge`].
//!
//! Two signatures cover the entry, the enrollment's one exception to the
//! owner-act contract's carrier-alone rule (CALLS "FIX 4920 enrollment
//! signatures"): the primary is an existing live owner root's (a root change
//! is signed by an existing root: the predecessor-authorized handoff), and the
//! one cosign is the carrier's install key (the owner's authenticated will).
//! The proof of possession shows only that the key's holder can sign; it
//! never authorizes the key, and the key never signs its own entry. A key the
//! roster ever named, even revoked, never enrols again: a replacement is a
//! fresh key and an ordinary `RevokeDevice` of the old one. An agent never
//! enrols an owner key: no Grant line names the act, and the codec refuses an
//! agent's act outright.
//!
//! A passkey is the owner's key in a second fixed shape (row
//! WEB-PASSKEY-OWNER-KEY; Engine ruling WAYBACK-E4, shape (b)): its ES256
//! credential key as a P-256 key, `ROLE_OWNER` alone, Software tier, no
//! transport binding, and an attestation ([`OWNER_PASSKEY_POSSESSION_KIND`])
//! whose evidence names the passkey's credential id and carries its
//! assertion over the same challenge, in the envelope of
//! [`decode_webauthn_assertion`] ([`owner_passkey_possession_evidence`]). The
//! credential id lets a browser that holds the passkey ask for it by name,
//! on every replica of the log; the predecessor's signature covers it, the
//! assertion does not. No vault machine holds a
//! passkey: its `machine` names the carrier that served the ceremony. Once
//! on the roster it signs as any owner root signs, through the same
//! signature check, and the key never leaves the authenticator.

use ed25519_dalek::Signature as Ed25519Signature;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_OWNER_KEY_ENROLL: &str = "owner_key_enroll";
const OWNER_KEY_ENROLL_KEYS: [&str; 5] = [OP_KEY_KIND, OP_KEY_ACT, "machine", "carrier", "device"];

/// The attestation kind an enrolled owner key carries: its evidence is the
/// key's strict Ed25519 signature over [`owner_key_enrollment_challenge`].
pub const OWNER_KEY_POSSESSION_KIND: &str = "owner-key-possession/v1";
/// The length of that evidence: one raw Ed25519 signature.
pub const OWNER_KEY_POSSESSION_PROOF_LEN: usize = 64;
/// The attestation kind an enrolled passkey carries: its evidence
/// ([`owner_passkey_possession_evidence`]) is the passkey's credential id
/// and its assertion over [`webauthn_challenge`] of
/// [`owner_key_enrollment_challenge`], in its envelope.
pub const OWNER_PASSKEY_POSSESSION_KIND: &str = "owner-passkey-possession/v1";
/// The longest credential id WebAuthn allows.
pub const MAX_PASSKEY_CREDENTIAL_ID_BYTES: usize = 1023;

/// A passkey's possession evidence: its credential id after its two-byte
/// big-endian length, then its assertion's envelope.
///
/// # Errors
/// An empty credential id or one over [`MAX_PASSKEY_CREDENTIAL_ID_BYTES`].
pub fn owner_passkey_possession_evidence(credential_id: &[u8], envelope: &[u8]) -> Result<Vec<u8>> {
    if credential_id.is_empty() || credential_id.len() > MAX_PASSKEY_CREDENTIAL_ID_BYTES {
        return Err(invalid_authority());
    }
    let prefix = u16::try_from(credential_id.len()).map_err(|_| invalid_authority())?;
    let mut out = Vec::with_capacity(2 + credential_id.len() + envelope.len());
    out.extend_from_slice(&prefix.to_be_bytes());
    out.extend_from_slice(credential_id);
    out.extend_from_slice(envelope);
    Ok(out)
}

/// The credential id and the assertion envelope a passkey's possession
/// evidence carries, when the credential id is in bounds and the rest is
/// one envelope of a top-level assertion; `None` for anything else.
#[must_use]
pub fn decode_owner_passkey_possession(evidence: &[u8]) -> Option<(&[u8], &[u8])> {
    let (prefix, rest) = evidence.split_first_chunk::<2>()?;
    let len = usize::from(u16::from_be_bytes(*prefix));
    if len == 0 || len > MAX_PASSKEY_CREDENTIAL_ID_BYTES || rest.len() < len {
        return None;
    }
    let (credential_id, envelope) = rest.split_at(len);
    webauthn_assertion_context(envelope)?;
    Some((credential_id, envelope))
}

/// The policy hook of CALLS "FIX 4920 enrollment shape": the `seen` of every
/// owner key enrollment act. Fresh keys only: the target is the key itself,
/// which nobody acted on before, so its revision is zero.
pub const OWNER_KEY_ENROLLMENT_SEEN: [u8; 32] = [0; 32];

/// The target an owner key enrollment act names: the key itself, in its
/// vault, as the content id of a domain-separated BLAKE3 over the vault id
/// and the public key (its canonical bytes: an Ed25519 key's 32, a P-256
/// key's compressed SEC1), so every install names the same target and a key
/// has one target for good.
pub fn owner_key_enrollment_target(
    vault_id: &AuthorityVaultId,
    public_key: &[u8],
) -> Result<EntityId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(OWNER_KEY_ENROLLMENT_TARGET_DOMAIN);
    hasher.update(vault_id);
    hasher.update(public_key);
    authority_log_entity_id_from_hash(hasher.finalize().as_bytes())
}

/// The bytes a device's new owner key signs to prove it holds the key: the
/// possession domain, then the canonical MessagePack map of the vault, the
/// machine that holds the key, the key, the owner whose act enrols it, the
/// act's target ([`owner_key_enrollment_target`]) and its `seen` (zero). The
/// device's keystore signs exactly these bytes; a passkey signs their
/// [`webauthn_challenge`]. No secret crosses.
pub fn owner_key_enrollment_challenge(
    vault_id: &AuthorityVaultId,
    machine: EntityId,
    public_key: &[u8],
    owner: EntityId,
) -> Result<Vec<u8>> {
    let target = owner_key_enrollment_target(vault_id, public_key)?;
    possession_transcript(
        vault_id,
        machine,
        public_key,
        owner,
        target,
        OWNER_KEY_ENROLLMENT_SEEN,
    )
}

fn possession_transcript(
    vault_id: &AuthorityVaultId,
    machine: EntityId,
    public_key: &[u8],
    owner: EntityId,
    target: EntityId,
    seen: [u8; 32],
) -> Result<Vec<u8>> {
    let body = encode_value(&Value::Map(vec![
        (Value::from("vault_id"), binary_value(*vault_id)),
        (Value::from("machine"), Value::from(machine.to_hex())),
        (
            Value::from("public_key"),
            Value::Binary(public_key.to_vec()),
        ),
        (Value::from("owner"), Value::from(owner.to_hex())),
        (Value::from("target"), Value::from(target.to_hex())),
        (Value::from("seen"), binary_value(seen)),
    ]))?;
    let mut transcript = Vec::with_capacity(
        OWNER_KEY_ENROLLMENT_POP_DOMAIN
            .len()
            .saturating_add(body.len()),
    );
    transcript.extend_from_slice(OWNER_KEY_ENROLLMENT_POP_DOMAIN);
    transcript.extend_from_slice(&body);
    Ok(transcript)
}

/// One owner enrollment of a device's own owner signing key, signed by an
/// existing live owner root and cosigned by the install key of `carrier`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyEnroll {
    /// The owner's act: who decided and from which surface. Its kind is
    /// `owner_key_enrollment`, its target the key
    /// ([`owner_key_enrollment_target`]) and its `seen` zero.
    pub act: OwnerAct,
    /// The machine that holds the key in its keystore; for a passkey, which
    /// no machine holds, the carrier that served its ceremony.
    pub machine: EntityId,
    /// The carrier: the machine whose install key cosigned the entry. It may
    /// be the same machine or another of the vault's.
    pub carrier: EntityId,
    /// The key, in the one shape an enrolled owner key has.
    pub device: DeviceAuthority,
}

impl OwnerKeyEnroll {
    /// A device's enrolled key as its Ed25519 bytes; `None` for a passkey,
    /// whose key is P-256.
    #[must_use]
    pub fn public_key(&self) -> Option<&[u8; 32]> {
        match &self.device.key {
            AuthorityKey::Ed25519(key) => Some(key),
            AuthorityKey::P256(_) => None,
        }
    }

    /// The enrolled key's canonical bytes, in either shape: the 32 bytes of
    /// a device's Ed25519 key, the compressed SEC1 bytes of a passkey's.
    #[must_use]
    pub fn key_bytes(&self) -> &[u8] {
        match &self.device.key {
            AuthorityKey::Ed25519(key) => key,
            AuthorityKey::P256(key) => key,
        }
    }

    /// Whether the enrolled key is a passkey's (the passkey shape).
    #[must_use]
    pub fn is_passkey(&self) -> bool {
        matches!(self.device.key, AuthorityKey::P256(_))
    }

    /// Where a passkey's enrollment assertion was made: the context every
    /// later passkey-form signature by its key must name (the fold pins it);
    /// `None` for a device's key.
    #[must_use]
    pub fn passkey_context(&self) -> Option<WebAuthnContext> {
        if !self.is_passkey() {
            return None;
        }
        let (_, envelope) = decode_owner_passkey_possession(&self.device.attestation.evidence)?;
        webauthn_assertion_context(envelope)
    }

    /// A passkey's credential id, as its evidence names it; `None` for a
    /// device's key.
    #[must_use]
    pub fn passkey_credential_id(&self) -> Option<&[u8]> {
        if !self.is_passkey() {
            return None;
        }
        decode_owner_passkey_possession(&self.device.attestation.evidence)
            .map(|(credential_id, _)| credential_id)
    }

    /// One of the two fixed device shapes and the owner's own act: no
    /// agent, no answered ask, and a zero `seen`.
    pub fn validate(&self) -> Result<()> {
        self.device.validate()?;
        let evidence = &self.device.attestation.evidence;
        let shape = match (&self.device.key, self.device.attestation.kind.as_str()) {
            (AuthorityKey::Ed25519(_), OWNER_KEY_POSSESSION_KIND) => {
                evidence.len() == OWNER_KEY_POSSESSION_PROOF_LEN
            }
            (AuthorityKey::P256(_), OWNER_PASSKEY_POSSESSION_KIND) => {
                decode_owner_passkey_possession(evidence).is_some()
            }
            _ => false,
        };
        if !shape
            || self.device.roles != ROLE_OWNER
            || self.device.tier != AuthorityTier::Software
            || self.device.transport_key_binding != [0; 32]
            || self.act.act != OwnerActKind::OwnerKeyEnrollment
            || self.act.by != ActBy::Owner
            || self.act.answer.is_some()
            || self.act.seen != OWNER_KEY_ENROLLMENT_SEEN
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// The act names this vault's target for the key; the entry carries the
    /// primary signature and exactly one cosign, an Ed25519 install key, and
    /// neither is the enrolled key; and the key's proof of possession
    /// verifies strictly over this vault's challenge.
    pub fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        let vault_id = entry.vault_id.ok_or_else(invalid_authority)?;
        self.act.validate_carried(
            OwnerActKind::OwnerKeyEnrollment,
            owner_key_enrollment_target(&vault_id, self.key_bytes())?,
        )?;
        let [cosign] = entry.cosigns.as_slice() else {
            return Err(invalid_authority());
        };
        if !matches!(cosign.public_key, AuthorityKey::Ed25519(_))
            || cosign.public_key == self.device.key
            || *entry.signer_key() == self.device.key
        {
            return Err(invalid_authority());
        }
        self.verify_possession(&vault_id)
    }

    /// The carrier's install key: the entry's one cosign.
    #[must_use]
    pub fn carrier_key(entry: &AuthorityLogEntry) -> Option<&[u8; 32]> {
        match entry.cosigns.as_slice() {
            [cosign] => match &cosign.public_key {
                AuthorityKey::Ed25519(key) => Some(key),
                AuthorityKey::P256(_) => None,
            },
            _ => None,
        }
    }

    /// The new key's proof over the challenge of this vault, machine, key,
    /// owner, target and `seen`: a device key's strict Ed25519 signature, or
    /// a passkey's assertion.
    fn verify_possession(&self, vault_id: &AuthorityVaultId) -> Result<()> {
        let transcript = possession_transcript(
            vault_id,
            self.machine,
            self.key_bytes(),
            self.act.owner,
            self.act.target,
            self.act.seen,
        )?;
        let key = match &self.device.key {
            AuthorityKey::Ed25519(key) => key,
            AuthorityKey::P256(key) => {
                let key =
                    P256VerifyingKey::from_sec1_bytes(key).map_err(|_| invalid_authority())?;
                let (_, envelope) =
                    decode_owner_passkey_possession(&self.device.attestation.evidence)
                        .ok_or_else(invalid_authority)?;
                return webauthn_assertion_verifies(&key, envelope, &transcript)
                    .then_some(())
                    .ok_or_else(invalid_authority);
            }
        };
        let proof: [u8; OWNER_KEY_POSSESSION_PROOF_LEN] = self
            .device
            .attestation
            .evidence
            .as_slice()
            .try_into()
            .map_err(|_| invalid_authority())?;
        strong_ed25519_key(key)?
            .verify_strict(&transcript, &Ed25519Signature::from_bytes(&proof))
            .map_err(|_| invalid_authority())
    }
}

pub(super) fn owner_key_enroll_value(enroll: &OwnerKeyEnroll) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_OWNER_KEY_ENROLL),
        ),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&enroll.act),
        ),
        (Value::from("machine"), Value::from(enroll.machine.to_hex())),
        (Value::from("carrier"), Value::from(enroll.carrier.to_hex())),
        (
            Value::from("device"),
            super::wire_encode::device_value(&enroll.device),
        ),
    ])
}

/// Strict: exactly the op's keys, and only the owner's own act; the op's
/// shape check then pins the device's shape and the envelope's canonical
/// re-encode every value's form.
pub(super) fn decode_owner_key_enroll(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &OWNER_KEY_ENROLL_KEYS)?;
    let act = super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?;
    if act.by != ActBy::Owner {
        return Err(invalid_authority());
    }
    Ok(AuthorityOp::OwnerKeyEnroll(OwnerKeyEnroll {
        act,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        carrier: decode_canonical_id(required(entries, "carrier")?)?,
        device: super::wire_decode::decode_device(required(entries, "device")?)?,
    }))
}
