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

use ed25519_dalek::Signature as Ed25519Signature;
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

/// The policy hook of CALLS "FIX 4920 enrollment shape": the `seen` of every
/// owner key enrollment act. Fresh keys only: the target is the key itself,
/// which nobody acted on before, so its revision is zero.
pub const OWNER_KEY_ENROLLMENT_SEEN: [u8; 32] = [0; 32];

/// The target an owner key enrollment act names: the key itself, in its
/// vault, as the content id of a domain-separated BLAKE3 over the vault id
/// and the public key, so every install names the same target and a key has
/// one target for good.
pub fn owner_key_enrollment_target(
    vault_id: &AuthorityVaultId,
    public_key: &[u8; 32],
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
/// device's keystore signs exactly these bytes; no secret crosses.
pub fn owner_key_enrollment_challenge(
    vault_id: &AuthorityVaultId,
    machine: EntityId,
    public_key: &[u8; 32],
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
    public_key: &[u8; 32],
    owner: EntityId,
    target: EntityId,
    seen: [u8; 32],
) -> Result<Vec<u8>> {
    let body = encode_value(&Value::Map(vec![
        (Value::from("vault_id"), binary_value(*vault_id)),
        (Value::from("machine"), Value::from(machine.to_hex())),
        (Value::from("public_key"), binary_value(*public_key)),
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
    /// The machine that holds the key in its keystore.
    pub machine: EntityId,
    /// The carrier: the machine whose install key cosigned the entry. It may
    /// be the same machine or another of the vault's.
    pub carrier: EntityId,
    /// The key, in the one shape an enrolled owner key has.
    pub device: DeviceAuthority,
}

impl OwnerKeyEnroll {
    /// The enrolled key's Ed25519 bytes; `None` for any other suite, which
    /// the shape check refuses.
    #[must_use]
    pub fn public_key(&self) -> Option<&[u8; 32]> {
        match &self.device.key {
            AuthorityKey::Ed25519(key) => Some(key),
            AuthorityKey::P256(_) => None,
        }
    }

    /// The fixed device shape and the owner's own act: no agent, no answered
    /// ask, and a zero `seen`.
    pub fn validate(&self) -> Result<()> {
        self.device.validate()?;
        if self.public_key().is_none()
            || self.device.roles != ROLE_OWNER
            || self.device.tier != AuthorityTier::Software
            || self.device.transport_key_binding != [0; 32]
            || self.device.attestation.kind != OWNER_KEY_POSSESSION_KIND
            || self.device.attestation.evidence.len() != OWNER_KEY_POSSESSION_PROOF_LEN
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
        let key = self.public_key().ok_or_else(invalid_authority)?;
        self.act.validate_carried(
            OwnerActKind::OwnerKeyEnrollment,
            owner_key_enrollment_target(&vault_id, key)?,
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

    /// The new key's strict Ed25519 signature over the challenge of this
    /// vault, machine, key, owner, target and `seen`.
    fn verify_possession(&self, vault_id: &AuthorityVaultId) -> Result<()> {
        let key = self.public_key().ok_or_else(invalid_authority)?;
        let transcript = possession_transcript(
            vault_id,
            self.machine,
            key,
            self.act.owner,
            self.act.target,
            self.act.seen,
        )?;
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
