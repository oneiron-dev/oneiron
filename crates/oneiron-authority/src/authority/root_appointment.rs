//! The owner anchor's appointment of a successor root key (row
//! OWNER-ANCHOR-ROOT-RECOVERY; Engine RULINGs 14 Nov 21:01, 21:47 and 22:32),
//! and its wire codec.
//!
//! When the roster holds no live root key, the anchor of an owner root signs
//! one row that names a fresh successor key. The anchor signs it alone, as it
//! signs its root record, with no cosign. The successor holds the roles
//! `ROLE_OWNER | ROLE_ADMIN` in one fixed, owner-held device shape, and its
//! attestation is the key's own proof of possession
//! ([`ROOT_APPOINTMENT_SUCCESSOR_PROOF_KIND`]) over
//! [`root_appointment_challenge`]: the vault, the root, the row's parents and
//! the key. The proof shows only that the key's holder can sign; it never
//! authorizes the key.
//!
//! Here are the row's shape and signatures only. Whether the row is valid (its
//! own ancestry holds no live root key, and its anchor is not burned) and
//! whether an install counts it are the fold's judgement in
//! `oneiron::authority`.

use ed25519_dalek::Signature as Ed25519Signature;
use rmpv::Value;

use crate::error::Result;

use super::*;

pub const OP_KIND_ROOT_APPOINTMENT: &str = "root_appointment";
const ROOT_APPOINTMENT_KEYS: [&str; 3] = [OP_KEY_KIND, "root", "successor"];

/// The attestation kind an appointed successor carries: its evidence is the
/// key's strict Ed25519 signature over [`root_appointment_challenge`].
pub const ROOT_APPOINTMENT_SUCCESSOR_PROOF_KIND: &str = "root-appointment-successor/v1";
/// The length of that evidence: one raw Ed25519 signature.
pub const ROOT_APPOINTMENT_SUCCESSOR_PROOF_LEN: usize = 64;
/// The roles an appointed successor holds: a root key that also consents.
pub const ROOT_APPOINTMENT_SUCCESSOR_ROLES: u16 = ROLE_OWNER | ROLE_ADMIN;

/// The bytes an appointed successor key signs to prove it holds the key: the
/// successor domain, then the canonical MessagePack map of the vault, the
/// root whose anchor appoints, the row's parents in ascending order, and the
/// key. A copy of the row on other parents or in another vault fails it.
pub fn root_appointment_challenge(
    vault_id: &AuthorityVaultId,
    root: &RecoveryRootId,
    parents: &[AuthorityEntryHash],
    successor: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut parents = parents.to_vec();
    parents.sort_unstable();
    let body = encode_value(&Value::Map(vec![
        (Value::from("vault_id"), binary_value(*vault_id)),
        (Value::from("root"), binary_value(root.0)),
        (
            Value::from("parents"),
            Value::Array(parents.into_iter().map(binary_value).collect()),
        ),
        (Value::from("successor"), binary_value(*successor)),
    ]))?;
    let mut transcript = Vec::with_capacity(
        ROOT_APPOINTMENT_SUCCESSOR_DOMAIN
            .len()
            .saturating_add(body.len()),
    );
    transcript.extend_from_slice(ROOT_APPOINTMENT_SUCCESSOR_DOMAIN);
    transcript.extend_from_slice(&body);
    Ok(transcript)
}

/// One appointment of a successor root key, signed by the anchor of `root`
/// alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAppointment {
    /// The owner root whose anchor appoints.
    pub root: RecoveryRootId,
    /// The successor root key, in the one shape an appointed key has.
    pub successor: DeviceAuthority,
}

impl RootAppointment {
    /// The successor's Ed25519 bytes; `None` for any other suite, which the
    /// shape check refuses.
    #[must_use]
    pub fn successor_key(&self) -> Option<&[u8; 32]> {
        match &self.successor.key {
            AuthorityKey::Ed25519(key) => Some(key),
            AuthorityKey::P256(_) => None,
        }
    }

    /// The anchor that signs `entry`: its Ed25519 primary signer.
    #[must_use]
    pub fn anchor_key(entry: &AuthorityLogEntry) -> Option<[u8; 32]> {
        match &entry.signer.public_key {
            AuthorityKey::Ed25519(key) => Some(*key),
            AuthorityKey::P256(_) => None,
        }
    }

    /// The fixed successor shape: an Ed25519 key with the roles
    /// [`ROOT_APPOINTMENT_SUCCESSOR_ROLES`] exactly, held by the owner (never
    /// `ROLE_CLOUD` or [`AuthorityTier::CloudCustodial`]), with no transport
    /// binding and its proof of possession as the attestation.
    pub fn validate(&self) -> Result<()> {
        self.successor.validate()?;
        if self.successor_key().is_none()
            || self.successor.roles != ROOT_APPOINTMENT_SUCCESSOR_ROLES
            || self.successor.tier == AuthorityTier::CloudCustodial
            || self.successor.transport_key_binding != [0; 32]
            || self.successor.attestation.kind != ROOT_APPOINTMENT_SUCCESSOR_PROOF_KIND
            || self.successor.attestation.evidence.len() != ROOT_APPOINTMENT_SUCCESSOR_PROOF_LEN
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// The entry the record rides: an Ed25519 primary signer alone, with no
    /// cosign, which is not the successor; and the successor's proof of
    /// possession verifies strictly over this vault's challenge for the
    /// entry's own parents.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        let vault_id = entry.vault_id.ok_or_else(invalid_authority)?;
        let successor = self.successor_key().ok_or_else(invalid_authority)?;
        if entry.signer.suite != AuthoritySignatureSuite::Ed25519
            || Self::anchor_key(entry).is_none()
            || !entry.cosigns.is_empty()
            || entry.signer.public_key == self.successor.key
        {
            return Err(invalid_authority());
        }
        let challenge =
            root_appointment_challenge(&vault_id, &self.root, &entry.parent_hashes, successor)?;
        let proof: [u8; ROOT_APPOINTMENT_SUCCESSOR_PROOF_LEN] = self
            .successor
            .attestation
            .evidence
            .as_slice()
            .try_into()
            .map_err(|_| invalid_authority())?;
        strong_ed25519_key(successor)?
            .verify_strict(&challenge, &Ed25519Signature::from_bytes(&proof))
            .map_err(|_| invalid_authority())
    }
}

pub(super) fn root_appointment_value(appointment: &RootAppointment) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_ROOT_APPOINTMENT),
        ),
        (Value::from("root"), binary_value(appointment.root.0)),
        (
            Value::from("successor"),
            super::wire_encode::device_value(&appointment.successor),
        ),
    ])
}

/// Strict: exactly the op's keys; the op's shape check then pins the
/// successor's shape, and the envelope's canonical re-encode every value's
/// form.
pub(super) fn decode_root_appointment(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &ROOT_APPOINTMENT_KEYS)?;
    Ok(AuthorityOp::RootAppointment(RootAppointment {
        root: RecoveryRootId(decode_hash(required(entries, "root")?)?),
        successor: super::wire_decode::decode_device(required(entries, "successor")?)?,
    }))
}
