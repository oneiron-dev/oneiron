//! Explicit successor input and committed recovery receipts; no authority is inferred here.

use oneiron::authority::{
    AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthoritySignatureSuite, AuthorityTier,
    DeviceAuthority, authority_entry_hash,
};
use serde::{Deserialize, Serialize};

use crate::owner::vault_key::hex;
use crate::owner::{OwnerError, OwnerResult};

/// All native successor fields are supplied by the caller, without defaults.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceAuthorityInput {
    key: KeyInput,
    /// The actual transport binding, 64 hex digits; never inferred from a host key.
    transport_key_binding: String,
    attestation: AttestationInput,
    /// Native tier: software, hardware or cloud_custodial.
    tier: String,
    roles: u16,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct KeyInput {
    /// Native signature suite: ed25519 or p256.
    suite: String,
    /// The actual public key, in hex; P-256 uses canonical compressed SEC1 bytes.
    public_key: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct AttestationInput {
    kind: String,
    /// The caller's opaque attestation evidence, in hex.
    evidence: String,
}

impl DeviceAuthorityInput {
    pub(crate) fn into_native(self) -> OwnerResult<DeviceAuthority> {
        let public_key = hex_bytes(&self.key.public_key, "new_device.key.public_key")?;
        let key = match AuthoritySignatureSuite::parse(&self.key.suite) {
            Some(AuthoritySignatureSuite::Ed25519) => {
                AuthorityKey::Ed25519(public_key.try_into().map_err(|_| {
                    invalid("new_device.key.public_key must be a 32-byte Ed25519 public key")
                })?)
            }
            Some(AuthoritySignatureSuite::P256) => AuthorityKey::P256(public_key),
            None => return Err(invalid("new_device.key.suite must be ed25519 or p256")),
        };
        let transport_key_binding = hex_bytes(
            &self.transport_key_binding,
            "new_device.transport_key_binding",
        )?
        .try_into()
        .map_err(|_| invalid("new_device.transport_key_binding must be 32 bytes"))?;
        let tier = AuthorityTier::parse(&self.tier).ok_or_else(|| {
            invalid("new_device.tier must be software, hardware or cloud_custodial")
        })?;
        let device = DeviceAuthority {
            key,
            transport_key_binding,
            attestation: AuthorityAttestation {
                kind: self.attestation.kind,
                evidence: hex_bytes(
                    &self.attestation.evidence,
                    "new_device.attestation.evidence",
                )?,
            },
            tier,
            roles: self.roles,
        };
        device.validate()?;
        Ok(device)
    }
}

fn invalid(message: &str) -> OwnerError {
    OwnerError::Invalid(message.to_owned())
}

fn hex_bytes(text: &str, field: &str) -> OwnerResult<Vec<u8>> {
    let malformed = || invalid(&format!("{field} must be hex bytes"));
    if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(malformed());
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).map_err(|_| malformed()))
        .collect()
}

#[derive(Serialize, schemars::JsonSchema)]
pub(crate) struct RecoveryReceipt {
    entry: String,
    vault_id: Option<String>,
    seq: u64,
}

impl RecoveryReceipt {
    /// Only called with the entry returned after the core recovery writer commits.
    pub(crate) fn committed(entry: &AuthorityLogEntry) -> OwnerResult<Self> {
        Ok(Self {
            entry: hex(&authority_entry_hash(entry)?),
            vault_id: entry.vault_id.as_ref().map(|id| hex(id)),
            seq: entry.seq,
        })
    }
}
