//! One-way authenticated courtesy deletion requests. No remote result protocol.

use crate::authority::{
    AuthorityKey, AuthoritySignature, AuthoritySignatureSuite, FederationPactStatus,
    verify_authority_signature,
};
use crate::entity_id::LocalWorldId;
use crate::error::{Error, RecordError, Result};
use crate::{EntityId, Vault};
use rmpv::Value;

/// Domain for an authenticated ask, not evidence of remote deletion.
pub const COOP_DELETION_REQUEST_DOMAIN: &[u8] = b"oneiron/deletion/coop-request/v1";
/// Wire schema version.
pub const COOP_DELETION_REQUEST_SCHEMA_VERSION: u64 = 1;
/// Exact canonical body keys, in wire order.
pub const COOP_DELETION_REQUEST_BODY_KEYS: [&str; 8] = [
    "schema_version",
    "pact_id",
    "requester_vault_id",
    "peer_vault_id",
    "worlds",
    "epoch_cutoff",
    "ts",
    "nonce",
];
/// Maximum explicitly named worlds. An empty list means the entire pact.
pub const MAX_COOP_DELETION_WORLDS: usize = 256;

/// A courtesy ask about content authored/shared by the requester.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooperativeDeletionRequest {
    pub pact_id: [u8; 32],
    pub requester_vault_id: [u8; 32],
    pub peer_vault_id: [u8; 32],
    pub worlds: Vec<EntityId>,
    pub epoch_cutoff: u64,
    pub ts: u64,
    pub nonce: [u8; 16],
}

/// Authenticated one-way bytes. There is intentionally no response type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCooperativeDeletionRequest {
    pub body: CooperativeDeletionRequest,
    pub signature: AuthoritySignature,
}

fn invalid() -> Error {
    RecordError::InvalidCooperativeDeletionRequest.into()
}
fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| invalid())?;
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> Result<Value> {
    // Bound allocation before invoking the general MessagePack reader.
    if bytes.len() > 32_768 {
        return Err(invalid());
    }
    let mut cursor = std::io::Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid());
    }
    Ok(value)
}
fn fields<'a>(value: &'a Value, keys: &[&str]) -> Result<Vec<&'a Value>> {
    let pairs = value.as_map().ok_or_else(invalid)?;
    if pairs.len() != keys.len()
        || pairs
            .iter()
            .zip(keys)
            .any(|((key, _), expected)| key.as_str() != Some(*expected))
    {
        return Err(invalid());
    }
    Ok(pairs.iter().map(|(_, value)| value).collect())
}
fn binary<const N: usize>(v: &Value) -> Result<[u8; N]> {
    let Value::Binary(bytes) = v else {
        return Err(invalid());
    };
    bytes.as_slice().try_into().map_err(|_| invalid())
}
fn uint(v: &Value) -> Result<u64> {
    v.as_u64().ok_or_else(invalid)
}

/// Encodes the canonical body, sorting and deduplicating the local world list.
pub fn encode_cooperative_deletion_request_body(
    body: &CooperativeDeletionRequest,
) -> Result<Vec<u8>> {
    if body.pact_id == [0; 32]
        || body.requester_vault_id == [0; 32]
        || body.peer_vault_id == [0; 32]
        || body.nonce == [0; 16]
        || body.worlds.len() > MAX_COOP_DELETION_WORLDS
    {
        return Err(invalid());
    }
    let mut worlds = body.worlds.clone();
    for world in &worlds {
        LocalWorldId::from_entity_id(*world)?;
    }
    worlds.sort_unstable();
    worlds.dedup();
    let values = [
        Value::from(COOP_DELETION_REQUEST_SCHEMA_VERSION),
        Value::Binary(body.pact_id.to_vec()),
        Value::Binary(body.requester_vault_id.to_vec()),
        Value::Binary(body.peer_vault_id.to_vec()),
        Value::Array(worlds.iter().map(|id| Value::from(id.to_hex())).collect()),
        Value::from(body.epoch_cutoff),
        Value::from(body.ts),
        Value::Binary(body.nonce.to_vec()),
    ];
    encode(&Value::Map(
        COOP_DELETION_REQUEST_BODY_KEYS
            .iter()
            .zip(values)
            .map(|(k, v)| (Value::from(*k), v))
            .collect(),
    ))
}

/// Encodes a request as the two-key body/signature envelope.
pub fn encode_signed_cooperative_deletion_request(
    req: &SignedCooperativeDeletionRequest,
) -> Result<Vec<u8>> {
    let body = encode_cooperative_deletion_request_body(&req.body)?;
    let (suite, key) = match &req.signature.public_key {
        AuthorityKey::Ed25519(key) => ("ed25519", key.to_vec()),
        AuthorityKey::P256(key) => ("p256", key.clone()),
    };
    if !verify_authority_signature(
        &req.signature,
        &[COOP_DELETION_REQUEST_DOMAIN, &body].concat(),
    ) {
        return Err(invalid());
    }
    encode(&Value::Map(vec![
        (Value::from("body"), Value::Binary(body)),
        (
            Value::from("signature"),
            Value::Map(vec![
                (Value::from("suite"), Value::from(suite)),
                (Value::from("public_key"), Value::Binary(key)),
                (
                    Value::from("signature"),
                    Value::Binary(req.signature.signature.clone()),
                ),
            ]),
        ),
    ]))
}

/// Verifies the ASK's authenticity only. It is NOT a deletion proof and no
/// proof exists in this protocol. Rejects unknown keys, duplicates and tails.
pub fn decode_and_verify_cooperative_deletion_request(
    bytes: &[u8],
    expected_signer: &AuthorityKey,
) -> Result<CooperativeDeletionRequest> {
    let value = decode(bytes)?;
    let outer = fields(&value, &["body", "signature"])?;
    let Value::Binary(body_bytes) = outer[0] else {
        return Err(invalid());
    };
    let sig = fields(outer[1], &["suite", "public_key", "signature"])?;
    let (suite, public_key) = match sig[0].as_str() {
        Some("ed25519") => (
            AuthoritySignatureSuite::Ed25519,
            AuthorityKey::Ed25519(binary(sig[1])?),
        ),
        Some("p256") => {
            let Value::Binary(key) = sig[1] else {
                return Err(invalid());
            };
            (
                AuthoritySignatureSuite::P256,
                AuthorityKey::P256(key.clone()),
            )
        }
        _ => return Err(invalid()),
    };
    let signature = AuthoritySignature {
        suite,
        public_key,
        signature: binary::<64>(sig[2])?.to_vec(),
    };
    if &signature.public_key != expected_signer
        || !verify_authority_signature(
            &signature,
            &[COOP_DELETION_REQUEST_DOMAIN, body_bytes].concat(),
        )
    {
        return Err(invalid());
    }
    let body_value = decode(body_bytes)?;
    let f = fields(&body_value, &COOP_DELETION_REQUEST_BODY_KEYS)?;
    if uint(f[0])? != COOP_DELETION_REQUEST_SCHEMA_VERSION {
        return Err(invalid());
    }
    let world_values = f[4].as_array().ok_or_else(invalid)?;
    if world_values.len() > MAX_COOP_DELETION_WORLDS {
        return Err(invalid());
    }
    let worlds = world_values
        .iter()
        .map(|v| EntityId::from_hex(v.as_str().ok_or_else(invalid)?))
        .collect::<Result<Vec<_>>>()?;
    let body = CooperativeDeletionRequest {
        pact_id: binary(f[1])?,
        requester_vault_id: binary(f[2])?,
        peer_vault_id: binary(f[3])?,
        worlds,
        epoch_cutoff: uint(f[5])?,
        ts: uint(f[6])?,
        nonce: binary(f[7])?,
    };
    // Canonical re-encoding rejects unsorted/duplicate worlds and alternate spellings.
    if encode_cooperative_deletion_request_body(&body)? != *body_bytes {
        return Err(invalid());
    }
    Ok(body)
}

impl Vault {
    /// Signs a one-way courtesy request only after disconnect or dissolution.
    pub fn sign_cooperative_deletion_request<S>(
        &self,
        pact_id: &[u8; 32],
        worlds: Vec<EntityId>,
        epoch_cutoff: u64,
        nonce: [u8; 16],
        signer_key: AuthorityKey,
        signer: S,
    ) -> Result<SignedCooperativeDeletionRequest>
    where
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        let fold = self.authority_fold()?;
        let pact = fold
            .federation_pacts
            .get(pact_id)
            .filter(|p| {
                matches!(
                    p.status,
                    FederationPactStatus::Disconnected | FederationPactStatus::Dissolved
                )
            })
            .ok_or(RecordError::CooperativeDeletionRequiresTerminalPact)?;
        if epoch_cutoff > pact.terminal_epoch.unwrap_or(pact.pact_epoch) {
            return Err(invalid());
        }
        let mut body = CooperativeDeletionRequest {
            pact_id: *pact_id,
            requester_vault_id: fold.vault_id.ok_or_else(invalid)?,
            peer_vault_id: pact.peer_vault_id,
            worlds,
            epoch_cutoff,
            ts: crate::unix_seconds_now(),
            nonce,
        };
        body.worlds.sort_unstable();
        body.worlds.dedup();
        let bytes = encode_cooperative_deletion_request_body(&body)?;
        let transcript = [COOP_DELETION_REQUEST_DOMAIN, &bytes].concat();
        let signature = AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: signer(&transcript)?,
        };
        if !verify_authority_signature(&signature, &transcript) {
            return Err(invalid());
        }
        Ok(SignedCooperativeDeletionRequest { body, signature })
    }
}
