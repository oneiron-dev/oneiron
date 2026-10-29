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
/// Wire schema version: v2 names the page an ask is of its selection (FIX
/// 7941). There is no v1 reader.
pub const COOP_DELETION_REQUEST_SCHEMA_VERSION: u64 = 2;
/// Exact canonical body keys, in wire order.
pub const COOP_DELETION_REQUEST_BODY_KEYS: [&str; 10] = [
    "schema_version",
    "pact_id",
    "requester_vault_id",
    "peer_vault_id",
    "worlds",
    "page",
    "pages",
    "epoch_cutoff",
    "ts",
    "nonce",
];
/// The most worlds one page names (FIX 7941). An owner's selection of any
/// size goes whole, as consecutive pages of its sorted, deduplicated worlds,
/// each its own signed ask: a page stays far below the codec's body bound,
/// and each goes as its own delivery, in turn with every other ask, under
/// its own give-up deadline. An empty list means the entire pact.
pub const MAX_COOP_DELETION_PAGE_WORLDS: usize = 256;
/// The domain a page's own nonce derives under, from its selection's.
const COOP_DELETION_PAGE_NONCE_DOMAIN: &str = "oneiron/deletion/coop-request/page-nonce/v1";
/// The courtesy codec's bound on one body: an ask, an answer or a
/// succession page (FIX 3014), each read whole.
pub(super) const COOP_DELETION_BODY_MAX_BYTES: usize = 32_768;

/// A courtesy ask about content authored/shared by the requester: one page
/// of the owner's selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooperativeDeletionRequest {
    pub pact_id: [u8; 32],
    pub requester_vault_id: [u8; 32],
    pub peer_vault_id: [u8; 32],
    pub worlds: Vec<EntityId>,
    /// This page's index in its selection, from 0.
    pub page: u32,
    /// How many pages its selection went as; at least 1.
    pub pages: u32,
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

pub(super) fn invalid() -> Error {
    RecordError::InvalidCooperativeDeletionRequest.into()
}
pub(super) fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| invalid())?;
    Ok(bytes)
}
pub(super) fn decode(bytes: &[u8]) -> Result<Value> {
    // Bound allocation before invoking the general MessagePack reader.
    if bytes.len() > COOP_DELETION_BODY_MAX_BYTES {
        return Err(invalid());
    }
    let mut cursor = std::io::Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid());
    }
    Ok(value)
}
pub(super) fn fields<'a>(value: &'a Value, keys: &[&str]) -> Result<Vec<&'a Value>> {
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
pub(super) fn binary<const N: usize>(v: &Value) -> Result<[u8; N]> {
    let Value::Binary(bytes) = v else {
        return Err(invalid());
    };
    bytes.as_slice().try_into().map_err(|_| invalid())
}
pub(super) fn uint(v: &Value) -> Result<u64> {
    v.as_u64().ok_or_else(invalid)
}

/// The owner's whole selection as pages (FIX 7941): its sorted,
/// deduplicated worlds in consecutive runs of at most
/// [`MAX_COOP_DELETION_PAGE_WORLDS`]. An empty selection, the entire pact,
/// is one empty page.
fn selection_pages(mut worlds: Vec<EntityId>) -> Vec<Vec<EntityId>> {
    worlds.sort_unstable();
    worlds.dedup();
    if worlds.is_empty() {
        return vec![Vec::new()];
    }
    worlds
        .chunks(MAX_COOP_DELETION_PAGE_WORLDS)
        .map(<[EntityId]>::to_vec)
        .collect()
}

/// The nonce page `page` of `pages` carries: a one-page ask's is its
/// selection's own; a longer selection's pages each derive their own from
/// it, so each page is its own ask under the replay fence and the same
/// selection signed again gives the same pages.
fn page_nonce(nonce: &[u8; 16], page: u32, pages: u32) -> [u8; 16] {
    if pages == 1 {
        return *nonce;
    }
    let mut material = [0; 24];
    material[..16].copy_from_slice(nonce);
    material[16..20].copy_from_slice(&page.to_be_bytes());
    material[20..].copy_from_slice(&pages.to_be_bytes());
    let derived = blake3::derive_key(COOP_DELETION_PAGE_NONCE_DOMAIN, &material);
    let mut out = [0; 16];
    out.copy_from_slice(&derived[..16]);
    out
}

/// Encodes the canonical body, sorting and deduplicating the local world list.
/// A page names at most [`MAX_COOP_DELETION_PAGE_WORLDS`] worlds, its index
/// is below its page count, and only a one-page ask may name none.
pub fn encode_cooperative_deletion_request_body(
    body: &CooperativeDeletionRequest,
) -> Result<Vec<u8>> {
    if body.pact_id == [0; 32]
        || body.requester_vault_id == [0; 32]
        || body.peer_vault_id == [0; 32]
        || body.nonce == [0; 16]
        || body.worlds.len() > MAX_COOP_DELETION_PAGE_WORLDS
        || body.page >= body.pages
        || (body.pages > 1 && body.worlds.is_empty())
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
        Value::from(body.page),
        Value::from(body.pages),
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
    if !verify_authority_signature(
        &req.signature,
        &[COOP_DELETION_REQUEST_DOMAIN, &body].concat(),
    ) {
        return Err(invalid());
    }
    encode(&Value::Map(vec![
        (Value::from("body"), Value::Binary(body)),
        (Value::from("signature"), signature_value(&req.signature)),
    ]))
}

/// The envelope's signature, read without trusting it.
pub(super) fn envelope_signature(sig: &Value) -> Result<AuthoritySignature> {
    let sig = fields(sig, &["suite", "public_key", "signature"])?;
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
    Ok(AuthoritySignature {
        suite,
        public_key,
        signature: binary::<64>(sig[2])?.to_vec(),
    })
}

/// The envelope's signature as a map, for re-encoding.
pub(super) fn signature_value(signature: &AuthoritySignature) -> Value {
    let (suite, key) = match &signature.public_key {
        AuthorityKey::Ed25519(key) => ("ed25519", key.to_vec()),
        AuthorityKey::P256(key) => ("p256", key.clone()),
    };
    Value::Map(vec![
        (Value::from("suite"), Value::from(suite)),
        (Value::from("public_key"), Value::Binary(key)),
        (
            Value::from("signature"),
            Value::Binary(signature.signature.clone()),
        ),
    ])
}

/// The pact an envelope names, read WITHOUT verifying anything: a lookup
/// hint for finding the key to verify it against, never a trusted value.
pub fn peek_cooperative_deletion_pact(bytes: &[u8]) -> Result<[u8; 32]> {
    let value = decode(bytes)?;
    let outer = fields(&value, &["body", "signature"])?;
    let Value::Binary(body_bytes) = outer[0] else {
        return Err(invalid());
    };
    let body = decode(body_bytes)?;
    let pact = body
        .as_map()
        .ok_or_else(invalid)?
        .iter()
        .find(|(key, _)| key.as_str() == Some("pact_id"))
        .ok_or_else(invalid)?;
    binary(&pact.1)
}

/// Decodes an envelope and verifies it against the key it carries: the
/// owner-signed bytes a client hands its own host, checked for shape and
/// self-consistency before they are queued. The peer verifies again against
/// the key it pinned.
pub fn decode_self_signed_cooperative_deletion_request(
    bytes: &[u8],
) -> Result<SignedCooperativeDeletionRequest> {
    let value = decode(bytes)?;
    let outer = fields(&value, &["body", "signature"])?;
    let signature = envelope_signature(outer[1])?;
    let body = decode_and_verify_cooperative_deletion_request(bytes, &signature.public_key)?;
    Ok(SignedCooperativeDeletionRequest { body, signature })
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
    let signature = envelope_signature(outer[1])?;
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
    if world_values.len() > MAX_COOP_DELETION_PAGE_WORLDS {
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
        page: u32::try_from(uint(f[5])?).map_err(|_| invalid())?,
        pages: u32::try_from(uint(f[6])?).map_err(|_| invalid())?,
        epoch_cutoff: uint(f[7])?,
        ts: uint(f[8])?,
        nonce: binary(f[9])?,
    };
    // Canonical re-encoding rejects unsorted/duplicate worlds and alternate spellings.
    if encode_cooperative_deletion_request_body(&body)? != *body_bytes {
        return Err(invalid());
    }
    Ok(body)
}

impl Vault {
    /// Signs a one-way courtesy request only after disconnect or dissolution:
    /// the owner's whole selection, as one signed ask per page (FIX 7941),
    /// each under `signer_key` and the same pact claim, with its page and
    /// page count in the signed bytes and one clock for every page. Nothing
    /// refuses a selection for its size.
    pub fn sign_cooperative_deletion_request<S>(
        &self,
        pact_id: &[u8; 32],
        worlds: Vec<EntityId>,
        epoch_cutoff: u64,
        nonce: [u8; 16],
        signer_key: AuthorityKey,
        mut signer: S,
    ) -> Result<Vec<SignedCooperativeDeletionRequest>>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
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
        let requester_vault_id = fold.vault_id.ok_or_else(invalid)?;
        let ts = crate::unix_seconds_now();
        let selection = selection_pages(worlds);
        let pages = u32::try_from(selection.len()).map_err(|_| invalid())?;
        let mut signed = Vec::with_capacity(selection.len());
        for (page, worlds) in (0..pages).zip(selection) {
            let body = CooperativeDeletionRequest {
                pact_id: *pact_id,
                requester_vault_id,
                peer_vault_id: pact.peer_vault_id,
                worlds,
                page,
                pages,
                epoch_cutoff,
                ts,
                nonce: page_nonce(&nonce, page, pages),
            };
            let bytes = encode_cooperative_deletion_request_body(&body)?;
            let transcript = [COOP_DELETION_REQUEST_DOMAIN, &bytes].concat();
            let signature = AuthoritySignature {
                suite: signer_key.suite(),
                public_key: signer_key.clone(),
                signature: signer(&transcript)?,
            };
            if !verify_authority_signature(&signature, &transcript) {
                return Err(invalid());
            }
            signed.push(SignedCooperativeDeletionRequest { body, signature });
        }
        Ok(signed)
    }
}
