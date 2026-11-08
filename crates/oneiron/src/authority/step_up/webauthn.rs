//! The WebAuthn pieces a passkey step-up reads (W3C Web Authentication
//! Level 2): the client data the browser signed over, the authenticator
//! data, the credential's public key and its signature. Pure functions over
//! bytes; the ceremony rules and the stored rows live in the parent module.
//!
//! Two COSE algorithms are admitted: ES256 (-7, ECDSA P-256 with SHA-256,
//! a DER signature) and EdDSA (-8, Ed25519). The public key arrives as the
//! SubjectPublicKeyInfo the browser's `getPublicKey()` returns, so no CBOR
//! is parsed here; attestation statements are not judged (the "none"
//! attestation every passkey provider supports).

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// COSE algorithm identifier for ES256.
pub(super) const COSE_ES256: i64 = -7;
/// COSE algorithm identifier for EdDSA over Ed25519.
pub(super) const COSE_EDDSA: i64 = -8;

/// User present.
const FLAG_UP: u8 = 0x01;
/// User verified: the authenticator checked the person (PIN, biometric).
const FLAG_UV: u8 = 0x04;
/// Attested credential data follows the fixed header.
const FLAG_AT: u8 = 0x40;

/// The fixed header of authenticator data: rpIdHash, flags, signCount.
const AUTH_DATA_HEADER_LEN: usize = 37;
/// Longest credential id WebAuthn allows.
pub(super) const MAX_CREDENTIAL_ID_LEN: usize = 1023;

/// SubjectPublicKeyInfo DER prefix of an uncompressed P-256 key
/// (id-ecPublicKey, prime256v1, BIT STRING of 66 bytes).
const SPKI_P256_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// SubjectPublicKeyInfo DER prefix of an Ed25519 key (id-Ed25519, BIT
/// STRING of 33 bytes).
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Decodes base64url, with or without padding.
pub(super) fn from_b64url(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .ok()
}

/// Encodes base64url without padding, as WebAuthn's JSON forms spell bytes.
pub(super) fn to_b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub(super) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The fields of `CollectedClientData` a ceremony checks.
pub(super) struct ClientData {
    pub(super) kind: String,
    pub(super) challenge: Vec<u8>,
    pub(super) origin: String,
    pub(super) cross_origin: bool,
}

/// Parses the client data JSON the browser hashed into the signature.
pub(super) fn client_data(json: &[u8]) -> Option<ClientData> {
    let value: serde_json::Value = serde_json::from_slice(json).ok()?;
    let object = value.as_object()?;
    let kind = object.get("type")?.as_str()?.to_owned();
    let challenge = from_b64url(object.get("challenge")?.as_str()?)?;
    let origin = object.get("origin")?.as_str()?.to_owned();
    let cross_origin = object
        .get("crossOrigin")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Some(ClientData {
        kind,
        challenge,
        origin,
        cross_origin,
    })
}

/// The fixed header of authenticator data, and what follows it.
pub(super) struct AuthData<'a> {
    pub(super) rp_id_hash: [u8; 32],
    pub(super) flags: u8,
    pub(super) sign_count: u32,
    rest: &'a [u8],
}

impl AuthData<'_> {
    /// The person was present and verified by the authenticator.
    pub(super) fn user_verified(&self) -> bool {
        self.flags & FLAG_UP != 0 && self.flags & FLAG_UV != 0
    }

    /// The credential id in the attested credential data a registration
    /// carries: AAGUID (16), id length (2, big-endian), id.
    pub(super) fn attested_credential_id(&self) -> Option<&[u8]> {
        if self.flags & FLAG_AT == 0 {
            return None;
        }
        let len_bytes = self.rest.get(16..18)?;
        let len = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
        self.rest.get(18..18usize.checked_add(len)?)
    }
}

/// Parses authenticator data's fixed header.
pub(super) fn auth_data(bytes: &[u8]) -> Option<AuthData<'_>> {
    if bytes.len() < AUTH_DATA_HEADER_LEN {
        return None;
    }
    let rp_id_hash: [u8; 32] = bytes[..32].try_into().ok()?;
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes(bytes[33..37].try_into().ok()?);
    Some(AuthData {
        rp_id_hash,
        flags,
        sign_count,
        rest: &bytes[AUTH_DATA_HEADER_LEN..],
    })
}

/// The raw public key a SubjectPublicKeyInfo carries for `algorithm`: the
/// 65-byte uncompressed SEC1 point for ES256, the 32-byte key for EdDSA.
/// The key must also decode as a point of its curve.
pub(super) fn spki_public_key(algorithm: i64, spki: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        COSE_ES256 => {
            let point = spki.strip_prefix(&SPKI_P256_PREFIX[..])?;
            if point.len() != 65 || point[0] != 0x04 {
                return None;
            }
            p256::ecdsa::VerifyingKey::from_sec1_bytes(point).ok()?;
            Some(point.to_vec())
        }
        COSE_EDDSA => {
            let key: [u8; 32] = spki
                .strip_prefix(&SPKI_ED25519_PREFIX[..])?
                .try_into()
                .ok()?;
            ed25519_dalek::VerifyingKey::from_bytes(&key).ok()?;
            Some(key.to_vec())
        }
        _ => None,
    }
}

/// Whether `signature` by the credential key `public_key` covers
/// `authenticator_data || SHA-256(client_data_json)`.
pub(super) fn signature_verifies(
    algorithm: i64,
    public_key: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> bool {
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(&sha256(client_data_json));
    match algorithm {
        COSE_ES256 => {
            use p256::ecdsa::signature::Verifier as _;
            let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else {
                return false;
            };
            let Ok(signature) = p256::ecdsa::Signature::from_der(signature) else {
                return false;
            };
            key.verify(&signed, &signature).is_ok()
        }
        COSE_EDDSA => {
            let Ok(key_bytes) = <[u8; 32]>::try_from(public_key) else {
                return false;
            };
            let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) else {
                return false;
            };
            let Ok(signature_bytes) = <[u8; 64]>::try_from(signature) else {
                return false;
            };
            let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
            key.verify_strict(&signed, &signature).is_ok()
        }
        _ => false,
    }
}

/// Whether a ceremony at `origin` may name `rp_id`: a secure origin
/// (`https`, or `http` on a loopback host) whose host is the RP id or a
/// subdomain of it, as the browser itself requires.
pub(super) fn origin_admits_rp_id(origin: &str, rp_id: &str) -> bool {
    if rp_id.is_empty()
        || rp_id.len() > 253
        || rp_id.starts_with('.')
        || rp_id.ends_with('.')
        || !rp_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return false;
    }
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if rest.contains('/') || rest.contains('@') {
        return false;
    }
    let host = match rest.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => rest,
    };
    let host = host.to_ascii_lowercase();
    let host_matches = host == rp_id
        || host
            .strip_suffix(rp_id)
            .is_some_and(|label| label.ends_with('.'));
    match scheme {
        "https" => host_matches,
        "http" => host_matches && matches!(host.as_str(), "localhost" | "127.0.0.1"),
        _ => false,
    }
}
