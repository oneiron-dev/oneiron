//! A passkey's signature on an authority transcript (row
//! WEB-PASSKEY-OWNER-KEY; Engine ruling WAYBACK-E4, shape (b)).
//!
//! A passkey never signs the bytes it is handed. A WebAuthn assertion (W3C
//! Web Authentication Level 2, section 7.2) signs the authenticator data
//! followed by SHA-256 of the client data JSON, and the client data names
//! the challenge. So a passkey's ES256 key is an ordinary P-256 authority
//! key, and its signature takes a second form: in place of 64 raw bytes
//! r || s over the transcript, the assertion whose challenge is
//! [`webauthn_challenge`] of the transcript (SHA-256 after this format's own
//! domain), in this module's envelope. The
//! fold verifies it where it verifies every authority signature, so the
//! key never leaves the authenticator and each signature asks the person
//! at the authenticator.
//!
//! The envelope: one format byte ([`WEBAUTHN_ASSERTION_FORMAT`]), the
//! authenticator data and the client data JSON, each after its two-byte
//! big-endian length, then the signature as 64 bytes r || s with a low S.
//! Every length is exact, so one assertion has one envelope. The check
//! reads the client data's `type` (`webauthn.get`), `challenge`, `origin`,
//! `crossOrigin` and `topOrigin` (each at most once, each of its JSON type),
//! the authenticator's user present and user verified flags, and the
//! signature. Where an assertion was made, its [`WebAuthnContext`] (the RP id
//! hash and the origin), is the fold's to pin: a passkey signs only in the
//! context of its own enrollment's assertion, so a sibling origin under the
//! same RP id gets no owner signature (Sol xhigh F2).

use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::error::Result;

use super::invalid_authority;

/// The first byte of a passkey assertion envelope.
pub const WEBAUTHN_ASSERTION_FORMAT: u8 = 1;
/// The fixed header of authenticator data: RP id hash, flags, sign count.
pub const WEBAUTHN_AUTHENTICATOR_DATA_MIN_BYTES: usize = 37;
/// The longest authenticator data an envelope carries.
pub const MAX_WEBAUTHN_AUTHENTICATOR_DATA_BYTES: usize = 512;
/// The longest client data JSON an envelope carries.
pub const MAX_WEBAUTHN_CLIENT_DATA_JSON_BYTES: usize = 1024;
/// A P-256 signature as fixed-width r || s.
const P256_SIGNATURE_BYTES: usize = 64;
/// Where the flag byte sits in authenticator data: after the 32-byte RP id
/// hash.
const FLAGS_OFFSET: usize = 32;
/// The authenticator's flag byte: the user was present.
const FLAG_USER_PRESENT: u8 = 0x01;
/// The authenticator's flag byte: the authenticator verified the user (its
/// PIN, biometric or platform unlock).
const FLAG_USER_VERIFIED: u8 = 0x04;
/// The client data type of an assertion; a registration's is
/// `webauthn.create`.
const WEBAUTHN_GET: &str = "webauthn.get";
/// The domain of the challenge a passkey's assertion names: this format's
/// own, so no other ceremony's digest of the same bytes is taken for it.
pub const WEBAUTHN_AUTHORITY_CHALLENGE_DOMAIN: &[u8] = b"oneiron/webauthn-authority-assertion/v1\0";

/// The challenge a passkey signs for `message` (an authority transcript or a
/// possession transcript, each with its own domain): SHA-256 of
/// [`WEBAUTHN_AUTHORITY_CHALLENGE_DOMAIN`] and `message`, hashed once.
#[must_use]
pub fn webauthn_challenge(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(WEBAUTHN_AUTHORITY_CHALLENGE_DOMAIN);
    hasher.update(message);
    hasher.finalize().into()
}

/// Where a passkey's assertion was made: the RP id hash its authenticator
/// data names and the origin its client data names.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct WebAuthnContext {
    /// SHA-256 of the relying party id.
    pub rp_id_hash: [u8; 32],
    /// The web origin of the ceremony, as the browser wrote it.
    pub origin: String,
}

/// One passkey assertion as its envelope carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebAuthnAssertion<'a> {
    /// The authenticator data, as the authenticator returned it.
    pub authenticator_data: &'a [u8],
    /// The client data JSON, as the browser serialized it.
    pub client_data_json: &'a [u8],
    /// The signature as r || s, S low.
    pub signature: &'a [u8; P256_SIGNATURE_BYTES],
}

/// The envelope of an assertion as the browser returns it: its
/// authenticator data, its client data JSON and its DER signature. A high
/// S is replaced by its low twin, which verifies the same bytes, so one
/// assertion has one envelope.
///
/// # Errors
/// A part over its bound, authenticator data shorter than its header, or a
/// signature that is not a DER P-256 signature.
pub fn webauthn_assertion_envelope(
    authenticator_data: &[u8],
    client_data_json: &[u8],
    der_signature: &[u8],
) -> Result<Vec<u8>> {
    let signature = P256Signature::from_der(der_signature).map_err(|_| invalid_authority())?;
    let signature = signature.normalize_s().unwrap_or(signature);
    let bytes = signature.to_bytes();
    let raw: [u8; P256_SIGNATURE_BYTES] = bytes[..].try_into().map_err(|_| invalid_authority())?;
    encode_webauthn_assertion(&WebAuthnAssertion {
        authenticator_data,
        client_data_json,
        signature: &raw,
    })
}

/// The envelope bytes of `assertion`.
///
/// # Errors
/// A part over its bound, or authenticator data shorter than its header.
pub fn encode_webauthn_assertion(assertion: &WebAuthnAssertion<'_>) -> Result<Vec<u8>> {
    let auth_len = assertion.authenticator_data.len();
    let client_len = assertion.client_data_json.len();
    if !(WEBAUTHN_AUTHENTICATOR_DATA_MIN_BYTES..=MAX_WEBAUTHN_AUTHENTICATOR_DATA_BYTES)
        .contains(&auth_len)
        || client_len == 0
        || client_len > MAX_WEBAUTHN_CLIENT_DATA_JSON_BYTES
    {
        return Err(invalid_authority());
    }
    let auth_prefix = u16::try_from(auth_len).map_err(|_| invalid_authority())?;
    let client_prefix = u16::try_from(client_len).map_err(|_| invalid_authority())?;
    let mut out = Vec::with_capacity(5 + auth_len + client_len + P256_SIGNATURE_BYTES);
    out.push(WEBAUTHN_ASSERTION_FORMAT);
    out.extend_from_slice(&auth_prefix.to_be_bytes());
    out.extend_from_slice(assertion.authenticator_data);
    out.extend_from_slice(&client_prefix.to_be_bytes());
    out.extend_from_slice(assertion.client_data_json);
    out.extend_from_slice(assertion.signature);
    Ok(out)
}

/// The assertion an envelope carries, when every length is exact and in
/// bounds; `None` for anything else, a raw 64-byte signature included.
#[must_use]
pub fn decode_webauthn_assertion(envelope: &[u8]) -> Option<WebAuthnAssertion<'_>> {
    let (&format, rest) = envelope.split_first()?;
    if format != WEBAUTHN_ASSERTION_FORMAT {
        return None;
    }
    let (authenticator_data, rest) = length_prefixed(rest)?;
    let (client_data_json, rest) = length_prefixed(rest)?;
    let signature: &[u8; P256_SIGNATURE_BYTES] = rest.try_into().ok()?;
    let assertion = WebAuthnAssertion {
        authenticator_data,
        client_data_json,
        signature,
    };
    // Only what the encoder writes decodes: no part out of its bounds.
    (encode_webauthn_assertion(&assertion).ok()?.as_slice() == envelope).then_some(assertion)
}

/// One part after its two-byte big-endian length, and what follows it.
fn length_prefixed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (prefix, rest) = bytes.split_first_chunk::<2>()?;
    let len = usize::from(u16::from_be_bytes(*prefix));
    (rest.len() >= len).then(|| rest.split_at(len))
}

/// The fields of the client data the check reads. Any other field is
/// ignored; a repeated field or one of another JSON type refuses the parse.
#[derive(serde::Deserialize)]
struct ClientData<'a> {
    #[serde(rename = "type", borrow)]
    kind: &'a str,
    #[serde(borrow)]
    challenge: &'a str,
    #[serde(borrow)]
    origin: &'a str,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
    #[serde(rename = "topOrigin", borrow, default)]
    top_origin: Option<&'a str>,
}

/// The client data of a well-formed envelope, when it parses as an
/// assertion made by a top-level page (no `crossOrigin` true, no
/// `topOrigin`).
fn top_level_client_data<'a>(assertion: &WebAuthnAssertion<'a>) -> Option<ClientData<'a>> {
    let client = serde_json::from_slice::<ClientData<'a>>(assertion.client_data_json).ok()?;
    (client.kind == WEBAUTHN_GET
        && client.cross_origin != Some(true)
        && client.top_origin.is_none())
    .then_some(client)
}

/// The context `envelope`'s assertion names ([`WebAuthnContext`]), when the
/// envelope is well formed and its client data is a top-level assertion's;
/// its signature is not checked here.
#[must_use]
pub fn webauthn_assertion_context(envelope: &[u8]) -> Option<WebAuthnContext> {
    let assertion = decode_webauthn_assertion(envelope)?;
    let client = top_level_client_data(&assertion)?;
    Some(WebAuthnContext {
        rp_id_hash: assertion.authenticator_data[..FLAGS_OFFSET]
            .try_into()
            .ok()?,
        origin: client.origin.to_owned(),
    })
}

/// Whether `envelope` is a passkey assertion by `key` over `message`: an
/// assertion (`webauthn.get`) by a top-level page whose challenge is
/// [`webauthn_challenge`] of `message`, made with the user present and
/// verified, whose low-S signature verifies over the authenticator data and
/// SHA-256 of the client data JSON. Where it was made is not judged here:
/// the fold pins [`webauthn_assertion_context`] per key.
#[must_use]
pub fn webauthn_assertion_verifies(
    key: &P256VerifyingKey,
    envelope: &[u8],
    message: &[u8],
) -> bool {
    let Some(assertion) = decode_webauthn_assertion(envelope) else {
        return false;
    };
    let flags = assertion.authenticator_data[FLAGS_OFFSET];
    if flags & FLAG_USER_PRESENT == 0 || flags & FLAG_USER_VERIFIED == 0 {
        return false;
    }
    let Some(client) = top_level_client_data(&assertion) else {
        return false;
    };
    if client.challenge != base64url(&webauthn_challenge(message)) {
        return false;
    }
    let Ok(signature) = P256Signature::from_slice(assertion.signature) else {
        return false;
    };
    if signature.normalize_s().is_some() {
        return false;
    }
    let mut signed = Vec::with_capacity(assertion.authenticator_data.len() + 32);
    signed.extend_from_slice(assertion.authenticator_data);
    signed.extend_from_slice(&Sha256::digest(assertion.client_data_json));
    key.verify(&signed, &signature).is_ok()
}

/// Base64url without padding, as WebAuthn's client data spells the
/// challenge (RFC 4648 section 5).
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let sextets = [
            b0 >> 2,
            ((b0 & 0x03) << 4) | (b1 >> 4),
            ((b1 & 0x0f) << 2) | (b2 >> 6),
            b2 & 0x3f,
        ];
        for sextet in &sextets[..=chunk.len()] {
            out.push(char::from(ALPHABET[usize::from(*sextet)]));
        }
    }
    out
}
