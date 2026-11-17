//! A browser passkey signs as an owner root (row WEB-PASSKEY-OWNER-KEY; lead
//! ruling CARRIER-HOSTED-WEB-ACTS = C, Engine ruling WAYBACK-E4 shape (b)).
//!
//! A passkey's ES256 key is an ordinary P-256 authority key, and its
//! signature is its WebAuthn assertion: the authenticator data and SHA-256
//! of the client data JSON, signed, with the client data naming SHA-256 of
//! the authority transcript, after the format's own domain, as its
//! challenge. The entry gate
//! (`validate_shape` then `verify_entry_signatures`, as the fold runs them)
//! takes that assertion in its envelope where it takes 64 raw bytes r || s,
//! and refuses an assertion that is a registration, names another
//! transcript or a challenge without the domain, comes from a cross-origin
//! frame, repeats a client data field, lacks user verification, carries a
//! high S or a trailing byte, or rides an Ed25519 key.
//!
//! The envelope is built here by hand, byte for byte as the wire names it:
//! format byte 1, the authenticator data and the client data JSON each after
//! its two-byte big-endian length, then r || s.
//!
//! `cargo test --locked -p oneiron-authority --test passkey_owner_signature`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use oneiron_authority::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    AuthoritySignatureSuite, authority_transcript, verify_authority_signature,
    verify_entry_signatures,
};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest as _, Sha256};

/// The domain the challenge of a passkey's authority assertion names.
const CHALLENGE_DOMAIN: &[u8] = b"oneiron/webauthn-authority-assertion/v1\0";
/// User present and user verified.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;
/// User present alone.
const FLAGS_PRESENT_ONLY: u8 = 0x01;
/// The order of the P-256 group, big-endian.
const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// The passkey a platform authenticator holds, as a software key.
fn passkey() -> P256SigningKey {
    P256SigningKey::from_slice(&[0x5A; 32]).expect("a P-256 scalar")
}

/// The passkey's public key as the roster names it: compressed SEC1.
fn passkey_key() -> AuthorityKey {
    AuthorityKey::P256(
        passkey()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    )
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let sextets = [
            b[0] >> 2,
            ((b[0] & 0x03) << 4) | (b[1] >> 4),
            ((b[1] & 0x0f) << 2) | (b[2] >> 6),
            b[2] & 0x3f,
        ];
        for sextet in &sextets[..=chunk.len()] {
            out.push(char::from(ALPHABET[usize::from(*sextet)]));
        }
    }
    out
}

/// Authenticator data: the RP id hash, `flags`, a zero sign count (a synced
/// passkey counts nothing).
fn authenticator_data(flags: u8) -> Vec<u8> {
    let mut data = Sha256::digest(b"oneiron.test").to_vec();
    data.push(flags);
    data.extend_from_slice(&[0; 4]);
    data
}

/// The challenge a passkey's assertion names for `transcript`.
fn challenge_of(transcript: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_DOMAIN);
    hasher.update(transcript);
    hasher.finalize().to_vec()
}

/// The client data JSON a browser writes for a ceremony of `kind` over
/// `challenge`, with `tail` as its last members.
fn client_data_with(kind: &str, challenge: &[u8], tail: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"https://oneiron.test"{tail}}}"#,
        base64url(challenge)
    )
    .into_bytes()
}

/// The client data JSON a browser writes for a top-level ceremony of
/// `kind` over `challenge`.
fn client_data(kind: &str, challenge: &[u8]) -> Vec<u8> {
    client_data_with(kind, challenge, r#","crossOrigin":false"#)
}

/// The low-S r || s signature of the passkey over the authenticator data and
/// SHA-256 of the client data.
fn assertion_signature(authenticator_data: &[u8], client_data: &[u8]) -> [u8; 64] {
    let mut signed = authenticator_data.to_vec();
    signed.extend_from_slice(&Sha256::digest(client_data));
    let signature: P256Signature = passkey().sign(&signed);
    let signature = signature.normalize_s().unwrap_or(signature);
    let bytes = signature.to_bytes();
    bytes[..].try_into().expect("64 bytes")
}

/// The envelope, byte for byte.
fn envelope(authenticator_data: &[u8], client_data: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(
        &u16::try_from(authenticator_data.len())
            .unwrap()
            .to_be_bytes(),
    );
    out.extend_from_slice(authenticator_data);
    out.extend_from_slice(&u16::try_from(client_data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(client_data);
    out.extend_from_slice(signature);
    out
}

/// The passkey's assertion over `transcript`, as a browser's
/// `navigator.credentials.get` returns it with the transcript's challenge,
/// in its envelope.
fn passkey_assertion(transcript: &[u8], kind: &str, flags: u8) -> Vec<u8> {
    signed_envelope(&client_data(kind, &challenge_of(transcript)), flags)
}

/// The envelope of an assertion whose client data is `client`.
fn signed_envelope(client: &[u8], flags: u8) -> Vec<u8> {
    let data = authenticator_data(flags);
    envelope(&data, client, &assertion_signature(&data, client))
}

/// An entry the passkey signs: the revoke of a device key, in some vault.
/// Only the signature gate is read here, not the fold.
fn revoke_signed_by(signature: Vec<u8>) -> AuthorityLogEntry {
    let revoked = Ed25519SigningKey::from_bytes(&[0x33; 32])
        .verifying_key()
        .to_bytes();
    AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some([0x11; 32]),
        seq: 1,
        parent_hashes: vec![[0x22; 32]],
        op: AuthorityOp::RevokeDevice {
            revoked_key: AuthorityKey::Ed25519(revoked),
        },
        signer: AuthoritySignature {
            suite: AuthoritySignatureSuite::P256,
            public_key: passkey_key(),
            signature,
        },
        cosigns: Vec::new(),
        ts: 0,
    }
}

/// The transcript of the entry, which names no signature bytes.
fn transcript() -> Vec<u8> {
    authority_transcript(&revoke_signed_by(vec![0; 64])).expect("transcript")
}

/// Whether the entry gate takes `entry`.
fn gate_admits(entry: &AuthorityLogEntry) -> bool {
    entry.validate_shape().is_ok() && verify_entry_signatures(entry).is_ok()
}

/// `n - s`: the high-S twin of a low S, which verifies the same bytes.
fn high_s(signature: &[u8; 64]) -> [u8; 64] {
    let mut out = *signature;
    let mut borrow = 0i16;
    for (digit, order) in out[32..].iter_mut().rev().zip(P256_ORDER.iter().rev()) {
        let value = i16::from(*order) - i16::from(*digit) - borrow;
        borrow = i16::from(value < 0);
        *digit = u8::try_from(value.rem_euclid(256)).unwrap();
    }
    out
}

#[test]
fn a_passkey_assertion_over_the_transcript_is_its_p256_roster_keys_signature() {
    let transcript = transcript();
    let entry = revoke_signed_by(passkey_assertion(
        &transcript,
        "webauthn.get",
        FLAGS_PRESENT_VERIFIED,
    ));
    assert_eq!(
        authority_transcript(&entry).expect("transcript"),
        transcript,
        "guard: the transcript names no signature bytes"
    );
    assert!(
        entry.signer.validate().is_ok(),
        "the envelope is a valid P-256 signature form"
    );
    assert!(
        verify_authority_signature(&entry.signer, &transcript),
        "the passkey's assertion verifies over the transcript"
    );
    assert!(
        gate_admits(&entry),
        "the entry gate the fold runs takes a passkey-signed entry"
    );
}

#[test]
fn a_raw_p256_signature_still_verifies_beside_the_passkey_form() {
    let transcript = transcript();
    let signature: P256Signature = passkey().sign(&transcript);
    let signature = signature.normalize_s().unwrap_or(signature);
    let entry = revoke_signed_by(signature.to_bytes().to_vec());
    assert!(
        gate_admits(&entry),
        "a Secure Enclave key's 64 raw bytes over the transcript stay a signature"
    );
}

#[test]
fn a_passkey_assertion_that_is_not_over_this_transcript_is_refused() {
    let transcript = transcript();
    let registration = revoke_signed_by(passkey_assertion(
        &transcript,
        "webauthn.create",
        FLAGS_PRESENT_VERIFIED,
    ));
    assert!(
        !gate_admits(&registration),
        "a registration's client data signs no act"
    );
    let mut other = transcript.clone();
    other.push(0);
    let elsewhere = revoke_signed_by(passkey_assertion(
        &other,
        "webauthn.get",
        FLAGS_PRESENT_VERIFIED,
    ));
    assert!(
        !gate_admits(&elsewhere),
        "an assertion whose challenge names another transcript signs nothing here"
    );
}

#[test]
fn a_passkey_assertion_without_user_verification_is_refused() {
    let entry = revoke_signed_by(passkey_assertion(
        &transcript(),
        "webauthn.get",
        FLAGS_PRESENT_ONLY,
    ));
    assert!(
        !gate_admits(&entry),
        "an owner act asks the authenticator to verify the person, not only to see them"
    );
}

#[test]
fn a_passkey_envelope_has_one_encoding() {
    let transcript = transcript();
    let data = authenticator_data(FLAGS_PRESENT_VERIFIED);
    let client = client_data("webauthn.get", &challenge_of(&transcript));
    let signature = assertion_signature(&data, &client);
    assert!(
        gate_admits(&revoke_signed_by(envelope(&data, &client, &signature))),
        "guard: the low-S envelope verifies"
    );
    assert!(
        !gate_admits(&revoke_signed_by(envelope(
            &data,
            &client,
            &high_s(&signature)
        ))),
        "the high-S twin of the same signature is refused"
    );
    let mut trailing = envelope(&data, &client, &signature);
    trailing.push(0);
    assert!(
        !gate_admits(&revoke_signed_by(trailing)),
        "a byte after the signature is refused"
    );
    let mut other_format = envelope(&data, &client, &signature);
    other_format[0] = 2;
    assert!(
        !gate_admits(&revoke_signed_by(other_format)),
        "an unknown format byte is refused"
    );
}

#[test]
fn an_ed25519_key_never_signs_in_the_passkey_form() {
    let transcript = transcript();
    let mut entry = revoke_signed_by(passkey_assertion(
        &transcript,
        "webauthn.get",
        FLAGS_PRESENT_VERIFIED,
    ));
    entry.signer = AuthoritySignature {
        suite: AuthoritySignatureSuite::Ed25519,
        public_key: AuthorityKey::Ed25519(
            Ed25519SigningKey::from_bytes(&[0x44; 32])
                .verifying_key()
                .to_bytes(),
        ),
        signature: entry.signer.signature,
    };
    assert!(
        !gate_admits(&entry),
        "the envelope is a P-256 signature form alone"
    );
}

#[test]
fn a_passkey_assertion_names_this_formats_own_challenge() {
    let transcript = transcript();
    let undomained = signed_envelope(
        &client_data("webauthn.get", &Sha256::digest(&transcript)),
        FLAGS_PRESENT_VERIFIED,
    );
    assert!(
        !gate_admits(&revoke_signed_by(undomained)),
        "a challenge of the bare transcript digest is another ceremony's, not this format's"
    );
}

#[test]
fn a_passkey_assertion_from_a_cross_origin_frame_is_refused() {
    let transcript = transcript();
    let challenge = challenge_of(&transcript);
    let framed = signed_envelope(
        &client_data_with("webauthn.get", &challenge, r#","crossOrigin":true"#),
        FLAGS_PRESENT_VERIFIED,
    );
    assert!(
        !gate_admits(&revoke_signed_by(framed)),
        "an assertion made inside a cross-origin frame signs no act"
    );
    let topped = signed_envelope(
        &client_data_with(
            "webauthn.get",
            &challenge,
            r#","crossOrigin":false,"topOrigin":"https://elsewhere.test""#,
        ),
        FLAGS_PRESENT_VERIFIED,
    );
    assert!(
        !gate_admits(&revoke_signed_by(topped)),
        "an assertion that names a top origin was made in a frame"
    );
    let plain = signed_envelope(
        &client_data_with("webauthn.get", &challenge, ""),
        FLAGS_PRESENT_VERIFIED,
    );
    assert!(
        gate_admits(&revoke_signed_by(plain)),
        "guard: a top-level assertion with no crossOrigin member verifies"
    );
}

#[test]
fn client_data_that_repeats_a_field_is_refused() {
    let transcript = transcript();
    let challenge = challenge_of(&transcript);
    let repeated = signed_envelope(
        &client_data_with(
            "webauthn.get",
            &challenge,
            r#","origin":"https://elsewhere.test""#,
        ),
        FLAGS_PRESENT_VERIFIED,
    );
    assert!(
        !gate_admits(&revoke_signed_by(repeated)),
        "two origins in one client data are no origin"
    );
}
