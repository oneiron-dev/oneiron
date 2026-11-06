//! APNs auth sessions: one finite configured app, topic and environment per pool.

use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use zeroize::Zeroizing;

use super::{ApnsAppConfig, ServedChannelSink};
use crate::{Error, Result};

/// Apple requires a token refresh between 20 and 60 minutes, and rejects
/// more frequent token changes on one HTTP/2 connection.
const TOKEN_REFRESH_SECS: u64 = 20 * 60;

pub(super) struct AuthSession {
    key_fingerprint: blake3::Hash,
    issued_at: u64,
    client: reqwest::blocking::Client,
}

/// The live T0 door calls this even when a session exists. Key rotation opens
/// a fresh pool, so old authentication is never reused with another key.
pub(super) fn credentials(
    cache: &Mutex<Option<AuthSession>>,
    config: &ApnsAppConfig,
    key: &[u8],
    now: u64,
) -> Result<(reqwest::blocking::Client, Zeroizing<String>)> {
    let fingerprint = blake3::hash(key);
    let mut cache = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if cache
        .as_ref()
        .is_none_or(|session| session.key_fingerprint != fingerprint || now < session.issued_at)
    {
        let client = ServedChannelSink::client()?;
        *cache = Some(AuthSession {
            key_fingerprint: fingerprint,
            issued_at: now,
            client,
        });
    }
    let session = cache.as_mut().expect("APNs session was initialized");
    if now - session.issued_at >= TOKEN_REFRESH_SECS {
        session.issued_at = now;
    }
    // RFC6979 signing is deterministic: the same key and issued-at produce
    // the same JWT. Keep only its public timestamp, never a bearer credential
    // outside the current T0 callback.
    let token = provider_token(config, key, session.issued_at)?;
    Ok((session.client.clone(), token))
}

fn provider_token(config: &ApnsAppConfig, key: &[u8], now: u64) -> Result<Zeroizing<String>> {
    let invalid = || Error::InvalidClaimBody("APNs signing key is not P-256 PKCS8 PEM");
    let pem = std::str::from_utf8(key).map_err(|_| invalid())?;
    let signer = SigningKey::from_pkcs8_pem(pem).map_err(|_| invalid())?;
    let header = serde_json::to_vec(&serde_json::json!({"alg": "ES256", "kid": config.key_id}))
        .map_err(|_| Error::InvalidClaimBody("APNs JWT encoding failed"))?;
    let claims = serde_json::to_vec(&serde_json::json!({"iss": config.team_id, "iat": now}))
        .map_err(|_| Error::InvalidClaimBody("APNs JWT encoding failed"))?;
    let signed = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let signature: Signature = signer
        .try_sign(signed.as_bytes())
        .map_err(|_| Error::InvalidClaimBody("APNs JWT signing failed"))?;
    Ok(Zeroizing::new(format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )))
}
