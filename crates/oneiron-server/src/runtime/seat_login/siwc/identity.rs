//! Verify the vendor's ID token, never an OAuth relay or cloud credential.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub(super) struct Identity {
    aud: serde_json::Value,
    azp: Option<String>,
    pub sub: String,
    pub email: Option<String>,
    nonce: Option<String>,
}

pub(super) fn verify(token: &str, client: &str, nonce: &str) -> anyhow::Result<Identity> {
    let identity = verify_token(token, client)?;
    anyhow::ensure!(
        identity.nonce.as_deref() == Some(nonce),
        "SIWC ID token nonce mismatch"
    );
    Ok(identity)
}

pub(super) fn verify_refresh(
    token: &str,
    client: &str,
    subject: &str,
    nonce: &str,
) -> anyhow::Result<Identity> {
    let identity = verify_token(token, client)?;
    anyhow::ensure!(
        identity.sub == subject && identity.nonce.as_deref().is_none_or(|value| value == nonce),
        "SIWC refresh identity or nonce mismatch"
    );
    Ok(identity)
}

fn verify_token(token: &str, client: &str) -> anyhow::Result<Identity> {
    let invalid = || anyhow::anyhow!("SIWC ID token validation failed");
    let header = decode_header(token).map_err(|_| invalid())?;
    anyhow::ensure!(
        header.alg == Algorithm::RS256,
        "unsupported SIWC ID token algorithm"
    );
    let kid = header.kid.as_deref().ok_or_else(invalid)?;
    let keys = |refresh| -> anyhow::Result<jsonwebtoken::jwk::JwkSet> {
        let body = crate::oauth_relay::identity_provider_jwks(super::JWKS_URI, refresh)
            .map_err(|_| invalid())?;
        serde_json::from_str(&body).map_err(|_| invalid())
    };
    let mut jwks = keys(false)?;
    if jwks.find(kid).is_none() {
        jwks = keys(true)?;
    }
    let key = DecodingKey::from_jwk(jwks.find(kid).ok_or_else(invalid)?).map_err(|_| invalid())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 0;
    validation.set_issuer(&[super::ISSUER]);
    validation.set_audience(&[client]);
    validation.set_required_spec_claims(&["iss", "aud", "sub", "exp"]);
    let identity = decode::<Identity>(token, &key, &validation)
        .map_err(|_| invalid())?
        .claims;
    anyhow::ensure!(!identity.sub.is_empty(), "SIWC ID token subject is empty");
    let multiple_audiences = identity.aud.as_array().is_some_and(|aud| aud.len() > 1);
    anyhow::ensure!(
        identity.azp.as_deref().is_none_or(|party| party == client)
            && (!multiple_audiences || identity.azp.as_deref() == Some(client)),
        "SIWC ID token authorized party mismatch"
    );
    Ok(identity)
}
