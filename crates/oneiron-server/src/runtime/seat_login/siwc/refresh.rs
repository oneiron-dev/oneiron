//! Refresh one already-verified issued registration. Publication stays with
//! the caller holding its protected record lock, never a detached verifier.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::dispatch_byoa::SIWC_RESPONSES_BASE_URL;
use serde::Deserialize;
use zeroize::Zeroize as _;

use super::record::CredentialRecord;

#[derive(Deserialize)]
struct Tokens {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: String,
    expires_in: u64,
    scope: Option<String>,
    earliest_refresh_at: Option<serde_json::Value>,
}

impl Drop for Tokens {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.id_token.zeroize();
    }
}

pub(super) async fn rotate(
    mut record: CredentialRecord,
    timeout: Duration,
) -> anyhow::Result<CredentialRecord> {
    let refresh_token = record
        .refresh_token
        .as_deref()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("local SIWC credentials have no refresh token; sign in again")
        })?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(timeout)
        .build()?;
    let response = http
        .post(super::TOKEN_ENDPOINT)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", record.client_id.as_str()),
            ("refresh_token", refresh_token),
            ("resource", SIWC_RESPONSES_BASE_URL),
        ])
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("SIWC refresh failed; the remote grant may have rotated"))?;
    anyhow::ensure!(
        response.status().is_success(),
        "SIWC refresh refused; sign in again if the grant is no longer valid"
    );
    let mut tokens: Tokens = response
        .json()
        .await
        .map_err(|_| anyhow::anyhow!("invalid SIWC refresh response"))?;
    let saved_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    anyhow::ensure!(
        tokens.token_type.eq_ignore_ascii_case("Bearer")
            && !tokens.access_token.is_empty()
            && tokens
                .refresh_token
                .as_deref()
                .is_none_or(|token| !token.is_empty()),
        "unsupported SIWC refresh response"
    );
    let expires_at = saved_at
        .checked_add(tokens.expires_in)
        .ok_or_else(|| anyhow::anyhow!("invalid SIWC token expiry"))?;
    tokio::task::spawn_blocking(move || {
        if let Some(token) = tokens.id_token.as_mut() {
            let identity = super::identity::verify_refresh(
                token,
                &record.client_id,
                &record.subject,
                &record.nonce,
            )?;
            record.email = identity.email;
            std::mem::swap(&mut record.id_token, token);
        }
        std::mem::swap(&mut record.access_token, &mut tokens.access_token);
        if tokens.refresh_token.is_some() {
            std::mem::swap(&mut record.refresh_token, &mut tokens.refresh_token);
        }
        // OAuth refresh may omit an unchanged scope or refresh token. An
        // explicitly returned empty scope is not the previous grant.
        if let Some(scope) = tokens.scope.as_deref() {
            record.scopes = scope.split_whitespace().map(str::to_owned).collect();
        }
        record.saved_at = saved_at;
        record.expires_at = expires_at;
        record.earliest_refresh_at = tokens.earliest_refresh_at.take();
        Ok(record)
    })
    .await
    .map_err(|_| anyhow::anyhow!("SIWC refresh verification stopped"))?
}
