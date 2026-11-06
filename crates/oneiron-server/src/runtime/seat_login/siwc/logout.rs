//! Explicit local credential clearing and renewable-session revocation.
//! The issued account registration stays available for the next sign-in.

use std::path::PathBuf;
use std::time::Duration;

use super::record::{self, CredentialRecord};

pub(crate) struct RevokeOptions {
    pub credential_file: PathBuf,
    pub retries: u32,
    pub backoff: Duration,
    pub timeout: Duration,
}

pub(crate) enum SignOut {
    NoLocalRecord,
    LocalOnly,
    Revoked,
    RevocationUnconfirmed,
}

pub(crate) fn clear(path: PathBuf) -> anyhow::Result<SignOut> {
    let path = std::path::absolute(path)?;
    let _lock = record::lock(&path)?;
    let Some(mut record) = CredentialRecord::read(&path)? else {
        return Ok(SignOut::NoLocalRecord);
    };
    record.clear_tokens();
    record.write(&path)?;
    Ok(SignOut::LocalOnly)
}

pub(crate) async fn revoke(options: RevokeOptions) -> anyhow::Result<SignOut> {
    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => Err(anyhow::anyhow!(
            "SIWC revocation cancelled; remote state is unconfirmed; rerun revoke or clear local tokens"
        )),
        result = attempt(options) => result,
    }
}

async fn attempt(mut options: RevokeOptions) -> anyhow::Result<SignOut> {
    options.credential_file = std::path::absolute(&options.credential_file)?;
    let _lock = record::lock(&options.credential_file)?;
    let Some(mut record) = CredentialRecord::read(&options.credential_file)? else {
        return Ok(SignOut::NoLocalRecord);
    };
    // Stop fresh opens and every physical release before contacting the
    // vendor. Retain protected tokens until the revocation attempt ends.
    record.session_active = false;
    record.write(&options.credential_file)?;
    let confirmed = match record
        .refresh_token
        .as_deref()
        .filter(|token| !token.is_empty())
    {
        Some(token) => end_session(&record.client_id, token, &options).await,
        None => false,
    };
    let outcome = if confirmed {
        SignOut::Revoked
    } else {
        SignOut::RevocationUnconfirmed
    };
    // Never overwrite a different registration or restore a removed file
    // from the pre-request snapshot. A cancelled task cannot publish later.
    let Some(current) = CredentialRecord::read(&options.credential_file)? else {
        return Ok(outcome);
    };
    anyhow::ensure!(
        current == record,
        "SIWC record changed during revocation; kept current local credentials (remote revocation confirmed: {confirmed})"
    );
    record.clear_tokens();
    record.write(&options.credential_file)?;
    Ok(outcome)
}

async fn end_session(client_id: &str, token: &str, options: &RevokeOptions) -> bool {
    let Ok(http) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(options.timeout)
        .build()
    else {
        return false;
    };
    for attempt in 0..=options.retries {
        let retry = match http
            .post(super::REVOCATION_ENDPOINT)
            .form(&[
                ("token", token),
                ("token_type_hint", "refresh_token"),
                ("client_id", client_id),
            ])
            .send()
            .await
        {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return true,
            Ok(response) => response.status().is_server_error(),
            Err(_) => true,
        };
        if !retry || attempt == options.retries {
            break;
        }
        tokio::time::sleep(options.backoff.saturating_mul(attempt.saturating_add(1))).await;
    }
    false
}
