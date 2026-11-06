//! One explicit local sign-in attempt. The callback is consumed once and
//! never becomes an API credential until its signed identity is verified.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    extract::Query,
    http::{StatusCode, Uri},
    routing::get,
};
use oneiron::dispatch_byoa::{
    SIWC_DYNAMIC_AGENT_CLIENT, SIWC_RESPONSES_BASE_URL, siwc_authorize_url,
};
use serde::Deserialize;
use tokio::sync::oneshot;
use zeroize::{Zeroize as _, Zeroizing};

use super::record::{self, CredentialRecord};

pub(crate) struct LoginOptions {
    pub credential_file: PathBuf,
    pub host_id_file: PathBuf,
    pub callback_uri: String,
    pub agent_name: String,
    pub timeout: std::time::Duration,
}

#[derive(Deserialize)]
struct Callback {
    state: String,
    code: Option<String>,
    client_id: Option<String>,
    error: Option<String>,
}

impl Drop for Callback {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

#[derive(Deserialize)]
struct Tokens {
    access_token: String,
    refresh_token: Option<String>,
    id_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
    earliest_refresh_at: Option<serde_json::Value>,
}

impl Drop for Tokens {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.id_token.zeroize();
    }
}

/// Drop closes every callback connection even when the command is cancelled
/// or a peer keeps an unrelated loopback connection open during shutdown.
struct Listener(tokio::task::JoinHandle<std::io::Result<()>>);

impl Drop for Listener {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Returns only whether the verified grant enables direct plan inference.
/// There is deliberately no token-bearing receipt or public serde type.
pub(crate) async fn login(options: LoginOptions) -> anyhow::Result<bool> {
    tokio::select! {
        result = attempt(options) => result,
        _ = tokio::signal::ctrl_c() => Err(anyhow::anyhow!("SIWC sign-in cancelled")),
    }
}

async fn attempt(options: LoginOptions) -> anyhow::Result<bool> {
    let _record_lock = record::lock(&options.credential_file)?;
    let previous = CredentialRecord::read(&options.credential_file)?;
    let host_id = record::host_id(&options.host_id_file)?;
    let mut redirect = reqwest::Url::parse(&options.callback_uri)
        .map_err(|_| anyhow::anyhow!("invalid SIWC callback URI"))?;
    anyhow::ensure!(
        redirect.scheme() == "http"
            && redirect.host_str() == Some("127.0.0.1")
            && redirect.username().is_empty()
            && redirect.password().is_none()
            && redirect.query().is_none()
            && redirect.fragment().is_none(),
        "SIWC requires an HTTP callback on 127.0.0.1, without userinfo, query or fragment"
    );
    let mut registered_redirect = redirect.clone();
    registered_redirect
        .set_port(None)
        .map_err(|_| anyhow::anyhow!("invalid callback port"))?;
    let registered_redirect = registered_redirect.to_string();
    if let Some(previous) = &previous {
        anyhow::ensure!(
            previous.ext_agent_host_id == host_id && previous.redirect_uri == registered_redirect,
            "SIWC reauthorization must keep the selected registration's host and callback path"
        );
    }
    let port = redirect
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("SIWC callback needs a port"))?;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let port = listener.local_addr()?.port();
    redirect
        .set_port(Some(port))
        .map_err(|_| anyhow::anyhow!("invalid callback port"))?;
    let state = record::random();
    let nonce = record::random();
    let verifier = Zeroizing::new(record::random());
    let client_id = previous
        .as_ref()
        .map_or(SIWC_DYNAMIC_AGENT_CLIENT, |record| &record.client_id);
    let request = super::super::siwc_authorize_request(
        client_id.to_owned(),
        redirect.to_string(),
        &verifier,
        state.clone(),
        nonce.clone(),
        host_id.clone(),
        Some(options.agent_name),
        None,
    )
    .map_err(anyhow::Error::msg)?;
    let authorize = siwc_authorize_url(&request)
        .map_err(|_| anyhow::anyhow!("invalid SIWC authorize request"))?;
    let (callback_tx, callback_rx) = oneshot::channel::<Callback>();
    let callback_tx = Arc::new(Mutex::new(Some(callback_tx)));
    let expected_state = state;
    let expected_path = redirect.path().to_owned();
    let app = Router::new().fallback(get(move |uri: Uri, Query(callback): Query<Callback>| {
        let sender = Arc::clone(&callback_tx);
        let expected = expected_state.clone();
        let path = expected_path.clone();
        async move {
            if uri.path() != path {
                return StatusCode::NOT_FOUND;
            }
            if callback.state != expected {
                return StatusCode::BAD_REQUEST;
            }
            match sender.lock().ok().and_then(|mut sender| sender.take()) {
                Some(sender) => {
                    if sender.send(callback).is_ok() {
                        StatusCode::NO_CONTENT
                    } else {
                        StatusCode::GONE
                    }
                }
                None => StatusCode::GONE,
            }
        }
    }));
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let mut serving = Listener(tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stop_rx.await;
            })
            .await
    }));
    // No token hint is added: this URL contains only public authorization
    // request data. The person opens it; this command opens no browser.
    writeln!(std::io::stdout().lock(), "{authorize}")?;
    let callback = tokio::select! {
        result = callback_rx => result.map_err(|_| anyhow::anyhow!("SIWC callback listener stopped")),
        _ = &mut serving.0 => Err(anyhow::anyhow!("SIWC callback listener stopped")),
    };
    let _ = stop_tx.send(());
    let callback = callback?;
    anyhow::ensure!(
        callback.error.is_none(),
        "SIWC authorization was not granted; start a fresh sign-in"
    );
    let issued = match &previous {
        Some(previous) => {
            anyhow::ensure!(
                callback
                    .client_id
                    .as_ref()
                    .is_none_or(|id| id == &previous.client_id),
                "SIWC callback changed the selected registration's client ID"
            );
            previous.client_id.clone()
        }
        None => callback
            .client_id
            .clone()
            .filter(|id| !id.is_empty() && id != SIWC_DYNAMIC_AGENT_CLIENT)
            .ok_or_else(|| anyhow::anyhow!("SIWC registration returned no issued client ID"))?,
    };
    let code = callback
        .code
        .as_deref()
        .filter(|code| !code.is_empty())
        .ok_or_else(|| anyhow::anyhow!("SIWC callback returned no authorization code"))?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(options.timeout)
        .build()?;
    let response = http
        .post(super::TOKEN_ENDPOINT)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", issued.as_str()),
            ("code", code),
            ("code_verifier", verifier.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("resource", SIWC_RESPONSES_BASE_URL),
        ])
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("SIWC code exchange failed; start a fresh sign-in"))?;
    anyhow::ensure!(
        response.status().is_success(),
        "SIWC code exchange refused; discard this code and start a fresh sign-in"
    );
    let mut tokens: Tokens = response
        .json()
        .await
        .map_err(|_| anyhow::anyhow!("invalid SIWC token response"))?;
    let saved_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    anyhow::ensure!(
        tokens.token_type.eq_ignore_ascii_case("Bearer") && !tokens.access_token.is_empty(),
        "unsupported SIWC token response"
    );
    let expires_at = saved_at
        .checked_add(tokens.expires_in)
        .ok_or_else(|| anyhow::anyhow!("invalid SIWC token expiry"))?;
    let record_path = options.credential_file;
    let record = tokio::task::spawn_blocking(move || {
        let identity = super::identity::verify(&tokens.id_token, &issued, &nonce)?;
        if let Some(previous) = &previous {
            anyhow::ensure!(
                identity.sub == previous.subject,
                "SIWC identity differs from the selected account; keep its original credentials"
            );
        }
        let record = CredentialRecord {
            version: 1,
            issuer: super::ISSUER.to_owned(),
            subject: identity.sub,
            email: identity.email,
            client_id: issued,
            ext_agent_host_id: host_id,
            redirect_uri: registered_redirect,
            nonce,
            session_active: true,
            access_token: std::mem::take(&mut tokens.access_token),
            id_token: std::mem::take(&mut tokens.id_token),
            refresh_token: tokens.refresh_token.take(),
            scopes: tokens.scope.split_whitespace().map(str::to_owned).collect(),
            saved_at,
            expires_at,
            earliest_refresh_at: tokens.earliest_refresh_at.take(),
        };
        Ok::<_, anyhow::Error>(record)
    })
    .await
    .map_err(|_| anyhow::anyhow!("SIWC credential verification stopped"))??;
    record.write(&record_path)?;
    Ok(record.plan_usage_enabled())
}
