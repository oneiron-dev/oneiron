//! An unattended sign-in ([`super::CodeDelivery::Unattended`]): no browser.
//! The command loads the consent page itself, which records the request and
//! files the owner's inbox ask, and polls his answer with the page's token,
//! as the page's script does; the allow's redirect carries the code (row
//! HOOK-HOSTED-HAND-OVER-OAUTH-READ-TIER; the change in lead ruling B, Sat
//! 21 Nov 07:0x).

use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::api::{AUTHORIZE_STATUS_PATH, PAGE_TOKEN_HEADER, PAGE_TOKEN_META};
use crate::commands::oauth_sign_in::MAX_ANSWER_BYTES;

/// How often an unattended sign-in asks the vault for the owner's answer,
/// as the page's script does.
const ANSWER_POLL: Duration = Duration::from_secs(2);

/// How an unattended sign-in ended with no code: the owner's answer, or
/// none within the request's life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::commands::hook) enum SignInEnded {
    /// The owner denied the request in his inbox.
    Denied,
    /// The request lapsed, or the command stopped waiting, before he
    /// answered.
    Lapsed,
}

impl std::fmt::Display for SignInEnded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Denied => "the owner denied the sign-in request; nothing was recorded",
            Self::Lapsed => {
                "the sign-in request lapsed before the owner answered; nothing was recorded"
            }
        })
    }
}

impl std::error::Error for SignInEnded {}

/// The poll's answer: where the request stands, and the redirect an
/// answer that settled it carries.
#[derive(Deserialize)]
struct Polled {
    status: String,
    #[serde(default)]
    redirect: Option<String>,
}

/// The code of the sign-in request `authorize` names, with no browser:
/// loads the consent page, which records the request and files the owner's
/// inbox ask, then polls his answer with the page's token until `deadline`,
/// as the page's script does. An allow's redirect carries the code, checked
/// for this sign-in's `state` and `issuer`; a deny or a lapse ends it
/// ([`SignInEnded`]).
pub(super) async fn polled_code(
    client: &reqwest::Client,
    authorize: &reqwest::Url,
    state: &str,
    issuer: &str,
    deadline: Instant,
) -> anyhow::Result<String> {
    let page = client
        .get(authorize.as_str())
        .send()
        .await
        .map_err(|error| {
            anyhow::anyhow!("could not reach the sign-in page: {}", error.without_url())
        })?;
    if page.status().is_redirection() {
        // A request the vault refuses goes back to the client with `error`.
        let error = page
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|location| location.to_str().ok())
            .and_then(|location| reqwest::Url::parse(location).ok())
            .and_then(|url| query_value(&url, "error"))
            .unwrap_or_default();
        anyhow::bail!(
            "the vault refused the sign-in request ({})",
            printable(&error)
        );
    }
    anyhow::ensure!(
        page.status().is_success(),
        "the sign-in page answered HTTP {}",
        page.status().as_u16()
    );
    let page = bounded_text(page).await?;
    let token = page_token(&page)
        .ok_or_else(|| anyhow::anyhow!("the sign-in page carries no request token"))?;
    let status_url = authorize.join(AUTHORIZE_STATUS_PATH)?;
    loop {
        if Instant::now() >= deadline {
            return Err(SignInEnded::Lapsed.into());
        }
        let answer = client
            .get(status_url.clone())
            .header(PAGE_TOKEN_HEADER, token)
            .send()
            .await
            .map_err(|error| {
                anyhow::anyhow!("could not reach the vault: {}", error.without_url())
            })?;
        let polled: Polled = serde_json::from_str(&bounded_text(answer).await?)
            .map_err(|_| anyhow::anyhow!("the vault answered the poll with no status"))?;
        match polled.status.as_str() {
            "pending" => {
                tokio::time::sleep(
                    ANSWER_POLL.min(deadline.saturating_duration_since(Instant::now())),
                )
                .await;
            }
            "allowed" => {
                let redirect = polled
                    .redirect
                    .ok_or_else(|| anyhow::anyhow!("the vault's allow names no redirect"))?;
                return code_from_redirect(&redirect, state, issuer);
            }
            "denied" => return Err(SignInEnded::Denied.into()),
            "expired" => return Err(SignInEnded::Lapsed.into()),
            other => anyhow::bail!(
                "the vault no longer knows this sign-in request ({})",
                printable(other)
            ),
        }
    }
}

/// The code an allow's redirect `redirect` carries, when it is this
/// sign-in's (`state`) from `issuer`.
fn code_from_redirect(redirect: &str, state: &str, issuer: &str) -> anyhow::Result<String> {
    let url = reqwest::Url::parse(redirect)
        .map_err(|_| anyhow::anyhow!("the vault's allow names no redirect URL"))?;
    anyhow::ensure!(
        query_value(&url, "state").as_deref() == Some(state),
        "the vault's allow is not this sign-in's; nothing was recorded"
    );
    anyhow::ensure!(
        query_value(&url, "iss").is_none_or(|iss| iss == issuer),
        "the sign-in came back from an issuer other than {issuer}; nothing was recorded"
    );
    query_value(&url, "code").ok_or_else(|| anyhow::anyhow!("the vault's allow brought no code"))
}

/// The one value `url`'s query gives `name`, when it gives one.
fn query_value(url: &reqwest::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// The token the consent page `page` carries for its poll: hex digits and
/// one dot, as the vault mints it.
fn page_token(page: &str) -> Option<&str> {
    let marker = format!("<meta name={PAGE_TOKEN_META} content=\"");
    let start = page.find(&marker)? + marker.len();
    let token = &page[start..start + page[start..].find('"')?];
    (!token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'.'))
    .then_some(token)
}

/// `response`'s body as text, read up to [`MAX_ANSWER_BYTES`].
async fn bounded_text(response: reqwest::Response) -> anyhow::Result<String> {
    let body = response.bytes().await.map_err(|error| {
        anyhow::anyhow!("the vault's answer broke off: {}", error.without_url())
    })?;
    anyhow::ensure!(
        body.len() <= MAX_ANSWER_BYTES,
        "the vault's answer is too large"
    );
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// At most 64 printable ASCII characters of `text`, as an error names a
/// vault's word.
fn printable(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_graphic)
        .take(64)
        .collect()
}
