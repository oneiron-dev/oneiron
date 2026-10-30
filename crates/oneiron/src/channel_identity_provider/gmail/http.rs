//! Production Gmail send wire: one POST to `users.messages.send` (OF-374),
//! and the `Authorization` value a stored Gmail grant presents, which the
//! host's read wire uses as well.
//!
//! The Bearer header exists only inside the send authority's door callback,
//! marked sensitive, and is dropped with it. Redirects are off and the client
//! is HTTPS-only, so the token can only reach Google's fixed API host.

use std::io::Read;
use std::time::Duration;

use base64::Engine as _;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use super::send::{GmailSendAuthority, GmailSendWire, GmailSendWireError, GmailSentMessage};
use crate::error::{Error, Result};

const GMAIL_SEND_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send";
const GMAIL_MESSAGES_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me/messages";
/// Google's OAuth token endpoint: where a stored refresh token is exchanged
/// for the access token a request presents.
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const MAX_RESPONSE_BYTES: u64 = 1_048_576;

/// Host-side Gmail REST send wire over `reqwest::blocking`.
///
/// Call it from a blocking context (it owns an internal runtime). The token
/// the custody door injects is read by [`gmail_authorization`].
pub struct HttpGmailSendWire {
    client: reqwest::blocking::Client,
}

impl HttpGmailSendWire {
    /// Builds the wire: HTTPS only, no redirects, a 30 s timeout.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the TLS client cannot be built.
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| Error::InvalidConfig("gmail HTTP client setup failed".to_owned()))?;
        Ok(Self { client })
    }

    fn post_send(
        &self,
        auth: &HeaderValue,
        body: &Value,
    ) -> std::result::Result<GmailSentMessage, GmailSendWireError> {
        let response = self
            .client
            .post(GMAIL_SEND_URL)
            .header(AUTHORIZATION, auth.clone())
            .json(body)
            .send()
            .map_err(|error| {
                if error.is_connect() || error.is_builder() {
                    GmailSendWireError::NotSent("gmail_send_connect_failed".to_owned())
                } else {
                    GmailSendWireError::Uncertain("gmail_send_transport_uncertain".to_owned())
                }
            })?;
        let status = response.status();
        // A 4xx is Google refusing the request (bad message, auth, scope,
        // quota): nothing was sent. A 5xx or anything else may have been.
        if status.is_client_error() {
            return Err(GmailSendWireError::NotSent(format!(
                "gmail_send_rejected_{}",
                status.as_u16()
            )));
        }
        if !status.is_success() {
            return Err(GmailSendWireError::Uncertain(format!(
                "gmail_send_status_{}",
                status.as_u16()
            )));
        }
        let value = read_bounded_json(response).ok_or_else(|| {
            GmailSendWireError::Uncertain("gmail_send_response_unreadable".into())
        })?;
        let id = value.get("id").and_then(Value::as_str);
        let thread_id = value.get("threadId").and_then(Value::as_str);
        let (Some(id), Some(thread_id)) = (id, thread_id) else {
            return Err(GmailSendWireError::Uncertain(
                "gmail_send_response_missing_ids".to_owned(),
            ));
        };
        Ok(GmailSentMessage {
            gmail_message_id: id.to_owned(),
            gmail_thread_id: thread_id.to_owned(),
            rfc_message_id: None,
        })
    }

    /// Reads back the RFC `Message-ID` Gmail kept on the sent message. Best
    /// effort: the send already happened, so a failure keeps the plan's id.
    fn read_rfc_message_id(&self, auth: &HeaderValue, gmail_message_id: &str) -> Option<String> {
        if gmail_message_id.is_empty()
            || !gmail_message_id.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return None;
        }
        let response = self
            .client
            .get(format!("{GMAIL_MESSAGES_URL}/{gmail_message_id}"))
            .query(&[("format", "metadata"), ("metadataHeaders", "Message-ID")])
            .header(AUTHORIZATION, auth.clone())
            .send()
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let value = read_bounded_json(response)?;
        value
            .pointer("/payload/headers")?
            .as_array()?
            .iter()
            .find(|header| {
                header
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.eq_ignore_ascii_case("Message-ID"))
            })?
            .get("value")?
            .as_str()
            .map(str::to_owned)
    }
}

impl GmailSendWire for HttpGmailSendWire {
    fn send_message(
        &self,
        authority: &GmailSendAuthority<'_>,
        raw: &[u8],
        gmail_thread_id: Option<&str>,
    ) -> std::result::Result<GmailSentMessage, GmailSendWireError> {
        let mut body = json!({
            "raw": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
        });
        if let Some(thread_id) = gmail_thread_id {
            body["threadId"] = Value::from(thread_id);
        }
        let mut outcome = None;
        let door = authority.with_token_at_door(&mut |token: &[u8]| {
            let auth = gmail_authorization(&self.client, token)?;
            let mut sent = self.post_send(&auth, &body);
            if let Ok(message) = sent.as_mut() {
                message.rfc_message_id = self.read_rfc_message_id(&auth, &message.gmail_message_id);
            }
            outcome = Some(sent);
            Ok(())
        });
        // The provider's answer outranks a later door error: once the POST
        // ran, what Google said is the delivery fact.
        match (outcome, door) {
            (Some(sent), _) => sent,
            (None, _) => Err(GmailSendWireError::NotSent(
                "gmail_send_credential_door_refused".to_owned(),
            )),
        }
    }
}

/// The sensitive `Authorization: Bearer` value a stored Gmail grant presents.
///
/// A grant that carries a refresh token and the OAuth client it was issued to
/// (the shape Google's own tools store) is exchanged at Google's token
/// endpoint on `client`, as the `gmail.profile` check does; a grant that
/// carries only an access token presents it; bare text is the access token.
/// Call it inside the credential door: the exchanged token lives only in the
/// returned value, and is never kept.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the grant holds no usable token, or Google
/// refused its refresh token.
pub fn gmail_authorization(
    client: &reqwest::blocking::Client,
    stored: &[u8],
) -> Result<HeaderValue> {
    let invalid =
        || Error::InvalidConfig("gmail credential is not a usable access token".to_owned());
    let text = std::str::from_utf8(stored).map_err(|_| invalid())?.trim();
    let access_token = if text.starts_with('{') {
        let grant: StoredGoogleGrant = serde_json::from_str(text).map_err(|_| invalid())?;
        match (present(&grant.refresh_token), present(&grant.client_id)) {
            (Some(refresh_token), Some(client_id)) => exchange_refresh_token(
                client,
                refresh_token,
                client_id,
                present(&grant.client_secret),
            )?,
            _ => Zeroizing::new(present(&grant.access_token).ok_or_else(invalid)?.to_owned()),
        }
    } else {
        Zeroizing::new(text.to_owned())
    };
    if access_token.trim().is_empty() {
        return Err(invalid());
    }
    let header = Zeroizing::new(format!("Bearer {}", access_token.trim()));
    let mut value = HeaderValue::from_str(&header).map_err(|_| invalid())?;
    value.set_sensitive(true);
    Ok(value)
}

/// Exchanges a stored refresh token at Google's token endpoint for a fresh
/// access token, held only for the call that presents it.
fn exchange_refresh_token(
    client: &reqwest::blocking::Client,
    refresh_token: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<Zeroizing<String>> {
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(secret) = client_secret {
        form.push(("client_secret", secret));
    }
    let response = client
        .post(GOOGLE_TOKEN_URL)
        .form(&form)
        .send()
        .map_err(|_| {
            Error::InvalidConfig("gmail could not reach Google's token endpoint".into())
        })?;
    let status = response.status();
    let mut body = Zeroizing::new(Vec::new());
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| Error::InvalidConfig("Google's token reply is unreadable".to_owned()))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(Error::InvalidConfig(
            "Google's token reply exceeds its bound".to_owned(),
        ));
    }
    let mut reply: GoogleTokenReply = serde_json::from_slice(&body)
        .map_err(|_| Error::InvalidConfig("Google's token reply is not JSON".to_owned()))?;
    match reply.access_token.take().map(Zeroizing::new) {
        Some(token) if status.is_success() && !token.trim().is_empty() => Ok(token),
        _ => Err(Error::InvalidConfig(format!(
            "Google refused the stored Gmail refresh token (HTTP {})",
            status.as_u16()
        ))),
    }
}

/// A stored Gmail grant, wiped on drop.
#[derive(Deserialize)]
struct StoredGoogleGrant {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

impl Drop for StoredGoogleGrant {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.client_secret.zeroize();
    }
}

/// Google's token reply: the fresh access token, wiped on drop.
#[derive(Deserialize)]
struct GoogleTokenReply {
    #[serde(default)]
    access_token: Option<String>,
}

impl Drop for GoogleTokenReply {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

/// A stored field's value, trimmed, when it holds one.
fn present(field: &Option<String>) -> Option<&str> {
    field
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn read_bounded_json(response: reqwest::blocking::Response) -> Option<Value> {
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}
