//! The JSON a call writes and keeps: one POST of a JSON body, and a
//! foreign value kept serialized until it goes back.

use oneiron::outbound_consent::zeroizing_json_body;
use zeroize::Zeroizing;

use super::*;

/// A POST of `body` to `endpoint`; `timeout` bounds the whole request, and
/// `None` leaves each read to the client's own bound. The body's text goes
/// in zeroizing storage the request takes without a copy, wiped once the
/// request lets it go (FIX 8309, L10 09:30).
pub(super) fn post_json(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    body: &Value,
    auth: Option<&HeaderValue>,
    session: Option<&HeaderValue>,
    timeout: Option<Duration>,
) -> reqwest::blocking::RequestBuilder {
    let mut request = client
        .post(endpoint)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, ACCEPT_BOTH)
        .body(axum::body::Bytes::from_owner(zeroizing_json_body(body)));
    if let Some(timeout) = timeout {
        request = request.timeout(timeout);
    }
    if let Some(auth) = auth {
        request = request.header(AUTHORIZATION, auth.clone());
    }
    if let Some(session) = session {
        request = request.header(SESSION_HEADER, session.clone());
    }
    request
}

/// A foreign value the exchange hands back exactly as the connector sent it:
/// a stream request's id, a retried call's request state. A connector may
/// put the presented value in it, so while it waits for the next answer it
/// is kept serialized in zeroizing storage, scrubbed once replaced or
/// dropped, and never cleared or rewritten (FIX 8054).
pub(super) struct KeptWire(Zeroizing<String>);

impl KeptWire {
    pub(super) fn keep(value: &Value) -> Self {
        Self(Zeroizing::new(value.to_string()))
    }

    /// The kept value, for one message: its own serialization parses back
    /// to the same value, key order included.
    pub(super) fn value(&self) -> Value {
        serde_json::from_str(&self.0).unwrap_or(Value::Null)
    }

    /// The kept serialization, for a round's resume state (FIX 9157).
    pub(super) fn text(&self) -> &str {
        self.0.as_str()
    }

    /// A value a round's resume state kept, as its serialization.
    pub(super) const fn of_text(text: Zeroizing<String>) -> Self {
        Self(text)
    }
}
