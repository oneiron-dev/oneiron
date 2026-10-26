//! The client's one HTTP path (L14 lead call 08:3x): the admission host's
//! blocking client, with its bounds as they are (no redirect, no proxy,
//! connect 10 s, whole request 30 s), a device poll's bound capped by its
//! code's remaining lifetime, and no retry. A form POST carries no
//! `Authorization` header; a bearer goes on a GET alone, and only where the
//! caller names it (the pinned audience). Every form is encoded into one
//! buffer and every answer body read into one, each sized before it is
//! written and wiped on drop. The HTTP stack's own buffers (reqwest's body
//! chunks, hyper's, TLS's) still hold copies, which nothing here wipes.

use std::io::{Cursor, Read as _};
use std::time::Duration;

use reqwest::Url;
use reqwest::blocking::{Body, Client, RequestBuilder};
use zeroize::Zeroizing;

use super::wire::{ErrorReply, Failure};

/// The admission client's own whole-request bound
/// (`connector_admission_host::client`), which a poll's cap never exceeds.
const CLIENT_REQUEST_BOUND: Duration = Duration::from_secs(30);

/// The most answer bytes read (CALLS G7_ANSWER_BYTES): far above every LC
/// reply, so one past it is off the wire.
const ANSWER_MAX_BYTES: usize = 64 * 1024;

/// One answer: its status, its media type and its body.
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) media_type: String,
    pub(crate) body: Zeroizing<Vec<u8>>,
}

impl Reply {
    /// The body as `T`, or why it is off the wire.
    pub(crate) fn json<T: serde::de::DeserializeOwned>(&self, what: &str) -> Result<T, Failure> {
        serde_json::from_slice(&self.body)
            .map_err(|_| Failure::OffWire(format!("the {what} answer is not the wire's shape")))
    }

    /// The failure a non-200 answer is: any 503 is cloud registration
    /// unavailable, with its optional description verbatim; an OAuth error
    /// is its code; anything else is off the wire.
    pub(crate) fn failure(&self, what: &str) -> Failure {
        let error = serde_json::from_slice::<ErrorReply>(&self.body).ok();
        if self.status == 503 {
            return Failure::Unavailable(error.and_then(|error| error.error_description));
        }
        match error {
            Some(error) if matches!(self.status, 400 | 401) => Failure::Refused(error.error),
            _ => Failure::OffWire(format!("the {what} answered HTTP {}", self.status)),
        }
    }
}

/// The client, built once per act on a blocking worker.
pub(crate) struct Http {
    client: Client,
}

impl Http {
    pub(crate) fn new() -> Result<Self, Failure> {
        Ok(Self {
            client: crate::connector_admission_host::client()?,
        })
    }

    /// `GET url`, with `bearer` as its `Authorization` when named.
    pub(crate) fn get(&self, url: &Url, bearer: Option<&str>) -> Result<Reply, Failure> {
        let request = self.client.get(url.clone());
        let request = match bearer {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        send(request)
    }

    /// `POST url` with `form`, UTF-8 form-urlencoded, each field once, no
    /// `Authorization`. The body owns its encoded buffer until reqwest drops
    /// it. `within` caps the request's bound by what is left of a code's
    /// lifetime.
    pub(crate) fn post_form(
        &self,
        url: &Url,
        form: &[(&str, &str)],
        within: Option<Duration>,
    ) -> Result<Reply, Failure> {
        let body = form_body(form);
        let len = body.len() as u64;
        let request = self
            .client
            .post(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::sized(Cursor::new(body), len));
        let request = match within {
            Some(left) if left < CLIENT_REQUEST_BOUND => request.timeout(left),
            _ => request,
        };
        send(request)
    }
}

/// Whether a form serializer keeps `byte` as it is.
const fn form_kept(byte: u8) -> bool {
    matches!(byte, b'*' | b'-' | b'.' | b'0'..=b'9' | b'A'..=b'Z' | b'_' | b'a'..=b'z')
}

/// How many bytes `text` takes form-encoded: three for each it escapes.
fn form_len(text: &str) -> usize {
    let escaped = text
        .bytes()
        .filter(|&byte| !form_kept(byte) && byte != b' ')
        .count();
    text.len() + 2 * escaped
}

/// Appends `text` form-encoded to `body`.
fn form_encode(body: &mut Vec<u8>, text: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in text.bytes() {
        if form_kept(byte) {
            body.push(byte);
        } else if byte == b' ' {
            body.push(b'+');
        } else {
            body.push(b'%');
            body.push(HEX[usize::from(byte >> 4)]);
            body.push(HEX[usize::from(byte & 0xf)]);
        }
    }
}

/// `form` as `application/x-www-form-urlencoded`, byte for byte as a form
/// serializer writes it (`name=value` pairs joined by `&`; `*-._`, digits
/// and letters kept, a space as `+`, every other byte `%XX`), in one buffer
/// sized first, so it never grows and leaves no partial copy behind.
fn form_body(form: &[(&str, &str)]) -> Zeroizing<Vec<u8>> {
    let len = form
        .iter()
        .map(|(name, value)| form_len(name) + 1 + form_len(value))
        .sum::<usize>()
        + form.len().saturating_sub(1);
    let mut body = Zeroizing::new(Vec::with_capacity(len));
    for (index, (name, value)) in form.iter().enumerate() {
        if index > 0 {
            body.push(b'&');
        }
        form_encode(&mut body, name);
        body.push(b'=');
        form_encode(&mut body, value);
    }
    body
}

/// Sends `request` and reads its answer whole, bounded, into a buffer
/// sized for the bound first, so the read never moves it. A send or read
/// that fails is `Lost`: the issuer may have acted.
fn send(request: RequestBuilder) -> Result<Reply, Failure> {
    let response = request.send().map_err(|_| Failure::Lost)?;
    let status = response.status().as_u16();
    let media_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let mut body = Zeroizing::new(Vec::with_capacity(ANSWER_MAX_BYTES + 1));
    response
        .take(ANSWER_MAX_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| Failure::Lost)?;
    if body.len() > ANSWER_MAX_BYTES {
        return Err(Failure::OffWire(
            "an answer is larger than any on the wire".to_owned(),
        ));
    }
    Ok(Reply {
        status,
        media_type,
        body,
    })
}
