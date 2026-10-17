//! One call's header and its reply's header, and the checks both sides run.

use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::digest::{is_auth_header, request_digest};
use crate::frame::{MAX_HEADER, PROTOCOL_VERSION};
use crate::{Failure, MAX_BODY, Refusal, Shape};

/// Request headers a call may not carry: the HTTP stack writes the framing and
/// connection ones itself, the broker sets the encoding (so the reply stays
/// strippable) and adds the auth.
const RESERVED_HEADERS: [&str; 13] = [
    "accept-encoding",
    "connection",
    "content-encoding",
    "content-length",
    "expect",
    "host",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "cookie",
];

const MAX_HEADERS: usize = 32;
const MAX_HEADER_VALUE: usize = 1024;

/// What the daemon asks the broker to send. The body and the key travel as
/// their own raw segments after it (see `frame`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallHeader {
    /// [`PROTOCOL_VERSION`].
    pub version: u32,
    /// The daemon's id for the call (its lease), echoed in the reply.
    pub call: String,
    /// The wire protocol.
    pub shape: Shape,
    /// The handle's exact `https` origin, as `https://host[:port]`.
    pub origin: String,
    /// The shape's method.
    pub method: String,
    /// The path under the origin, ending in the shape's endpoint (and its
    /// one query, for a shape that takes one).
    pub path: String,
    /// The request's headers, lowercase names, no auth.
    pub headers: Vec<(String, String)>,
    /// The offer's wire model: the selector the body or the path must carry.
    /// A shape that names no model on the wire (a bodyless read of a job or a
    /// file) is bound to it here alone.
    pub wire_model: String,
    /// [`request_digest`] of the method, path, headers and body.
    pub digest: String,
}

impl CallHeader {
    /// A call for `body`, with its digest.
    #[must_use]
    pub fn new(
        call: String,
        shape: Shape,
        origin: String,
        path: String,
        headers: Vec<(String, String)>,
        wire_model: String,
        body: &[u8],
    ) -> Self {
        let method = shape.method().to_owned();
        let digest = request_digest(&method, &path, &headers, body);
        Self {
            version: PROTOCOL_VERSION,
            call,
            shape,
            origin,
            method,
            path,
            headers,
            wire_model,
            digest,
        }
    }

    /// Every check on the request, with no I/O: the daemon runs it before it
    /// reads the key, and the broker again before it sends. Returns the URL the
    /// request goes to. A call too large to frame is refused here too, so the
    /// daemon never reads a key for a frame the broker would not read.
    pub fn check(&self, body: &[u8]) -> Result<Url, Refusal> {
        if self.version != PROTOCOL_VERSION {
            return Err(Refusal::Version);
        }
        if body.len() > MAX_BODY {
            return Err(Refusal::Body);
        }
        if !serde_json::to_vec(self).is_ok_and(|header| header.len() <= MAX_HEADER) {
            return Err(Refusal::Frame);
        }
        if self.method != self.shape.method() {
            return Err(Refusal::Method);
        }
        self.shape.check_path(&self.path)?;
        let url = exact_url(&self.origin, &self.path)?;
        check_headers(&self.headers)?;
        let named = self.shape.read_model(&self.path, &self.headers, body)?;
        if named.map_or(self.wire_model.is_empty(), |model| model != self.wire_model) {
            return Err(Refusal::WireModel);
        }
        if request_digest(&self.method, &self.path, &self.headers, body) != self.digest {
            return Err(Refusal::Digest);
        }
        Ok(url)
    }
}

/// The origin must be one `https` origin in its canonical spelling, and the
/// joined URL must keep that origin and that exact path and query.
fn exact_url(origin: &str, path: &str) -> Result<Url, Refusal> {
    let base = Url::parse(origin).map_err(|_| Refusal::Origin)?;
    let canonical = base.scheme() == "https"
        && base.username().is_empty()
        && base.password().is_none()
        && base.host().is_some()
        && base.origin().ascii_serialization() == origin;
    if !canonical {
        return Err(Refusal::Origin);
    }
    let url = Url::parse(&format!("{origin}{path}")).map_err(|_| Refusal::Path)?;
    let (plain, query) = match path.split_once('?') {
        Some((plain, query)) => (plain, Some(query)),
        None => (path, None),
    };
    if url.origin() != base.origin()
        || url.path() != plain
        || url.query() != query
        || url.fragment().is_some()
    {
        return Err(Refusal::Path);
    }
    Ok(url)
}

fn check_headers(headers: &[(String, String)]) -> Result<(), Refusal> {
    if headers.len() > MAX_HEADERS {
        return Err(Refusal::Header);
    }
    for (index, (name, value)) in headers.iter().enumerate() {
        let token = !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        let visible = value.len() <= MAX_HEADER_VALUE
            && value.bytes().all(|byte| (0x20..0x7f).contains(&byte));
        let repeated = headers[..index].iter().any(|(earlier, _)| earlier == name);
        if !token
            || !visible
            || repeated
            || is_auth_header(name)
            || RESERVED_HEADERS.contains(&name.as_str())
        {
            return Err(Refusal::Header);
        }
    }
    Ok(())
}

/// The broker's answer to one call. The reply body follows as its own segment,
/// or as chunks for a shape that streams (see `frame`); it is empty unless
/// the call was answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyHeader {
    /// [`PROTOCOL_VERSION`].
    pub version: u32,
    /// The call this answers.
    pub call: String,
    /// The digest the broker checked, the call's own.
    pub digest: String,
    /// What happened.
    pub outcome: Outcome,
}

/// What happened to a call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    /// The provider answered (any status). The headers are stripped, and so
    /// is a buffered body; a streamed body is checked and passed unchanged.
    Answered {
        /// The HTTP status.
        status: u16,
        /// Response headers, stripped, lowercase names.
        headers: Vec<(String, String)>,
    },
    /// Nothing left for the provider.
    Refused {
        /// Why.
        reason: Refusal,
    },
    /// The request may have left, and there is no answer.
    Failed {
        /// Why.
        reason: Failure,
    },
}

#[cfg(test)]
mod tests;
