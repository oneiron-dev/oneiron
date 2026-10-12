//! The broker's one send: verified TLS, no redirect, no retry, no proxy, and
//! no content encoding, so the reply it strips is the reply the daemon reads.

use std::time::Duration;

use reqwest::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, HeaderMap, HeaderValue, TRANSFER_ENCODING,
};
use reqwest::{Certificate, Client, Method, Url};
use zeroize::Zeroizing;

use crate::strip::{admits, contains_key, strip};
use crate::{CallHeader, Failure, MAX_BODY, MAX_SECRET, Outcome, Refusal};

/// The shortest key the broker injects. Stripping a shorter one would redact
/// ordinary text, and no provider issues one.
const MIN_SECRET: usize = 8;

/// The reply headers kept, at most, and their total size.
const MAX_REPLY_HEADERS: usize = 64;
const MAX_REPLY_HEADER_BYTES: usize = 32 << 10;

/// How the broker's client sends.
#[derive(Debug, Clone)]
pub struct SendPolicy {
    /// The whole call's time limit, from connect to the last reply byte.
    pub timeout: Duration,
    /// Extra trust anchors (PEM) for a self-hosted provider's private CA,
    /// beside the WebPKI and the platform roots.
    pub extra_roots: Vec<Vec<u8>>,
}

/// The client every call of one broker sends through.
pub(crate) struct Sender {
    client: Client,
}

impl Sender {
    pub(crate) fn new(policy: &SendPolicy) -> Result<Self, reqwest::Error> {
        let mut builder = Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .tls_built_in_root_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(policy.timeout.min(Duration::from_secs(30)))
            .timeout(policy.timeout);
        for pem in &policy.extra_roots {
            for root in Certificate::from_pem_bundle(pem)? {
                builder = builder.add_root_certificate(root);
            }
        }
        Ok(Self {
            client: builder.build()?,
        })
    }

    /// Sends `body` to `url` once with the key in the shape's auth header,
    /// then strips the key from what came back. `call` has passed
    /// [`CallHeader::check`].
    pub(crate) async fn send(
        &self,
        call: &CallHeader,
        url: Url,
        body: &[u8],
        secret: &[u8],
    ) -> (Outcome, Zeroizing<Vec<u8>>) {
        let empty = Zeroizing::new(Vec::new());
        let request = match self.request(call, url, body, secret) {
            Ok(request) => request,
            Err(refusal) => return (Outcome::Refused { reason: refusal }, empty),
        };
        let mut response = match self.client.execute(request).await {
            Ok(response) => response,
            // A connect error comes before any request byte is written.
            Err(error) if error.is_connect() => {
                return (
                    Outcome::Refused {
                        reason: Refusal::Connect,
                    },
                    empty,
                );
            }
            Err(error) => return (failed(&error), empty),
        };
        if encoded(response.headers()) {
            return (
                Outcome::Failed {
                    reason: Failure::ReplyEncoded,
                },
                empty,
            );
        }
        let mut raw = Zeroizing::new(Vec::new());
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if raw.len() + chunk.len() > MAX_BODY {
                        return (
                            Outcome::Failed {
                                reason: Failure::ReplyTooLarge,
                            },
                            empty,
                        );
                    }
                    push_wiped(&mut raw, &chunk);
                }
                Ok(None) => break,
                Err(error) => return (failed(&error), empty),
            }
        }
        let headers = reply_headers(response.headers(), secret);
        let body = strip(secret, &raw);
        let status = response.status().as_u16();
        (Outcome::Answered { status, headers }, body)
    }

    fn request(
        &self,
        call: &CallHeader,
        url: Url,
        body: &[u8],
        secret: &[u8],
    ) -> Result<reqwest::Request, Refusal> {
        // Only a key the strip rule is sure to find in a reply: ASCII, so no
        // key byte hides inside a multibyte one, in the rule's own alphabet.
        if secret.len() < MIN_SECRET || secret.len() > MAX_SECRET || !admits(secret) {
            return Err(Refusal::Secret);
        }
        let mut auth = Zeroizing::new(call.shape.auth_prefix().as_bytes().to_vec());
        auth.extend_from_slice(secret);
        let mut auth = HeaderValue::from_bytes(&auth).map_err(|_| Refusal::Secret)?;
        auth.set_sensitive(true);
        let method = Method::from_bytes(call.method.as_bytes()).map_err(|_| Refusal::Method)?;
        let mut builder = self
            .client
            .request(method, url)
            .header(ACCEPT_ENCODING, "identity")
            .header(call.shape.auth_header(), auth);
        for (name, value) in &call.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        builder
            .body(body.to_vec())
            .build()
            .map_err(|_| Refusal::Header)
    }
}

/// Whether the body arrives under a coding the HTTP stack did not undo, so
/// the strip would read encoded bytes: any content coding but `identity`, or
/// any transfer coding but `chunked`, in any value of either header.
fn encoded(headers: &HeaderMap) -> bool {
    let other = |name: reqwest::header::HeaderName, plain: &[&str]| {
        headers.get_all(name).iter().any(|value| {
            !value.to_str().is_ok_and(|codings| {
                codings.split(',').all(|coding| {
                    plain
                        .iter()
                        .any(|plain| coding.trim().eq_ignore_ascii_case(plain))
                })
            })
        })
    };
    other(CONTENT_ENCODING, &["identity"]) || other(TRANSFER_ENCODING, &["chunked"])
}

fn failed(error: &reqwest::Error) -> Outcome {
    Outcome::Failed {
        reason: if error.is_timeout() {
            Failure::Timeout
        } else {
            Failure::Send
        },
    }
}

/// Appends `chunk`, growing into a fresh buffer when full so the old one is
/// wiped as it drops instead of freed with reply bytes in it.
fn push_wiped(buffer: &mut Zeroizing<Vec<u8>>, chunk: &[u8]) {
    let needed = buffer.len() + chunk.len();
    if needed > buffer.capacity() {
        let mut grown = Zeroizing::new(Vec::with_capacity(needed.max(buffer.capacity() * 2)));
        grown.extend_from_slice(buffer);
        *buffer = grown;
    }
    buffer.extend_from_slice(chunk);
}

/// The reply's headers, each value stripped. A header whose name holds the
/// key is dropped whole, and so is any past the bounds.
fn reply_headers(headers: &reqwest::header::HeaderMap, secret: &[u8]) -> Vec<(String, String)> {
    let mut kept = Vec::new();
    let mut size = 0;
    for (name, value) in headers {
        if contains_key(secret, name.as_str().as_bytes()) {
            continue;
        }
        let value = strip(secret, value.as_bytes());
        let value = String::from_utf8_lossy(&value).into_owned();
        size += name.as_str().len() + value.len();
        if kept.len() == MAX_REPLY_HEADERS || size > MAX_REPLY_HEADER_BYTES {
            break;
        }
        kept.push((name.as_str().to_owned(), value));
    }
    kept
}
