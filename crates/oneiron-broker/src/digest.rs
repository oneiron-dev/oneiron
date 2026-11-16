//! The request digest (ARCH-0069 `#broker-digest`): blake3 over the method,
//! the path, the sorted non-auth headers and the body bytes. A `use(handle)`
//! permit binds it at admission, the broker recomputes it before it sends, and
//! the daemon checks the reply carries it.
//!
//! The daemon and the broker each take it, so a daemon and a broker on two
//! builds must agree on its bytes: every request digest starts through the
//! fingerprint crate's K door under a `purposes::broker` legacy purpose
//! (PLAN-UC-04 4.2), whose tag is the derive-key context.

use oneiron_fingerprint::{LegacyDigest, purposes};

use crate::Refusal;

/// Request headers that carry a credential. The digest leaves them out, and a
/// call frame may not carry them: the broker adds the shape's own.
const AUTH_HEADERS: [&str; 6] = [
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "xi-api-key",
];

/// Whether `name` is an auth header, in any letter case.
#[must_use]
pub fn is_auth_header(name: &str) -> bool {
    AUTH_HEADERS
        .iter()
        .any(|auth| auth.eq_ignore_ascii_case(name))
}

/// The digest of one request, as lowercase hex. Each field is length-prefixed,
/// so no two requests share an input. Header names are compared lowercase and
/// the headers sorted, so their order on the wire does not change the digest.
#[must_use]
pub fn request_digest(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> String {
    let sorted = sorted_headers(headers);
    let mut digest = LegacyDigest::new(purposes::broker::REQUEST);
    framed_part(&mut digest, method.as_bytes());
    framed_part(&mut digest, path.as_bytes());
    digest.len_u64_le(sorted.len());
    for (name, value) in &sorted {
        framed_part(&mut digest, name.as_bytes());
        framed_part(&mut digest, value.as_bytes());
    }
    framed_part(&mut digest, body);
    oneiron_hex::encode(&digest.finish())
}

/// `headers` as a digest takes them: auth headers left out, names
/// lowercase, sorted.
pub(crate) fn sorted_headers(headers: &[(String, String)]) -> Vec<(String, &str)> {
    let mut sorted: Vec<(String, &str)> = headers
        .iter()
        .filter(|(name, _)| !is_auth_header(name))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.as_str()))
        .collect();
    sorted.sort_unstable();
    sorted
}

/// One length-prefixed field of a digest: its length as a u64
/// little-endian, then its bytes.
pub(crate) fn framed_part(digest: &mut LegacyDigest, bytes: &[u8]) {
    digest.len_u64_le(bytes.len()).raw(bytes);
}

/// Whether `text` is a 32-byte digest in its lowercase hex form: a request
/// digest, or an LFS object's SHA-256.
pub(crate) fn is_hex_digest(text: &str) -> bool {
    oneiron_hex::is_lower_hex(text, Some(64))
}

/// The body half of a digest taken as its body passes (a git or an LFS
/// exchange): the digest its target and headers began, then the body's
/// length and its bytes, checked against that length once the body ended.
pub(crate) struct BodyDigest {
    digest: LegacyDigest,
    expected: u64,
    seen: u64,
}

impl BodyDigest {
    /// Begins a body of `body_len` bytes after what `digest` holds.
    pub(crate) fn new(mut digest: LegacyDigest, body_len: u64) -> Self {
        digest.raw(&body_len.to_le_bytes());
        Self {
            digest,
            expected: body_len,
            seen: 0,
        }
    }

    /// Takes the next `bytes` of the body.
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.seen = self.seen.saturating_add(bytes.len() as u64);
        self.digest.raw(bytes);
    }

    /// The digest, as lowercase hex, once the whole body passed.
    ///
    /// # Errors
    ///
    /// [`Refusal::Body`] when the body's bytes are not the length the
    /// digest began with.
    pub(crate) fn finish(self) -> Result<String, Refusal> {
        if self.seen != self.expected {
            return Err(Refusal::Body);
        }
        Ok(oneiron_hex::encode(&self.digest.finish()))
    }
}
