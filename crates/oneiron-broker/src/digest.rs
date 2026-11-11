//! The request digest (ARCH-0069 `#broker-digest`): blake3 over the method,
//! the path, the sorted non-auth headers and the body bytes. A `use(handle)`
//! permit binds it at admission, the broker recomputes it before it sends, and
//! the daemon checks the reply carries it.

use crate::Refusal;

/// The blake3 key-derivation context: a digest of this form never equals a
/// digest of another one.
const CONTEXT: &str = "oneiron-broker 2026-10-11 request digest v1";

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
    let mut hasher = blake3::Hasher::new_derive_key(CONTEXT);
    field(&mut hasher, method.as_bytes());
    field(&mut hasher, path.as_bytes());
    hasher.update(&(sorted.len() as u64).to_le_bytes());
    for (name, value) in &sorted {
        field(&mut hasher, name.as_bytes());
        field(&mut hasher, value.as_bytes());
    }
    field(&mut hasher, body);
    hasher.finalize().to_hex().to_string()
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

/// One length-prefixed field of a digest.
pub(crate) fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Whether `text` is a 32-byte digest in its lowercase hex form: a request
/// digest, or an LFS object's SHA-256.
pub(crate) fn is_hex_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The body half of a digest taken as its body passes (a git or an LFS
/// exchange): the hasher its target and headers began, then the body's
/// length and its bytes, checked against that length once the body ended.
pub(crate) struct BodyDigest {
    hasher: blake3::Hasher,
    expected: u64,
    seen: u64,
}

impl BodyDigest {
    /// Begins a body of `body_len` bytes after what `hasher` holds.
    pub(crate) fn new(mut hasher: blake3::Hasher, body_len: u64) -> Self {
        hasher.update(&body_len.to_le_bytes());
        Self {
            hasher,
            expected: body_len,
            seen: 0,
        }
    }

    /// Takes the next `bytes` of the body.
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.seen = self.seen.saturating_add(bytes.len() as u64);
        self.hasher.update(bytes);
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
        Ok(self.hasher.finalize().to_hex().to_string())
    }
}
