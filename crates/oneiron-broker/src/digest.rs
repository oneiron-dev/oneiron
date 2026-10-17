//! The request digest (ARCH-0069 `#broker-digest`): blake3 over the method,
//! the path, the sorted non-auth headers and the body bytes. A `use(handle)`
//! permit binds it at admission, the broker recomputes it before it sends, and
//! the daemon checks the reply carries it.

/// The blake3 key-derivation context: a digest of this form never equals a
/// digest of another one.
const CONTEXT: &str = "oneiron-broker 2026-10-11 request digest v1";

/// Request headers that carry a credential. The digest leaves them out, and a
/// call frame may not carry them: the broker adds the shape's own.
const AUTH_HEADERS: [&str; 5] = [
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
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
    let mut sorted: Vec<(String, &str)> = headers
        .iter()
        .filter(|(name, _)| !is_auth_header(name))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.as_str()))
        .collect();
    sorted.sort_unstable();
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

fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}
