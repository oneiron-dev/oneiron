//! Canonical manifest codec, digest, and suggestion key.
use super::errors::{PluginResult, PluginSectionError};
use super::manifest::SectionManifestEnvelope;
use sha2::{Digest, Sha256};

/// Length of a canonical lowercase hex digest at a serialized boundary.
const DIGEST_HEX_LEN: usize = 64;

// ---------------------------------------------------------------------------
// §2 — codec
// ---------------------------------------------------------------------------
/// Canonical MessagePack encoding (named fields, pinned field order from the
/// struct definition). The digest that binds owner consent is taken over
/// exactly these bytes.
pub fn encode_section_manifest(manifest: &SectionManifestEnvelope) -> PluginResult<Vec<u8>> {
    rmp_serde::to_vec_named(manifest).map_err(|_| PluginSectionError::ManifestCodec)
}

/// Strict decode. `deny_unknown_fields` on both structs means an unknown field
/// is a rejection, not a silently dropped one.
pub fn decode_section_manifest(bytes: &[u8]) -> PluginResult<SectionManifestEnvelope> {
    rmp_serde::from_slice(bytes).map_err(|_| PluginSectionError::ManifestCodec)
}

/// SHA-256 over the canonical manifest bytes.
#[must_use]
pub fn section_manifest_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Lowercase hex of a 32-byte digest — the one canonical boundary form.
#[must_use]
pub fn digest_to_hex(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(DIGEST_HEX_LEN);
    for byte in digest {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

const fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

pub(super) fn digest_from_hex(value: &str) -> PluginResult<[u8; 32]> {
    if value.len() != DIGEST_HEX_LEN {
        return Err(PluginSectionError::MalformedSuggestionKey);
    }
    let bytes = value.as_bytes();
    let mut out = [0_u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let high = hex_value(bytes[index * 2])?;
        let low = hex_value(bytes[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Ok(out)
}

/// Lowercase-only on purpose: a canonical boundary form with two spellings is
/// not canonical, and a mixed-case twin would hash to a different key.
fn hex_value(byte: u8) -> PluginResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(PluginSectionError::MalformedSuggestionKey),
    }
}

// ---------------------------------------------------------------------------
// §3 — suggestion key
// ---------------------------------------------------------------------------
/// A Dreamer suggestion identity. `[u8; 32]` internally; every serialized claim
/// or API boundary carries exactly one canonical lowercase 64-character hex
/// `String`, converted here exactly once. ONE-1707 must reuse this conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginSuggestionKey([u8; 32]);

impl PluginSuggestionKey {
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub fn parse_hex(value: &str) -> PluginResult<Self> {
        digest_from_hex(value).map(Self)
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        digest_to_hex(&self.0)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
