//! Canonical manifest codec, digest, and suggestion key.
use super::errors::{PluginResult, PluginSectionError};
use super::manifest::SectionManifestEnvelope;
use oneiron_contracts::fingerprint::{LegacyDigest, purposes};

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

/// SHA-256 over the canonical manifest bytes. An install claim carries it beside the
/// bytes and is refused when they differ, and owner consent binds it, so it keeps its
/// bytes (K, PLAN-UC-04 stage 6.1).
#[must_use]
pub fn section_manifest_digest(bytes: &[u8]) -> [u8; 32] {
    LegacyDigest::new(purposes::plugin::SECTION_MANIFEST)
        .raw(bytes)
        .finish()
}

/// Lowercase hex of a 32-byte digest — the one canonical boundary form.
#[must_use]
pub fn digest_to_hex(digest: &[u8; 32]) -> String {
    oneiron_hex::encode(digest)
}

pub(super) fn digest_from_hex(value: &str) -> PluginResult<[u8; 32]> {
    oneiron_hex::decode::<32>(value).ok_or(PluginSectionError::MalformedSuggestionKey)
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
