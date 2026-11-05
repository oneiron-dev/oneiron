//! Engine-emitted effect digest value.

/// Engine-computed digest of one composed effect.
///
/// There is no public constructor from caller bytes on the ask path: a digest
/// is derived by `consent::ComposedEffect::digest` over engine-owned facts, so a
/// caller cannot forge the identity of the op an approve-once receipt covers.
/// [`EffectDigest::from_bytes`] exists only to rehydrate a digest the engine
/// already emitted (e.g. from a receipt row).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EffectDigest(pub(super) [u8; 32]);

impl EffectDigest {
    /// Rehydrates a previously engine-emitted digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding, used in receipts and registry rows.
    #[must_use]
    pub fn to_hex(&self) -> String {
        oneiron_contracts::entity_id::bytes_to_hex_lower(&self.0)
    }
}
