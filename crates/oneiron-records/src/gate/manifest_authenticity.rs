//! Moved from `crates/oneiron/src/gate/manifest_authenticity.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ManifestContribution {
    pub id: String,
    pub trusted: bool,
    /// An untrusted contribution: a proposal that enters no effective policy,
    /// narrowing included, until a policy holder authors its values through
    /// the manifest put (FIX 8780).
    pub restrict_only: bool,
    pub quarantined: bool,
}
