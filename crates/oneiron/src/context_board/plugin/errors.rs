//! Plugin-seam error type and result alias.
use super::super::frame::BoardFrameError;
use crate::skill::SkillLifecycle;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
/// Every fail-closed reason the plugin seam can refuse for.
///
/// Deliberately typed rather than a string: the oracle counts rejections per
/// missing recipe component, and a caller that wants to distinguish "unknown
/// verb" from "skill is still Candidate" must not have to match on prose.
/// Not `Clone`/`Eq`: the transparent vault arm wraps [`crate::error::Error`],
/// which is neither, and flattening it to prose would lose the typed cause.
#[derive(Debug, thiserror::Error)]
pub enum PluginSectionError {
    #[error("unsupported section manifest schema version: {found} (expected {expected})")]
    UnsupportedSchemaVersion { found: u16, expected: u16 },
    #[error("section manifest field is empty or malformed: {field}")]
    MalformedField { field: &'static str },
    #[error("section manifest field exceeds its byte ceiling: {field}")]
    FieldTooLong { field: &'static str },
    #[error("plugin section id collides with an engine-defined core section: {section_id}")]
    CoreSectionCollision { section_id: String },
    #[error("plugin section id is already admitted: {section_id}")]
    SectionIdCollision { section_id: String },
    #[error("section manifest advertises a verb outside the exported engine surface: {verb}")]
    UnknownVerb { verb: String },
    #[error("section manifest advertises a duplicate verb: {verb}")]
    DuplicateVerb { verb: String },
    #[error("section manifest advertises no verbs")]
    MissingVerbs,
    #[error("section manifest state family does not resolve: {family}")]
    UnresolvedStateFamily { family: String },
    #[error("section manifest authority lane does not resolve: {lane}")]
    UnresolvedAuthorityLane { lane: String },
    #[error("section manifest budget policy does not resolve: {policy}")]
    UnresolvedBudgetPolicy { policy: String },
    #[error("plugin sections must map to the plugin shed rank, never a pinned policy")]
    NonPluginSectionPolicy,
    #[error("section manifest provenance does not match the exact candidate package")]
    ProvenanceMismatch,
    #[error("plugin install target is not present: {reference}")]
    MissingInstallTarget { reference: String },
    #[error("checked import landed at {found}, not the consented {expected}")]
    ImportRefDrift { expected: String, found: String },
    #[error("supplying skill is not Active; plugin sections never render from {found:?}")]
    SkillNotActive { found: SkillLifecycle },
    #[error("plugin install claim is not approved")]
    ClaimNotApproved,
    #[error("plugin install claim payload is malformed: {field}")]
    MalformedClaimPayload { field: &'static str },
    #[error("plugin install claim was not found")]
    ClaimNotFound,
    #[error("plugin install proposal produced no bound pending-consent record")]
    MissingPendingConsent,
    #[error("plugin suggestion key must be exactly 64 lowercase hex characters")]
    MalformedSuggestionKey,
    #[error("section snapshot is missing for admitted section: {section_id}")]
    MissingSnapshot { section_id: String },
    #[error("canonical MessagePack codec failure for the section manifest")]
    ManifestCodec,
    #[error(transparent)]
    Frame(#[from] BoardFrameError),
    #[error(transparent)]
    Vault(#[from] crate::error::Error),
}

/// The plugin seam's result alias.
pub type PluginResult<T> = std::result::Result<T, PluginSectionError>;
