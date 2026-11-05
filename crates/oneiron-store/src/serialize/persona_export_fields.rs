//! Field projections and omitted-reference key of persona snapshot exports.

/// Minimal projection: enough to answer "what was exported and when?".
pub const PERSONA_SNAPSHOT_EXPORT_FIELDS_MINIMAL: &[&str] = &["subjectRef", "exportedAtSecs"];

/// Standard projection: the export spine without the row-id lists.
pub const PERSONA_SNAPSHOT_EXPORT_FIELDS_STANDARD: &[&str] = &[
    "subjectRef",
    "audienceRef",
    "identityLine",
    "compiledAtSecs",
    "staleAfterSecs",
    "grantedBy",
    "exportedAtSecs",
];

/// Full projection: every pinned body key, then the optional `omittedRefs`
/// key a copy made without its vault refs stores.
pub const PERSONA_SNAPSHOT_EXPORT_FIELDS_FULL: &[&str] = &[
    "schemaVersion",
    "subjectRef",
    "audienceRef",
    "identityLine",
    "compiledAtSecs",
    "staleAfterSecs",
    "compiledFingerprint",
    "takesIncluded",
    "grantedBy",
    "grantedAtSecs",
    "exportedAtSecs",
    "includedRowIds",
    "struckRowIds",
    "artifactFingerprint",
    KEY_OMITTED_REFS,
];

/// Optional body key, outside the pinned set: the vault ref slots a copy
/// made without its refs left out (FIX 1199). A copy that carries its refs
/// stores no such key.
pub const KEY_OMITTED_REFS: &str = "omittedRefs";
