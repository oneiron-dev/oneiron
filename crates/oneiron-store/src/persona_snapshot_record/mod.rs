//! Persisted persona snapshot export vocabulary and exact MessagePack codec.

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeSet;

pub mod codec;
pub use codec::{decode_persona_snapshot_export_body, encode_persona_snapshot_export_body};
pub use codec::{
    hash_hex, invalid_snapshot, validate_fingerprint_hex,
    validate_persona_snapshot_export_body_bytes, validate_row_id_list,
};

/// Schema version string carried by every persona snapshot compile stamp.
///
/// The stamp identity (`{schema_version}:{compiled_fingerprint}`) matches the
/// `persona_compile_stamp` value format of the OF-369/RS9 context receipt
/// field-set, so persona-card export receipts and emit receipts read
/// uniformly.
pub const PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION: &str =
    "oneiron.persona_snapshot_compile.v1";

/// Current PERSONA_SNAPSHOT_EXPORT record body schema version.
pub const PERSONA_SNAPSHOT_EXPORT_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for PERSONA_SNAPSHOT_EXPORT bodies.
pub const PERSONA_SNAPSHOT_EXPORT_BODY_KEYS: [&str; 14] = [
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
];

const MAX_IDENTITY_LINE_BYTES: usize = 2_048;

pub const FINGERPRINT_HEX_LEN: usize = 64;

pub const KEY_SCHEMA_VERSION: &str = "schemaVersion";

pub const KEY_SUBJECT_REF: &str = "subjectRef";

pub const KEY_AUDIENCE_REF: &str = "audienceRef";

pub const KEY_IDENTITY_LINE: &str = "identityLine";

pub const KEY_COMPILED_AT_SECS: &str = "compiledAtSecs";

pub const KEY_STALE_AFTER_SECS: &str = "staleAfterSecs";

pub const KEY_COMPILED_FINGERPRINT: &str = "compiledFingerprint";

pub const KEY_TAKES_INCLUDED: &str = "takesIncluded";

pub const KEY_GRANTED_BY: &str = "grantedBy";

pub const KEY_GRANTED_AT_SECS: &str = "grantedAtSecs";

pub const KEY_EXPORTED_AT_SECS: &str = "exportedAtSecs";

pub const KEY_INCLUDED_ROW_IDS: &str = "includedRowIds";

pub const KEY_STRUCK_ROW_IDS: &str = "struckRowIds";

pub const KEY_ARTIFACT_FINGERPRINT: &str = "artifactFingerprint";

pub use crate::serialize::persona_export_fields::KEY_OMITTED_REFS;

/// Persisted PERSONA_SNAPSHOT_EXPORT record body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaSnapshotExportRecord {
    /// The card's subject.
    pub subject_ref: EntityId,
    /// Audience actor ref when the card was compiled FOR someone.
    pub audience_ref: Option<String>,
    /// The compiled identity line.
    pub identity_line: String,
    /// Compile wall-clock time (Unix seconds).
    pub compiled_at_secs: u64,
    /// Relative stale_after freshness hint.
    pub stale_after_secs: u64,
    /// blake3 hex fingerprint of the compiled content.
    pub compiled_fingerprint: String,
    /// Whether agent takes were toggled into the card.
    pub takes_included: bool,
    /// Consenting actor ref.
    pub granted_by: String,
    /// Consent wall-clock time (Unix seconds).
    pub granted_at_secs: u64,
    /// Export wall-clock time (Unix seconds).
    pub exported_at_secs: u64,
    /// Row ids included in the artifact.
    pub included_row_ids: Vec<String>,
    /// Row ids struck out of the artifact.
    pub struck_row_ids: Vec<String>,
    /// blake3 hex fingerprint over both renders.
    pub artifact_fingerprint: String,
    /// The vault ref slots both renders left out, for a copy made without
    /// its refs (FIX 1199); empty, and not stored, for one that carries them.
    pub omitted_refs: Vec<String>,
}

impl PersonaSnapshotExportRecord {
    /// Returns the RCPT-7 `persona_compile_stamp` value for this export.
    #[must_use]
    pub fn compile_stamp_identity(&self) -> String {
        format!(
            "{PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION}:{}",
            self.compiled_fingerprint
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.identity_line.is_empty() || self.identity_line.len() > MAX_IDENTITY_LINE_BYTES {
            return Err(invalid_snapshot(
                "identityLine must be non-empty and at most 2048 bytes",
            ));
        }
        validate_fingerprint_hex(&self.compiled_fingerprint)?;
        validate_fingerprint_hex(&self.artifact_fingerprint)?;
        if self.granted_by.trim().is_empty() {
            return Err(invalid_snapshot("grantedBy must be non-empty"));
        }
        if let Some(audience_ref) = self.audience_ref.as_deref()
            && audience_ref.trim().is_empty()
        {
            return Err(invalid_snapshot("audienceRef must be non-empty when set"));
        }
        validate_row_id_list(&self.included_row_ids, "includedRowIds")?;
        validate_row_id_list(&self.struck_row_ids, "struckRowIds")?;
        let struck: BTreeSet<&str> = self.struck_row_ids.iter().map(String::as_str).collect();
        if self
            .included_row_ids
            .iter()
            .any(|row_id| struck.contains(row_id.as_str()))
        {
            return Err(invalid_snapshot(
                "includedRowIds and struckRowIds must be disjoint",
            ));
        }
        Ok(())
    }
}
