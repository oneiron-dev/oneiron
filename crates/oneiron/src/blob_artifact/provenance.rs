//! Blob version provenance: producer enum and claim-envelope value constructors.

use rmpv::Value;

use crate::batch::secret_scan;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::error::{Error, Result};

use super::body::validate_text_field;
use super::store_keys::{BLOB_ARTIFACT_CONTENT_HASH_LEN, BLOB_ARTIFACT_RUN_REF_MAX_BYTES};
use super::versions::{KEY_CONTENT_HASH, KEY_PROVENANCE, KEY_RUN_REF, KEY_VERSION};

pub(crate) const BLOB_VERSION_CLAIM_PREDICATE: &str = "blob.version";

const PROVENANCE_USER_UPLOAD: &str = "user_upload";

const PROVENANCE_AGENT_RUN: &str = "agent_run";

/// Who produced one blob artifact version: a direct user upload or an agent
/// run identified by its stable run reference.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlobVersionProvenance {
    UserUpload,
    AgentRun { run_ref: String },
}

impl BlobVersionProvenance {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UserUpload => PROVENANCE_USER_UPLOAD,
            Self::AgentRun { .. } => PROVENANCE_AGENT_RUN,
        }
    }

    #[must_use]
    pub fn run_ref(&self) -> Option<&str> {
        match self {
            Self::UserUpload => None,
            Self::AgentRun { run_ref } => Some(run_ref),
        }
    }

    pub(super) fn from_parts(kind: &str, run_ref: Option<String>) -> Result<Self> {
        match (kind, run_ref) {
            (PROVENANCE_USER_UPLOAD, None) => Ok(Self::UserUpload),
            (PROVENANCE_AGENT_RUN, Some(run_ref)) => Ok(Self::AgentRun { run_ref }),
            _ => Err(Error::InvalidBlobArtifactBody(
                "provenance must be user_upload without run_ref or agent_run with run_ref",
            )),
        }
    }

    pub(super) fn claim_source(&self) -> ClaimSource {
        match self {
            Self::UserUpload => ClaimSource::UserStated,
            Self::AgentRun { .. } => ClaimSource::Generated,
        }
    }

    /// Generated sources need an explicit Gate permit for `Auto`, so
    /// agent-run LEDGER events park as `Proposed` — the same stance as the
    /// OF-320 code-run dispatcher for first-party generated effects.
    pub(super) fn approval_status(&self) -> ClaimApprovalStatus {
        match self {
            Self::UserUpload => ClaimApprovalStatus::Auto,
            Self::AgentRun { .. } => ClaimApprovalStatus::Proposed,
        }
    }
}

pub(super) fn validate_provenance(provenance: &BlobVersionProvenance) -> Result<()> {
    if let BlobVersionProvenance::AgentRun { run_ref } = provenance {
        validate_text_field(
            run_ref,
            BLOB_ARTIFACT_RUN_REF_MAX_BYTES,
            "run_ref must be non-empty and at most 1024 bytes",
        )?;
        if run_ref.trim().is_empty() {
            return Err(Error::InvalidBlobArtifactBody(
                "run_ref must be non-empty and at most 1024 bytes",
            ));
        }
        secret_scan::scan_metadata_field(run_ref)?;
    }
    Ok(())
}

pub(super) fn blob_version_claim_value(
    version: u64,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    provenance: &BlobVersionProvenance,
) -> Value {
    let mut entries = vec![
        (Value::from(KEY_VERSION), Value::Integer(version.into())),
        (
            Value::from(KEY_CONTENT_HASH),
            Value::Binary(content_hash.to_vec()),
        ),
        (
            Value::from(KEY_PROVENANCE),
            Value::from(provenance.as_str()),
        ),
    ];
    if let Some(run_ref) = provenance.run_ref() {
        entries.push((Value::from(KEY_RUN_REF), Value::from(run_ref)));
    }
    Value::Map(entries)
}

pub(super) fn write_provenance_value(provenance: &BlobVersionProvenance) -> Value {
    let mut entries = vec![
        (Value::from("surface"), Value::from("blob_artifact")),
        (Value::from("op"), Value::from("append_version")),
    ];
    if let Some(run_ref) = provenance.run_ref() {
        entries.push((Value::from(KEY_RUN_REF), Value::from(run_ref)));
    }
    Value::Map(entries)
}
