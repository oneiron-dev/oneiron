//! Blob version provenance: producer enum and claim-envelope value constructors.

use rmpv::Value;

use crate::batch::secret_scan;
use crate::error::{Error, Result};
use oneiron_contracts::claim::{ClaimApprovalStatus, ClaimSource};

use super::body::validate_text_field;
use super::store_keys::{BLOB_ARTIFACT_CONTENT_HASH_LEN, BLOB_ARTIFACT_RUN_REF_MAX_BYTES};
use super::versions::{
    CalcEngineStamp, KEY_CALC_ENGINE, KEY_CALC_ENGINE_VERSION, KEY_CONTENT_HASH,
    KEY_FORK_OF_VERSION, KEY_MADE_BY, KEY_PARENT_VERSION, KEY_PROVENANCE, KEY_RUN_REF, KEY_VERSION,
};
use crate::error::ArtifactError;

pub(super) const BLOB_VERSION_CLAIM_PREDICATE: &str = "blob.version";

const PROVENANCE_USER_UPLOAD: &str = "user_upload";

const PROVENANCE_AGENT_RUN: &str = "agent_run";

const PROVENANCE_QUEUE_CHECK: &str = "queue_check";

/// Who produced one blob artifact version: a direct user upload, an agent
/// run identified by its stable run reference, or a queue-check completion
/// holding actual execution exhaust (FIX 7227).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlobVersionProvenance {
    UserUpload,
    /// Bearer-authorized input is user-stated data, not an authenticated
    /// owner assertion. The blob-version claim remains Proposed.
    CapabilityUpload,
    AgentRun {
        run_ref: String,
    },
    /// Actual queue-check exhaust bytes, completed in the finish writer.
    /// `check_ref` reuses the existing `run_ref` record key (no new key).
    QueueCheck {
        check_ref: String,
    },
}

impl BlobVersionProvenance {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UserUpload => PROVENANCE_USER_UPLOAD,
            Self::CapabilityUpload => "capability_upload",
            Self::AgentRun { .. } => PROVENANCE_AGENT_RUN,
            Self::QueueCheck { .. } => PROVENANCE_QUEUE_CHECK,
        }
    }

    #[must_use]
    pub fn run_ref(&self) -> Option<&str> {
        match self {
            Self::UserUpload | Self::CapabilityUpload => None,
            Self::AgentRun { run_ref } => Some(run_ref),
            Self::QueueCheck { check_ref } => Some(check_ref),
        }
    }

    pub(super) fn from_parts(kind: &str, run_ref: Option<String>) -> Result<Self> {
        match (kind, run_ref) {
            (PROVENANCE_USER_UPLOAD, None) => Ok(Self::UserUpload),
            ("capability_upload", None) => Ok(Self::CapabilityUpload),
            (PROVENANCE_AGENT_RUN, Some(run_ref)) => Ok(Self::AgentRun { run_ref }),
            (PROVENANCE_QUEUE_CHECK, Some(check_ref)) => Ok(Self::QueueCheck { check_ref }),
            _ => Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "provenance must be user_upload without run_ref or agent_run/queue_check with run_ref",
            ))),
        }
    }

    pub(super) fn claim_source(&self) -> ClaimSource {
        match self {
            Self::UserUpload | Self::CapabilityUpload => ClaimSource::UserStated,
            Self::AgentRun { .. } | Self::QueueCheck { .. } => ClaimSource::Generated,
        }
    }

    /// Generated sources need an explicit Gate permit for `Auto`, so
    /// agent-run LEDGER events park as `Proposed` — the same stance as the
    /// OF-320 code-run dispatcher for first-party generated effects.
    /// Queue-check exhaust parks the same way (no invented Auto).
    pub(super) fn approval_status(&self) -> ClaimApprovalStatus {
        match self {
            Self::UserUpload => ClaimApprovalStatus::Auto,
            Self::CapabilityUpload | Self::AgentRun { .. } | Self::QueueCheck { .. } => {
                ClaimApprovalStatus::Proposed
            }
        }
    }
}

pub(super) fn validate_provenance(provenance: &BlobVersionProvenance) -> Result<()> {
    let check_ref = match provenance {
        BlobVersionProvenance::AgentRun { run_ref } => Some(run_ref),
        BlobVersionProvenance::QueueCheck { check_ref } => Some(check_ref),
        _ => None,
    };
    if let Some(check_ref) = check_ref {
        validate_text_field(
            check_ref,
            BLOB_ARTIFACT_RUN_REF_MAX_BYTES,
            "run_ref must be non-empty and at most 1024 bytes",
        )?;
        if check_ref.trim().is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "run_ref must be non-empty and at most 1024 bytes",
            )));
        }
        secret_scan::scan_metadata_field(check_ref)?;
    }
    Ok(())
}

pub(super) fn blob_version_claim_value(
    version: u64,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    provenance: &BlobVersionProvenance,
    parent_version: Option<u64>,
    fork_of_version: Option<u64>,
    calc_engine: Option<&CalcEngineStamp>,
    made_by: &str,
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
    entries.push((
        Value::from(KEY_CALC_ENGINE),
        calc_engine.map_or(Value::Nil, |s| Value::from(s.engine())),
    ));
    entries.push((
        Value::from(KEY_CALC_ENGINE_VERSION),
        calc_engine.map_or(Value::Nil, |s| Value::from(s.version())),
    ));
    if let Some(run_ref) = provenance.run_ref() {
        entries.push((Value::from(KEY_RUN_REF), Value::from(run_ref)));
    }
    entries.push((Value::from(KEY_MADE_BY), Value::from(made_by)));
    if let Some(parent) = parent_version {
        entries.push((
            Value::from(KEY_PARENT_VERSION),
            Value::Integer(parent.into()),
        ));
    }
    if let Some(fork) = fork_of_version {
        entries.push((
            Value::from(KEY_FORK_OF_VERSION),
            Value::Integer(fork.into()),
        ));
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
