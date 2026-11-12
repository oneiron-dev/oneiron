//! Moved from `crates/oneiron/src/office_body/verbs.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::office_body::consent::SettleVerdict;
use crate::office_body::docx::DocxBodyOp;
use crate::office_body::xlsx::XlsxBodyOp;
use oneiron_docedit::live::ApproveScope;
use oneiron_docedit::live::DeckOp;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeSet;

/// `vault.artifacts.body.head`: the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyArtifactRequest {
    pub artifact_ref: String,
}

/// `vault.artifacts.body.commits`: the artifact, and the one actor whose
/// commits are wanted, when only theirs are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyCommitsRequest {
    pub artifact_ref: String,
    #[serde(default)]
    pub actor_ref: Option<String>,
}

/// `vault.artifacts.body.import`: one DOCX, XLSX or PPTX version (the head
/// when `version` is absent) imported as the artifact's live body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyImportRequest {
    pub artifact_ref: String,
    #[serde(default)]
    pub version: Option<u64>,
    /// The import commit's envelope; absent, the caller's own.
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
}

/// `vault.artifacts.body.read`: the typed body at its head, or at an earlier
/// frontier of its history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyReadRequest {
    pub artifact_ref: String,
    #[serde(default)]
    pub at: Option<Vec<u8>>,
    /// Why an agent needs the lifted secrets the body's text holds: with
    /// it, the body reads whole for that agent once a grant covers their
    /// keys, for this read alone, and its ask goes to the owner otherwise.
    #[serde(default)]
    pub why: Option<String>,
}

/// One call's typed operations, in the body's format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum OfficeBodyOps {
    Docx { ops: Vec<DocxBodyOp> },
    Xlsx { ops: Vec<XlsxBodyOp> },
    Pptx { ops: Vec<DeckOp> },
}

/// `vault.artifacts.body.edit`: a person's operations on the live body, read
/// against `base` (the head when absent).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyEditRequest {
    pub artifact_ref: String,
    #[serde(default)]
    pub base: Option<Vec<u8>>,
    pub ops: OfficeBodyOps,
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
}

/// `vault.artifacts.body.fork.open`: a fork of the live body for machine work.
/// A DOCX or XLSX fork joins `proposal_ref`, an unsettled proposal by id;
/// absent, it opens its own under the fork's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyForkOpenRequest {
    pub artifact_ref: String,
    #[serde(default)]
    pub proposal_ref: Option<String>,
}

/// `vault.artifacts.body.fork.diff` and `.discard`: one fork of the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyForkRequest {
    pub artifact_ref: String,
    pub fork_ref: String,
}

/// `vault.artifacts.body.fork.edit`: the opener's operations on its fork.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyForkEditRequest {
    pub artifact_ref: String,
    pub fork_ref: String,
    pub ops: OfficeBodyOps,
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
}

/// `vault.artifacts.body.fork.merge`: land a reviewed fork, naming the live
/// head and the fork head the review read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyForkMergeRequest {
    pub artifact_ref: String,
    pub fork_ref: String,
    pub reviewed_head: Vec<u8>,
    /// The diff's `fork_head`.
    pub reviewed_fork: Vec<u8>,
}

/// `vault.artifacts.body.proposal.read`: one office proposal on the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyProposalRequest {
    pub artifact_ref: String,
    pub proposal_ref: String,
}

/// One member fork as the review read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyReviewedFork {
    /// The member artifact this fork edits.
    pub artifact_ref: String,
    pub fork_ref: String,
    /// The live head on that artifact that its diff read.
    pub reviewed_head: Vec<u8>,
    /// The fork's diff's `fork_head`.
    pub reviewed_fork: Vec<u8>,
}

/// `vault.artifacts.body.proposal.settle`: answer the reviewed members of a
/// proposal that `scope` covers (absent, the proposal itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyProposalSettleRequest {
    pub artifact_ref: String,
    pub proposal_ref: String,
    pub verdict: SettleVerdict,
    #[serde(default)]
    pub scope: Option<ApproveScope>,
    pub reviewed: Vec<OfficeBodyReviewedFork>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// `vault.artifacts.body.export`: project the body onto its imported package
/// and land it as the artifact's next version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyExportVerbRequest {
    pub artifact_ref: String,
    pub run_ref: String,
    /// The revision author a DOCX export shows; absent, the caller's id.
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
    /// The caller's offset east of UTC now: a workbook's TODAY() and NOW()
    /// read local time there. Absent, UTC.
    #[serde(default)]
    pub utc_offset_minutes: Option<i16>,
    /// The IANA zone that offset was read from, kept as a label.
    #[serde(default)]
    pub iana_timezone: Option<String>,
}

/// `vault.artifacts.body.preview`: the artifact, and the caller's local
/// time, as an export takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyPreviewRequest {
    pub artifact_ref: String,
    #[serde(default)]
    pub utc_offset_minutes: Option<i16>,
    #[serde(default)]
    pub iana_timezone: Option<String>,
}
