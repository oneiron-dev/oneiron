//! `vault.artifacts.body.*`: the live office body doors as agent verbs
//! (ARCH-0075, "An agent authors through the SDK"). Each binds the facade's
//! actor and reads the artifact through the facade's admission. Reads and the
//! three-way diff take any reader. Live edits stay a person's; machine work
//! opens a fork, which joins a proposal, and lands on a person's word from
//! outside its opener's lineage or on a standing grant (CALLS "OF-505 slice
//! D"). A deck reads, edits and forks through these rows too; its review,
//! merge, export and gate are `vault.artifacts.body.deck.*` (`pptx::verbs`).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    BodyBlockKind, BodyCell, BodyName, DeckBodyView, DocxBody, DocxBodyOp, OfficeBodyDiff,
    OfficeBodyEdit, OfficeBodyExportRecord, OfficeBodyExportRequest, OfficeBodyFork,
    OfficeBodyHead, OfficeBodyKind, OfficeBodyProposal, OfficeRecalcZone, ProposalSettleRequest,
    ReviewedFork, SettleVerdict, XlsxArea, XlsxBody, XlsxBodyOp, XlsxPreview, XlsxStyle,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess};
use crate::provenance::text_commit::TextCommitReceipt;
use crate::write_envelope::WriteActor;
use oneiron_docedit::docx_body::DocxRun;
use oneiron_docedit::live::{ApproveScope, DeckOp};

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

/// One commit of a live body, in commit order: who made it and its receipt,
/// or why it names no one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyCommitView {
    /// The actor whose receipt it carries; `None` when it carries none.
    pub actor: Option<String>,
    pub receipt: Option<TextCommitReceipt>,
    /// Why `actor` is `None`.
    pub reason: Option<OfficeBodyCommitGap>,
}

/// Why a body commit names no actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeBodyCommitGap {
    /// It carries no receipt the engine honours.
    ReceiptMissing,
}

impl OfficeBodyCommitView {
    pub(super) fn of(receipt: Option<TextCommitReceipt>) -> Self {
        match receipt {
            Some(receipt) => Self {
                actor: Some(receipt.made_by.process.actor.to_hex()),
                receipt: Some(receipt),
                reason: None,
            },
            None => Self {
                actor: None,
                receipt: None,
                reason: Some(OfficeBodyCommitGap::ReceiptMissing),
            },
        }
    }
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

/// `vault.artifacts.body.fork.open`: a fork of the live body for machine work
/// in the run `run_root_ref`. A DOCX or XLSX fork joins `proposal_ref`, an
/// unsettled proposal on the same artifact; absent, it opens its own under
/// the fork's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeBodyForkOpenRequest {
    pub artifact_ref: String,
    #[serde(default)]
    pub run_root_ref: Option<String>,
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
    pub fork_ref: String,
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
    /// The live head every reviewed diff was read at.
    pub reviewed_head: Vec<u8>,
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

/// One DOCX table cell's text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxCellView {
    pub row: usize,
    pub col: usize,
    pub text: String,
}

/// One DOCX block, its table cells listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxBlockView {
    pub id: String,
    pub kind: BodyBlockKind,
    pub role: Option<String>,
    pub imported: bool,
    pub locked: bool,
    pub text: String,
    /// The paragraph's text as runs of one mark set each.
    pub runs: Vec<DocxRun>,
    pub cells: Vec<DocxCellView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxBodyView {
    pub blocks: Vec<DocxBlockView>,
}

/// One sheet, its cells in row-major order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XlsxSheetView {
    pub name: String,
    pub cells: Vec<BodyCell>,
    pub locked: Vec<XlsxArea>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XlsxBodyView {
    pub date1904: bool,
    pub sheets: Vec<XlsxSheetView>,
    pub names: Vec<BodyName>,
    pub styles: Vec<XlsxStyle>,
}

/// `vault.artifacts.body.read`: the typed body, by format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum OfficeBodyView {
    Docx { body: DocxBodyView },
    Xlsx { body: XlsxBodyView },
    Pptx { body: DeckBodyView },
}

/// `vault.artifacts.body.export`: the frontier exported, and the version's
/// record; no record when the body equals its import and nothing landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyExportView {
    pub frontier: Vec<u8>,
    pub record: Option<OfficeBodyExportRecord>,
}

impl From<DocxBody> for DocxBodyView {
    fn from(body: DocxBody) -> Self {
        Self {
            blocks: body
                .blocks
                .into_iter()
                .map(|block| DocxBlockView {
                    id: block.id,
                    kind: block.kind,
                    role: block.role,
                    imported: block.imported,
                    locked: block.locked,
                    text: block.text,
                    runs: block.runs,
                    cells: block
                        .cells
                        .into_iter()
                        .map(|((row, col), text)| DocxCellView { row, col, text })
                        .collect(),
                })
                .collect(),
        }
    }
}

impl From<XlsxBody> for XlsxBodyView {
    fn from(body: XlsxBody) -> Self {
        Self {
            date1904: body.date1904,
            sheets: body
                .sheets
                .into_iter()
                .map(|sheet| XlsxSheetView {
                    name: sheet.name,
                    cells: sheet.cells.into_values().collect(),
                    locked: sheet.locked,
                })
                .collect(),
            names: body.names.into_values().collect(),
            styles: body.styles,
        }
    }
}

fn invalid(reason: &str) -> MemoryError {
    MemoryError::bad_request(reason.to_owned())
}

impl Memory<'_> {
    pub(super) fn body_actor(&self) -> WriteActor {
        WriteActor::new(self.actor(), self.actor_class())
    }

    pub(super) fn body_ref(&self, reference: &str) -> MemoryResult<EntityId> {
        crate::memory::resolve_entity_ref(self.vault(), reference)
    }

    /// The caller's envelope, or its own: this actor as the process, stated
    /// by a person and concluded by a machine, under `identity`.
    pub(super) fn body_made_by(
        &self,
        made_by: Option<&serde_json::Value>,
        identity: &str,
    ) -> MemoryResult<MadeBy> {
        if let Some(value) = made_by.filter(|value| !value.is_null()) {
            return serde_json::from_value(value.clone())
                .map_err(|_| invalid("made_by is not a valid envelope"));
        }
        let actor = self.body_actor();
        Ok(MadeBy {
            inputs: Vec::new(),
            process: MadeByProcess {
                actor: actor.entity_ref(),
                class: if actor.actor_class() == EdgeActorClass::Human {
                    MadeByClass::Stated
                } else {
                    MadeByClass::Concluded
                },
                identity: identity.to_owned(),
                version: "1".to_owned(),
                params_hash: format!("{:x}", Sha256::digest([])),
            },
            at: self.vault().now_recorded_at(),
            trigger: None,
        })
    }

    /// `vault.artifacts.body.import`.
    pub fn artifacts_body_import(
        &self,
        input: &OfficeBodyImportRequest,
    ) -> MemoryResult<OfficeBodyHead> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let made_by = self.body_made_by(input.made_by.as_ref(), "office_body.import")?;
        Ok(self.vault().import_office_body(
            &artifact,
            input.version,
            self.body_actor(),
            &made_by,
        )?)
    }

    /// `vault.artifacts.body.head`: the body's source, frontiers and commit
    /// count; `None` when the artifact has no live body.
    pub fn artifacts_body_head(
        &self,
        input: &OfficeBodyArtifactRequest,
    ) -> MemoryResult<Option<OfficeBodyHead>> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        Ok(self.vault().office_body_head(&artifact)?)
    }

    /// `vault.artifacts.body.read`: the body in its format.
    pub fn artifacts_body_read(
        &self,
        input: &OfficeBodyReadRequest,
    ) -> MemoryResult<OfficeBodyView> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let head = self
            .vault()
            .office_body_head(&artifact)?
            .ok_or_else(|| MemoryError::not_found("the artifact has no live body"))?;
        let at = input.at.as_deref();
        Ok(match head.kind {
            OfficeBodyKind::Docx => OfficeBodyView::Docx {
                body: self.vault().read_docx_body(&artifact, at)?.into(),
            },
            OfficeBodyKind::Xlsx => OfficeBodyView::Xlsx {
                body: self.vault().read_xlsx_body(&artifact, at)?.into(),
            },
            OfficeBodyKind::Pptx => OfficeBodyView::Pptx {
                body: self.vault().read_pptx_body(&artifact, at)?.into(),
            },
        })
    }

    /// `vault.artifacts.body.commits`: every commit, in commit order, with
    /// its actor and receipt, or why it has none; with `actor_ref`, that
    /// actor's alone.
    pub fn artifacts_body_commits(
        &self,
        input: &OfficeBodyCommitsRequest,
    ) -> MemoryResult<Vec<OfficeBodyCommitView>> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let actor = input
            .actor_ref
            .as_deref()
            .map(|actor| self.body_ref(actor))
            .transpose()?;
        Ok(self
            .vault()
            .office_body_commits(&artifact, actor.as_ref())?)
    }

    /// `vault.artifacts.body.edit`: a person's live edit.
    pub fn artifacts_body_edit(
        &self,
        input: &OfficeBodyEditRequest,
    ) -> MemoryResult<OfficeBodyEdit> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let made_by = self.body_made_by(input.made_by.as_ref(), "office_body.edit")?;
        let base = input.base.as_deref();
        let actor = self.body_actor();
        Ok(match &input.ops {
            OfficeBodyOps::Docx { ops } => self
                .vault()
                .edit_docx_body(&artifact, base, ops, actor, &made_by)?,
            OfficeBodyOps::Xlsx { ops } => self
                .vault()
                .edit_xlsx_body(&artifact, base, ops, actor, &made_by)?,
            OfficeBodyOps::Pptx { ops } => self
                .vault()
                .edit_pptx_body(&artifact, base, ops, actor, &made_by)?,
        })
    }

    /// `vault.artifacts.body.fork.open`.
    pub fn artifacts_body_fork_open(
        &self,
        input: &OfficeBodyForkOpenRequest,
    ) -> MemoryResult<OfficeBodyFork> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let run_root = input
            .run_root_ref
            .as_deref()
            .map(|reference| self.body_ref(reference))
            .transpose()?;
        let proposal = input
            .proposal_ref
            .as_deref()
            .map(|reference| self.body_ref(reference))
            .transpose()?;
        Ok(self.vault().open_office_body_fork(
            &artifact,
            self.body_actor(),
            run_root.as_ref(),
            proposal.as_ref(),
        )?)
    }

    /// `vault.artifacts.body.fork.edit`: the opener's operations.
    pub fn artifacts_body_fork_edit(
        &self,
        input: &OfficeBodyForkEditRequest,
    ) -> MemoryResult<OfficeBodyEdit> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let fork = self.body_ref(&input.fork_ref)?;
        let made_by = self.body_made_by(input.made_by.as_ref(), "office_body.fork_edit")?;
        let actor = self.body_actor();
        Ok(match &input.ops {
            OfficeBodyOps::Docx { ops } => self
                .vault()
                .edit_docx_body_fork(&artifact, &fork, ops, actor, &made_by)?,
            OfficeBodyOps::Xlsx { ops } => self
                .vault()
                .edit_xlsx_body_fork(&artifact, &fork, ops, actor, &made_by)?,
            OfficeBodyOps::Pptx { ops } => self
                .vault()
                .edit_pptx_body_fork(&artifact, &fork, ops, actor, &made_by)?,
        })
    }

    /// `vault.artifacts.body.fork.diff`: the fork's three-way read against the
    /// live head.
    pub fn artifacts_body_fork_diff(
        &self,
        input: &OfficeBodyForkRequest,
    ) -> MemoryResult<OfficeBodyDiff> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let fork = self.body_ref(&input.fork_ref)?;
        Ok(self.vault().office_body_fork_diff(&artifact, &fork)?)
    }

    /// `vault.artifacts.body.fork.merge`: lands one reviewed fork, its
    /// proposal settled for that item: on the caller's word when the caller is
    /// a person outside the opener's lineage, else on a standing grant.
    pub fn artifacts_body_fork_merge(
        &self,
        input: &OfficeBodyForkMergeRequest,
    ) -> MemoryResult<OfficeBodyDiff> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let fork = self.body_ref(&input.fork_ref)?;
        Ok(self.vault().merge_office_body_fork(
            &artifact,
            &fork,
            (&input.reviewed_head, &input.reviewed_fork),
            self.body_actor(),
        )?)
    }

    /// `vault.artifacts.body.proposal.read`.
    pub fn artifacts_body_proposal_read(
        &self,
        input: &OfficeBodyProposalRequest,
    ) -> MemoryResult<OfficeBodyProposal> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let proposal = self.body_ref(&input.proposal_ref)?;
        self.vault()
            .office_body_proposal(&artifact, &proposal)?
            .ok_or_else(|| MemoryError::not_found("no such proposal on the artifact"))
    }

    /// `vault.artifacts.body.proposal.settle`: the proposal after the answer.
    pub fn artifacts_body_proposal_settle(
        &self,
        input: &OfficeBodyProposalSettleRequest,
    ) -> MemoryResult<OfficeBodyProposal> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let proposal = self.body_ref(&input.proposal_ref)?;
        let reviewed = input
            .reviewed
            .iter()
            .map(|pin| {
                Ok(ReviewedFork {
                    fork: self.body_ref(&pin.fork_ref)?,
                    fork_head: pin.reviewed_fork.clone(),
                })
            })
            .collect::<MemoryResult<Vec<_>>>()?;
        let request = ProposalSettleRequest {
            verdict: input.verdict,
            scope: input.scope.clone(),
            head: &input.reviewed_head,
            reviewed: &reviewed,
            reason: input.reason.as_deref(),
        };
        Ok(self.vault().settle_office_body_proposal(
            &artifact,
            &proposal,
            &request,
            self.body_actor(),
        )?)
    }

    /// `vault.artifacts.body.fork.discard`: the discarded fork's record.
    pub fn artifacts_body_fork_discard(
        &self,
        input: &OfficeBodyForkRequest,
    ) -> MemoryResult<OfficeBodyFork> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let fork = self.body_ref(&input.fork_ref)?;
        self.vault()
            .discard_office_body_fork(&artifact, &fork, self.body_actor())?;
        self.vault()
            .office_body_fork(&artifact, &fork)?
            .ok_or_else(|| MemoryError::not_found("the fork is gone"))
    }

    /// `vault.artifacts.body.export`.
    pub fn artifacts_body_export(
        &self,
        input: &OfficeBodyExportVerbRequest,
    ) -> MemoryResult<OfficeBodyExportView> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let made_by = input
            .made_by
            .as_ref()
            .filter(|value| !value.is_null())
            .map(|value| self.body_made_by(Some(value), "office_body.export"))
            .transpose()?;
        let actor = self.body_actor();
        let author = match &input.author {
            Some(author) => author.clone(),
            None => actor.entity_ref().to_hex(),
        };
        let zone =
            OfficeRecalcZone::from_caller(input.utc_offset_minutes, input.iana_timezone.clone())?;
        let export = self.vault().export_office_body(
            &artifact,
            &OfficeBodyExportRequest {
                actor,
                author: &author,
                run_ref: &input.run_ref,
                made_by: made_by.as_ref(),
                zone: &zone,
            },
        )?;
        Ok(OfficeBodyExportView {
            frontier: export.frontier,
            record: export.record,
        })
    }

    /// `vault.artifacts.body.preview`: the workbook an export would land now,
    /// recalculated; nothing lands.
    pub fn artifacts_body_preview(
        &self,
        input: &OfficeBodyPreviewRequest,
    ) -> MemoryResult<XlsxPreview> {
        let artifact = self.body_ref(&input.artifact_ref)?;
        let zone =
            OfficeRecalcZone::from_caller(input.utc_offset_minutes, input.iana_timezone.clone())?;
        Ok(self.vault().preview_xlsx_body(&artifact, &zone)?)
    }
}
