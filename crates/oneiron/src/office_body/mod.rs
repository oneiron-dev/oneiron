//! Live office bodies (ARCH-0075; ARCH-0077, "Multiplayer: the target body
//! shape"): an imported DOCX, XLSX or PPTX as a typed model, edited together,
//! the file an export.
//!
//! People edit the live body. Machine work runs on a fork and lands as a
//! three-way diff. A DOCX or XLSX fork joins a proposal when it is opened, and
//! lands on a person's word from outside its opener's lineage or on a standing
//! grant ([`consent`]). Every commit keeps a MadeBy receipt over its exact
//! operations. An export projects the body onto
//! the imported package and lands it as a new version of the artifact, recorded
//! with the body frontier it projects.
//!
//! Every body is a Loro document on the entity-document plane's typed-body
//! door ([`crate::typed_body`], schemas `office.docx.v1`, `office.xlsx.v1` and
//! `office.pptx.v1`), which keeps its commits and receipts. A DOCX export
//! lands as one tracked revision. An XLSX body is a map keyed by sheet and
//! address; its export writes the changed cells and names and recalculates in
//! process, and [`Vault::preview_xlsx_body`] shows the recalculated values
//! without landing a version. DOCX and XLSX forks are typed-body forks.
//!
//! A PPTX body is the OF-510 live deck: one tree with a rich-text body per
//! text shape, whose concurrent edits merge and must still keep the deck's
//! tree rules. Its machine work runs on a deck fork kept in this module's
//! tables and lands through the deck preflight, and its export stays a
//! proposal artifact until the deck export gate opens. Erasing the artifact
//! erases its office rows ([`erase_in_txn`]).

mod consent;
mod docx;
mod fork;
mod holder_ask;
mod pptx;
mod verbs;
mod xlsx;

pub(crate) use consent::MergeAdmission;
pub use consent::{
    AnsweringAuthority, BundleVerdict, MemberAnswer, MemberVerdict, OFFICE_BODY_EDIT_CLASS,
    OfficeBodyProposal, ProposalAsk, ProposalHeader, ProposalMember, ProposalSettleRequest,
    ProposalSettlement, ReviewedFork, SettleVerdict,
};
pub use docx::{BodyBlock, BodyBlockKind, DocxBody, DocxBodyOp};
pub use fork::{BlockChange, BodyConflict, ChangeKind, ConflictKind, OfficeBodyDiff};
pub use oneiron_docedit::live::LandingReceipt;
pub use oneiron_docedit::xlsx_body::{XlsxArea, XlsxBook, XlsxLock, XlsxStyle, XlsxValue};
pub(crate) use pptx::live_refused;
pub use pptx::{
    DeckBodyView, DeckExportRequest, DeckExportView, DeckForkMergeRequest, DeckGateRequest,
    DeckGateView, DeckNodeView, DeckOracleRequest, DeckPreview, DeckPreviewRequest,
    DeckPreviewSlide, DeckReviewView, PptxBody, PptxExport, PptxReview,
};
pub use verbs::{
    DocxBlockView, DocxBodyView, DocxCellView, OfficeBodyArtifactRequest, OfficeBodyCommitGap,
    OfficeBodyCommitView, OfficeBodyCommitsRequest, OfficeBodyEditRequest,
    OfficeBodyExportVerbRequest, OfficeBodyExportView, OfficeBodyForkEditRequest,
    OfficeBodyForkMergeRequest, OfficeBodyForkOpenRequest, OfficeBodyForkRequest,
    OfficeBodyImportRequest, OfficeBodyOps, OfficeBodyPreviewRequest, OfficeBodyProposalRequest,
    OfficeBodyProposalSettleRequest, OfficeBodyReadRequest, OfficeBodyReviewedFork, OfficeBodyView,
    XlsxBodyView, XlsxSheetView,
};
pub use xlsx::{BodyCell, BodyFormat, BodyName, BodySheet, XlsxBody, XlsxBodyOp};

use crate::Vault;
use crate::blob_artifact::{BlobArtifactVersion, BlobVersionProvenance, CalcEngineStamp};
use crate::edge::EdgeActorClass;
use crate::edit_roundtrip::OfficeFormat;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::made_by::MadeBy;
use crate::provenance::text_commit::TextCommitReceipt;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::typed_body::{
    TypedBodyFork, TypedBodyHead, TypedBodyWriter, TypedForkState, birth_typed_body_in_txn,
    discard_typed_body_fork_in_txn, edit_typed_body_fork_in_txn, edit_typed_body_in_txn,
    open_typed_body_fork_in_txn, typed_body_fork_in_txn, typed_body_in_txn,
};
use crate::write_envelope::WriteActor;
use heed::{RoTxn, RwTxn};
use loro::LoroDoc;
use oneiron_docedit::ArchiveLimits;
use oneiron_docedit::docx_body::{DocxRevision, project_docx, read_docx_blocks};
use oneiron_docedit::retained_opc::Limits;
use oneiron_docedit::xlsx_body::{mark_full_calc, project_xlsx, read_xlsx_cells};
use oneiron_xlsx_formula::RecalcClock;
use oneiron_xlsx_formula::engine::FormualizerEngine;
use serde::{Deserialize, Serialize};

/// Each artifact's office facts: its format and the version it imported.
const SOURCES: SideTable<EntityId, OfficeBodySource, Named> =
    SideTable::new(&side_table::OFFICE_BODY_HEAD);
/// Deck forks' office records (the run each belongs to), by artifact and
/// fork; the fork's document is its typed-body fork.
const FORKS: SideTable<(EntityId, EntityId), OfficeBodyFork, Named> =
    SideTable::new(&side_table::OFFICE_BODY_FORK);
const EXPORTS: SideTable<Vec<u8>, OfficeBodyExportRecord, Named> =
    SideTable::new(&side_table::OFFICE_BODY_EXPORT);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeBodyKind {
    Docx,
    Xlsx,
    Pptx,
}

impl OfficeBodyKind {
    /// The body's typed-body schema tag.
    fn schema(self) -> &'static str {
        match self {
            Self::Docx => "office.docx.v1",
            Self::Xlsx => "office.xlsx.v1",
            Self::Pptx => "office.pptx.v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OfficeBodySource {
    kind: OfficeBodyKind,
    source_version: u64,
    source_hash: [u8; 32],
}

/// One artifact's live body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyHead {
    pub artifact: EntityId,
    pub kind: OfficeBodyKind,
    /// The imported version every export projects onto.
    pub source_version: u64,
    pub source_hash: [u8; 32],
    /// The body as imported: every export's base.
    pub import_frontier: Vec<u8>,
    pub frontier: Vec<u8>,
    /// Commits on the body so far, merged forks' included.
    pub commits: u64,
}

/// One call's commit: the new frontier, the ids it minted in operation order
/// (paragraphs, deck nodes; none for a workbook), and its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyEdit {
    pub frontier: Vec<u8>,
    pub minted: Vec<String>,
    pub receipt: TextCommitReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ForkState {
    Open,
    Merged {
        by: EntityId,
        at: u64,
        head: Vec<u8>,
    },
    Discarded {
        by: EntityId,
        at: u64,
    },
}

/// Machine work on a body: opened at a live frontier, written only by its opener,
/// merged by someone else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyFork {
    pub id: EntityId,
    pub artifact: EntityId,
    pub opener: EntityId,
    pub base: Vec<u8>,
    pub commits: u64,
    pub opened_at: u64,
    pub state: ForkState,
    /// The run the fork belongs to, whose approve-all scope covers it.
    #[serde(default)]
    pub run_root: Option<EntityId>,
}

pub struct OfficeBodyExportRequest<'a> {
    pub actor: WriteActor,
    /// The revision author a DOCX export shows; recorded for every export.
    pub author: &'a str,
    pub run_ref: &'a str,
    /// The envelope the export version carries; `None` gives it the
    /// exporter's own.
    pub made_by: Option<&'a MadeBy>,
    /// The local time a workbook recalculates at.
    pub zone: &'a OfficeRecalcZone,
}

/// The local time a workbook export or preview recalculates TODAY() and
/// NOW() at, as the caller's device knows it: its offset east of UTC now,
/// and the IANA zone it read that from, kept as a label. The vault keeps no
/// owner zone; a caller that names none gets the default, UTC (FIX 790).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OfficeRecalcZone {
    pub utc_offset_minutes: i16,
    pub iana_timezone: Option<String>,
}

impl OfficeRecalcZone {
    /// The caller's zone, checked as an outbound schedule's is: a zone label
    /// comes with its offset, and an offset is within ±14 hours.
    pub fn from_caller(
        utc_offset_minutes: Option<i16>,
        iana_timezone: Option<String>,
    ) -> Result<Self> {
        if iana_timezone.is_some() && utc_offset_minutes.is_none() {
            return Err(invalid("iana_timezone requires utc_offset_minutes"));
        }
        let utc_offset_minutes = utc_offset_minutes.unwrap_or_default();
        if !(-840..=840).contains(&utc_offset_minutes) {
            return Err(invalid("utc_offset_minutes must be in -840..=840"));
        }
        if iana_timezone.as_deref().is_some_and(|label| {
            label.trim().is_empty() || label.chars().any(char::is_control) || label.len() > 255
        }) {
            return Err(invalid(
                "iana_timezone must be non-blank and contain no controls",
            ));
        }
        Ok(Self {
            utc_offset_minutes,
            iana_timezone,
        })
    }
}

/// An export version and the exact body it projects. The version keeps a
/// pointer to its body frontier, not a second body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyExportRecord {
    pub artifact: EntityId,
    pub version: u64,
    pub frontier: Vec<u8>,
    pub source_version: u64,
    pub actor: EntityId,
    pub author: String,
    pub at: u64,
    pub changes: u64,
    /// The engine that recalculated an XLSX export and the local time it
    /// read; `None` when the file recalculates on open, and for DOCX.
    pub recalc: Option<String>,
}

/// `version` is `None` when the body equals its import: a no-op keeps the
/// original package and lands nothing.
#[derive(Debug, Clone)]
pub struct OfficeBodyExport {
    pub frontier: Vec<u8>,
    pub version: Option<BlobArtifactVersion>,
    pub record: Option<OfficeBodyExportRecord>,
}

/// The workbook an XLSX export would land now, recalculated, read back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XlsxPreview {
    pub frontier: Vec<u8>,
    pub book: XlsxBook,
    /// The engine that recalculated it and the local time it read; `None`
    /// when it could not, and formula values are blank until the file is
    /// opened.
    pub recalc: Option<String>,
}

impl Vault {
    /// Import one DOCX, XLSX or PPTX version of `artifact` (the head when
    /// `version` is `None`) as its live body. One artifact has one body.
    pub fn import_office_body(
        &self,
        artifact: &EntityId,
        version: Option<u64>,
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<OfficeBodyHead> {
        let body = self
            .get_blob_artifact(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let kind = match OfficeFormat::from_media_type(&body.media_type)? {
            OfficeFormat::Docx => OfficeBodyKind::Docx,
            OfficeFormat::Xlsx => OfficeBodyKind::Xlsx,
            OfficeFormat::Pptx => OfficeBodyKind::Pptx,
        };
        let version = match version {
            Some(version) => version,
            None => {
                self.blob_artifact_head(artifact)?
                    .ok_or(Error::EntityNotFound)?
                    .version
            }
        };
        let bytes = self
            .read_blob_artifact_version(artifact, version)?
            .ok_or(Error::EntityNotFound)?;
        let source = OfficeBodySource {
            kind,
            source_version: version,
            source_hash: *blake3::hash(&bytes).as_bytes(),
        };
        let writer = writer(kind, actor, made_by);
        match kind {
            OfficeBodyKind::Docx => {
                let blocks = read_docx_blocks(&bytes, ArchiveLimits::DEFAULT)
                    .map_err(|_| invalid("the DOCX package could not be read"))?;
                self.with_write_txn_grouped(|wtxn| {
                    claim_source(&self.store, wtxn, artifact, &source)?;
                    birth_typed_body_in_txn(self, wtxn, artifact, writer, |doc| {
                        docx::import(doc, &blocks)
                    })
                    .map(drop)
                })?;
            }
            OfficeBodyKind::Xlsx => {
                let book = read_xlsx_cells(&bytes, self.docedit_package_limits()?)
                    .map_err(|_| invalid("the XLSX package could not be read"))?;
                self.with_write_txn_grouped(|wtxn| {
                    claim_source(&self.store, wtxn, artifact, &source)?;
                    birth_typed_body_in_txn(self, wtxn, artifact, writer, |doc| {
                        xlsx::import(doc, &book)
                    })
                    .map(drop)
                })?;
            }
            OfficeBodyKind::Pptx => {
                let deck = pptx::import_deck(&bytes, self.docedit_package_limits()?)?;
                self.with_write_txn_grouped(|wtxn| {
                    claim_source(&self.store, wtxn, artifact, &source)?;
                    birth_typed_body_in_txn(self, wtxn, artifact, writer, |doc| {
                        pptx::birth(doc, &deck)
                    })
                    .map(drop)
                })?;
            }
        }
        self.office_body_head(artifact)?
            .ok_or(Error::EntityNotFound)
    }

    pub fn office_body_head(&self, artifact: &EntityId) -> Result<Option<OfficeBodyHead>> {
        let txn = self.store.env.read_txn()?;
        if !SOURCES.contains(&self.store, &txn, artifact)? {
            return Ok(None);
        }
        self.head_in_txn(&txn, artifact).map(Some)
    }

    /// The typed body at its head, or at an earlier frontier of its history.
    pub fn read_docx_body(&self, artifact: &EntityId, at: Option<&[u8]>) -> Result<DocxBody> {
        let txn = self.store.env.read_txn()?;
        docx::read(&self.loro_body(&txn, artifact, OfficeBodyKind::Docx, at)?.1)
    }

    /// The typed workbook body at its head, or at an earlier frontier.
    pub fn read_xlsx_body(&self, artifact: &EntityId, at: Option<&[u8]>) -> Result<XlsxBody> {
        let txn = self.store.env.read_txn()?;
        xlsx::read(&self.loro_body(&txn, artifact, OfficeBodyKind::Xlsx, at)?.1)
    }

    /// Every commit of the body in commit order, a landed fork's included,
    /// each with its receipt. A commit with no honoured receipt is listed
    /// with no actor, never dropped. With `actor`, that actor's commits alone.
    pub fn office_body_commits(
        &self,
        artifact: &EntityId,
        actor: Option<&EntityId>,
    ) -> Result<Vec<OfficeBodyCommitView>> {
        Ok(self
            .typed_body_receipts(artifact)?
            .into_iter()
            .filter(|receipt| {
                actor.is_none_or(|actor| {
                    receipt
                        .as_ref()
                        .is_some_and(|receipt| receipt.made_by.process.actor == *actor)
                })
            })
            .map(OfficeBodyCommitView::of)
            .collect())
    }

    /// A person's operations on the live body. Operations read against an older
    /// `base` frontier apply there and merge into the head, as a CRDT peer's
    /// would; machine work goes through a fork instead.
    pub fn edit_docx_body(
        &self,
        artifact: &EntityId,
        base: Option<&[u8]>,
        ops: &[DocxBodyOp],
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<OfficeBodyEdit> {
        bounded_ops(ops.len())?;
        self.edit_live(
            artifact,
            OfficeBodyKind::Docx,
            base,
            (actor, made_by),
            |_, _| Ok(()),
            |doc| apply_all(doc, ops),
        )
    }

    /// A person's operations on a live workbook body, as [`Self::edit_docx_body`].
    /// A cell takes one value, so operations read against an older `base` that
    /// write a cell or name the head changed since refuse rather than lose
    /// either write.
    pub fn edit_xlsx_body(
        &self,
        artifact: &EntityId,
        base: Option<&[u8]>,
        ops: &[XlsxBodyOp],
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<OfficeBodyEdit> {
        bounded_ops(ops.len())?;
        self.edit_live(
            artifact,
            OfficeBodyKind::Xlsx,
            base,
            (actor, made_by),
            |base, head| xlsx::admit_at(base, head, ops),
            |doc| apply_xlsx(doc, ops),
        )
    }

    fn edit_live(
        &self,
        artifact: &EntityId,
        kind: OfficeBodyKind,
        base: Option<&[u8]>,
        (actor, made_by): (WriteActor, &MadeBy),
        admit: impl FnOnce(&LoroDoc, &LoroDoc) -> Result<()>,
        edit: impl FnOnce(&LoroDoc) -> Result<Vec<String>>,
    ) -> Result<OfficeBodyEdit> {
        if actor.actor_class() != EdgeActorClass::Human {
            return Err(invalid("machine work edits a fork, not the live body"));
        }
        self.with_write_txn_grouped(|wtxn| {
            if let Some(base) = base {
                let (_, live) = self.loro_body(wtxn, artifact, kind, None)?;
                let (_, target) = self.loro_body(wtxn, artifact, kind, Some(base))?;
                admit(&target, &live)?;
            }
            let writer = writer(kind, actor, made_by);
            let (minted, commit) =
                edit_typed_body_in_txn(self, wtxn, artifact, base, writer, edit)?;
            validate(kind, &self.loro_body(wtxn, artifact, kind, None)?.1)?;
            Ok(OfficeBodyEdit {
                frontier: commit.frontier,
                minted,
                receipt: commit.receipt,
            })
        })
    }

    /// Open a fork of the live body at its head for `actor`'s machine work in
    /// the run `run_root`, whose approve-all scope then covers it. A DOCX or
    /// XLSX fork joins `proposal`, an unsettled proposal on this artifact, or
    /// opens its own under the fork's id. A deck fork joins no proposal; it
    /// lands through the deck merge door.
    pub fn open_office_body_fork(
        &self,
        artifact: &EntityId,
        actor: WriteActor,
        run_root: Option<&EntityId>,
        proposal: Option<&EntityId>,
    ) -> Result<OfficeBodyFork> {
        self.with_write_txn_grouped(|wtxn| match source(&self.store, wtxn, artifact)?.kind {
            OfficeBodyKind::Pptx if proposal.is_some() => Err(invalid(
                "a deck fork joins no proposal; its run's approve scope covers it",
            )),
            OfficeBodyKind::Pptx => self.open_deck_fork(wtxn, artifact, actor, run_root),
            kind => {
                let record =
                    open_typed_body_fork_in_txn(self, wtxn, artifact, kind.schema(), actor)?;
                consent::join_in_txn(&self.store, wtxn, &record, run_root, proposal)?;
                let mut fork = fork_view(record);
                fork.run_root = run_root.copied();
                Ok(fork)
            }
        })
    }

    pub fn office_body_fork(
        &self,
        artifact: &EntityId,
        fork: &EntityId,
    ) -> Result<Option<OfficeBodyFork>> {
        let txn = self.store.env.read_txn()?;
        if source(&self.store, &txn, artifact)?.kind == OfficeBodyKind::Pptx {
            return FORKS.get(&self.store, &txn, &(*artifact, *fork));
        }
        let Some((record, _)) = typed_body_fork_in_txn(&self.store, &txn, artifact, fork)? else {
            return Ok(None);
        };
        let mut view = fork_view(record);
        view.run_root = consent::member_run_root(&self.store, &txn, artifact, fork)?;
        Ok(Some(view))
    }

    /// The opener's operations on its open fork of a DOCX body.
    pub fn edit_docx_body_fork(
        &self,
        artifact: &EntityId,
        fork: &EntityId,
        ops: &[DocxBodyOp],
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<OfficeBodyEdit> {
        bounded_ops(ops.len())?;
        self.edit_fork(
            (artifact, fork),
            OfficeBodyKind::Docx,
            (actor, made_by),
            |doc| apply_all(doc, ops),
        )
    }

    /// The opener's operations on its open fork of a workbook body.
    pub fn edit_xlsx_body_fork(
        &self,
        artifact: &EntityId,
        fork: &EntityId,
        ops: &[XlsxBodyOp],
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<OfficeBodyEdit> {
        bounded_ops(ops.len())?;
        self.edit_fork(
            (artifact, fork),
            OfficeBodyKind::Xlsx,
            (actor, made_by),
            |doc| apply_xlsx(doc, ops),
        )
    }

    fn edit_fork(
        &self,
        (artifact, fork): (&EntityId, &EntityId),
        kind: OfficeBodyKind,
        (actor, made_by): (WriteActor, &MadeBy),
        edit: impl FnOnce(&LoroDoc) -> Result<Vec<String>>,
    ) -> Result<OfficeBodyEdit> {
        self.with_write_txn_grouped(|wtxn| {
            if source(&self.store, wtxn, artifact)?.kind != kind {
                return Err(invalid("the artifact's live body is another format"));
            }
            let writer = writer(kind, actor, made_by);
            let (minted, commit) =
                edit_typed_body_fork_in_txn(self, wtxn, artifact, fork, writer, edit)?;
            let proposal = typed_body_fork_in_txn(&self.store, wtxn, artifact, fork)?
                .and_then(|(_, doc)| doc)
                .ok_or_else(|| invalid("the fork is not open"))?;
            validate(kind, &proposal)?;
            Ok(OfficeBodyEdit {
                frontier: commit.frontier,
                minted,
                receipt: commit.receipt,
            })
        })
    }

    /// The fork's proposal against the live head, read at both frontiers.
    pub fn office_body_fork_diff(
        &self,
        artifact: &EntityId,
        fork: &EntityId,
    ) -> Result<OfficeBodyDiff> {
        let txn = self.store.env.read_txn()?;
        let kind = loro_kind(&self.store, &txn, artifact)?;
        let (record, proposal) = open_fork(&self.store, &txn, artifact, fork)?;
        let (head, live) = self.loro_body(&txn, artifact, kind, None)?;
        three_way(kind, &live, &proposal, &record.base, &head.frontier)
    }

    /// Land one reviewed fork: its proposal settled for that one item
    /// ([`Self::settle_office_body_proposal`]). The reviewer names the live
    /// head and the fork head it read; a moved head, a fork edited since, a
    /// blocking conflict, or a merged body that no longer reads refuses. A
    /// fork nothing answers (a caller in the opener's lineage with no grant
    /// that covers it) refuses and keeps waiting.
    pub fn merge_office_body_fork(
        &self,
        artifact: &EntityId,
        fork: &EntityId,
        pins: (&[u8], &[u8]),
        actor: WriteActor,
    ) -> Result<OfficeBodyDiff> {
        self.merge_office_body_fork_or_wait(artifact, fork, pins, actor)?
            .map_err(|proposal| fork_waits(&proposal))
    }

    /// [`Self::merge_office_body_fork`], with the proposal a fork nothing
    /// answers waits in, in place of its refusal.
    pub(crate) fn merge_office_body_fork_or_wait(
        &self,
        artifact: &EntityId,
        fork: &EntityId,
        (expected_head, expected_fork): (&[u8], &[u8]),
        actor: WriteActor,
    ) -> Result<std::result::Result<OfficeBodyDiff, EntityId>> {
        self.with_write_txn_grouped(|wtxn| {
            loro_kind(&self.store, wtxn, artifact)?;
            let proposal = consent::proposal_of(&self.store, wtxn, artifact, fork)?;
            let reviewed = [ReviewedFork {
                fork: *fork,
                fork_head: expected_fork.to_vec(),
            }];
            let request = ProposalSettleRequest {
                verdict: SettleVerdict::Accept,
                scope: None,
                head: expected_head,
                reviewed: &reviewed,
                reason: None,
            };
            let (_, landed) =
                consent::settle_in_txn(self, wtxn, artifact, &proposal, &request, actor)?;
            Ok(landed
                .into_iter()
                .next()
                .map(|(_, diff)| diff)
                .ok_or(proposal))
        })
    }

    /// Abandon an open fork's unlanded work.
    pub fn discard_office_body_fork(
        &self,
        artifact: &EntityId,
        fork: &EntityId,
        actor: WriteActor,
    ) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            if source(&self.store, wtxn, artifact)?.kind == OfficeBodyKind::Pptx {
                return self.discard_deck_fork(wtxn, artifact, fork, actor);
            }
            discard_typed_body_fork_in_txn(self, wtxn, artifact, fork, actor)?;
            consent::let_go_in_txn(&self.store, wtxn, artifact, fork, self.now_recorded_at())
        })
    }

    /// Project the body onto its imported package and land it as the artifact's
    /// next version: a DOCX body as one tracked revision, an XLSX body as its
    /// changed cells and names, recalculated. The projection is deterministic
    /// in the body's content, the author and the export time; no vault ref (a
    /// frontier, an input hash) enters the file (OF-491). A deck exports
    /// through [`Self::export_pptx_body`].
    pub fn export_office_body(
        &self,
        artifact: &EntityId,
        request: &OfficeBodyExportRequest<'_>,
    ) -> Result<OfficeBodyExport> {
        if request.author.trim().is_empty()
            || request.author.len() > 256
            || request.run_ref.trim().is_empty()
            || request.run_ref.len() > 256
        {
            return Err(invalid("invalid office body export author or run"));
        }
        let head = self
            .office_body_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let at = self.now_recorded_at();
        let Some((bytes, changes, recalc)) =
            self.project_body(artifact, &head, request.author, at, request.zone)?
        else {
            return Ok(OfficeBodyExport {
                frontier: head.frontier,
                version: None,
                record: None,
            });
        };
        let provenance = if request.actor.actor_class() == EdgeActorClass::Human {
            BlobVersionProvenance::UserUpload
        } else {
            BlobVersionProvenance::AgentRun {
                run_ref: request.run_ref.to_owned(),
            }
        };
        self.with_write_txn_grouped(|wtxn| {
            if self.head_in_txn(wtxn, artifact)?.frontier != head.frontier {
                return Err(invalid("the body moved during the export; export again"));
            }
            // The version carries the calculator that computed its cached
            // values and the export's envelope (ARCH-0075 calculation;
            // ARCH-0078 made_by).
            let version = self.append_blob_artifact_version_with_engine_and_parent_in_txn(
                wtxn,
                artifact,
                &bytes,
                &provenance,
                recalc.as_ref(),
                request.actor,
                TimeRange { start: at, end: at },
                at,
                None,
                request.made_by,
            )?;
            let record = OfficeBodyExportRecord {
                artifact: *artifact,
                version: version.version,
                frontier: head.frontier.clone(),
                source_version: head.source_version,
                actor: request.actor.entity_ref(),
                author: request.author.to_owned(),
                at,
                changes: changes as u64,
                recalc: recalc
                    .as_ref()
                    .map(|stamp| recalc_label(stamp, request.zone)),
            };
            EXPORTS.put(
                &self.store,
                wtxn,
                &version_key(artifact, version.version),
                &record,
            )?;
            Ok(OfficeBodyExport {
                frontier: head.frontier.clone(),
                version: Some(version),
                record: Some(record),
            })
        })
    }

    /// The workbook an export would land now: the body projected onto its
    /// imported package and recalculated, then read back. Nothing lands.
    pub fn preview_xlsx_body(
        &self,
        artifact: &EntityId,
        zone: &OfficeRecalcZone,
    ) -> Result<XlsxPreview> {
        let head = self
            .office_body_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        if head.kind != OfficeBodyKind::Xlsx {
            return Err(invalid("the artifact's live body is another format"));
        }
        let at = self.now_recorded_at();
        let limits = self.docedit_package_limits()?;
        let (bytes, recalc) = match self.project_body(artifact, &head, "preview", at, zone)? {
            Some((bytes, _, recalc)) => (bytes, recalc),
            None => recalc_xlsx(&self.body_source(artifact, &head)?, limits, at, zone)?,
        };
        let book = read_xlsx_cells(&bytes, limits)
            .map_err(|_| invalid("the projected workbook could not be read"))?;
        Ok(XlsxPreview {
            frontier: head.frontier,
            book,
            recalc: recalc.as_ref().map(|stamp| recalc_label(stamp, zone)),
        })
    }

    /// The body frontier an export version projects, when it is one.
    pub fn office_body_export(
        &self,
        artifact: &EntityId,
        version: u64,
    ) -> Result<Option<OfficeBodyExportRecord>> {
        let txn = self.store.env.read_txn()?;
        EXPORTS.get(&self.store, &txn, &version_key(artifact, version))
    }

    /// The body at `head` projected onto its imported package: the bytes, the
    /// change count and the engine that recalculated a workbook. `None` when the
    /// body equals its import, so a no-op keeps the original package.
    fn project_body(
        &self,
        artifact: &EntityId,
        head: &OfficeBodyHead,
        author: &str,
        at: u64,
        zone: &OfficeRecalcZone,
    ) -> Result<Option<(Vec<u8>, usize, Option<CalcEngineStamp>)>> {
        if head.kind == OfficeBodyKind::Pptx {
            return Err(invalid(
                "a deck exports through vault.artifacts.body.deck.export, which lands only once its export gate opens",
            ));
        }
        let (live, base) = {
            let txn = self.store.env.read_txn()?;
            let live = self
                .loro_body(&txn, artifact, head.kind, Some(&head.frontier))?
                .1;
            let base = self
                .loro_body(&txn, artifact, head.kind, Some(&head.import_frontier))?
                .1;
            (live, base)
        };
        if head.kind == OfficeBodyKind::Docx {
            let changes = docx::changes(&docx::read(&base)?, &docx::read(&live)?)?;
            if changes.is_empty() {
                return Ok(None);
            }
            let date = timestamp(at)?.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            // The group names this revision by what it changes, not by the
            // vault frontier it was read at: frontiers never leave (OF-491).
            let mut group = blake3::Hasher::new();
            group.update(b"oneiron.office_body.docx_revision_group.v1\0");
            for part in [author, date.as_str(), format!("{changes:?}").as_str()] {
                group.update(&(part.len() as u64).to_le_bytes());
                group.update(part.as_bytes());
            }
            let revision = DocxRevision {
                author: author.to_owned(),
                date,
                group: group.finalize().to_hex()[..16].to_owned(),
            };
            let bytes = project_docx(
                &self.body_source(artifact, head)?,
                &changes,
                &revision,
                ArchiveLimits::DEFAULT,
            )
            .map_err(|_| invalid("the body could not be projected onto its package"))?;
            return Ok(Some((bytes, changes.len(), None)));
        }
        let changes = xlsx::changes(&xlsx::read(&base)?, &xlsx::read(&live)?)?;
        if changes.is_empty() {
            return Ok(None);
        }
        let limits = self.docedit_package_limits()?;
        let projected = project_xlsx(&self.body_source(artifact, head)?, &changes, limits)
            .map_err(|_| invalid("the body could not be projected onto its package"))?;
        let (bytes, recalc) = recalc_xlsx(&projected, limits, at, zone)?;
        Ok(Some((bytes, changes.len(), recalc)))
    }

    /// The imported version, checked against the hash the import recorded.
    fn body_source(&self, artifact: &EntityId, head: &OfficeBodyHead) -> Result<Vec<u8>> {
        let source = self
            .read_blob_artifact_version(artifact, head.source_version)?
            .ok_or(Error::EntityNotFound)?;
        if *blake3::hash(&source).as_bytes() != head.source_hash {
            return Err(Error::CorruptedIndex("office body source version"));
        }
        Ok(source)
    }

    fn head_in_txn(&self, txn: &RoTxn<'_>, artifact: &EntityId) -> Result<OfficeBodyHead> {
        let source = source(&self.store, txn, artifact)?;
        let (head, _) = self.loro_body(txn, artifact, source.kind, None)?;
        Ok(OfficeBodyHead {
            artifact: *artifact,
            kind: source.kind,
            source_version: source.source_version,
            source_hash: source.source_hash,
            import_frontier: head.birth,
            frontier: head.frontier,
            commits: head.commits,
        })
    }

    /// The Loro body of `artifact` as `kind`, at its head or a detached copy at
    /// an earlier frontier.
    fn loro_body(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
        kind: OfficeBodyKind,
        at: Option<&[u8]>,
    ) -> Result<(TypedBodyHead, LoroDoc)> {
        if source(&self.store, txn, artifact)?.kind != kind {
            return Err(invalid("the artifact's live body is another format"));
        }
        typed_body_in_txn(&self.store, txn, artifact, kind.schema(), at)?
            .ok_or(Error::CorruptedIndex("office body document missing"))
    }
}

/// Removes `artifact`'s office rows: its format record, its deck forks'
/// office records, its proposals and its export records. The body itself, a Loro document in
/// every format, goes with its forks in the typed body's own eraser.
/// Registered in `deletion/derived_rows.rs`.
pub(crate) fn erase_in_txn(store: &Store, txn: &mut RwTxn<'_>, entity: &EntityId) -> Result<()> {
    FORKS.delete_from(store, txn, entity.as_bytes())?;
    consent::erase_in_txn(store, txn, entity)?;
    EXPORTS.delete_from(store, txn, entity.as_bytes())?;
    SOURCES.delete(store, txn, entity)?;
    Ok(())
}

fn claim_source(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    artifact: &EntityId,
    source: &OfficeBodySource,
) -> Result<()> {
    if SOURCES.contains(store, wtxn, artifact)? {
        return Err(invalid("the artifact already has a live body"));
    }
    SOURCES.put(store, wtxn, artifact, source)
}

fn source(store: &Store, txn: &RoTxn<'_>, artifact: &EntityId) -> Result<OfficeBodySource> {
    SOURCES
        .get(store, txn, artifact)?
        .ok_or(Error::EntityNotFound)
}

/// A Loro body's kind; a deck has its own fork doors.
fn loro_kind(store: &Store, txn: &RoTxn<'_>, artifact: &EntityId) -> Result<OfficeBodyKind> {
    match source(store, txn, artifact)?.kind {
        OfficeBodyKind::Pptx => Err(invalid(
            "a deck fork reviews and lands through vault.artifacts.body.deck.review and .deck.merge",
        )),
        kind => Ok(kind),
    }
}

/// An open fork's record and proposal document.
fn open_fork(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    fork: &EntityId,
) -> Result<(TypedBodyFork, LoroDoc)> {
    let (record, proposal) =
        typed_body_fork_in_txn(store, txn, artifact, fork)?.ok_or(Error::EntityNotFound)?;
    Ok((
        record,
        proposal.ok_or_else(|| invalid("the fork is not open"))?,
    ))
}

fn fork_view(record: TypedBodyFork) -> OfficeBodyFork {
    OfficeBodyFork {
        id: record.fork,
        artifact: record.entity,
        opener: record.opener,
        base: record.base,
        commits: record.commits,
        opened_at: record.opened_at,
        state: match record.state {
            TypedForkState::Open => ForkState::Open,
            TypedForkState::Merged { by, at, head } => ForkState::Merged { by, at, head },
            TypedForkState::Discarded { by, at } => ForkState::Discarded { by, at },
        },
        run_root: None,
    }
}

fn writer(kind: OfficeBodyKind, actor: WriteActor, made_by: &MadeBy) -> TypedBodyWriter<'_> {
    TypedBodyWriter {
        schema: kind.schema(),
        actor,
        made_by,
    }
}

fn check_made_by(actor: WriteActor, made_by: &MadeBy) -> Result<()> {
    if made_by.process.actor != actor.entity_ref()
        || !made_by.process.is_valid()
        || made_by.inputs.len() > 1024
    {
        return Err(invalid(
            "the MadeBy envelope does not name this actor's process",
        ));
    }
    Ok(())
}

fn apply_all(doc: &LoroDoc, ops: &[DocxBodyOp]) -> Result<Vec<String>> {
    let mut minted = Vec::new();
    for op in ops {
        docx::apply(doc, op, &mut minted)?;
    }
    Ok(minted)
}

fn apply_xlsx(doc: &LoroDoc, ops: &[XlsxBodyOp]) -> Result<Vec<String>> {
    for op in ops {
        xlsx::apply(doc, op)?;
    }
    Ok(Vec::new())
}

/// Fail closed on a document that no longer reads as its kind.
fn validate(kind: OfficeBodyKind, doc: &LoroDoc) -> Result<()> {
    match kind {
        OfficeBodyKind::Docx => docx::read(doc).map(drop),
        OfficeBodyKind::Xlsx => xlsx::read(doc).map(drop),
        OfficeBodyKind::Pptx => pptx::validate(doc),
    }
}

fn three_way(
    kind: OfficeBodyKind,
    live: &LoroDoc,
    proposal: &LoroDoc,
    base: &[u8],
    head: &[u8],
) -> Result<OfficeBodyDiff> {
    let frontier = loro::Frontiers::decode(base).map_err(|_| invalid("invalid body frontier"))?;
    let before = live
        .fork_at(&frontier)
        .map_err(|_| invalid("unknown body frontier"))?;
    let frontiers = (
        base.to_vec(),
        head.to_vec(),
        proposal.oplog_frontiers().encode(),
    );
    Ok(match kind {
        OfficeBodyKind::Docx => fork::diff(
            &docx::read(&before)?,
            &docx::read(live)?,
            &docx::read(proposal)?,
            frontiers,
        ),
        OfficeBodyKind::Xlsx => xlsx::diff(
            &xlsx::read(&before)?,
            &xlsx::read(live)?,
            &xlsx::read(proposal)?,
            frontiers,
        ),
        OfficeBodyKind::Pptx => {
            return Err(invalid(
                "a deck fork reviews and lands through vault.artifacts.body.deck.review and .deck.merge",
            ));
        }
    })
}

/// Recalculate a projected workbook in process at `at`, read in `zone`'s
/// local time, seeded by the projected package, so the result is
/// deterministic in all three and no vault frontier reaches the file
/// (OF-491). A workbook the engine refuses is marked to recalculate when it
/// is opened instead.
fn recalc_xlsx(
    bytes: &[u8],
    limits: Limits,
    at: u64,
    zone: &OfficeRecalcZone,
) -> Result<(Vec<u8>, Option<CalcEngineStamp>)> {
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&blake3::hash(bytes).as_bytes()[..8]);
    let clock = RecalcClock::new(
        timestamp(at)?,
        zone.utc_offset_minutes,
        u64::from_le_bytes(seed),
    )
    .ok_or_else(|| invalid("office body recalc clock"))?;
    match FormualizerEngine::new().recalculate_xlsx(bytes, limits, &clock, None) {
        Ok(report) => Ok((
            report.bytes,
            Some(CalcEngineStamp::new(
                report.engine.engine,
                report.engine.version,
            )?),
        )),
        Err(_) => Ok((
            mark_full_calc(bytes, limits).map_err(|_| {
                invalid("the projected workbook could not be marked to recalculate")
            })?,
            None,
        )),
    }
}

/// The calculator and the local time it read, as the export record and the
/// preview name them: `formualizer 0.5.1 at UTC+09:00 (Asia/Tokyo)`.
fn recalc_label(stamp: &CalcEngineStamp, zone: &OfficeRecalcZone) -> String {
    let sign = if zone.utc_offset_minutes < 0 {
        '-'
    } else {
        '+'
    };
    let minutes = zone.utc_offset_minutes.unsigned_abs();
    let mut label = format!(
        "{} {} at UTC{sign}{:02}:{:02}",
        stamp.engine(),
        stamp.version(),
        minutes / 60,
        minutes % 60
    );
    if let Some(name) = &zone.iana_timezone {
        label.push_str(&format!(" ({name})"));
    }
    label
}

fn timestamp(at: u64) -> Result<chrono::DateTime<chrono::Utc>> {
    i64::try_from(at)
        .ok()
        .and_then(|at| chrono::DateTime::from_timestamp(at, 0))
        .ok_or_else(|| invalid("office body export time"))
}

fn bounded_ops(count: usize) -> Result<()> {
    if count == 0 || count > docx::MAX_OPS {
        return Err(invalid("an office body call takes 1 to 256 operations"));
    }
    Ok(())
}

/// An id16 followed by a big-endian sequence or version number.
fn version_key(owner: &EntityId, number: u64) -> Vec<u8> {
    let mut key = owner.as_bytes().to_vec();
    key.extend_from_slice(&number.to_be_bytes());
    key
}

/// The refusal of a fork nothing answers, which waits in `proposal`.
pub(crate) fn fork_waits(proposal: &EntityId) -> Error {
    Error::InvalidConfig(format!(
        "the fork waits in proposal {} for a person outside its opener's lineage; no grant covers it, so its holders are asked",
        proposal.to_hex()
    ))
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}
