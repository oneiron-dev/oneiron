//! Live office bodies (ARCH-0075; ARCH-0077, "Multiplayer: the target body
//! shape"): an imported DOCX as a typed model in one Loro document, edited
//! together, the file an export.
//!
//! People edit the live body. Machine work runs on a fork and lands as a
//! three-way diff that someone other than its opener merges. Every commit runs
//! under a fresh peer stamped with its actor and keeps a MadeBy receipt over its
//! exact operation span. An export projects the body onto the imported package
//! as one tracked revision and lands it as a new version of the artifact,
//! recorded with the body frontier it projects.
//!
//! An XLSX body is a map keyed by sheet and address. Its export writes the
//! changed cells and names into the imported package and recalculates it in
//! process; [`Vault::preview_xlsx_body`] shows the recalculated values without
//! landing a version.
//!
//! The Loro document lives in this module's side tables until the
//! entity-document plane has a typed-body door. PPTX bodies follow.

mod docx;
mod fork;
mod xlsx;

pub use docx::{BodyBlock, BodyBlockKind, DocxBody, DocxBodyOp};
pub use fork::{BlockChange, BodyConflict, ChangeKind, ConflictKind, OfficeBodyDiff};
pub use oneiron_docedit::xlsx_body::{XlsxArea, XlsxBook, XlsxLock, XlsxStyle, XlsxValue};
pub use xlsx::{BodyCell, BodyName, BodySheet, XlsxBody, XlsxBodyOp};

use crate::Vault;
use crate::blob_artifact::{BlobArtifactVersion, BlobVersionProvenance};
use crate::edge::EdgeActorClass;
use crate::edit_roundtrip::OfficeFormat;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::made_by::MadeBy;
use crate::provenance::text_commit::TextCommitReceipt;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use heed::{RoTxn, RwTxn};
use loro::{CommitOptions, ExportMode, Frontiers, LoroDoc};
use oneiron_docedit::ArchiveLimits;
use oneiron_docedit::docx_body::{DocxRevision, project_docx, read_docx_blocks};
use oneiron_docedit::retained_opc::Limits;
use oneiron_docedit::xlsx_body::{mark_full_calc, project_xlsx, read_xlsx_cells};
use oneiron_xlsx_formula::RecalcClock;
use oneiron_xlsx_formula::engine::FormualizerEngine;
use serde::{Deserialize, Serialize};

const HEADS: SideTable<EntityId, OfficeBodyHead, Named> =
    SideTable::new(&side_table::OFFICE_BODY_HEAD);
const DOCS: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::OFFICE_BODY_DOC);
const COMMITS: SideTable<Vec<u8>, TextCommitReceipt, Named> =
    SideTable::new(&side_table::OFFICE_BODY_COMMIT);
const FORKS: SideTable<EntityId, OfficeBodyFork, Named> =
    SideTable::new(&side_table::OFFICE_BODY_FORK);
const EXPORTS: SideTable<Vec<u8>, OfficeBodyExportRecord, Named> =
    SideTable::new(&side_table::OFFICE_BODY_EXPORT);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeBodyKind {
    Docx,
    Xlsx,
}

/// One artifact's live body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyHead {
    pub artifact: EntityId,
    pub kind: OfficeBodyKind,
    pub schema: u32,
    /// The imported version every export projects onto.
    pub source_version: u64,
    pub source_hash: [u8; 32],
    /// The body as imported: every export's base.
    pub import_frontier: Vec<u8>,
    pub frontier: Vec<u8>,
    /// Commit receipts kept for the body so far.
    pub commits: u64,
}

/// One call's commit: the new frontier, the paragraph ids it minted in operation
/// order (none for a workbook), and its receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

pub struct OfficeBodyExportRequest<'a> {
    pub actor: WriteActor,
    /// The revision author a DOCX export shows; recorded for every export.
    pub author: &'a str,
    pub run_ref: &'a str,
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
    /// The engine that recalculated an XLSX export; `None` when the file
    /// recalculates on open, and for DOCX.
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
#[derive(Debug, Clone)]
pub struct XlsxPreview {
    pub frontier: Vec<u8>,
    pub book: XlsxBook,
    /// The engine that recalculated it; `None` when it could not, and formula
    /// values are blank until the file is opened.
    pub recalc: Option<String>,
}

impl Vault {
    /// Import one DOCX or XLSX version of `artifact` (the head when `version` is
    /// `None`) as its live body. One artifact has one body.
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
        let format = OfficeFormat::from_media_type(&body.media_type)?;
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
        let doc = LoroDoc::new();
        doc.set_record_timestamp(true);
        let (kind, schema, receipt) = match format {
            OfficeFormat::Docx => {
                let blocks = read_docx_blocks(&bytes, ArchiveLimits::DEFAULT)
                    .map_err(|_| invalid("the DOCX package could not be read"))?;
                let ((), receipt) = stamped(&doc, *artifact, actor, made_by, "import", |doc| {
                    docx::import(doc, &blocks)
                })?;
                (OfficeBodyKind::Docx, docx::SCHEMA, receipt)
            }
            OfficeFormat::Xlsx => {
                let book = read_xlsx_cells(&bytes, self.docedit_package_limits()?)
                    .map_err(|_| invalid("the XLSX package could not be read"))?;
                let ((), receipt) = stamped(&doc, *artifact, actor, made_by, "import", |doc| {
                    xlsx::import(doc, &book)
                })?;
                (OfficeBodyKind::Xlsx, xlsx::SCHEMA, receipt)
            }
            OfficeFormat::Pptx => return Err(invalid("PPTX office bodies are not built yet")),
        };
        let frontier = doc.oplog_frontiers().encode();
        let mut head = OfficeBodyHead {
            artifact: *artifact,
            kind,
            schema,
            source_version: version,
            source_hash: *blake3::hash(&bytes).as_bytes(),
            import_frontier: frontier.clone(),
            frontier,
            commits: 0,
        };
        self.with_write_txn_grouped(|wtxn| {
            if HEADS.contains(&self.store, wtxn, artifact)? {
                return Err(invalid("the artifact already has a live body"));
            }
            self.store_doc(wtxn, artifact, &doc)?;
            self.record_commit(wtxn, artifact, &mut head.commits, &receipt)?;
            HEADS.put(&self.store, wtxn, artifact, &head)
        })?;
        Ok(head)
    }

    pub fn office_body_head(&self, artifact: &EntityId) -> Result<Option<OfficeBodyHead>> {
        let txn = self.store.env.read_txn()?;
        HEADS.get(&self.store, &txn, artifact)
    }

    /// The typed body at its head, or at an earlier frontier of its history.
    pub fn read_docx_body(&self, artifact: &EntityId, at: Option<&[u8]>) -> Result<DocxBody> {
        docx::read(&self.body_at(artifact, OfficeBodyKind::Docx, at)?)
    }

    /// The typed workbook body at its head, or at an earlier frontier.
    pub fn read_xlsx_body(&self, artifact: &EntityId, at: Option<&[u8]>) -> Result<XlsxBody> {
        xlsx::read(&self.body_at(artifact, OfficeBodyKind::Xlsx, at)?)
    }

    fn body_at(&self, artifact: &EntityId, kind: OfficeBodyKind, at: Option<&[u8]>) -> Result<LoroDoc> {
        let txn = self.store.env.read_txn()?;
        let head = HEADS
            .get(&self.store, &txn, artifact)?
            .ok_or(Error::EntityNotFound)?;
        if head.kind != kind {
            return Err(invalid("the artifact's live body is another format"));
        }
        let doc = self.load_doc(&txn, artifact, Some(&head.frontier))?;
        match at {
            None => Ok(doc),
            Some(frontier) => fork_at(&doc, frontier),
        }
    }

    /// Every commit receipt of the body, in commit order.
    pub fn office_body_commits(&self, artifact: &EntityId) -> Result<Vec<TextCommitReceipt>> {
        let txn = self.store.env.read_txn()?;
        Ok(COMMITS
            .scan_from(&self.store, &txn, artifact.as_bytes())?
            .into_iter()
            .map(|(_, receipt)| receipt)
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
        self.edit_live(artifact, OfficeBodyKind::Docx, base, actor, made_by, |doc| {
            apply_all(doc, ops)
        })
    }

    /// A person's operations on a live workbook body, as [`Self::edit_docx_body`].
    pub fn edit_xlsx_body(
        &self,
        artifact: &EntityId,
        base: Option<&[u8]>,
        ops: &[XlsxBodyOp],
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<OfficeBodyEdit> {
        bounded_ops(ops.len())?;
        self.edit_live(artifact, OfficeBodyKind::Xlsx, base, actor, made_by, |doc| {
            apply_xlsx(doc, ops)
        })
    }

    fn edit_live(
        &self,
        artifact: &EntityId,
        kind: OfficeBodyKind,
        base: Option<&[u8]>,
        actor: WriteActor,
        made_by: &MadeBy,
        edit: impl FnOnce(&LoroDoc) -> Result<Vec<String>>,
    ) -> Result<OfficeBodyEdit> {
        if actor.actor_class() != EdgeActorClass::Human {
            return Err(invalid("machine work edits a fork, not the live body"));
        }
        self.with_write_txn_grouped(|wtxn| {
            let mut head = HEADS
                .get(&self.store, wtxn, artifact)?
                .ok_or(Error::EntityNotFound)?;
            if head.kind != kind {
                return Err(invalid("the artifact's live body is another format"));
            }
            let live = self.load_doc(wtxn, artifact, Some(&head.frontier))?;
            let target = match base {
                Some(base) => fork_at(&live, base)?,
                None => live.fork(),
            };
            let before = target.oplog_vv();
            let (minted, receipt) = stamped(&target, *artifact, actor, made_by, "edit", edit)?;
            let updates = target
                .export(ExportMode::updates(&before))
                .map_err(|_| invalid("office body update export"))?;
            live.import(&updates)
                .map_err(|_| invalid("office body update import"))?;
            validate(kind, &live)?;
            head.frontier = self.store_doc(wtxn, artifact, &live)?;
            self.record_commit(wtxn, artifact, &mut head.commits, &receipt)?;
            HEADS.put(&self.store, wtxn, artifact, &head)?;
            Ok(OfficeBodyEdit {
                frontier: head.frontier.clone(),
                minted,
                receipt,
            })
        })
    }

    /// Open a fork of the live body at its head for `actor`'s machine work.
    pub fn open_office_body_fork(
        &self,
        artifact: &EntityId,
        actor: WriteActor,
    ) -> Result<OfficeBodyFork> {
        let id = self.new_entity_id()?;
        let at = self.now_recorded_at();
        self.with_write_txn_grouped(|wtxn| {
            let head = HEADS
                .get(&self.store, wtxn, artifact)?
                .ok_or(Error::EntityNotFound)?;
            let live = self.load_doc(wtxn, artifact, Some(&head.frontier))?;
            let fork = OfficeBodyFork {
                id,
                artifact: *artifact,
                opener: actor.entity_ref(),
                base: head.frontier,
                commits: 0,
                opened_at: at,
                state: ForkState::Open,
            };
            self.store_doc(wtxn, &id, &live.fork())?;
            FORKS.put(&self.store, wtxn, &id, &fork)?;
            Ok(fork)
        })
    }

    pub fn office_body_fork(&self, fork: &EntityId) -> Result<Option<OfficeBodyFork>> {
        let txn = self.store.env.read_txn()?;
        FORKS.get(&self.store, &txn, fork)
    }

    /// The opener's operations on its open fork of a DOCX body.
    pub fn edit_docx_body_fork(
        &self,
        fork: &EntityId,
        ops: &[DocxBodyOp],
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<OfficeBodyEdit> {
        bounded_ops(ops.len())?;
        self.edit_fork(fork, OfficeBodyKind::Docx, actor, made_by, |doc| {
            apply_all(doc, ops)
        })
    }

    /// The opener's operations on its open fork of a workbook body.
    pub fn edit_xlsx_body_fork(
        &self,
        fork: &EntityId,
        ops: &[XlsxBodyOp],
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<OfficeBodyEdit> {
        bounded_ops(ops.len())?;
        self.edit_fork(fork, OfficeBodyKind::Xlsx, actor, made_by, |doc| {
            apply_xlsx(doc, ops)
        })
    }

    fn edit_fork(
        &self,
        fork: &EntityId,
        kind: OfficeBodyKind,
        actor: WriteActor,
        made_by: &MadeBy,
        edit: impl FnOnce(&LoroDoc) -> Result<Vec<String>>,
    ) -> Result<OfficeBodyEdit> {
        self.with_write_txn_grouped(|wtxn| {
            let mut record = FORKS
                .get(&self.store, wtxn, fork)?
                .ok_or(Error::EntityNotFound)?;
            if record.state != ForkState::Open || record.opener != actor.entity_ref() {
                return Err(invalid("only the opener writes to its open fork"));
            }
            let head = HEADS
                .get(&self.store, wtxn, &record.artifact)?
                .ok_or(Error::EntityNotFound)?;
            if head.kind != kind {
                return Err(invalid("the artifact's live body is another format"));
            }
            let doc = self.load_doc(wtxn, fork, None)?;
            let (minted, receipt) = stamped(&doc, record.artifact, actor, made_by, "fork", edit)?;
            validate(kind, &doc)?;
            let frontier = self.store_doc(wtxn, fork, &doc)?;
            self.record_commit(wtxn, fork, &mut record.commits, &receipt)?;
            FORKS.put(&self.store, wtxn, fork, &record)?;
            Ok(OfficeBodyEdit {
                frontier,
                minted,
                receipt,
            })
        })
    }

    /// The fork's proposal against the live head, read at both frontiers.
    pub fn office_body_fork_diff(&self, fork: &EntityId) -> Result<OfficeBodyDiff> {
        let txn = self.store.env.read_txn()?;
        let record = FORKS
            .get(&self.store, &txn, fork)?
            .ok_or(Error::EntityNotFound)?;
        let head = HEADS
            .get(&self.store, &txn, &record.artifact)?
            .ok_or(Error::EntityNotFound)?;
        let live = self.load_doc(&txn, &record.artifact, Some(&head.frontier))?;
        let proposal = self.load_doc(&txn, fork, None)?;
        three_way(head.kind, &live, &proposal, &record.base, &head.frontier)
    }

    /// Land a reviewed fork. The reviewer names the head it read; a moved head,
    /// a blocking conflict, the opener as merger, or a merged body that no longer
    /// reads refuses the merge. The fork's actual operations are imported into a
    /// scratch copy first; nothing is cherry-picked or rewritten. The fork's
    /// receipts join the body's.
    pub fn merge_office_body_fork(
        &self,
        fork: &EntityId,
        expected_head: &[u8],
        actor: WriteActor,
    ) -> Result<OfficeBodyDiff> {
        let at = self.now_recorded_at();
        self.with_write_txn_grouped(|wtxn| {
            let mut record = FORKS
                .get(&self.store, wtxn, fork)?
                .ok_or(Error::EntityNotFound)?;
            if record.state != ForkState::Open {
                return Err(invalid("the fork is not open"));
            }
            // "The opener's lineage and its forks never settle their own proposal."
            if record.opener == actor.entity_ref() {
                return Err(invalid("a fork's opener cannot merge it"));
            }
            let mut head = HEADS
                .get(&self.store, wtxn, &record.artifact)?
                .ok_or(Error::EntityNotFound)?;
            if head.frontier != expected_head {
                return Err(invalid(
                    "the body moved since the review; read the diff again",
                ));
            }
            let live = self.load_doc(wtxn, &record.artifact, Some(&head.frontier))?;
            let proposal = self.load_doc(wtxn, fork, None)?;
            let diff = three_way(head.kind, &live, &proposal, &record.base, &head.frontier)?;
            if diff.blocking() {
                return Err(invalid("the fork conflicts with the live body"));
            }
            let updates = proposal
                .export(ExportMode::all_updates())
                .map_err(|_| invalid("office body fork export"))?;
            let scratch = live.fork();
            scratch
                .import(&updates)
                .map_err(|_| invalid("office body fork import"))?;
            validate(head.kind, &scratch)?;
            live.import(&updates)
                .map_err(|_| invalid("office body fork import"))?;
            head.frontier = self.store_doc(wtxn, &record.artifact, &live)?;
            for (_, receipt) in COMMITS.scan_from(&self.store, wtxn, fork.as_bytes())? {
                self.record_commit(wtxn, &record.artifact, &mut head.commits, &receipt)?;
            }
            HEADS.put(&self.store, wtxn, &record.artifact, &head)?;
            record.state = ForkState::Merged {
                by: actor.entity_ref(),
                at,
                head: head.frontier.clone(),
            };
            FORKS.put(&self.store, wtxn, fork, &record)?;
            DOCS.delete(&self.store, wtxn, fork)?;
            Ok(diff)
        })
    }

    /// Abandon an open fork's unlanded work.
    pub fn discard_office_body_fork(&self, fork: &EntityId, actor: WriteActor) -> Result<()> {
        let at = self.now_recorded_at();
        self.with_write_txn_grouped(|wtxn| {
            let mut record = FORKS
                .get(&self.store, wtxn, fork)?
                .ok_or(Error::EntityNotFound)?;
            if record.state != ForkState::Open {
                return Err(invalid("the fork is not open"));
            }
            record.state = ForkState::Discarded {
                by: actor.entity_ref(),
                at,
            };
            FORKS.put(&self.store, wtxn, fork, &record)?;
            DOCS.delete(&self.store, wtxn, fork)?;
            Ok(())
        })
    }

    /// Project the body onto its imported package and land it as the artifact's
    /// next version: a DOCX body as one tracked revision, an XLSX body as its
    /// changed cells and names, recalculated. The projection is deterministic
    /// in the body frontier, the author and the export time.
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
        let Some((bytes, changes, recalc)) = self.project_body(artifact, &head, request.author, at)?
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
            let current = HEADS
                .get(&self.store, wtxn, artifact)?
                .ok_or(Error::EntityNotFound)?;
            if current.frontier != head.frontier {
                return Err(invalid("the body moved during the export; export again"));
            }
            let version = self.append_blob_artifact_version_in_txn(
                wtxn,
                artifact,
                &bytes,
                &provenance,
                request.actor,
                TimeRange { start: at, end: at },
                at,
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
                recalc,
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
    pub fn preview_xlsx_body(&self, artifact: &EntityId) -> Result<XlsxPreview> {
        let head = self
            .office_body_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        if head.kind != OfficeBodyKind::Xlsx {
            return Err(invalid("the artifact's live body is another format"));
        }
        let at = self.now_recorded_at();
        let limits = self.docedit_package_limits()?;
        let (bytes, recalc) = match self.project_body(artifact, &head, "preview", at)? {
            Some((bytes, _, recalc)) => (bytes, recalc),
            None => recalc_xlsx(&self.body_source(artifact, &head)?, limits, at, &head.frontier)?,
        };
        let book = read_xlsx_cells(&bytes, limits)
            .map_err(|_| invalid("the projected workbook could not be read"))?;
        Ok(XlsxPreview {
            frontier: head.frontier,
            book,
            recalc,
        })
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
    ) -> Result<Option<(Vec<u8>, usize, Option<String>)>> {
        let (live, base) = {
            let txn = self.store.env.read_txn()?;
            let live = self.load_doc(&txn, artifact, Some(&head.frontier))?;
            let base = fork_at(&live, &head.import_frontier)?;
            (live, base)
        };
        match head.kind {
            OfficeBodyKind::Docx => {
                let changes = docx::changes(&docx::read(&base)?, &docx::read(&live)?)?;
                if changes.is_empty() {
                    return Ok(None);
                }
                let revision = DocxRevision {
                    author: author.to_owned(),
                    date: timestamp(at)?.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    group: blake3::hash(&head.frontier).to_hex()[..16].to_owned(),
                };
                let bytes = project_docx(
                    &self.body_source(artifact, head)?,
                    &changes,
                    &revision,
                    ArchiveLimits::DEFAULT,
                )
                .map_err(|_| invalid("the body could not be projected onto its package"))?;
                Ok(Some((bytes, changes.len(), None)))
            }
            OfficeBodyKind::Xlsx => {
                let changes = xlsx::changes(&xlsx::read(&base)?, &xlsx::read(&live)?)?;
                if changes.is_empty() {
                    return Ok(None);
                }
                let limits = self.docedit_package_limits()?;
                let projected = project_xlsx(&self.body_source(artifact, head)?, &changes, limits)
                    .map_err(|_| invalid("the body could not be projected onto its package"))?;
                let (bytes, recalc) = recalc_xlsx(&projected, limits, at, &head.frontier)?;
                Ok(Some((bytes, changes.len(), recalc)))
            }
        }
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

    /// The body frontier an export version projects, when it is one.
    pub fn office_body_export(
        &self,
        artifact: &EntityId,
        version: u64,
    ) -> Result<Option<OfficeBodyExportRecord>> {
        let txn = self.store.env.read_txn()?;
        EXPORTS.get(&self.store, &txn, &version_key(artifact, version))
    }

    fn load_doc(&self, txn: &RoTxn<'_>, id: &EntityId, frontier: Option<&[u8]>) -> Result<LoroDoc> {
        let bytes = DOCS
            .get(&self.store, txn, id)?
            .ok_or(Error::CorruptedIndex("office body document missing"))?;
        let doc = LoroDoc::from_snapshot(&bytes)
            .map_err(|_| Error::CorruptedIndex("office body document"))?;
        if frontier.is_some_and(|frontier| doc.oplog_frontiers().encode() != frontier) {
            return Err(Error::CorruptedIndex("office body frontier"));
        }
        doc.set_record_timestamp(true);
        Ok(doc)
    }

    fn store_doc(&self, wtxn: &mut RwTxn<'_>, id: &EntityId, doc: &LoroDoc) -> Result<Vec<u8>> {
        let bytes = doc
            .export(ExportMode::Snapshot)
            .map_err(|_| invalid("office body snapshot"))?;
        DOCS.put(&self.store, wtxn, id, &bytes)?;
        Ok(doc.oplog_frontiers().encode())
    }

    fn record_commit(
        &self,
        wtxn: &mut RwTxn<'_>,
        owner: &EntityId,
        sequence: &mut u64,
        receipt: &TextCommitReceipt,
    ) -> Result<()> {
        COMMITS.put(&self.store, wtxn, &version_key(owner, *sequence), receipt)?;
        *sequence += 1;
        Ok(())
    }
}

/// Run one call's operations under a fresh peer and commit them stamped with the
/// actor; the receipt covers exactly that peer's operations.
fn stamped<T>(
    doc: &LoroDoc,
    document: EntityId,
    actor: WriteActor,
    made_by: &MadeBy,
    verb: &str,
    edit: impl FnOnce(&LoroDoc) -> Result<T>,
) -> Result<(T, TextCommitReceipt)> {
    if made_by.process.actor != actor.entity_ref()
        || !made_by.process.is_valid()
        || made_by.inputs.len() > 1024
    {
        return Err(invalid(
            "the MadeBy envelope does not name this actor's process",
        ));
    }
    doc.set_peer_id(LoroDoc::new().peer_id())
        .map_err(|_| invalid("office body peer"))?;
    let peer = doc.peer_id();
    let value = edit(doc)?;
    let at = i64::try_from(made_by.at).map_err(|_| invalid("office body commit time"))?;
    let message = format!(
        "oneiron.office_body.v1 {verb} actor={}.{}",
        actor.entity_ref().to_hex(),
        crate::edit_distance::actor_class_token(actor.actor_class()),
    );
    doc.commit_with(CommitOptions::new().commit_msg(&message).timestamp(at));
    let end = doc.oplog_vv().get(&peer).copied().unwrap_or(0);
    if end <= 0 {
        return Err(invalid("the call changed nothing"));
    }
    Ok((
        value,
        TextCommitReceipt {
            document,
            peer,
            start: 0,
            end,
            made_by: made_by.clone(),
        },
    ))
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
    }
}

fn three_way(
    kind: OfficeBodyKind,
    live: &LoroDoc,
    proposal: &LoroDoc,
    base: &[u8],
    head: &[u8],
) -> Result<OfficeBodyDiff> {
    let before = fork_at(live, base)?;
    let frontiers = (base.to_vec(), head.to_vec());
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
    })
}

/// Recalculate a projected workbook in process at `at` (UTC), seeded by the
/// body frontier, so the result is deterministic in both. A workbook the engine
/// refuses is marked to recalculate when it is opened instead.
fn recalc_xlsx(
    bytes: &[u8],
    limits: Limits,
    at: u64,
    frontier: &[u8],
) -> Result<(Vec<u8>, Option<String>)> {
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&blake3::hash(frontier).as_bytes()[..8]);
    let clock = RecalcClock::new(timestamp(at)?, 0, u64::from_le_bytes(seed))
        .ok_or_else(|| invalid("office body recalc clock"))?;
    match FormualizerEngine::new().recalculate_xlsx(bytes, limits, &clock, None) {
        Ok(report) => Ok((
            report.bytes,
            Some(format!("{} {}", report.engine.engine, report.engine.version)),
        )),
        Err(_) => Ok((
            mark_full_calc(bytes, limits)
                .map_err(|_| invalid("the projected workbook could not be marked to recalculate"))?,
            None,
        )),
    }
}

fn timestamp(at: u64) -> Result<chrono::DateTime<chrono::Utc>> {
    i64::try_from(at)
        .ok()
        .and_then(|at| chrono::DateTime::from_timestamp(at, 0))
        .ok_or_else(|| invalid("office body export time"))
}

fn fork_at(doc: &LoroDoc, frontier: &[u8]) -> Result<LoroDoc> {
    let frontier = Frontiers::decode(frontier).map_err(|_| invalid("invalid body frontier"))?;
    doc.fork_at(&frontier)
        .map_err(|_| invalid("unknown body frontier"))
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

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}
