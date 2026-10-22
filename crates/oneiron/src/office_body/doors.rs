//! Vault doors for office body import, edits, forks and export.
//! Entry: `Vault::import_office_body`.
//! Definitions live here; office_body forwards their original names.

use super::*;

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
                // The vault's DOCX row as this writer's, not the shipped
                // default (FIX 8763), read in the host's memory (FIX 8570).
                let limits = self.office_docx_limits(Some(actor.entity_ref()))?;
                let blocks = crate::office_body::document_resources()
                    .docx(|| read_docx_blocks(&bytes, limits))
                    .map_err(|error| docx_error(&error, "the DOCX package could not be read"))?;
                self.with_write_txn_grouped(|wtxn| {
                    claim_source(&self.store, wtxn, artifact, &source)?;
                    birth_typed_body_in_txn(self, wtxn, artifact, writer, |doc| {
                        docx::import(doc, &blocks)
                    })
                    .map(drop)
                })?;
            }
            OfficeBodyKind::Xlsx => {
                let book = read_xlsx_cells(
                    &bytes,
                    self.docedit_package_limits()?,
                    &crate::office_body::document_resources(),
                )
                .map_err(|error| {
                    super::document_error(error.resource(), "the XLSX package could not be read")
                })?;
                // Past the row it asks; the workbook is imported whole.
                let cells: usize = book.sheets.iter().map(|sheet| sheet.cells.len()).sum();
                self.measure_limit(
                    crate::limit_ask::EngineLimit::ImportXlsxLiveCells,
                    u64::try_from(cells).unwrap_or(u64::MAX),
                );
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

    /// The body `vault.artifacts.body.read` shows, at its head or at an
    /// earlier frontier `at`, read in one snapshot with the keys and custody
    /// records of the lifted texts it may show: the live body's and each
    /// open fork's, and the document read at `at` (FIX 2939). A value only
    /// that version held is marked first ([`Self::mark_body_at`]), so it
    /// reads as its handle. `None` when the artifact has no live body.
    pub(super) fn office_body_read(
        &self,
        artifact: &EntityId,
        at: Option<&[u8]>,
    ) -> Result<Option<OfficeBodyRead>> {
        if let Some(at) = at {
            self.mark_body_at(artifact, at)?;
        }
        let txn = self.store.env.read_txn()?;
        let Some(source) = SOURCES.get(&self.store, &txn, artifact)? else {
            return Ok(None);
        };
        let (head, doc) = self.loro_body(&txn, artifact, source.kind, at)?;
        let view = match source.kind {
            OfficeBodyKind::Docx => OfficeBodyView::Docx {
                body: docx::read(&doc)?.into(),
            },
            OfficeBodyKind::Xlsx => OfficeBodyView::Xlsx {
                body: xlsx::read(&doc)?.into(),
            },
            OfficeBodyKind::Pptx => {
                let frontier = at.map_or(head.frontier, <[u8]>::to_vec);
                OfficeBodyView::Pptx {
                    body: pptx::body_in_txn(&self.store, &txn, artifact, &doc, frontier)?.into(),
                }
            }
        };
        let (keys, lifted) =
            self.typed_body_read_lifted_in_txn(&txn, artifact, at.map(|_| &doc))?;
        Ok(Some(OfficeBodyRead { view, keys, lifted }))
    }

    /// Marks the keys `artifact`'s body holds at the earlier frontier `at`
    /// that no mark covers yet, as the lift sweep marks the live body's, in
    /// a write of its own that completes before the read that shows them
    /// (FIX 2939). Only custody and span rows are written; the body, its
    /// operations, receipts and frontiers stay as they are. A body whose
    /// texts at `at` are all marked or clean writes nothing.
    pub(super) fn mark_body_at(&self, artifact: &EntityId, at: &[u8]) -> Result<()> {
        let unmarked = {
            let txn = self.store.env.read_txn()?;
            let Some(source) = SOURCES.get(&self.store, &txn, artifact)? else {
                return Ok(());
            };
            let (_, doc) = self.loro_body(&txn, artifact, source.kind, Some(at))?;
            self.typed_body_unmarked_in_txn(&txn, &doc)?
        };
        if !unmarked {
            return Ok(());
        }
        self.with_write_txn_grouped(|wtxn| {
            let kind = source(&self.store, wtxn, artifact)?.kind;
            let (_, doc) = self.loro_body(wtxn, artifact, kind, Some(at))?;
            self.mark_typed_body_at_in_txn(wtxn, artifact, &doc)
        })
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
        let mut effects = Vec::new();
        let mut edit = self.edit_live(
            artifact,
            OfficeBodyKind::Xlsx,
            base,
            (actor, made_by),
            |base, head| xlsx::admit_at(base, head, ops),
            |doc| apply_xlsx(doc, ops, &mut effects),
        )?;
        edit.effects = effects;
        Ok(edit)
    }

    pub(super) fn edit_live(
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
                effects: Vec::new(),
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
        self.with_write_txn_grouped(|wtxn| {
            self.open_office_body_fork_in_txn(wtxn, artifact, actor, run_root, None, proposal)
        })
    }

    /// [`Self::open_office_body_fork`] in `wtxn`, the writer that commits
    /// the fork, from `origin`: the try a host bound the opening surface to,
    /// proved in this same writer (FIX 3551). A DOCX or XLSX member's
    /// run-and-children scope matches that try alone; `run_root`, the run
    /// the caller names, is kept as its label. With no origin the fork
    /// belongs to no run.
    pub(crate) fn open_office_body_fork_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact: &EntityId,
        actor: WriteActor,
        run_root: Option<&EntityId>,
        origin: Option<crate::attempt_queue::AttemptId>,
        proposal: Option<&EntityId>,
    ) -> Result<OfficeBodyFork> {
        match source(&self.store, wtxn, artifact)?.kind {
            OfficeBodyKind::Pptx if proposal.is_some() => Err(invalid(
                "a deck fork joins no proposal; its run's approve scope covers it",
            )),
            OfficeBodyKind::Pptx => self.open_deck_fork(wtxn, artifact, actor, run_root),
            kind => {
                let record =
                    open_typed_body_fork_in_txn(self, wtxn, artifact, kind.schema(), actor)?;
                consent::join_in_txn(&self.store, wtxn, &record, run_root, origin, proposal)?;
                let mut fork = fork_view(record);
                fork.run_root = run_root.copied();
                Ok(fork)
            }
        }
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
        let mut effects = Vec::new();
        let mut edit = self.edit_fork(
            (artifact, fork),
            OfficeBodyKind::Xlsx,
            (actor, made_by),
            |doc| apply_xlsx(doc, ops, &mut effects),
        )?;
        edit.effects = effects;
        Ok(edit)
    }

    pub(super) fn edit_fork(
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
                effects: Vec::new(),
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
            .map_err(|proposal| fork_waits(&proposal, None))
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
        if request
            .author
            .is_some_and(|author| author.trim().is_empty() || author.len() > 256)
            || request.run_ref.trim().is_empty()
            || request.run_ref.len() > 256
        {
            return Err(invalid("invalid office body export author or run"));
        }
        let head = self
            .office_body_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        // FIX 4513: a DOCX export with no author lands a token, not its actor.
        let author = author_token::ExportAuthor::of(self, head.kind, request)?;
        let at = self.now_recorded_at();
        let Some((bytes, changes, recalc, effects)) =
            self.project_body(artifact, &head, &author.landed, at, request.zone)?
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
                actor: BodyActor::Actor(request.actor.entity_ref()),
                author: author.shown.clone(),
                token: author.token.clone(),
                at,
                changes: changes as u64,
                recalc: recalc
                    .as_ref()
                    .map(|stamp| recalc_label(stamp, request.zone)),
                effects,
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
            Some((bytes, _, recalc, _)) => (bytes, recalc),
            None => recalc_xlsx(&self.body_source(artifact, &head)?, limits, at, zone)?,
        };
        let book = read_xlsx_cells(&bytes, limits, &crate::office_body::document_resources())
            .map_err(|error| {
                super::document_error(error.resource(), "the projected workbook could not be read")
            })?;
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
    /// change count, the engine that recalculated a workbook and what the
    /// projection adapted. `None` when the body equals its import, so a no-op
    /// keeps the original package.
    pub(super) fn project_body(
        &self,
        artifact: &EntityId,
        head: &OfficeBodyHead,
        author: &str,
        at: u64,
        zone: &OfficeRecalcZone,
    ) -> Result<Option<(Vec<u8>, usize, Option<CalcEngineStamp>, Vec<String>)>> {
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
            // The vault's DOCX row, not the shipped default (FIX 8763), in
            // the host's memory (FIX 8570).
            let limits = self.office_docx_limits(None)?;
            let source = self.body_source(artifact, head)?;
            let bytes = crate::office_body::document_resources()
                .docx(|| project_docx(&source, &changes, &revision, limits))
                .map_err(|error| {
                    docx_error(&error, "the body could not be projected onto its package")
                })?;
            return Ok(Some((bytes, changes.len(), None, Vec::new())));
        }
        let changes = xlsx::changes(&xlsx::read(&base)?, &xlsx::read(&live)?)?;
        if changes.is_empty() {
            return Ok(None);
        }
        let limits = self.docedit_package_limits()?;
        let projected = project_xlsx(
            &self.body_source(artifact, head)?,
            &changes,
            limits,
            &crate::office_body::document_resources(),
        )
        .map_err(|error| {
            super::document_error(
                error.resource(),
                "the body could not be projected onto its package",
            )
        })?;
        let (bytes, recalc) = recalc_xlsx(&projected.bytes, limits, at, zone)?;
        Ok(Some((bytes, changes.len(), recalc, projected.effects)))
    }

    /// The imported version, checked against the hash the import recorded.
    pub(super) fn body_source(
        &self,
        artifact: &EntityId,
        head: &OfficeBodyHead,
    ) -> Result<Vec<u8>> {
        let source = self
            .read_blob_artifact_version(artifact, head.source_version)?
            .ok_or(Error::EntityNotFound)?;
        if *blake3::hash(&source).as_bytes() != head.source_hash {
            return Err(Error::CorruptedIndex("office body source version"));
        }
        Ok(source)
    }

    pub(super) fn head_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
    ) -> Result<OfficeBodyHead> {
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
    pub(super) fn loro_body(
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

    /// The vault's DOCX archive row as `holder`'s (FIX 8763): a trusted
    /// owner's row, else the shipped one. A policy that cannot resolve keeps
    /// the shipped default these doors read under before, so no body read
    /// gains a refusal it did not have.
    fn office_docx_limits(&self, holder: Option<EntityId>) -> Result<ArchiveLimits> {
        let rtxn = self.store.env.read_txn()?;
        Ok(crate::gate::resolve_policy_manifest(&self.store, &rtxn)?
            .docx_archive_limits(holder)
            .unwrap_or(ArchiveLimits::DEFAULT))
    }
}
