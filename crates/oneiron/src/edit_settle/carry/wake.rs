//! Re-asking carried editor answers after their original wake.

use super::*;

impl Vault {
    /// Wakes one withdrawal's proposer: the ask's question is asked again of
    /// each changed unit on the head, as `actor` through `decider`, and the
    /// answers wait as a fresh proposal for Keep. A changed slide is asked
    /// over `renderer`'s render of it on the head; with no renderer the wake
    /// fails. The asked units are marked woken whatever the answers, so each
    /// is asked again once; a wake that fails is held, then tried again. The
    /// ask runs outside any transaction; its proposal, its entry in a standing
    /// question's ask log and the wake's marks commit in one (FIX 9174), and a
    /// failed ask is logged on its own.
    #[expect(clippy::too_many_arguments)]
    pub fn wake_answer_proposer(
        &self,
        wake: &UnitWithdrawal,
        actor: WriteActor,
        decider: &dyn UnitDecider,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        renderer: Option<&dyn SlideRenderer>,
        now: u64,
    ) -> Result<Option<PendingProposalView>> {
        let key = settlement_key_parts(&wake.artifact, &wake.proposal_ref);
        let mut read = None;
        let woke = self.reask(wake, actor, decider, dial, policy, renderer, now, &mut read);
        // A wake that asked nothing (a replay, or no unit left) logs no ask.
        let asked = !matches!(woke, Ok((Reasked::Nothing, _) | (Reasked::Replay, _)));
        let committed = woke.and_then(|(reasked, reask_ref)| {
            self.commit_reask(wake, &key, actor, now, reasked, &reask_ref, read.as_deref())
        });
        if let Err(error) = &committed {
            let _ = self.with_write_txn(|wtxn| {
                if let Some(mut row) = WITHDRAWALS.get(&self.store, wtxn, &key)? {
                    row.retry_at = Some(now.saturating_add(FAILED_WAKE_HOLD_SECS));
                    WITHDRAWALS.put(&self.store, wtxn, &key, &row)?;
                }
                Ok(())
            });
            if asked && let Some(read) = &read {
                crate::llm::decision::questions::record_failed_standing_reask(
                    self,
                    &standing_reask(wake, read, &[], now, None),
                    error.kind(),
                );
            }
        }
        // Staging is after the cohort, log and woken prefix committed. A byte
        // failure never re-asks those paid units or writes a second failed log.
        committed.and_then(|(proposed, deadline, deferred_floor)| {
            if let Some(refusal) = deferred_floor {
                return Err(crate::office_body::machine_memory_refused(refusal));
            }
            match (proposed, deadline) {
                (Some(view), Some(deadline)) => self
                    .finish_pending_sheet_answers(&wake.artifact, &view.proposal_ref, deadline)
                    .map(Some),
                (view, _) => Ok(view),
            }
        })
    }

    /// The ask a wake makes, and the ref its proposal waits under. Nothing is
    /// retained here (FIX 9174): [`Self::commit_reask`] commits what it made.
    /// `read` takes the head versions the ask reads once it passes the replay
    /// guard, so a failed ask is logged as the ask it was.
    #[expect(clippy::too_many_arguments)]
    fn reask(
        &self,
        wake: &UnitWithdrawal,
        actor: WriteActor,
        decider: &dyn UnitDecider,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        renderer: Option<&dyn SlideRenderer>,
        now: u64,
        read: &mut Option<Vec<(EntityId, u64)>>,
    ) -> Result<(Reasked, String)> {
        let head = self
            .blob_artifact_head(&wake.artifact)?
            .ok_or(Error::EntityNotFound)?;
        // The live body's commit count names a wake after an edit never
        // exported, which moves no version (FIX 2115).
        let live = self
            .office_body_pin(&wake.artifact)?
            .map_or_else(String::new, |pin| format!(":{}", pin.commits));
        // What this ask reads, for its standing question's log (FIX 9174).
        // The withdrawn unit set and its current source revisions also name
        // the ref (FIX 9826): a new withdrawal while the destination head
        // stays put asks under its own ref instead of reusing an earlier
        // reask ref, so its evaluation is never skipped and no unit is marked
        // woken without one.
        let files: Vec<EntityId> = wake
            .answers
            .iter()
            .filter_map(|answer| match answer.unit {
                WithdrawnUnit::FolderItem { file, .. } => Some(file),
                _ => None,
            })
            .collect();
        let mut versions = self.observed_versions(&wake.artifact, &files)?;
        if let Some(first) = versions.first_mut() {
            first.1 = head.version;
        }
        let units: Vec<&WithdrawnUnit> = wake.answers.iter().map(|answer| &answer.unit).collect();
        let binding = serde_json::to_vec(&(&units, &versions))
            .map_err(|_| Error::InvariantViolation("reask binding encoding"))
            .map(|bytes| blake3::hash(&bytes).to_hex()[..16].to_string())?;
        let reask_ref = format!(
            "reask:{}:{}{live}:{binding}",
            &blake3::hash(wake.proposal_ref.as_bytes()).to_hex()[..16],
            head.version
        );
        // A wake that asked but was not marked asks nothing again.
        if self.pending_proposal(&wake.artifact, &reask_ref)?.is_some()
            || self
                .blob_artifact_settlement(&wake.artifact, &reask_ref)?
                .is_some()
        {
            return Ok((Reasked::Replay, reask_ref));
        }
        *read = Some(versions);
        let ask = ArtifactAsk {
            question: &wake.question,
            principal: wake.principal,
            dial,
            policy,
            reversibility: Reversibility::ReversibleRead,
            decider,
            evidence: &[],
            budget: WAKE_UNIT_BUDGET,
            deadline: Instant::now() + WAKE_DEADLINE,
            run_ref: &reask_ref,
        };
        // The wake holds no credential: the artifact a sheet, paragraph or
        // slide re-ask reads is read inside the asking version's saved lane,
        // as a folder item's files are below (FIX 11830).
        if !matches!(wake.shape, ReaskShape::FolderItems { .. })
            && !crate::llm::decision::questions::wake_artifact_reads(
                self,
                wake.principal,
                &wake.question,
                &[wake.artifact],
            )?
            .readable
            .contains(&wake.artifact)
        {
            return Ok((Reasked::Nothing, reask_ref));
        }
        let mut deferred_floor = None;
        let (proposal, sheet_answers, units, read_rows, next_sheet_row) = match &wake.shape {
            ReaskShape::SheetRows {
                sheet,
                answer_col,
                reads,
                max_count_override,
            } => {
                let rows: BTreeSet<u32> = wake
                    .answers
                    .iter()
                    .filter_map(|answer| match answer.unit {
                        WithdrawnUnit::SheetRow { row } => Some(row),
                        _ => None,
                    })
                    .collect();
                let (Some(first), Some(last)) = (rows.first().copied(), rows.last().copied())
                else {
                    return Ok((Reasked::Nothing, reask_ref));
                };
                let selected: SheetRowSelection = rows.iter().copied().collect();
                let run = self.ask_blob_artifact_sheet_rows(
                    &wake.artifact,
                    &SheetRowsAsk {
                        ask,
                        sheet,
                        rows: RangeRef {
                            start: CellRef {
                                col: reads.first_col,
                                row: first,
                            },
                            end: CellRef {
                                col: reads.last_col,
                                row: last,
                            },
                        },
                        answer_col: *answer_col,
                        header_row: reads.header_row,
                        max_count_override: *max_count_override,
                        only_rows: Some(&selected),
                    },
                )?;
                deferred_floor = run.deferred_floor;
                let units = crate::llm::decision::questions::artifact_unit_receipts(&run);
                (
                    run.proposal,
                    run.sheet_answers,
                    units,
                    run.read_rows,
                    run.next_sheet_row,
                )
            }
            ReaskShape::FolderItems {
                sheet,
                answer_col,
                max_count_override,
            } => {
                let items: Vec<FolderItem> = wake
                    .answers
                    .iter()
                    .filter_map(|answer| match answer.unit {
                        WithdrawnUnit::FolderItem { file, row } => Some(FolderItem {
                            artifact: file,
                            row,
                        }),
                        _ => None,
                    })
                    .collect();
                // The wake holds no credential: its files are read inside the
                // asking version's saved lane, under the sight that lane holds
                // now (FIX 2116).
                let ids: Vec<EntityId> = std::iter::once(wake.artifact)
                    .chain(items.iter().map(|item| item.artifact))
                    .collect();
                let reads = crate::llm::decision::questions::wake_artifact_reads(
                    self,
                    wake.principal,
                    &wake.question,
                    &ids,
                )?;
                let items: Vec<FolderItem> = items
                    .into_iter()
                    .filter(|item| reads.readable.contains(&item.artifact))
                    .collect();
                if items.is_empty() || !reads.readable.contains(&wake.artifact) {
                    return Ok((Reasked::Nothing, reask_ref));
                }
                let run = self.ask_folder_items_into_sheet(
                    &wake.artifact,
                    &FolderAsk {
                        ask,
                        items: &items,
                        sheet,
                        answer_col: *answer_col,
                        max_count_override: *max_count_override,
                        sight: reads.sight,
                    },
                )?;
                let units = crate::llm::decision::questions::artifact_unit_receipts(&run);
                (
                    run.proposal,
                    run.sheet_answers,
                    units,
                    run.read_rows,
                    run.next_sheet_row,
                )
            }
            ReaskShape::Paragraphs { author, labels } => {
                let blocks: Vec<String> = wake
                    .answers
                    .iter()
                    .filter_map(|answer| match &answer.unit {
                        WithdrawnUnit::Paragraph { block } => Some(block.clone()),
                        _ => None,
                    })
                    .collect();
                if blocks.is_empty() {
                    return Ok((Reasked::Nothing, reask_ref));
                }
                let run = self.ask_blob_artifact_paragraphs(
                    &wake.artifact,
                    &ParagraphAsk {
                        ask,
                        blocks: &blocks,
                        author,
                        labels,
                    },
                )?;
                let units = crate::llm::decision::questions::artifact_unit_receipts(&run);
                (
                    run.proposal,
                    run.sheet_answers,
                    units,
                    run.read_rows,
                    run.next_sheet_row,
                )
            }
            ReaskShape::Slides { author, labels } => {
                let bytes = self
                    .read_blob_artifact_version(&wake.artifact, head.version)?
                    .ok_or(Error::EntityNotFound)?;
                // A live deck is asked as it renders at its head; the comments
                // still land on the version (FIX 11981).
                let live = self.live_head_deck(&wake.artifact)?;
                let targets = live::reask_slide_targets(
                    wake,
                    &bytes,
                    live.as_ref().map(|(_, deck)| deck.as_slice()),
                    self.docedit_package_limits()?,
                )?;
                if targets.is_empty() {
                    return Ok((Reasked::Nothing, reask_ref));
                }
                let renderer = renderer.ok_or_else(|| {
                    Error::InvalidConfig("no slide renderer on this host".to_owned())
                })?;
                let numbers: Vec<u64> = targets.iter().map(|(_, number)| *number).collect();
                let rendered = live
                    .as_ref()
                    .map_or(bytes.as_slice(), |(_, deck)| deck.as_slice());
                let images = renderer.render(rendered, &numbers)?;
                if images.len() != targets.len() {
                    return Err(Error::InvalidConfig(
                        "the slide renderer returned the wrong number of images".to_owned(),
                    ));
                }
                // The review's own copy of the images is admitted first, and
                // given back once it is done (FIX 8244).
                let copies = review_copy_bytes(&images);
                renderer.admit(copies)?;
                let units: Vec<SlideReviewUnit> = targets
                    .into_iter()
                    .zip(images)
                    .map(|((target, _), image)| SlideReviewUnit {
                        target,
                        image: SlideReviewImage::Rendered(image),
                        renderer: renderer.name().to_owned(),
                    })
                    .collect();
                let request = SlideReviewRequest {
                    units: &units,
                    question: &wake.question,
                    principal: wake.principal,
                    answered_by: actor.entity_ref(),
                    author,
                    dial,
                    resident_dial: None,
                    // The vault's stored policy row runs: a wake narrows none
                    // of it (FIX 9336).
                    limits: crate::blob_artifact::SlideReviewLimitsInput::default().limits(),
                    policy,
                    reversibility: Reversibility::ReversibleRead,
                    labels,
                    decider,
                    evidence: &[],
                    budget: WAKE_UNIT_BUDGET,
                    deadline: Instant::now() + WAKE_DEADLINE,
                    run_ref: &reask_ref,
                    // The comment writer stamps epoch milliseconds.
                    at: now.saturating_mul(1000),
                };
                let shown = live.as_ref().map(|(pin, deck)| (pin, deck.as_slice()));
                let run = self.review_blob_artifact_slides_at(
                    &wake.artifact,
                    head.version,
                    &bytes,
                    shown,
                    &request,
                );
                renderer.materialized(copies, 0);
                let run = run.map_err(|error| match error {
                    SlideReviewError::Vault(error) => error,
                    other => Error::InvalidConfig(other.to_string()),
                })?;
                // Standing artifact questions never ask slides, so a slide re-ask
                // logs nowhere; it carries no unit receipts.
                (run.proposal, None, Vec::new(), run.read_rows, None)
            }
        };
        Ok((
            Reasked::Asked {
                proposal,
                sheet_answers,
                units,
                read_rows,
                next_sheet_row,
                deferred_floor,
            },
            reask_ref,
        ))
    }
}
