//! Settle Vault transactions.

use super::codec::{
    decode_settlement_record, encode_settlement_record, settle_grant_bound, settlement_key,
};
use super::receipts::{
    already_settled, manifest_ref, settled_anchors_from_summary, settlement_receipt_record,
};
use super::records::{
    SettleConsent, SettleDiscardOutcome, SettleOutcomeKind, SettleReceiptDoor, SettleSelectOutcome,
    SettlementRecord, SheetAnswerReceipt,
};
use crate::Vault;
use crate::anchored_annotation::{ReanchorOp, ReanchorSummary};
use crate::batch::secret_scan;
use crate::blob_artifact::{
    BLOB_ARTIFACT_RUN_REF_MAX_BYTES, read_blob_artifact_head_in_txn, require_entity_type,
};
use crate::edit_roundtrip::judgment_cells::verify_sheet_answer_bytes;
use crate::edit_roundtrip::{EditOp, EditProposal, OfficeFormat};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

// ---------------------------------------------------------------------------
// Vault surface
// ---------------------------------------------------------------------------

impl Vault {
    /// Settle-selects a retained [`EditProposal`]: appends its bytes as a new
    /// blob-artifact version (provenance [`BlobVersionProvenance::AgentRun`]),
    /// replays the manifest's anchor effects onto the artifact's threads, and
    /// records the select in the consume-once ledger with a receipt.
    ///
    /// Consume-once: a proposal already settled (select or discard) is refused
    /// with [`ArtifactError::EditProposalAlreadySettled`](crate::error::ArtifactError::EditProposalAlreadySettled) before any side effect.
    ///
    /// [`BlobVersionProvenance::AgentRun`]: crate::blob_artifact::BlobVersionProvenance::AgentRun
    pub fn settle_select_edit_proposal(
        &self,
        artifact_id: &EntityId,
        proposal: &EditProposal,
        consent: &SettleConsent,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<SettleSelectOutcome> {
        self.ensure_selectable(artifact_id, proposal, actor)?;
        self.authorize_settle(consent, actor)?;
        let proposal_ref = proposal.run_ref.as_str();
        let key = settlement_key(artifact_id, proposal_ref);
        let manifest_hash = manifest_ref(&proposal.manifest)?;
        let manifest_ops = u64::try_from(proposal.manifest.ops.len()).unwrap_or(u64::MAX);
        let ops: Vec<ReanchorOp> = proposal
            .manifest
            .anchor_effects()
            .iter()
            .map(ReanchorOp::from)
            .collect();

        // The consume-once acquisition, the version append, and the re-anchor
        // sweep are ONE transaction: all-or-nothing. A racing second settle,
        // serialized by the LMDB write lock, sees the committed ledger row here
        // and rolls back with nothing appended; a crash rolls the whole settle
        // back so a retry re-appends cleanly rather than skipping the re-anchor.
        let (version, reanchor, record, stranded_proposal) = self.with_write_txn(|wtxn| {
            // Standing-grant authorization resolves INSIDE this txn (TOCTOU):
            // a revocation serialized before this commit makes it fail here.
            self.authorize_settle_in_txn(wtxn, consent, actor)?;
            if let Some(bundle) = &proposal.sheet_answers {
                let policy = crate::gate::resolve_policy_manifest(&self.store, &*wtxn)?;
                let cap = policy
                    .sheet_answer_limit(
                        &artifact_id.to_hex(),
                        &bundle.sheet,
                        bundle.max_count_override,
                    )
                    .ok_or(Error::Artifact(ArtifactError::InvalidEditManifest(
                        "typed answer count policy unavailable",
                    )))?;
                if u64::try_from(bundle.answers.len()).unwrap_or(u64::MAX) > cap {
                    return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                        "typed answer count exceeds policy",
                    )));
                }
            }
            // A policy revision under this write lock can only make the budget
            // stricter than the preflight. Re-evaluate before any durable row.
            let docx_limits = if proposal.format == OfficeFormat::Docx {
                let limits = self.docx_archive_limits_in_txn(wtxn, Some(actor.entity_ref()))?;
                oneiron_docedit::validate_blocking_with_limits(&proposal.new_bytes, limits)
                    .map_err(|_| {
                        Error::Artifact(ArtifactError::InvalidEditManifest(
                            "docx output fails the current archive budget or linker",
                        ))
                    })?;
                Some(limits)
            } else {
                None
            };
            // Ledger acquisition BEFORE any side effect.
            if let Some(raw) = self.store.vault_meta.get(wtxn, &key)? {
                return Err(already_settled(&decode_settlement_record(&raw)?));
            }
            // The stored artifact format, not public proposal tags, selects the
            // verifier. Recheck inside the write transaction so a forged XLSX
            // label can never bypass PowerPoint's semantic replay and write set.
            let body = self
                .get_blob_artifact_in_txn(wtxn, artifact_id)?
                .ok_or(Error::EntityNotFound)?;
            let format = OfficeFormat::from_media_type(&body.media_type)?;
            if format != proposal.format || format != proposal.manifest.format {
                return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                    "proposal and manifest formats must match the artifact media type",
                )));
            }
            // Base head read in-txn, consistent with the append below.
            let base = read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?
                .ok_or(Error::EntityNotFound)?;
            if let Some(limits) = docx_limits {
                // A public proposal is not an engine certificate. Replay its
                // *validated tracked* transaction against the exact version
                // named by the proposal, then bind every decompressed output
                // part to that result. This is separate from the independent
                // package linker and unknown-part passthrough checks.
                let source_version = proposal.base_version.unwrap_or(base.version);
                let source = self
                    .read_blob_artifact_version_in_txn(wtxn, artifact_id, source_version)?
                    .ok_or(Error::EntityNotFound)?;
                if *blake3::hash(&source).as_bytes() != proposal.base_content_hash {
                    return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                        "docx proposal base hash does not match its source version",
                    )));
                }
                let [EditOp::DocxRevision { transaction }] = proposal.manifest.ops.as_slice()
                else {
                    return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                        "docx proposal requires exactly one native tracked transaction",
                    )));
                };
                let expected = oneiron_docedit::revise_with_limits(&source, transaction, limits)
                    .map_err(|_| {
                        Error::Artifact(ArtifactError::InvalidEditManifest(
                            "docx transaction cannot replay against its pinned base",
                        ))
                    })?;
                if !crate::edit_roundtrip::docx_parts_match_replay(
                    &expected,
                    &proposal.new_bytes,
                    limits,
                )? || !crate::edit_roundtrip::validate_docx_passthrough(
                    &source,
                    &proposal.new_bytes,
                    limits,
                )? {
                    return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                        "docx output does not implement its tracked transaction and base",
                    )));
                }
            }
            // Retain stale output against this exact head. Consume the old ref
            // so a retry can never accidentally apply it after another head
            // change. Reconciliation is a new, explicitly reviewed proposal.
            if base.content_hash != proposal.base_content_hash
                || proposal.base_version.is_some_and(|v| v != base.version)
            {
                let stranded = self.retain_stale_edit_in_txn(
                    wtxn,
                    artifact_id,
                    proposal,
                    &base,
                    actor,
                    learned_at,
                )?;
                let record = SettlementRecord {
                    proposal_ref: proposal_ref.to_owned(),
                    outcome: SettleOutcomeKind::Proposed,
                    settled_at: learned_at,
                    actor_ref: Some(actor.entity_ref().to_hex()),
                    brief_ref: consent.brief_ref().map(str::to_owned),
                    before_version: proposal.base_version,
                    version: Some(base.version),
                    content_hash: Some(base.content_hash),
                    manifest_ref: Some(manifest_hash),
                    manifest_ops,
                    pptx_slide_creation_id_mints: Vec::new(),
                    pptx_review_identities: pptx_review_identities(proposal),
                    pptx_judgments: proposal.manifest.slide_judgments.clone(),
                    anchors: Vec::new(),
                    reason: Some("stale_base".to_owned()),
                    sheet_answers: proposal.sheet_answers.clone(),
                };
                self.store
                    .vault_meta
                    .put(wtxn, &key, &encode_settlement_record(&record)?)?;
                return Ok((base, ReanchorSummary::default(), record, Some(stranded)));
            }
            // Replay every PPTX comment operation against the pinned in-transaction
            // base. A public proposal/report cannot authorize XML changes on its own.
            let pptx_limits = if format == OfficeFormat::Pptx {
                Some(
                    crate::gate::resolve_policy_manifest(&self.store, wtxn)?
                        .pptx_comment_limits()
                        .ok_or(Error::Artifact(ArtifactError::InvalidEditManifest(
                            "PowerPoint comment limits policy failed closed",
                        )))?,
                )
            } else {
                None
            };
            if let Some(limits) = pptx_limits {
                if proposal.base_version != Some(base.version) {
                    return Err(Error::Artifact(ArtifactError::EditProposalStale));
                }
                let bytes = self
                    .read_blob_artifact_version_in_txn(wtxn, artifact_id, base.version)?
                    .ok_or(Error::EntityNotFound)?;
                crate::edit_roundtrip::pptx::verify_comment_proposal_with_limits(
                    &bytes, proposal, limits,
                )
                .map_err(|_| {
                    Error::Artifact(ArtifactError::InvalidEditManifest(
                        "PowerPoint comment proposal does not replay over its pinned base",
                    ))
                })?;
            }
            let version = self.append_blob_artifact_version_with_engine_and_parent_in_txn(
                wtxn,
                artifact_id,
                &proposal.new_bytes,
                &proposal.agent_run_provenance(),
                if proposal.recalc == crate::edit_roundtrip::RecalcStatus::Performed {
                    proposal.calc_engine.as_deref()
                } else {
                    base.calc_engine.as_ref()
                },
                actor,
                occurred,
                learned_at,
                (format == OfficeFormat::Pptx).then_some(base.version),
            )?;
            if let Some(limits) = pptx_limits {
                self.apply_pptx_comment_annotations_in_txn(
                    wtxn,
                    artifact_id,
                    base.version,
                    proposal,
                    actor,
                    occurred,
                    learned_at,
                    limits,
                )?;
            }
            // Replay the manifest anchor effects onto threads at the prior head.
            // A dedupe no-op append (identical bytes) advances no version, so
            // there is nothing to re-anchor.
            let reanchor = if version.version > base.version {
                self.reanchor_annotation_threads_in_txn(
                    wtxn,
                    artifact_id,
                    base.version,
                    version.version,
                    &ops,
                    actor,
                    occurred,
                    learned_at,
                )?
            } else {
                ReanchorSummary::default()
            };
            let record = SettlementRecord {
                proposal_ref: proposal_ref.to_owned(),
                outcome: SettleOutcomeKind::Selected,
                settled_at: learned_at,
                actor_ref: Some(actor.entity_ref().to_hex()),
                brief_ref: consent.brief_ref().map(str::to_owned),
                before_version: Some(base.version),
                version: Some(version.version),
                content_hash: Some(version.content_hash),
                manifest_ref: Some(manifest_hash),
                manifest_ops,
                pptx_slide_creation_id_mints: proposal
                    .manifest
                    .ops
                    .iter()
                    .filter_map(|op| {
                        if let crate::edit_roundtrip::EditOp::MintPptxSlideCreationId {
                            slide,
                            creation_id,
                        } = op
                        {
                            Some((*slide, *creation_id))
                        } else {
                            None
                        }
                    })
                    .collect(),
                pptx_review_identities: pptx_review_identities(proposal),
                pptx_judgments: proposal.manifest.slide_judgments.clone(),
                anchors: settled_anchors_from_summary(&reanchor),
                reason: None,
                sheet_answers: proposal.sheet_answers.clone(),
            };
            self.store
                .vault_meta
                .put(wtxn, &key, &encode_settlement_record(&record)?)?;
            Ok((version, reanchor, record, None))
        })?;

        let receipt = settlement_receipt_record(*artifact_id, &record)?;
        Ok(SettleSelectOutcome {
            stranded_proposal,
            version,
            reanchor,
            receipt,
        })
    }

    /// Settle-discards a retained [`EditProposal`]: drops it and records the
    /// discard (with `reason`) in the consume-once ledger with a receipt.
    /// Nothing is appended to the version chain and no anchor moves.
    ///
    /// Consume-once: a proposal already settled is refused with
    /// [`ArtifactError::EditProposalAlreadySettled`](crate::error::ArtifactError::EditProposalAlreadySettled).
    pub fn settle_discard_edit_proposal(
        &self,
        artifact_id: &EntityId,
        proposal: &EditProposal,
        consent: &SettleConsent,
        actor: WriteActor,
        reason: &str,
        learned_at: u64,
    ) -> Result<SettleDiscardOutcome> {
        validate_settle_proposal_ref(&proposal.run_ref)?;
        crate::edit_roundtrip::slides_review::verify_judgments(proposal)?;
        self.authorize_settle(consent, actor)?;
        let proposal_ref = proposal.run_ref.as_str();
        let key = settlement_key(artifact_id, proposal_ref);

        let reason = reason.trim();
        let record = SettlementRecord {
            proposal_ref: proposal_ref.to_owned(),
            outcome: SettleOutcomeKind::Discarded,
            settled_at: learned_at,
            actor_ref: Some(actor.entity_ref().to_hex()),
            brief_ref: consent.brief_ref().map(str::to_owned),
            before_version: None,
            version: None,
            content_hash: None,
            manifest_ref: None,
            manifest_ops: 0,
            pptx_slide_creation_id_mints: Vec::new(),
            pptx_review_identities: pptx_review_identities(proposal),
            pptx_judgments: proposal.manifest.slide_judgments.clone(),
            anchors: Vec::new(),
            reason: (!reason.is_empty()).then(|| reason.to_owned()),
            sheet_answers: None,
        };
        let encoded = encode_settlement_record(&record)?;

        // One txn: the artifact-existence check and the consume-once acquisition
        // commit together, so a discard never lands a durable ledger row for a
        // nonexistent artifact and a racing second settle is refused.
        self.with_write_txn(|wtxn| {
            // Standing-grant authorization resolves INSIDE this txn (TOCTOU):
            // a revocation serialized before this commit makes it fail here.
            self.authorize_settle_in_txn(wtxn, consent, actor)?;
            require_entity_type(
                &self.store,
                wtxn,
                artifact_id,
                ENTITY_TYPE_BLOB_ARTIFACT,
                "settle-discard target must be a BLOB_ARTIFACT entity",
            )?;
            if let Some(raw) = self.store.vault_meta.get(wtxn, &key)? {
                return Err(already_settled(&decode_settlement_record(&raw)?));
            }
            self.store.vault_meta.put(wtxn, &key, &encoded)?;
            Ok(())
        })?;

        let receipt = settlement_receipt_record(*artifact_id, &record)?;
        Ok(SettleDiscardOutcome { receipt })
    }

    /// Reads the consume-once ledger entry for `(artifact, proposal_ref)`, or
    /// `None` if the proposal has not been settled.
    pub fn blob_artifact_settlement(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
    ) -> Result<Option<SettlementRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let key = settlement_key(artifact_id, proposal_ref);
        let Some(raw) = self.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_settlement_record(&raw).map(Some)
    }

    /// Resolves the tappable door of a *select* settle: the committed
    /// `artifact@version` plus the anchor set that moved. Returns `None` when
    /// the proposal was not settled or was discarded (a discard has no
    /// artifact@version to open).
    pub fn settle_receipt_door(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
    ) -> Result<Option<SettleReceiptDoor>> {
        let Some(record) = self.blob_artifact_settlement(artifact_id, proposal_ref)? else {
            return Ok(None);
        };
        let (Some(version), SettleOutcomeKind::Selected) = (record.version, record.outcome) else {
            return Ok(None);
        };
        Ok(Some(SettleReceiptDoor {
            artifact_id: *artifact_id,
            version,
            anchors: record.anchors,
        }))
    }

    /// Reads per-cell typed answer receipts only after a successful Keep.
    /// Discarded and stale proposals have no kept answers.
    pub fn sheet_answer_receipts(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
    ) -> Result<Vec<SheetAnswerReceipt>> {
        let Some(record) = self.blob_artifact_settlement(artifact_id, proposal_ref)? else {
            return Ok(Vec::new());
        };
        if record.outcome != SettleOutcomeKind::Selected {
            return Ok(Vec::new());
        }
        let Some(bundle) = record.sheet_answers else {
            return Ok(Vec::new());
        };
        let version = record
            .version
            .ok_or(Error::CorruptedIndex("selected sheet answer version"))?;
        let kept_by = record
            .actor_ref
            .ok_or(Error::CorruptedIndex("selected sheet answer actor"))?;
        Ok(bundle
            .answers
            .into_iter()
            .map(|answer| SheetAnswerReceipt {
                artifact_id: *artifact_id,
                proposal_ref: record.proposal_ref.clone(),
                version,
                question: bundle.question.clone(),
                question_version: bundle.question_version.clone(),
                principal: bundle.principal.clone(),
                sheet: bundle.sheet.clone(),
                answer,
                kept_by: kept_by.clone(),
                kept_at: record.settled_at,
            })
            .collect())
    }

    /// Whether a live DEC-0006 standing ACTION grant authorizes `actor` to
    /// settle on exactly `brief_ref`, without a per-op consent prompt.
    ///
    /// This is the OF-368 D6 seam, now filled by the unified consent contract
    /// rather than by the outbound-*send* grant family (whose capability is
    /// sends-to-counterparties, not artifact writes — honoring one for a settle
    /// would conflate two capabilities, which is why the seam returned `false`
    /// until the contract landed).
    ///
    /// The required bound is exact on every axis, so each of these is refused:
    ///
    /// * a DISCLOSURE grant — wrong domain; the two are disjoint types;
    /// * another actor's settle grant — the acting `WriteActor` is the subject;
    /// * a wider-target assumption — the envelope must name this brief, so a
    ///   target-agnostic or differently-targeted grant does not cover it;
    /// * a REVOKED row — revocation is immediate;
    /// * a catastrophe class — non-rememberable, so no such row can exist.
    ///
    /// Fails closed: no covering grant means no standing settle authority.
    pub fn settle_standing_grant_authorizes(
        &self,
        actor: WriteActor,
        brief_ref: &str,
    ) -> Result<bool> {
        let required = settle_grant_bound(actor, brief_ref)?;
        // Only ACTIVE rows are returned, so a revoked grant stops authorizing
        // the moment it is revoked.
        Ok(self
            .active_standing_consent_grants()?
            .iter()
            .any(|grant| grant.bound().contains(&required)))
    }

    fn authorize_settle(&self, consent: &SettleConsent, actor: WriteActor) -> Result<()> {
        match consent {
            SettleConsent::OwnerConsent { .. } => Ok(()),
            SettleConsent::StandingGrant { brief_ref } => {
                if self.settle_standing_grant_authorizes(actor, brief_ref)? {
                    Ok(())
                } else {
                    Err(Error::Artifact(ArtifactError::SettleNotAuthorized(
                        "no standing actor×artifact.settle×brief grant covers this settle",
                    )))
                }
            }
        }
    }

    /// The transaction-composable form of [`Vault::authorize_settle`], run
    /// INSIDE the settle's write transaction.
    ///
    /// This closes the revocation TOCTOU: a `StandingGrant` resolution checked
    /// on its own read transaction could observe a grant row a concurrent
    /// `revoke_consent_grant` has not committed yet, then settle against it
    /// AFTER the revoke lands. Reading the grant set on `wtxn` means the
    /// revocation — serialized by the LMDB write lock — either committed
    /// before this txn opened (the row reads Revoked and the settle refuses)
    /// or commits only after this txn ends (its writes were authorized under
    /// the still-live grant). No post-revoke settle can commit.
    fn authorize_settle_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        consent: &SettleConsent,
        actor: WriteActor,
    ) -> Result<()> {
        match consent {
            SettleConsent::OwnerConsent { .. } => Ok(()),
            SettleConsent::StandingGrant { brief_ref } => {
                let required = settle_grant_bound(actor, brief_ref)?;
                let covered = self
                    .active_standing_consent_grants_in_txn(wtxn)?
                    .iter()
                    .any(|grant| grant.bound().contains(&required));
                if covered {
                    Ok(())
                } else {
                    Err(Error::Artifact(ArtifactError::SettleNotAuthorized(
                        "no standing actor×artifact.settle×brief grant covers this settle",
                    )))
                }
            }
        }
    }

    fn ensure_selectable(
        &self,
        artifact_id: &EntityId,
        proposal: &EditProposal,
        actor: WriteActor,
    ) -> Result<()> {
        validate_settle_proposal_ref(&proposal.run_ref)?;
        crate::edit_roundtrip::slides_review::verify_judgments(proposal)?;
        // An EditProposal only exists on a passed corruption gate, but a select
        // commits its bytes into the version chain — re-check fail-closed.
        if !proposal.validation.ok {
            return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "proposal failed the corruption gate; a rejected output is never settleable",
            )));
        }
        if proposal.new_bytes.is_empty() {
            return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "proposal has no bytes to settle",
            )));
        }
        if proposal.recalc == crate::edit_roundtrip::RecalcStatus::Performed
            && proposal.calc_engine.is_none()
        {
            return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "recalculated proposal must name its engine and version",
            )));
        }
        if let Some(bundle) = &proposal.sheet_answers {
            if bundle.ops()? != proposal.manifest.ops {
                return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                    "typed answers do not match the edit manifest",
                )));
            }
            let version = proposal.base_version.ok_or(Error::Artifact(
                ArtifactError::InvalidEditManifest(
                    "typed answers require an artifact base version",
                ),
            ))?;
            let source = self
                .read_blob_artifact_version(artifact_id, version)?
                .ok_or(Error::EntityNotFound)?;
            if blake3::hash(&source).as_bytes() != &proposal.base_content_hash {
                return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                    "typed answers have a mismatched source hash",
                )));
            }
            verify_sheet_answer_bytes(bundle, Some(&source), Some(&proposal.new_bytes))?;
        }
        // The spreadsheet door cannot settle a disguised PowerPoint manifest.
        if proposal.format == OfficeFormat::Xlsx
            && proposal.manifest.ops.iter().any(|op| {
                matches!(
                    op,
                    crate::edit_roundtrip::EditOp::PptxComment { .. }
                        | crate::edit_roundtrip::EditOp::MintPptxSlideCreationId { .. }
                )
            })
        {
            return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                "PowerPoint operations require a verified PPTX comment proposal",
            )));
        }
        // Reject a cross-format manifest. The spreadsheet and native Word
        // writers have separate entry doors and cannot substitute one another's
        // operations at settlement.
        if proposal.format == OfficeFormat::Docx {
            let rtxn = self.store.env.read_txn()?;
            let limits = self.docx_archive_limits_in_txn(&rtxn, Some(actor.entity_ref()))?;
            oneiron_docedit::validate_blocking_with_limits(&proposal.new_bytes, limits)
                .map_err(|_| Error::Artifact(ArtifactError::EditRoundtripFailed(
                    "native docx proposal exceeds archive limits or fails the Word package linker",
                )))?;
        }
        if proposal.format != proposal.manifest.format
            || match proposal.format {
                OfficeFormat::Xlsx => proposal
                    .manifest
                    .ops
                    .iter()
                    .any(|op| matches!(op, EditOp::DocxRevision { .. })),
                OfficeFormat::Docx => !matches!(
                    proposal.manifest.ops.as_slice(),
                    [EditOp::DocxRevision { transaction }]
                        if oneiron_docedit::validate_revision_transaction(transaction).is_ok()
                ),
                OfficeFormat::Pptx => proposal
                    .manifest
                    .ops
                    .iter()
                    .any(|op| matches!(op, EditOp::DocxRevision { .. })),
            }
        {
            return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                "settle refuses a cross-format or unsupported office edit manifest",
            )));
        }
        Ok(())
    }
}

fn pptx_review_identities(proposal: &EditProposal) -> Vec<super::records::PptxReviewIdentity> {
    proposal
        .manifest
        .ops
        .iter()
        .filter_map(|op| {
            let crate::edit_roundtrip::EditOp::PptxComment { patch } = op else {
                return None;
            };
            Some(super::records::PptxReviewIdentity {
                thread_id: patch.thread_id,
                asked_by: patch.asked_by,
                answered_by: patch.answered_by,
                export_author_guid: patch.author.guid.clone(),
                export_author_name: patch.author.name.clone(),
            })
        })
        .collect()
}

/// Validates a proposal ref before it lands in a durable ledger row — the same
/// non-empty / length / secret-scan bar `append_blob_artifact_version` applies
/// to an `AgentRun` run_ref, so a discard (which never reaches append) is held
/// to it too.
fn validate_settle_proposal_ref(run_ref: &str) -> Result<()> {
    if run_ref.trim().is_empty() || run_ref.len() > BLOB_ARTIFACT_RUN_REF_MAX_BYTES {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "proposal run_ref must be non-empty and within the run-ref length bound",
        )));
    }
    secret_scan::scan_metadata_field(run_ref)?;
    Ok(())
}
