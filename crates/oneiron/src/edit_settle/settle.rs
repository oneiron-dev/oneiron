//! Settle Vault transactions.

use super::codec::{
    decode_settlement_record, encode_settlement_record, settle_grant_bound, settlement_key,
};
use super::receipts::{
    already_settled, manifest_ref, settled_anchors_from_summary, settlement_receipt_record,
};
use super::records::{
    SettleConsent, SettleDiscardOutcome, SettleOutcomeKind, SettleReceiptDoor, SettleSelectOutcome,
    SettlementRecord,
};
use crate::Vault;
use crate::anchored_annotation::{ReanchorOp, ReanchorSummary};
use crate::batch::secret_scan;
use crate::blob_artifact::{
    BLOB_ARTIFACT_RUN_REF_MAX_BYTES, read_blob_artifact_head_in_txn, require_entity_type,
};
use crate::edit_roundtrip::{EditProposal, OfficeFormat};
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
        self.ensure_selectable(proposal)?;
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
        let (version, reanchor, record) = self.with_write_txn(|wtxn| {
            // Standing-grant authorization resolves INSIDE this txn (TOCTOU):
            // a revocation serialized before this commit makes it fail here.
            self.authorize_settle_in_txn(wtxn, consent, actor)?;
            // Ledger acquisition BEFORE any side effect.
            if let Some(raw) = self.store.vault_meta.get(wtxn, &key)? {
                return Err(already_settled(&decode_settlement_record(&raw)?));
            }
            // Base head read in-txn, consistent with the append below.
            let base = read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?
                .ok_or(Error::EntityNotFound)?;
            // Stale-proposal refusal: the head must still be the one the proposal
            // was produced from. An intervening edit changes the head hash, and
            // committing these bytes would clobber it and replay a stale manifest
            // onto newer anchors.
            if base.content_hash != proposal.base_content_hash {
                return Err(Error::Artifact(ArtifactError::EditProposalStale));
            }
            let version = self.append_blob_artifact_version_in_txn(
                wtxn,
                artifact_id,
                &proposal.new_bytes,
                &proposal.agent_run_provenance(),
                actor,
                occurred,
                learned_at,
            )?;
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
                anchors: settled_anchors_from_summary(&reanchor),
                reason: None,
            };
            self.store
                .vault_meta
                .put(wtxn, &key, &encode_settlement_record(&record)?)?;
            Ok((version, reanchor, record))
        })?;

        let receipt = settlement_receipt_record(*artifact_id, &record)?;
        Ok(SettleSelectOutcome {
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
            anchors: Vec::new(),
            reason: (!reason.is_empty()).then(|| reason.to_owned()),
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

    fn ensure_selectable(&self, proposal: &EditProposal) -> Result<()> {
        validate_settle_proposal_ref(&proposal.run_ref)?;
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
        // The op vocabulary and re-anchor replay are spreadsheet-specific, the
        // same gate ARTL-3 applies.
        if !matches!(proposal.format, OfficeFormat::Xlsx) {
            return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                "settle supports only xlsx proposals; docx and pptx are not yet supported",
            )));
        }
        Ok(())
    }
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
