//! The tested-revision seal at green (FIX 6868, G2 PR3).
//!
//! Each tree the queue proved green, the checked baseline first, earns one
//! durable complete-tree CodeRevision: the exact checked commit and tree,
//! the bound receipts it stands on, the applied sources in landing order
//! and the complete inventory of reviewed documents and untouched blobs.
//! It records what was tested; it grants no review authority over bytes no
//! one reviewed. Earlier green seals first; a missing receipt, object or
//! ancestor holds this seal by name, never a red verdict, and the batch,
//! its proposals and the green pointer are untouched. Objects are read
//! outside the store writer; the finalizer reads its rows again in one.
use std::collections::BTreeMap;

use super::check_store::{QueueCheckConfiguration, QueueCheckRequest};
use super::tested_store::SealState;
use super::{
    BatchState, CheckPhase, MergeBatch, MergeQueue, QUEUE_CHECK_CANDIDATE_PREFIX,
    QueueAppliedSource, QueueDriveHold, QueueDriveHoldReason, QueueDriveOutcome, QueueDrivePass,
    QueueExportHold, QueueExportHoldReason, QueueReceiptLink, QueueRevisionIntent,
    QueueRevisionLink, QueueRevisionSeal, QueueSealTarget, QueueTestedRevision, QueueTestedTarget,
    QueueWork,
};
use crate::EntityId;
use crate::code_document::CodeDocumentFrontier;
use crate::code_revision::{CodeRevision, CodeTreeInventory, queue_provenance_id};
use crate::contract_oracle::ContractOracle;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitWire};
use crate::repo_mutation::proposal::{RepoProposal, RepoProposalStatus};

/// What a seal stands on, read from the queue's and checker's rows.
pub(super) struct SealEvidence {
    pub(super) tested: QueueTestedRevision,
    /// The applied sources, in landing order; none for the baseline.
    pub(super) sources: Vec<RepoProposal>,
}

type Held<T> = std::result::Result<T, QueueExportHold>;

fn held<T>(reason: QueueExportHoldReason, detail: impl Into<String>) -> Result<Held<T>> {
    Ok(Err(QueueExportHold::new(reason, detail)))
}

impl MergeQueue<'_> {
    /// The seals the driver owes, earliest green first: the baseline, then
    /// each green batch along the landed chain. A held seal is asked again
    /// on a tick only; one waiting on its ancestor every pass.
    pub(super) fn seal_work(
        &self,
        works: &mut Vec<QueueWork>,
        batches: &[MergeBatch],
        pass: QueueDrivePass,
    ) -> Result<()> {
        let Some(config) = self
            .checker_configuration()?
            .filter(QueueCheckConfiguration::drives_queue)
        else {
            return Ok(());
        };
        let retry = pass.tick || pass.first;
        let due = |link: Option<&QueueRevisionLink>| match link {
            Some(QueueRevisionLink::Sealed { .. }) => false,
            Some(QueueRevisionLink::Pending { hold: Some(_), .. }) => retry,
            _ => true,
        };
        if due(self
            .seal_link(&config, &QueueSealTarget::Baseline)?
            .as_ref())
        {
            works.push(QueueWork::SealTested {
                target: QueueSealTarget::Baseline,
                order: 0,
            });
        }
        let mut at = config.baseline_commit.clone();
        let mut order = 0_u64;
        while let Some(batch) = batches
            .iter()
            .find(|batch| batch.state == BatchState::GreenAdvanced && batch.expected_head == at)
        {
            let Some(landed) = &batch.landed_head else {
                break;
            };
            order += 1;
            if due(batch.drive.as_ref().and_then(|drive| drive.tested.as_ref())) {
                works.push(QueueWork::SealTested {
                    target: QueueSealTarget::Landed {
                        batch: batch.id.clone(),
                    },
                    order,
                });
            }
            at.clone_from(landed);
            if order > batches.len() as u64 {
                break;
            }
        }
        Ok(())
    }

    /// One driven seal. A named hold is kept on the seal's link, so the
    /// queue's status shows it; waiting on an ancestor writes nothing.
    pub(super) fn drive_seal(&self, target: &QueueSealTarget) -> Result<QueueDriveOutcome> {
        let Ok(config) = self.initialized_configuration()? else {
            return Ok(QueueDriveOutcome::Done);
        };
        match self.seal_tested_revision(target)? {
            Ok(_) => Ok(QueueDriveOutcome::Changed),
            Err(hold) => {
                if !matches!(
                    hold.reason,
                    QueueExportHoldReason::HeldSealAncestor
                        | QueueExportHoldReason::SealPending
                        | QueueExportHoldReason::Unenrolled
                ) {
                    self.record_seal_hold(&config, target, hold.clone())?;
                }
                Ok(QueueDriveOutcome::Waiting(QueueDriveHold::new(
                    QueueDriveHoldReason::HeldSeal,
                    hold.detail,
                )))
            }
        }
    }

    /// Seals `target`'s tested revision, or names why it holds. A sealed
    /// target answers its revision; a retry reuses the persisted intent and
    /// finds the finalized record exactly as it was.
    ///
    /// # Errors
    /// A store failure.
    pub fn seal_tested_revision(&self, target: &QueueSealTarget) -> Result<Held<EntityId>> {
        let config = match self.initialized_configuration()? {
            Ok(config) if config.drives_queue() => config,
            _ => {
                return held(
                    QueueExportHoldReason::Unenrolled,
                    "no checked configuration drives this queue",
                );
            }
        };
        let intent = match self.seal_state(&config, target)? {
            SealState::Sealed(revision) => return Ok(Ok(revision)),
            SealState::Waiting(hold) => return Ok(Err(hold)),
            SealState::Pending(intent) => intent,
        };
        let parent = match &intent.parent_commit {
            None => None,
            Some(commit) => match self.sealed_at_commit(&config, commit)? {
                Some(id) => Some(
                    self.vault
                        .get_code_revision(&id)?
                        .ok_or(Error::EntityNotFound)?,
                ),
                None => {
                    return held(
                        QueueExportHoldReason::HeldSealAncestor,
                        format!("the green {commit} this tree landed on is not sealed yet"),
                    );
                }
            },
        };
        let evidence = match &intent.target {
            QueueSealTarget::Baseline => self.baseline_evidence(&config)?,
            QueueSealTarget::Landed { batch } => self.landed_evidence(&config, batch, &intent)?,
        };
        let SealEvidence {
            mut tested,
            sources,
        } = match evidence {
            Ok(evidence) => evidence,
            Err(hold) => return Ok(Err(hold)),
        };
        let wire = GitWire::new(self.vault)?;
        let inventory = match self.seal_inventory(&wire, &intent, &sources, parent.as_ref()) {
            Ok(Ok(inventory)) => inventory,
            Ok(Err(hold)) => return Ok(Err(hold)),
            Err(error) => {
                return held(
                    QueueExportHoldReason::HeldObject,
                    format!("the checked tree cannot be read: {error}"),
                );
            }
        };
        let metadata = match self.queue_commit_metadata(&intent, &sources, &inventory.modes)? {
            Ok(metadata) => metadata,
            Err(hold) => return Ok(Err(hold)),
        };
        let mut revision = match parent.as_ref() {
            None => CodeRevision::commit(intent.revision, intent.session, intent.sealed_at),
            Some(parent) => CodeRevision::commit_child(
                intent.revision,
                intent.session,
                parent.revision_id,
                intent.sealed_at,
            ),
        }
        .with_commit_metadata(metadata)
        .with_provenance_claim_id(queue_provenance_id(intent.revision)?);
        revision.file_frontiers = inventory.documents;
        revision.blob_frontiers = inventory.blobs;
        // A file bundle's removals, and a received one's complete-push
        // links (G4 PR2).
        match self.bundle_seal_evidence(&wire, &intent.tree, &sources, parent.as_ref())? {
            Ok((retired, pushes)) => {
                revision.retired_paths = retired;
                tested.received_pushes = pushes;
            }
            Err(hold) => return Ok(Err(hold)),
        }
        tested.inventory_digest = CodeTreeInventory::digest(&revision)?;
        revision.tested_queue = Some(tested);
        let seal = QueueRevisionSeal {
            revision,
            source: self.seal_source(&config, target),
            repo_ref: config.repo_ref.clone(),
        };
        match self.vault.finalize_queue_revision(&seal) {
            Ok(id) => Ok(Ok(id)),
            Err(Error::ConcurrentWrite(reason)) => held(
                QueueExportHoldReason::Unavailable,
                format!("the seal's rows moved: {reason}"),
            ),
            Err(error) => Err(error),
        }
    }

    /// The checked baseline's evidence: the latest generation in which
    /// both baseline phases passed on the approved tree under the frozen
    /// plan, with their receipts.
    fn baseline_evidence(&self, config: &QueueCheckConfiguration) -> Result<Held<SealEvidence>> {
        let digest = config
            .init_work
            .rsplit_once(':')
            .map_or(config.init_work.as_str(), |(_, digest)| digest);
        let Some(work) = self.check_work(digest)? else {
            return held(
                QueueExportHoldReason::HeldBinding,
                "the checked-init work is gone",
            );
        };
        let passing = |receipt: &&super::QueueCheckReceipt, phase: CheckPhase| {
            let inputs = &receipt.inputs;
            matches!(
                &inputs.target,
                super::QueueCheckTarget::Baseline { commit, tree, phase: ran }
                    if *commit == config.baseline_commit
                        && *tree == config.baseline_tree
                        && *ran == phase
            ) && inputs.plan_digest == config.plan.digest
                && receipt.tests_passed == Some(true)
                && receipt.run.is_some()
                && inputs
                    .digest()
                    .is_ok_and(|digest| digest == receipt.inputs_digest)
        };
        let pair = work.receipts.iter().rev().find_map(|slow| {
            if !passing(&slow, CheckPhase::Slow) {
                return None;
            }
            work.receipts
                .iter()
                .find(|fast| fast.generation == slow.generation && passing(fast, CheckPhase::Fast))
                .map(|fast| (fast, slow))
        });
        let Some((fast, slow)) = pair else {
            return held(
                QueueExportHoldReason::HeldBinding,
                "the checked baseline has no passing receipt for both phases",
            );
        };
        let link = |receipt: &super::QueueCheckReceipt, phase| QueueReceiptLink {
            phase,
            mask: 0,
            work_ref: work.work_ref().to_owned(),
            inputs_digest: receipt.inputs_digest.clone(),
            verdict_ref: receipt.verdict_ref.clone(),
        };
        let super::QueueCheckInitStage::Initialized { baseline_id } = &config.stage else {
            return held(
                QueueExportHoldReason::SealPending,
                "the checked initialization has not completed",
            );
        };
        Ok(Ok(SealEvidence {
            tested: self.tested_record(
                config,
                baseline_id,
                &config.baseline_commit,
                &config.baseline_tree,
                QueueTestedTarget::Baseline,
                vec![link(fast, CheckPhase::Fast)],
                link(slow, CheckPhase::Slow),
            ),
            sources: Vec::new(),
        }))
    }

    /// A green batch's evidence: every fast path and the slow check of its
    /// landed prefix, each a passing verdict bound to its stored receipt
    /// (FIX 7236: a callback-path verdict with no receipt holds), and its
    /// applied sources in landing order.
    fn landed_evidence(
        &self,
        config: &QueueCheckConfiguration,
        id: &str,
        intent: &QueueRevisionIntent,
    ) -> Result<Held<SealEvidence>> {
        let batch = self.batch(id)?;
        let landed = self.landed_path(&batch)?.clone();
        if batch.state != BatchState::GreenAdvanced
            || batch.landed_head.as_deref() != Some(intent.commit.as_str())
            || landed.tree != intent.tree
        {
            return held(
                QueueExportHoldReason::Unavailable,
                "the green batch no longer matches its seal intent",
            );
        }
        let mut fast = Vec::new();
        for path in &batch.paths {
            match self.bound_link(
                &batch,
                path.mask,
                &path.tree,
                &path.commit,
                CheckPhase::Fast,
                path.verdict.as_deref(),
            )? {
                Some(link) => fast.push(link),
                None => {
                    return held(
                        QueueExportHoldReason::HeldBinding,
                        format!("fast path {}: a verdict without a bound receipt", path.mask),
                    );
                }
            }
        }
        let Some(slow) = self.bound_link(
            &batch,
            landed.mask,
            &landed.tree,
            &intent.commit,
            CheckPhase::Slow,
            batch.slow_verdict.as_deref(),
        )?
        else {
            return held(
                QueueExportHoldReason::HeldBinding,
                "the slow check has a verdict without a bound receipt",
            );
        };
        let count = landed.mask.count_ones() as usize;
        let mut sources = Vec::new();
        let mut applied = Vec::new();
        for proposal in batch.proposals.iter().take(count) {
            let source = EntityId::from_hex(&proposal.id)
                .ok()
                .map(|id| self.vault.repo_proposal(id))
                .transpose()?
                .flatten();
            let Some(source) = source.filter(|source| {
                source.status == RepoProposalStatus::Applied && source.operation_seq.is_some()
            }) else {
                return held(
                    QueueExportHoldReason::HeldUnreviewedChange,
                    format!(
                        "landed source {} is not an applied reviewed proposal",
                        proposal.id
                    ),
                );
            };
            applied.push(QueueAppliedSource {
                proposal: source.id,
                operation_seq: source.operation_seq.unwrap_or_default(),
                session: source.session,
                provenance_claim: source.provenance_claim,
            });
            sources.push(source);
        }
        let pre_snapshot = batch
            .pre_snapshot
            .ok_or(Error::CorruptedIndex("landing snapshot missing"))?;
        let target = QueueTestedTarget::Landed {
            batch: batch.id.clone(),
            landed_mask: landed.mask,
            speculative_commit: landed.commit.clone(),
            expected_head: batch.expected_head.clone(),
            pre_snapshot,
            applied,
        };
        Ok(Ok(SealEvidence {
            tested: self.tested_record(
                config,
                &batch.baseline_id,
                &intent.commit,
                &intent.tree,
                target,
                fast,
                slow,
            ),
            sources,
        }))
    }

    /// The receipt link of one checked path: a passing verdict whose
    /// candidate names a stored receipt bound to these exact inputs.
    fn bound_link(
        &self,
        batch: &MergeBatch,
        mask: u64,
        tree: &str,
        commit: &str,
        phase: CheckPhase,
        verdict: Option<&str>,
    ) -> Result<Option<QueueReceiptLink>> {
        let Some(verdict) = verdict else {
            return Ok(None);
        };
        let Some(verdict) = ContractOracle::new(self.vault).verdict(verdict)? else {
            return Ok(None);
        };
        let Some(digest) = verdict.candidate.strip_prefix(QUEUE_CHECK_CANDIDATE_PREFIX) else {
            return Ok(None);
        };
        let Some(receipt) = self.bound_receipt(digest, &verdict.id)? else {
            return Ok(None);
        };
        if !verdict.passes()
            || receipt.tests_passed != Some(true)
            || !self.require_check_binding(batch, mask, tree, commit, phase, &verdict, None)?
        {
            return Ok(None);
        }
        let key = self.work_key(&QueueCheckRequest::Check {
            batch: batch.id.clone(),
            mask,
            phase,
            force_refresh: false,
        })?;
        let work_ref = key
            .rsplit_once(':')
            .map_or(key.as_str(), |(_, digest)| digest);
        Ok(Some(QueueReceiptLink {
            phase,
            mask,
            work_ref: work_ref.to_owned(),
            inputs_digest: receipt.inputs_digest,
            verdict_ref: Some(verdict.id),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn tested_record(
        &self,
        config: &QueueCheckConfiguration,
        oracle_baseline: &str,
        commit: &str,
        tree: &str,
        target: QueueTestedTarget,
        fast: Vec<QueueReceiptLink>,
        slow: QueueReceiptLink,
    ) -> QueueTestedRevision {
        QueueTestedRevision {
            schema_version: 1,
            repo: config.repo,
            store: self.repo.identity().as_hex(),
            init_work: config.init_work.clone(),
            baseline_commit: config.baseline_commit.clone(),
            baseline_tree: config.baseline_tree.clone(),
            oracle_baseline: oracle_baseline.to_owned(),
            plan_digest: config.plan.digest.clone(),
            commit: commit.to_owned(),
            tree: tree.to_owned(),
            target,
            fast,
            slow,
            inventory_digest: [0; 32],
            received_pushes: Vec::new(),
        }
    }

    /// The complete inventory of the checked tree. Each document is an
    /// applied source's own receipt frontier at its reviewed mode, or the
    /// parent's unchanged document; every other path a blob, which must be
    /// the parent's own unless the baseline is sealed. A changed path
    /// without an admitted reviewed operation holds.
    fn seal_inventory(
        &self,
        wire: &GitWire<'_>,
        intent: &QueueRevisionIntent,
        sources: &[RepoProposal],
        parent: Option<&CodeRevision>,
    ) -> Result<Held<CodeTreeInventory>> {
        if self.commit_tree(&intent.commit)? != intent.tree {
            return held(
                QueueExportHoldReason::HeldObject,
                "the checked commit names another tree",
            );
        }
        let tree = GitOid::parse_hex(intent.tree.clone())?;
        let mut documents: BTreeMap<String, (CodeDocumentFrontier, u32)> = BTreeMap::new();
        if let Some(parent) = parent {
            let Some(parent_tree) = parent.tested_queue.as_ref().map(|tested| &tested.tree) else {
                return Err(Error::CorruptedIndex("a tested parent has no queue record"));
            };
            let entries = CodeTreeInventory::entries(wire, &self.repo, &tree)?;
            let before = CodeTreeInventory::entries(
                wire,
                &self.repo,
                &GitOid::parse_hex(parent_tree.clone())?,
            )?;
            let mut edited = BTreeMap::new();
            let mut removed = std::collections::BTreeSet::new();
            for source in sources {
                // A file bundle lands every file under its own child
                // receipt, and may remove paths (G4 PR2).
                if source.is_file_bundle() {
                    let tree = match self.file_bundle_tree(source)? {
                        Ok(tree) => tree,
                        Err(hold) => return Ok(Err(hold)),
                    };
                    edited.extend(tree.documents);
                    removed.extend(tree.removed);
                    continue;
                }
                if let Some(edit) = self.vault.code_file_edit_receipt(source.id)? {
                    let mode = source.reviewed_file_mode(self.vault, &edit.after)?;
                    edited.insert(source.ordinary_file()?.0.to_owned(), (edit.after, mode));
                }
            }
            if let Some(path) = removed.iter().find(|path| entries.contains_key(*path)) {
                return held(
                    QueueExportHoldReason::HeldUnreviewedChange,
                    format!("{path}: a reviewed removal is still in the checked tree"),
                );
            }
            let inherited: BTreeMap<&str, (&CodeDocumentFrontier, u32)> = parent
                .file_frontiers
                .values()
                .map(|frontier| {
                    let mode = parent
                        .commit_metadata
                        .as_ref()
                        .and_then(|metadata| metadata.file_modes.get(&frontier.document_id))
                        .copied()
                        .unwrap_or(0o100_644);
                    (frontier.path.as_str(), (frontier, mode))
                })
                .collect();
            for (path, entry) in &entries {
                if let Some(document) = edited.remove(path) {
                    documents.insert(path.clone(), document);
                } else if before.get(path) == Some(entry) {
                    if let Some((frontier, mode)) = inherited.get(path.as_str()) {
                        documents.insert(path.clone(), ((*frontier).clone(), *mode));
                    }
                } else {
                    return held(
                        QueueExportHoldReason::HeldUnreviewedChange,
                        format!("{path} changed without an admitted reviewed operation"),
                    );
                }
            }
            if let Some(path) = edited.keys().next() {
                return held(
                    QueueExportHoldReason::HeldUnreviewedChange,
                    format!("{path}: a reviewed edit is not in the checked tree"),
                );
            }
            if let Some(path) = before
                .keys()
                .find(|path| !entries.contains_key(*path) && !removed.contains(*path))
            {
                return held(
                    QueueExportHoldReason::HeldUnreviewedChange,
                    format!("{path} was removed without an admitted reviewed operation"),
                );
            }
        }
        Ok(
            match CodeTreeInventory::capture(self.vault, wire, &self.repo, &tree, &documents)? {
                Ok(inventory) => Ok(inventory),
                Err(detail) => Err(QueueExportHold::new(
                    QueueExportHoldReason::HeldUnreviewedChange,
                    detail,
                )),
            },
        )
    }
}
