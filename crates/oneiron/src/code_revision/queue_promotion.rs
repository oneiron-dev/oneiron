//! Promotion of a tested queue revision (FIX 6868, G2 PR3): the queue-only
//! multi-source verifier over the same immutable promotion receipts.
//!
//! A green batch can carry several sources, each with its own session,
//! actor and provenance, so the ordinary one-session promotion cannot judge
//! it and is not weakened to. Each changed document must be the exact
//! frontier of an applied source's own document receipt, at its reviewed
//! mode; every untouched path must be the promoted parent's own entry. A
//! slow pass is never counted as review. The chain's root, a checked
//! baseline, holds untouched imported bytes: their admission is G4's
//! reviewed import manifest (FIX 6869, G4 PR1). The root's receipt is
//! exactly its typed import approval, judged again on every read, and
//! without one it is a named gap, never an approval.
use std::collections::{BTreeMap, BTreeSet, HashSet};

use super::CodeRevision;
use super::promotion::{promotion_receipt_in_txn, put_promotion_receipt_in_txn};
use super::queue_root::queue_chain_root_in_txn;
use super::storage::{get_code_revision_in_txn, read_code_revision_record_in_txn};
use super::tree_inventory::document_mode;
use crate::error::{ArtifactError, Error, Result};
use crate::merge_queue::{GreenQueueRevision, QueueTestedTarget};
use crate::repo_mutation::proposal::RepoProposalStatus;
use crate::scan_check::{EngineScan, ScanCount};
use crate::{EntityId, Vault};

/// Why a tested queue revision cannot be promoted yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QueuePromotionGap {
    /// The chain's root holds untouched bytes no reviewed import admitted.
    UntouchedBytes(String),
    /// A changed path has no admitted reviewed operation covering it.
    Unreviewed(String),
}

impl QueuePromotionGap {
    fn error(&self) -> Error {
        Error::InvalidClaimBody(match self {
            Self::UntouchedBytes(_) => {
                "untouched imported bytes have no reviewed import admission (G4)"
            }
            Self::Unreviewed(_) => "a tested queue revision change lacks its reviewed operation",
        })
    }
}

impl Vault {
    /// Promotes the current green's tested revision and each unpromoted
    /// ancestor, oldest first, each by its own applied sources. A gap
    /// writes nothing past it.
    ///
    /// # Errors
    /// A gap, an immutable receipt that differs, or a store failure.
    pub fn promote_queue_code_revision(&self, green: &GreenQueueRevision) -> Result<()> {
        if let Some(gap) = self.queue_root_gap(green.revision_id())? {
            return Err(gap.error());
        }
        for revision in self
            .unpromoted_queue_chain(green.revision_id())?
            .iter()
            .rev()
        {
            let ids = match self.queue_promotion_receipt(revision)? {
                Ok(ids) => ids,
                Err(gap) => return Err(gap.error()),
            };
            let mut txn = self.store.env.write_txn()?;
            match promotion_receipt_in_txn(&self.store, &txn, &revision.revision_id)? {
                Some(old) if old != ids => {
                    return Err(Error::ConcurrentWrite("revision promotion is immutable"));
                }
                Some(_) => {}
                None => {
                    put_promotion_receipt_in_txn(&self.store, &mut txn, &revision.revision_id, ids)?
                }
            }
            txn.commit()?;
        }
        Ok(())
    }

    /// A tested queue revision's stored promotion receipt, judged again:
    /// its parent promoted and its own sources still covering every change.
    ///
    /// # Errors
    /// A missing or differing receipt, a gap, or a store failure.
    pub(crate) fn require_queue_revision_promotion(&self, revision_id: EntityId) -> Result<()> {
        let (revision, stored, parent_promoted) = {
            let txn = self.store.env.read_txn()?;
            let revision = get_code_revision_in_txn(&self.store, &txn, &revision_id)?
                .ok_or(Error::EntityNotFound)?;
            let stored = promotion_receipt_in_txn(&self.store, &txn, &revision_id)?;
            let parent_promoted = match revision.parent_revision_id {
                Some(parent) => promotion_receipt_in_txn(&self.store, &txn, &parent)?.is_some(),
                None => true,
            };
            (revision, stored, parent_promoted)
        };
        let stored = stored.ok_or(Error::InvalidClaimBody(
            "revision promotion receipt missing",
        ))?;
        if !parent_promoted {
            return Err(Error::InvalidClaimBody(
                "a tested queue revision inherits from an unpromoted parent",
            ));
        }
        match self.queue_promotion_receipt(&revision)? {
            Ok(ids) if ids == stored => {}
            Ok(_) => return Err(Error::ConcurrentWrite("revision promotion is immutable")),
            Err(gap) => return Err(gap.error()),
        }
        // The root's import approval is judged again, never inherited from
        // its receipt's presence (G4 PR1).
        match self.queue_root_gap(revision_id)? {
            Some(gap) => Err(gap.error()),
            None => Ok(()),
        }
    }

    /// The first gap between `revision_id` and promotion, oldest first;
    /// `None` when its chain can be promoted now.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn queue_promotion_gap(
        &self,
        revision_id: EntityId,
    ) -> Result<Option<QueuePromotionGap>> {
        if let Some(gap) = self.queue_root_gap(revision_id)? {
            return Ok(Some(gap));
        }
        for revision in self.unpromoted_queue_chain(revision_id)?.iter().rev() {
            if let Err(gap) = self.queue_promotion_receipt(revision)? {
                return Ok(Some(gap));
            }
        }
        Ok(None)
    }

    /// The gap at `revision_id`'s chain root, the checked baseline: `None`
    /// once its import approval holds now (G4 PR1).
    fn queue_root_gap(&self, revision_id: EntityId) -> Result<Option<QueuePromotionGap>> {
        // The chain's root by its kept key, not by walking the links on
        // every readiness view and export (FIX 7391).
        let root = {
            let txn = self.store.env.read_txn()?;
            let revision = read_code_revision_record_in_txn(&self.store, &txn, &revision_id)?
                .ok_or(Error::EntityNotFound)?;
            queue_chain_root_in_txn(&self.store, &txn, revision)?
        };
        Ok(self.baseline_promotion_receipt(&root)?.err())
    }

    /// The root's receipt: exactly its typed import approval, judged again
    /// (G4 PR1). No approval, or one that no longer holds, is the named
    /// untouched-bytes gap.
    fn baseline_promotion_receipt(
        &self,
        revision: &CodeRevision,
    ) -> Result<std::result::Result<Vec<String>, QueuePromotionGap>> {
        let tested = revision
            .tested_queue
            .as_ref()
            .ok_or(Error::InvalidClaimBody("not a tested queue revision"))?;
        let gap = |detail: String| Ok(Err(QueuePromotionGap::UntouchedBytes(detail)));
        if revision.parent_revision_id.is_some() || tested.target != QueueTestedTarget::Baseline {
            return gap(format!(
                "the checked baseline {} holds untouched bytes no reviewed import admitted",
                tested.commit
            ));
        }
        let txn = self.store.env.read_txn()?;
        let Some(stored) = promotion_receipt_in_txn(&self.store, &txn, &revision.revision_id)?
        else {
            return gap(format!(
                "the checked baseline {} holds untouched bytes no reviewed import admitted",
                tested.commit
            ));
        };
        match self.require_imported_baseline_promotion_in_txn(&txn, revision, &stored)? {
            Ok(()) => Ok(Ok(stored)),
            Err(detail) => gap(format!("the checked baseline {}: {detail}", tested.commit)),
        }
    }

    /// `revision_id` and its ancestors back to, not including, the first
    /// promoted one: newest first.
    fn unpromoted_queue_chain(&self, revision_id: EntityId) -> Result<Vec<CodeRevision>> {
        let txn = self.store.env.read_txn()?;
        let mut count = ScanCount::start(
            &self.store,
            &txn,
            EngineScan::DagWalkRecords,
            revision_id.as_bytes(),
        )?;
        let mut visited = HashSet::new();
        let mut chain = Vec::new();
        let mut next = Some(revision_id);
        loop {
            let Some(id) = next else {
                count.defer(&self.store);
                return Ok(chain);
            };
            if !visited.insert(id) {
                count.defer(&self.store);
                return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                    "code revision parent chain contains a cycle",
                )));
            }
            count.row();
            if promotion_receipt_in_txn(&self.store, &txn, &id)?.is_some() {
                count.defer(&self.store);
                return Ok(chain);
            }
            let revision = if chain.is_empty() {
                get_code_revision_in_txn(&self.store, &txn, &id)?
            } else {
                read_code_revision_record_in_txn(&self.store, &txn, &id)?
            }
            .ok_or(Error::EntityNotFound)?;
            next = revision.parent_revision_id;
            chain.push(revision);
        }
    }

    /// The receipt ids that promote `revision` once its parent is promoted:
    /// its applied sources, sorted. Untouched entries must be the parent's
    /// own; each changed document the last applied source's receipt frontier
    /// at its reviewed mode.
    fn queue_promotion_receipt(
        &self,
        revision: &CodeRevision,
    ) -> Result<std::result::Result<Vec<String>, QueuePromotionGap>> {
        let tested = revision
            .tested_queue
            .as_ref()
            .ok_or(Error::InvalidClaimBody("not a tested queue revision"))?;
        let (Some(parent_id), QueueTestedTarget::Landed { applied, .. }) =
            (revision.parent_revision_id, &tested.target)
        else {
            return self.baseline_promotion_receipt(revision);
        };
        let parent = self
            .get_code_revision(&parent_id)?
            .ok_or(Error::EntityNotFound)?;
        let unreviewed = |path: &str, why: &str| {
            Ok(Err(QueuePromotionGap::Unreviewed(format!("{path}: {why}"))))
        };
        for (path, blob) in &revision.blob_frontiers {
            if parent.blob_frontiers.get(path) != Some(blob) {
                return unreviewed(
                    path.as_str(),
                    "an untouched path changed without a reviewed operation",
                );
            }
        }
        let paths: BTreeSet<&str> = revision
            .file_frontiers
            .values()
            .map(|frontier| frontier.path.as_str())
            .chain(revision.blob_frontiers.keys().map(String::as_str))
            .collect();
        let parent_paths = parent
            .file_frontiers
            .values()
            .map(|frontier| frontier.path.as_str())
            .chain(parent.blob_frontiers.keys().map(String::as_str));
        for path in parent_paths {
            // A retirement names the applied reviewed removal that made it,
            // proved when the seal was finalized (G4 PR2).
            let retired = revision.retired_paths.get(path).is_some_and(|retirement| {
                applied
                    .iter()
                    .any(|source| source.proposal == retirement.review_ref)
            });
            if !paths.contains(path) && !retired {
                return unreviewed(path, "removed without a reviewed operation");
            }
        }
        let mut reviewed = BTreeMap::new();
        for source in applied {
            let proposal = self
                .repo_proposal(source.proposal)?
                .ok_or(Error::EntityNotFound)?;
            if proposal.status != RepoProposalStatus::Applied
                || proposal.operation_seq != Some(source.operation_seq)
                || proposal.session != source.session
                || proposal.provenance_claim != source.provenance_claim
            {
                return unreviewed(
                    proposal.operation_subject().as_str(),
                    "a source is not the applied review it names",
                );
            }
            if proposal.is_file_bundle() {
                if let Err(gap) = self.bundle_promotion_documents(&proposal, &mut reviewed)? {
                    return Ok(Err(gap));
                }
                continue;
            }
            let Some(edit) = self.code_file_edit_receipt(source.proposal)? else {
                continue;
            };
            let mode = proposal.reviewed_file_mode(self, &edit.after)?;
            let (path, _) = proposal.ordinary_file()?;
            if edit.session_id != proposal.session
                || edit.actor.map(|actor| actor.entity_ref()) != proposal.actor.id()
                || edit.provenance != proposal.op_provenance
                || edit.edit.path != path
            {
                return unreviewed(path, "a document receipt is not its source's");
            }
            reviewed.insert(edit.document_id, (edit.after, mode));
        }
        for (id, frontier) in &revision.file_frontiers {
            let mode = document_mode(revision, id);
            if parent.file_frontiers.get(id) == Some(frontier) && document_mode(&parent, id) == mode
            {
                continue;
            }
            match reviewed.get(id) {
                Some((after, reviewed_mode)) if after == frontier && *reviewed_mode == mode => {}
                _ => {
                    return unreviewed(
                        frontier.path.as_str(),
                        "a changed document lacks its reviewed operation",
                    );
                }
            }
        }
        let mut ids: Vec<String> = applied
            .iter()
            .map(|source| source.proposal.to_hex())
            .collect();
        ids.sort();
        ids.dedup();
        Ok(Ok(ids))
    }

    /// Each present file of the applied file bundle `proposal`, as its own
    /// child receipt's frontier at its reviewed mode, into `reviewed` (G4
    /// PR2). A mode-only change earns its own fold here.
    fn bundle_promotion_documents(
        &self,
        proposal: &crate::repo_mutation::proposal::RepoProposal,
        reviewed: &mut BTreeMap<[u8; 32], (crate::code_document::CodeDocumentFrontier, u32)>,
    ) -> Result<std::result::Result<(), QueuePromotionGap>> {
        for (index, file) in proposal.files.iter().enumerate() {
            if file.content.is_none() {
                continue;
            }
            let gap = |why: &str| {
                Ok(Err(QueuePromotionGap::Unreviewed(format!(
                    "{}: {why}",
                    file.path
                ))))
            };
            let Some(mode) = file
                .metadata_edit
                .as_ref()
                .and_then(|edit| edit.replacement.mode)
            else {
                return gap("a bundle file has no reviewed state");
            };
            let operation = proposal.file_operation(index)?;
            let Some(edit) = self.code_file_edit_receipt(operation)? else {
                return gap("a bundle file has no document receipt");
            };
            if edit.session_id != proposal.session
                || edit.actor.map(|actor| actor.entity_ref()) != proposal.actor.id()
                || edit.edit.path != file.path
            {
                return gap("a document receipt is not its source's");
            }
            reviewed.insert(edit.document_id, (edit.after, mode));
        }
        Ok(Ok(()))
    }
}
