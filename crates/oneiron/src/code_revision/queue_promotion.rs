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
//! reviewed import manifest, so here it is a named gap, never an approval.
use std::collections::{BTreeMap, BTreeSet};

use super::CodeRevision;
use super::promotion::{promotion_receipt_in_txn, put_promotion_receipt_in_txn};
use super::storage::{get_code_revision_in_txn, read_code_revision_record_in_txn};
use super::tree_inventory::document_mode;
use crate::error::{Error, Result};
use crate::merge_queue::{GreenQueueRevision, QueueTestedTarget};
use crate::repo_mutation::proposal::RepoProposalStatus;
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
            Ok(ids) if ids == stored => Ok(()),
            Ok(_) => Err(Error::ConcurrentWrite("revision promotion is immutable")),
            Err(gap) => Err(gap.error()),
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
        for revision in self.unpromoted_queue_chain(revision_id)?.iter().rev() {
            if let Err(gap) = self.queue_promotion_receipt(revision)? {
                return Ok(Some(gap));
            }
        }
        Ok(None)
    }

    /// `revision_id` and its ancestors back to, not including, the first
    /// promoted one: newest first.
    fn unpromoted_queue_chain(&self, revision_id: EntityId) -> Result<Vec<CodeRevision>> {
        let txn = self.store.env.read_txn()?;
        let mut chain = Vec::new();
        let mut next = Some(revision_id);
        for _ in 0..crate::limits::MAX_ANCESTOR_DEPTH {
            let Some(id) = next else {
                return Ok(chain);
            };
            if promotion_receipt_in_txn(&self.store, &txn, &id)?.is_some() {
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
        Err(Error::IndexOverflow("tested queue revision chain"))
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
            return Ok(Err(QueuePromotionGap::UntouchedBytes(format!(
                "the checked baseline {} holds untouched bytes no reviewed import admitted",
                tested.commit
            ))));
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
            if !paths.contains(path) {
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
                    proposal.path.as_str(),
                    "a source is not the applied review it names",
                );
            }
            let Some(edit) = self.code_file_edit_receipt(source.proposal)? else {
                continue;
            };
            let mode = proposal.reviewed_file_mode(self, &edit.after)?;
            if edit.session_id != proposal.session
                || edit.actor.map(|actor| actor.entity_ref()) != proposal.actor.id()
                || edit.provenance != proposal.op_provenance
                || edit.edit.path != proposal.path
            {
                return unreviewed(
                    proposal.path.as_str(),
                    "a document receipt is not its source's",
                );
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
}
