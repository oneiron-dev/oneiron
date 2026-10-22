//! A received bundle's part of a tested seal (FIX 6869, G4 PR2): the
//! documents its present files landed as, each from its own deterministic
//! child receipt at its reviewed mode; each path it removed, retired with
//! its exact predecessor, its document if it had one, the child receipt
//! and the bundle's review; and the complete-push link, earned only when
//! the checked tree is the push's incoming tip.
use std::collections::BTreeMap;

use super::{CodePushSourceLink, MergeQueue, QueueExportHold, QueueExportHoldReason};
use crate::code_document::CodeDocumentFrontier;
use crate::code_revision::{CodePathRetirement, CodeRevision, CodeTreeBlob, CodeTreeInventory};
use crate::error::Result;
use crate::git_wire::{GitOid, GitWire};
use crate::repo_mutation::proposal::RepoProposal;
use crate::repo_mutation::received_file_operation;

type Held<T> = std::result::Result<T, QueueExportHold>;

/// The documents and removed paths of one received bundle, by path.
pub(super) struct ReceivedBundleTree {
    pub(super) documents: Vec<(String, (CodeDocumentFrontier, u32))>,
    pub(super) removed: Vec<String>,
}

fn unreviewed<T>(detail: String) -> Result<Held<T>> {
    Ok(Err(QueueExportHold::new(
        QueueExportHoldReason::HeldUnreviewedChange,
        detail,
    )))
}

impl MergeQueue<'_> {
    /// What the applied received bundle `source` landed: each present
    /// file's document from its own child receipt at its reviewed mode,
    /// and each path it removed.
    ///
    /// # Errors
    /// A store failure.
    pub(super) fn received_bundle_tree(
        &self,
        source: &RepoProposal,
    ) -> Result<Held<ReceivedBundleTree>> {
        let mut tree = ReceivedBundleTree {
            documents: Vec::new(),
            removed: Vec::new(),
        };
        for file in &source.files {
            if file.content.is_none() {
                tree.removed.push(file.path.clone());
                continue;
            }
            let (Some(operation), Some(mode)) = (
                file.source_operation,
                file.metadata_edit
                    .as_ref()
                    .and_then(|edit| edit.replacement.mode),
            ) else {
                return unreviewed(format!(
                    "{}: a received file has no reviewed state",
                    file.path
                ));
            };
            let operation = received_file_operation(source.id, operation)?;
            let Some(receipt) = self.vault.code_file_edit_receipt(operation)? else {
                return unreviewed(format!(
                    "{}: a received file has no document receipt",
                    file.path
                ));
            };
            if receipt.session_id != source.session || receipt.after.path != file.path {
                return unreviewed(format!(
                    "{}: a received document receipt is not its bundle's",
                    file.path
                ));
            }
            tree.documents
                .push((file.path.clone(), (receipt.after, mode)));
        }
        Ok(Ok(tree))
    }

    /// The retired paths and complete-push links the applied received
    /// `sources` give the seal of `tree` over `parent`. A removal names its
    /// predecessor exactly as the parent's checked tree held it.
    ///
    /// # Errors
    /// An object or store failure.
    pub(super) fn received_seal_evidence(
        &self,
        wire: &GitWire<'_>,
        tree: &str,
        sources: &[RepoProposal],
        parent: Option<&CodeRevision>,
    ) -> Result<
        Held<(
            BTreeMap<String, CodePathRetirement>,
            Vec<CodePushSourceLink>,
        )>,
    > {
        let mut retired = BTreeMap::new();
        let mut pushes = Vec::new();
        let received: Vec<&RepoProposal> = sources
            .iter()
            .filter(|source| source.received_candidate().is_some())
            .collect();
        if received.is_empty() {
            return Ok(Ok((retired, pushes)));
        }
        let Some(parent_tree) = parent.and_then(|parent| parent.tested_queue.as_ref()) else {
            return unreviewed("a received bundle landed with no tested parent".to_owned());
        };
        let before = CodeTreeInventory::entries(
            wire,
            &self.repo,
            &GitOid::parse_hex(parent_tree.tree.clone())?,
        )?;
        for source in received {
            for file in source.files.iter().filter(|file| file.content.is_none()) {
                let (Some(source_operation), Some((oid, mode))) =
                    (file.source_operation, before.get(&file.path))
                else {
                    return unreviewed(format!(
                        "{}: a received removal names no predecessor",
                        file.path
                    ));
                };
                let bytes = wire.read_object(&self.repo, &GitOid::parse_hex(oid.clone())?)?;
                let operation = received_file_operation(source.id, source_operation)?;
                let document = self
                    .vault
                    .code_file_edit_receipt(operation)?
                    .map(|receipt| receipt.after);
                retired.insert(
                    file.path.clone(),
                    CodePathRetirement {
                        previous: CodeTreeBlob {
                            git_oid: oid.clone(),
                            content_hash: *blake3::hash(&bytes).as_bytes(),
                            size_bytes: bytes.len() as u64,
                            mode: *mode,
                        },
                        document,
                        operation_receipt: operation,
                        review_ref: source.id,
                    },
                );
            }
            let Some(candidate) = source.received_candidate() else {
                continue;
            };
            // The tree a complete link names: the submitted one, or a masked
            // copy's canonical translated target (FIX 7608 2b-ii-B2, P8).
            if let Some((link, target_tree)) = self
                .vault
                .received_push_source_link(source.provenance_claim, candidate)?
                && target_tree == tree
            {
                pushes.push(link);
            }
        }
        pushes.sort();
        pushes.dedup();
        Ok(Ok((retired, pushes)))
    }
}
