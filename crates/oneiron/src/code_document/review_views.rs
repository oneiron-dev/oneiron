//! The code review views (OF-323). `vault.code.proposal_view` shows a repo
//! proposal as a semantic change from the file at its base, under the
//! provenance it was proposed with, and the operation it landed as once
//! applied. `vault.code.repo_diff` shows every file changed between two
//! trees, a tree being a code revision's tested files or a git snapshot's.
//! A rename is one document at a new path. A document's units name the
//! operations that wrote them; a git snapshot names none, since it holds no
//! operations and no authorship is made up for it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::verbs::{
    CodeChangeView, CodeOperationView, CodeStateView, change_view, operation_view, state_view,
};
use super::{CodeDocumentFrontier, CodeOpAttribution};
use crate::code_symbol::{
    CodeAttributedChange, render_attributed_semantic_diff, semantic_code_diff,
};
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::repo_mutation::mount::RepoMountRef;
use crate::repo_mutation::proposal::RepoProposalStatus;

/// The most files one side of a repo diff may hold.
const MAX_REPO_DIFF_FILES: usize = 1024;

/// One repo proposal, by ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeProposalViewRequest {
    pub proposal_ref: String,
}

/// Who proposed a change, and why: the stamp its landed operation carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeProposedStamp {
    pub actor_ref: String,
    pub session_ref: String,
    pub provenance_claim_ref: String,
    pub turn_ref: Option<String>,
    pub activity_ref: Option<String>,
    pub intent_ref: Option<String>,
    pub model_ref: Option<String>,
    pub reasoning_effort: Option<String>,
}

/// `vault.code.proposal_view`: one proposal as a reviewer reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeProposalView {
    pub proposal_ref: String,
    pub repo: String,
    pub path: String,
    pub message: String,
    pub status: RepoProposalStatus,
    pub proposed: CodeProposedStamp,
    /// The candidate against the file at the proposal's base, unit by unit.
    /// Every change is the proposal's; once it landed, each names that
    /// operation.
    pub changes: Vec<CodeChangeView>,
    /// The document operation the proposal landed as, once applied.
    pub landed: Option<CodeOperationView>,
    /// The changes as text, under the proposed stamp.
    pub rendered: String,
}

/// One side of a repo diff: a code revision's tested files
/// (`revision_ref`), or a git snapshot's files (`repo` and `snapshot_ref`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeTreeRequest {
    #[serde(default)]
    pub revision_ref: Option<String>,
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub snapshot_ref: Option<String>,
}

/// Two trees of a repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRepoDiffRequest {
    pub before: CodeTreeRequest,
    pub after: CodeTreeRequest,
}

/// How one file changed between the trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeFileChange {
    Added,
    Removed,
    Modified,
    Renamed,
}

/// One changed file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeFileDiffView {
    pub path: String,
    pub change: CodeFileChange,
    /// Its path before, when it moved.
    pub renamed_from: Option<String>,
    /// The tested document state on each side; absent on a snapshot side
    /// and on the side the file is missing from.
    pub before: Option<CodeStateView>,
    pub after: Option<CodeStateView>,
    pub changes: Vec<CodeChangeView>,
}

/// `vault.code.repo_diff`: every changed file, by path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeRepoDiffView {
    pub files: Vec<CodeFileDiffView>,
    /// Files a snapshot holds that are not UTF-8 text, so not compared.
    pub not_text: Vec<String>,
    /// The changes as text, file by file.
    pub rendered: String,
}

/// One file of a tree: its text and, from a code revision, its tested state.
struct TreeFile {
    path: String,
    text: String,
    tested: Option<(CodeDocumentFrontier, String)>,
}

fn invalid(reason: &'static str) -> MemoryError {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(reason)).into()
}

fn utf8(bytes: &[u8]) -> MemoryResult<&str> {
    std::str::from_utf8(bytes).map_err(|_| invalid("a code view reads UTF-8 text"))
}

impl Memory<'_> {
    /// `vault.code.proposal_view`: a repo proposal's candidate against the
    /// file at its base, with the provenance stamped on it.
    pub fn code_proposal_view(
        &self,
        input: &CodeProposalViewRequest,
    ) -> MemoryResult<Option<CodeProposalView>> {
        let vault = self.vault();
        let Some(proposal) = vault.repo_proposal(EntityId::from_hex(&input.proposal_ref)?)? else {
            return Ok(None);
        };
        let repo = RepoRef::parse(&proposal.repo)?;
        let base =
            vault.mount_repo_ref(&repo, RepoMountRef::Fork(proposal.pre_action_fork_hash))?;
        let old = utf8(base.read_file(&proposal.path)?.unwrap_or(b""))?;
        let new = utf8(&proposal.content)?;
        let landed = vault
            .code_file_edit_receipt(proposal.id)?
            .map(|receipt| CodeOpAttribution {
                operation: receipt.operation,
                session_id: receipt.session_id,
                actor: receipt.actor,
                sequence: receipt.sequence,
                provenance: receipt.provenance,
            });
        let changes: Vec<CodeAttributedChange> = semantic_code_diff(&proposal.path, old, new)?
            .into_iter()
            .map(|change| CodeAttributedChange {
                inserted_by: landed
                    .iter()
                    .filter(|_| change.after.is_some())
                    .cloned()
                    .collect(),
                deleted_by: landed
                    .iter()
                    .filter(|_| change.before.is_some())
                    .cloned()
                    .collect(),
                change,
            })
            .collect();
        let id = |id: Option<EntityId>| id.map(|id| id.to_hex());
        let provenance = &proposal.op_provenance;
        let proposed = CodeProposedStamp {
            actor_ref: proposal.actor.to_hex(),
            session_ref: proposal.session.to_hex(),
            provenance_claim_ref: proposal.provenance_claim.to_hex(),
            turn_ref: id(provenance.turn),
            activity_ref: id(provenance.activity),
            intent_ref: id(provenance.intent),
            model_ref: id(provenance.substrate_ref),
            reasoning_effort: provenance.reasoning_effort.clone(),
        };
        let shown = |id: &Option<String>| id.clone().unwrap_or_else(|| "-".to_owned());
        let rendered = format!(
            "# proposed actor:{} session:{} turn:{} activity:{} intent:{} model:{} effort:{}\n{}",
            proposed.actor_ref,
            proposed.session_ref,
            shown(&proposed.turn_ref),
            shown(&proposed.activity_ref),
            shown(&proposed.intent_ref),
            shown(&proposed.model_ref),
            shown(&proposed.reasoning_effort),
            render_attributed_semantic_diff(&changes),
        );
        Ok(Some(CodeProposalView {
            proposal_ref: proposal.id.to_hex(),
            repo: proposal.repo,
            path: proposal.path,
            message: proposal.message,
            status: proposal.status,
            proposed,
            changes: changes.into_iter().map(change_view).collect(),
            landed: landed.as_ref().map(operation_view),
            rendered,
        }))
    }

    /// `vault.code.repo_diff`: every file changed between two trees. A file
    /// pairs with the one of its document on the other side, else with the
    /// one at its path; a pair at two paths is a rename.
    pub fn code_repo_diff(
        &self,
        input: &CodeRepoDiffRequest,
    ) -> MemoryResult<Option<CodeRepoDiffView>> {
        let mut not_text = Vec::new();
        let (Some(before), Some(after)) = (
            self.code_tree(&input.before, &mut not_text)?,
            self.code_tree(&input.after, &mut not_text)?,
        ) else {
            return Ok(None);
        };
        let mut unpaired: Vec<Option<TreeFile>> = before.into_iter().map(Some).collect();
        let mut pairs = Vec::new();
        for new in after {
            let at = |same: &dyn Fn(&TreeFile) -> bool| {
                unpaired
                    .iter()
                    .position(|old| old.as_ref().is_some_and(|old| same(old)))
            };
            let index = at(&|old: &TreeFile| same_document(old, &new))
                .or_else(|| at(&|old: &TreeFile| old.path == new.path));
            pairs.push((index.and_then(|index| unpaired[index].take()), Some(new)));
        }
        pairs.extend(unpaired.into_iter().flatten().map(|old| (Some(old), None)));
        let mut files = Vec::new();
        for (old, new) in pairs {
            if let Some(file) = self.file_diff(old, new)? {
                files.push(file);
            }
        }
        files.sort_by(|a, b| a.0.path.cmp(&b.0.path));
        let mut rendered = String::new();
        for (file, changes) in &files {
            rendered.push_str(&format!("## {:?} {}", file.change, file.path));
            if let Some(from) = &file.renamed_from {
                rendered.push_str(&format!(" (from {from})"));
            }
            rendered.push('\n');
            rendered.push_str(&render_attributed_semantic_diff(changes));
        }
        not_text.sort();
        not_text.dedup();
        Ok(Some(CodeRepoDiffView {
            files: files
                .into_iter()
                .map(|(mut file, changes)| {
                    file.changes = changes.into_iter().map(change_view).collect();
                    file
                })
                .collect(),
            not_text,
            rendered,
        }))
    }

    /// A tree's files; `None` when its revision is not there.
    fn code_tree(
        &self,
        request: &CodeTreeRequest,
        not_text: &mut Vec<String>,
    ) -> MemoryResult<Option<Vec<TreeFile>>> {
        let vault = self.vault();
        let files = match (&request.revision_ref, &request.repo, &request.snapshot_ref) {
            (Some(revision_ref), None, None) => {
                let Some(revision) = vault.get_code_revision(&EntityId::from_hex(revision_ref)?)?
                else {
                    return Ok(None);
                };
                revision
                    .file_frontiers
                    .into_values()
                    .map(|frontier| -> MemoryResult<TreeFile> {
                        Ok(TreeFile {
                            path: frontier.path.clone(),
                            text: vault.code_document_at(&frontier)?,
                            tested: Some((frontier, revision_ref.clone())),
                        })
                    })
                    .collect::<MemoryResult<Vec<_>>>()?
            }
            (None, Some(repo), Some(snapshot)) => {
                let mount = vault.mount_repo_ref(
                    &RepoRef::parse(repo)?,
                    RepoMountRef::Snapshot(EntityId::from_hex(snapshot)?),
                )?;
                let mut files = Vec::new();
                for path in mount.list_files() {
                    let bytes = mount.read_file(path)?.unwrap_or_default();
                    match std::str::from_utf8(bytes) {
                        Ok(text) => files.push(TreeFile {
                            path: path.to_owned(),
                            text: text.to_owned(),
                            tested: None,
                        }),
                        Err(_) => not_text.push(path.to_owned()),
                    }
                }
                files
            }
            _ => {
                return Err(invalid(
                    "a code tree is a revision_ref, or a repo and a snapshot_ref",
                ));
            }
        };
        if files.len() > MAX_REPO_DIFF_FILES {
            return Err(invalid("a repo diff compares at most 1024 files a side"));
        }
        Ok(Some(files))
    }

    /// One pair's file view and its attributed changes; `None` when the
    /// file did not change.
    fn file_diff(
        &self,
        old: Option<TreeFile>,
        new: Option<TreeFile>,
    ) -> MemoryResult<Option<(CodeFileDiffView, Vec<CodeAttributedChange>)>> {
        let vault = self.vault();
        let (path, change, renamed_from) = match (&old, &new) {
            (Some(old), Some(new)) if old.path != new.path => (
                new.path.clone(),
                CodeFileChange::Renamed,
                Some(old.path.clone()),
            ),
            (Some(old), Some(new)) if old.text == new.text => return Ok(None),
            (Some(_), Some(new)) => (new.path.clone(), CodeFileChange::Modified, None),
            (None, Some(new)) => (new.path.clone(), CodeFileChange::Added, None),
            (Some(old), None) => (old.path.clone(), CodeFileChange::Removed, None),
            (None, None) => return Ok(None),
        };
        let changes = match (tested(&old), tested(&new)) {
            // Two states of one document: each unit with the operations
            // made between them.
            (Some((before, _)), Some((after, _))) if before.document_id == after.document_id => {
                vault.code_document_semantic_diff(before, after)?
            }
            // Otherwise the text is compared, and a newer unit names every
            // operation that wrote it; a snapshot names none.
            _ => {
                let text = |file: &Option<TreeFile>| {
                    file.as_ref()
                        .map_or_else(String::new, |file| file.text.clone())
                };
                let writers: BTreeMap<String, Vec<CodeOpAttribution>> = match tested(&new) {
                    Some((after, _)) => vault
                        .code_document_symbol_blame(after)?
                        .into_iter()
                        .map(|unit| {
                            let ops: Vec<CodeOpAttribution> =
                                unit.operations().into_iter().cloned().collect();
                            (unit.symbol, ops)
                        })
                        .collect(),
                    None => BTreeMap::new(),
                };
                semantic_code_diff(&path, &text(&old), &text(&new))?
                    .into_iter()
                    .map(|change| CodeAttributedChange {
                        inserted_by: change
                            .after
                            .as_ref()
                            .and_then(|_| writers.get(&change.symbol))
                            .cloned()
                            .unwrap_or_default(),
                        deleted_by: Vec::new(),
                        change,
                    })
                    .collect()
            }
        };
        let state = |file: &Option<TreeFile>| {
            tested(file).map(|(frontier, revision)| state_view(frontier, Some(revision.clone())))
        };
        Ok(Some((
            CodeFileDiffView {
                path,
                change,
                renamed_from,
                before: state(&old),
                after: state(&new),
                changes: Vec::new(),
            },
            changes,
        )))
    }
}

/// A file's tested state, when its tree is a code revision.
fn tested(file: &Option<TreeFile>) -> Option<&(CodeDocumentFrontier, String)> {
    file.as_ref().and_then(|file| file.tested.as_ref())
}

/// Whether two files are states of one document.
fn same_document(old: &TreeFile, new: &TreeFile) -> bool {
    matches!(
        (&old.tested, &new.tested),
        (Some((before, _)), Some((after, _))) if before.document_id == after.document_id
    )
}
