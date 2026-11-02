//! A reviewed file bundle (FIX 7608 slice 5): many files, each with its
//! exact state change, as ONE proposal, ONE merge-queue proposal, ONE
//! prepared commit and ONE grouped document ingress. A received push
//! bundle (G4 PR2) and a native bundle share every step here; only the
//! received one proves a source candidate, and only the native one is
//! built from a caller's request and carries a provenance trailer.
use std::collections::BTreeMap;
use std::path::Path;

use self::tree::{
    apply_prepared_bundle_files, bundle_post_snapshot, bundle_tree_edits,
    prepare_bundle_files_commit,
};
use super::git::validate_relative_repo_path;
use super::mount::RepoMountRef;
use super::proposal::{RepoProposal, RepoProposalOperation, RepoProposedFile, invalid};
use super::queue::{PreparedCommitFile, PreparedRepoMutationExecution};
use super::snapshot::{SnapshotCustody, StoredRepoSnapshot, StoredRepoSnapshotEntryKind};
use super::trailer::commit_message_with_provenance_trailer;
use super::types::{RepoBundleFile, RepoForkHash, RepoMutationOperation, RepoMutationRequest};
use crate::Vault;
use crate::code_document::{CodeFileEdit, CodeFileIngress, CodeFileMetadataEdit, CodeFilePresence};
use crate::codebase::{DEFAULT_CODE_FILE_MODE, RepoRef, entity_id_from_hash_material};
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};
use crate::merge_queue::{MergeFile, MergeFileExpected, MergeProposal};
use crate::write_envelope::WriteActor;

pub(crate) mod tree;

/// CALL BUNDLE-CHILD-OP: the hash domain of the deterministic document
/// operation a native bundle's file lowers to, from (proposal, index).
const BUNDLE_FILE_OPERATION_DOMAIN: &[u8] = b"oneiron:repo-bundle-file-op:v1";

/// The reviewed bytes one native bundle may hold, all files together: the
/// same bound one ordinary proposal's file has.
const BUNDLE_CONTENT_LIMIT_BYTES: usize = 32 * 1024 * 1024;

/// The paths a secret remediation read whole from its pinned commit (FIX
/// 7608 slice 6), each with the BLAKE3 of the bytes the commit held there,
/// `None` for a path it did not hold (FIX 10974).
pub(in crate::repo_mutation) type ProvenFiles = BTreeMap<String, Option<[u8; 32]>>;

/// CALL BUNDLE-NONEMPTY: a native bundle names at least one file, each
/// path once, at a kept mode, and a removal names no mode.
///
/// # Errors
/// A typed invalid record naming the first shape that fails.
pub(in crate::repo_mutation) fn validate_bundle_files(files: &[RepoBundleFile]) -> Result<()> {
    if files.is_empty() {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "a file bundle carries at least one file",
        )));
    }
    let mut paths = std::collections::BTreeSet::new();
    for file in files {
        validate_relative_repo_path(&file.path)?;
        if !paths.insert(file.path.as_str()) {
            return Err(invalid("a file bundle names each path once"));
        }
        match (&file.content, file.mode) {
            (None, Some(_)) => return Err(invalid("a bundle removal names no mode")),
            (Some(_), Some(mode)) => crate::codebase::validate_code_file_mode(mode)?,
            _ => {}
        }
    }
    Ok(())
}

/// CALL BUNDLE-SUBJECT: the oplog subject a native bundle lands under is
/// its stored message.
pub(crate) fn bundle_operation_subject(message: &str) -> String {
    message.to_owned()
}

impl RepoProposal {
    /// The document operation the file at `index` lowers to: an ordinary
    /// proposal's own id, a received file's child of its source operation,
    /// or a native bundle file's child of its index (CALL BUNDLE-CHILD-OP).
    ///
    /// # Errors
    /// An index with no file, a received file with no source, or an id
    /// derivation failure.
    pub(crate) fn file_operation(&self, index: usize) -> Result<EntityId> {
        let file = self
            .files
            .get(index)
            .ok_or(invalid("a proposal file index is out of range"))?;
        match self.operation {
            RepoProposalOperation::ReceivedFiles { .. } => super::received_file_operation(
                self.id,
                file.source_operation
                    .ok_or(invalid("a received file names its source operation"))?,
            ),
            RepoProposalOperation::CommitFiles => entity_id_from_hash_material(
                BUNDLE_FILE_OPERATION_DOMAIN,
                &[self.id.as_bytes(), &(index as u64).to_be_bytes()],
            ),
            RepoProposalOperation::CommitFile
            | RepoProposalOperation::ResolveConflictFile { .. } => Ok(self.id),
        }
    }
}

/// The request a stored native bundle lands as: its files at their
/// reviewed bytes and replacement modes, under its own message.
///
/// # Errors
/// A stored file with no reviewed state change.
pub(in crate::repo_mutation) fn bundle_request_operation(
    row: &RepoProposal,
) -> Result<RepoMutationOperation> {
    let files = row
        .files
        .iter()
        .map(|file| {
            let state = file
                .metadata_edit
                .as_ref()
                .ok_or(invalid("a bundle file carries its reviewed state change"))?;
            Ok(RepoBundleFile::new(
                file.path.clone(),
                file.content.clone(),
                state.replacement.mode,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(RepoMutationOperation::CommitFiles {
        files,
        message: row.message.clone(),
    })
}

/// A native bundle's stored files: each request file with its exact state
/// change against `pre_action`, in the request's order. A present file
/// keeps its base mode unless it names one; a new one is a regular file. A
/// file the snapshot withholds is changed only on a `proven` path (a secret
/// remediation's, FIX 7608 slice 6): its state is its kept mode, and its
/// old bytes stay out of the row; only their BLAKE3 is kept (FIX 10974).
///
/// # Errors
/// More bytes than the bound, a path the snapshot withholds and no
/// remediation proved, a proven withheld path its commit does not hold, a
/// removal of an absent path, or a file that changes nothing.
pub(in crate::repo_mutation) fn reviewed_bundle_files(
    pre_action: &StoredRepoSnapshot,
    files: Vec<RepoBundleFile>,
    proven: &ProvenFiles,
) -> Result<Vec<RepoProposedFile>> {
    let total = files
        .iter()
        .map(|file| file.content.as_ref().map_or(0, Vec::len))
        .try_fold(0_usize, usize::checked_add)
        .ok_or(Error::ArithmeticOverflow("bundle_content_bytes"))?;
    if total > BUNDLE_CONTENT_LIMIT_BYTES {
        return Err(invalid(
            "proposal requires bounded content and review lenses",
        ));
    }
    files
        .into_iter()
        .map(|file| {
            let entry = pre_action
                .entries
                .iter()
                .find(|entry| entry.path == file.path);
            let (expected, old, withheld_base_blake3) = match entry {
                None => (CodeFilePresence::absent(), None, None),
                Some(entry) => match entry.kind {
                    StoredRepoSnapshotEntryKind::File => (
                        CodeFilePresence::file(if entry.executable {
                            0o100_755
                        } else {
                            DEFAULT_CODE_FILE_MODE
                        }),
                        Some(entry.content.clone()),
                        None,
                    ),
                    StoredRepoSnapshotEntryKind::Symlink => (
                        CodeFilePresence::file(0o120_000),
                        entry.symlink_target.clone().map(String::into_bytes),
                        None,
                    ),
                    StoredRepoSnapshotEntryKind::Withheld if proven.contains_key(&file.path) => {
                        let Some(hash) = proven.get(&file.path).copied().flatten() else {
                            return Err(invalid("a remediated file is not in its pinned commit"));
                        };
                        (
                            CodeFilePresence::file(if entry.executable {
                                0o100_755
                            } else {
                                DEFAULT_CODE_FILE_MODE
                            }),
                            None,
                            Some(hash),
                        )
                    }
                    StoredRepoSnapshotEntryKind::Withheld => {
                        return Err(crate::secret_snapshot::SnapshotWithhold::Excluded.refusal());
                    }
                },
            };
            let replacement = match (&file.content, file.mode.or(expected.mode)) {
                (None, _) => CodeFilePresence::absent(),
                (Some(_), Some(mode)) => CodeFilePresence::file(mode),
                (Some(_), None) => CodeFilePresence::file(DEFAULT_CODE_FILE_MODE),
            };
            if !expected.present && !replacement.present {
                return Err(invalid("a bundle removes only a present file"));
            }
            if expected == replacement && file.content == old {
                return Err(invalid("a bundle file changes its path"));
            }
            Ok(RepoProposedFile {
                metadata_edit: Some(CodeFileMetadataEdit::between(
                    &file.path,
                    expected,
                    replacement,
                )),
                path: file.path,
                content: file.content,
                source_operation: None,
                withheld_base_blake3,
            })
        })
        .collect()
}

/// A native bundle's route: it runs only under its actor, session and
/// reviewed proposal, as one member of its merge-queue stack.
///
/// # Errors
/// A request with no actor, session or proposal, or one outside a stack.
pub(in crate::repo_mutation) fn require_bundle_route(
    request: &RepoMutationRequest,
    proposal: Option<EntityId>,
    stack: Option<&super::reviewed_stack::StackStep>,
) -> Result<()> {
    if request.actor_id.is_none() || request.session_id.is_none() || proposal.is_none() {
        return Err(invalid(
            "a file bundle lands under its actor, session and review",
        ));
    }
    if stack.is_none() {
        return Err(super::proposal::native_bundle_queue_only());
    }
    Ok(())
}

impl Vault {
    /// A file bundle's ONE staged commit: its stored files' exact tree
    /// change, prepared on the checkout's HEAD under the received bundle's
    /// own message, or a native bundle's message with its provenance
    /// trailer.
    pub(super) fn prepare_bundle_execution(
        &self,
        repo_root: &Path,
        request: &RepoMutationRequest,
        proposal: Option<EntityId>,
    ) -> Result<PreparedRepoMutationExecution> {
        let message = match &request.operation {
            RepoMutationOperation::ReceivedFiles { message, .. } => message.clone(),
            RepoMutationOperation::CommitFiles { message, .. } => {
                commit_message_with_provenance_trailer(message, request.provenance_claim_id)?
            }
            _ => return Err(Error::InvariantViolation("not a file bundle")),
        };
        let row = self
            .repo_proposal(proposal.ok_or(Error::InvariantViolation(
                "a file bundle lands under its proposal",
            ))?)?
            .ok_or(Error::EntityNotFound)?;
        let edits = bundle_tree_edits(&row.files)?;
        let commit = prepare_bundle_files_commit(repo_root, &edits, &message)?;
        Ok(PreparedRepoMutationExecution::FileBundle { commit, edits })
    }
}

/// The fork hash the checkout has once the prepared bundle lands on the
/// snapshot it was prepared on.
///
/// # Errors
/// An execution that is no bundle's, a HEAD that moved, or an encoding
/// failure.
pub(in crate::repo_mutation) fn bundle_post_action_fork_hash(
    custody: &SnapshotCustody,
    pre_action_snapshot: &StoredRepoSnapshot,
    execution: &PreparedRepoMutationExecution,
) -> Result<RepoForkHash> {
    let PreparedRepoMutationExecution::FileBundle { commit, edits } = execution else {
        return Err(Error::InvariantViolation(
            "a file bundle is missing its prepared tree change",
        ));
    };
    if pre_action_snapshot.head.as_deref() != Some(commit.base_head.as_str()) {
        return Err(Error::ConcurrentWrite(
            "repo HEAD changed while preparing write-ahead intent",
        ));
    }
    bundle_post_snapshot(custody, pre_action_snapshot, edits, &commit.new_head)
}

/// Moves the live checkout to a native bundle's prepared commit, once its
/// message still carries its provenance trailer.
///
/// # Errors
/// A trailer that does not build, or a Git failure.
pub(in crate::repo_mutation) fn apply_native_bundle(
    repo_root: &Path,
    request: &RepoMutationRequest,
    prepared: &PreparedCommitFile,
) -> Result<()> {
    let RepoMutationOperation::CommitFiles { message, .. } = &request.operation else {
        return Err(Error::InvariantViolation("not a native file bundle"));
    };
    let _ = commit_message_with_provenance_trailer(message, request.provenance_claim_id)?;
    apply_prepared_bundle_files(repo_root, prepared)
}

/// Lowers every file of the file bundle `row` into its document, in ONE
/// grouped ingress under each file's deterministic operation: text and
/// metadata together, a removal keeping its text and freeing its path,
/// and a removed untouched blob lowering to no document at all. A replay
/// with the same operations appends nothing.
///
/// # Errors
/// A masked copy's uncleared cause, a document that moved since the
/// bundle's base, bytes that are not UTF-8, or a store failure.
pub(in crate::repo_mutation) fn land_bundle_documents(
    vault: &Vault,
    row: &RepoProposal,
) -> Result<()> {
    // A masked copy's received bundle lands only once its typed cause is
    // cleared (FIX 7608 2b-ii-B2); every other bundle has none.
    if let Some(cause) = {
        let txn = vault.store.env.read_txn()?;
        super::received_file::projected_hold_in_txn(vault, &txn, row)?
    } {
        return Err(invalid(cause));
    }
    let repo = RepoRef::parse(&row.repo)?;
    let before = vault.mount_repo_ref(&repo, RepoMountRef::Fork(row.pre_action_fork_hash))?;
    let scope = super::oplog::repo_mutation_repo_key(&repo);
    let actor = WriteActor::new(row.actor.live()?, row.document_class()?);
    let utf8 = |bytes: &[u8]| -> Result<String> {
        String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::InvalidClaimBody("code document requires UTF-8"))
    };
    let mut items = Vec::new();
    for (index, file) in row.files.iter().enumerate() {
        let state = file
            .metadata_edit
            .as_ref()
            .ok_or(invalid("a bundle file carries its reviewed state change"))?;
        let base_text = before.read_file(&file.path)?;
        let mut old = utf8(base_text.unwrap_or(b""))?;
        // A file the base fork withholds (a remediated key's, FIX 7608 slice
        // 6) has no base text: a document already holding its path is
        // lowered from the text it holds, never refused (FIX 10975).
        let mut held = None;
        if base_text.is_none()
            && state.expected.present
            && vault.code_document_frontier(&scope, &file.path)?.is_some()
        {
            let session = vault.open_code_document(&scope, &file.path, &old, row.session)?;
            old = session.text();
            held = Some(session);
        }
        let changed_state = state.expected != state.replacement;
        let (edit, metadata_edit) = match &file.content {
            None => {
                // An untouched blob has no document to retire.
                if vault.code_document_frontier(&scope, &file.path)?.is_none() {
                    continue;
                }
                (
                    CodeFileEdit::between(&file.path, &old, &old),
                    Some(state.clone()),
                )
            }
            Some(new) => {
                let new = utf8(new)?;
                if new == old && !changed_state {
                    continue;
                }
                (
                    CodeFileEdit::between(&file.path, &old, &new),
                    changed_state.then(|| state.clone()),
                )
            }
        };
        let session = match held {
            Some(session) => session,
            None => vault.open_code_document(&scope, &file.path, &old, row.session)?,
        }
        .with_op_provenance(row.op_provenance.clone());
        items.push(CodeFileIngress {
            operation: row.file_operation(index)?,
            session,
            edit,
            metadata_edit,
            actor,
            expected_text: old,
        });
    }
    vault.apply_code_file_ingress_exact(&mut items)?;
    Ok(())
}

/// The ONE queue proposal a stored file bundle is: its id, the green it
/// is pinned at, and every file with the bytes its base fork holds there,
/// its reviewed bytes and its reviewed state change. A native bundle's
/// file the fork withholds (a secret remediation's, FIX 7608 slice 6) is
/// checked by the BLAKE3 its remediation read it at (FIX 10974), so no
/// old byte of it enters a queue row and no object store is read here.
/// The caller supplies no file, mode or removal.
///
/// # Errors
/// A row that is no file bundle, a base fork that cannot be read, or a
/// withheld file with no kept BLAKE3.
pub(crate) fn bundle_merge_proposal(
    vault: &Vault,
    row: &RepoProposal,
    base_green: &str,
) -> Result<MergeProposal> {
    if !row.is_file_bundle() {
        return Err(invalid("not a file bundle"));
    }
    let repo = RepoRef::parse(&row.repo)?;
    let base = vault.mount_repo_ref(&repo, RepoMountRef::Fork(row.pre_action_fork_hash))?;
    let native = matches!(row.operation, RepoProposalOperation::CommitFiles);
    let files = row
        .files
        .iter()
        .map(|file| {
            let present = file
                .metadata_edit
                .as_ref()
                .is_some_and(|state| state.expected.present);
            let expected = match base.read_file(&file.path)? {
                Some(bytes) => Some(MergeFileExpected::Bytes(bytes.to_vec())),
                None if native && present => Some(MergeFileExpected::Blake3(
                    file.withheld_base_blake3
                        .ok_or(invalid("a remediated file keeps its base's BLAKE3"))?,
                )),
                None => None,
            };
            Ok(MergeFile {
                path: file.path.clone(),
                expected,
                content: file.content.clone(),
                metadata_edit: file.metadata_edit.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(MergeProposal {
        id: row.id.to_hex(),
        base_green: base_green.to_owned(),
        files,
    })
}
