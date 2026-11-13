//! Door for `tests/code_view_edit.rs` (row 6 WORKING-VIEW-EDIT): a tested
//! revision of a repo's files, built from code documents as the code revision
//! lib tests build one; the edit operations a view's fork of a file records;
//! a view receipt that lists a file as a masked copy, as the masked
//! materializer writes one for a marked file; and the one admission every
//! ordinary repo edit door calls. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::TimeRange;
use crate::code_document::CodeFileEdit;
use crate::code_revision::CodeRevisionWriteOutcome;
use crate::code_view::{VIEW_FORK_FILES, view_receipt_in_txn};
use crate::codebase::RepoRef;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::federation::RepoTarget;
use crate::origin::secret_projection::{RepoFileProjectionKind, RepoFileProjectionView};
use crate::session_lifecycle::SessionMintOutcome;
use crate::store::code_revision_record::CodeRevision;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

/// One edit operation a view's fork of a file records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewForkEdit {
    pub operation: EntityId,
    /// The actor; `None` once that actor was erased.
    pub actor: Option<EntityId>,
    pub revision: u64,
}

/// A finalized tested revision of `repo` holding `files` (path, text): each
/// path a code document whose tested state holds that text, edited into it
/// by `owner`, in a sitting minted for `owner`; its revision id.
///
/// # Errors
/// The writers'.
pub fn commit_tested_revision(
    vault: &Vault,
    owner: EntityId,
    repo: EntityId,
    files: &[(&str, &str)],
) -> Result<EntityId> {
    let body = vault
        .get_code_artifact(&repo)?
        .ok_or(Error::EntityNotFound)?;
    let identity = vault.resolve_repo_identity(&RepoRef::parse(&body.repo_ref)?)?;
    let at =
        vault.with_write_txn_grouped(|txn| crate::ports::recorded_at_in_txn(&vault.store, txn))?;
    let session = match vault.mint_session(vault.local_session_key(owner)?, at)? {
        SessionMintOutcome::Minted(id) | SessionMintOutcome::AlreadyOpen(id) => id,
    };
    let revision_id = EntityId::now();
    vault.put_code_artifact(&revision_id, &body, TimeRange { start: at, end: at }, at)?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let mut revision = CodeRevision::commit(revision_id, session, at);
    for (path, text) in files {
        let mut document = vault.open_code_document(identity.as_str(), path, "", session)?;
        let current = document.text();
        let tested = if current == *text {
            document.frontier()?
        } else {
            vault
                .apply_code_file_edit(
                    &mut document,
                    &CodeFileEdit::between(path, &current, text),
                    actor,
                )?
                .after
        };
        revision = revision.with_file_frontier(tested);
    }
    match vault.commit_code_revision(&revision)? {
        CodeRevisionWriteOutcome::Finalized => Ok(revision_id),
        CodeRevisionWriteOutcome::Proposed(_) => Err(Error::ConcurrentWrite(
            "the tested revision was proposed, not finalized",
        )),
    }
}

/// The edit operations view `view`'s fork of `path` records, oldest first;
/// empty while the view has not edited it.
///
/// # Errors
/// A store failure, or a row that does not decode.
pub fn view_fork_edits(vault: &Vault, view: EntityId, path: &str) -> Result<Vec<ViewForkEdit>> {
    let txn = vault.store.env.read_txn()?;
    Ok(VIEW_FORK_FILES
        .get(&vault.store, &txn, &(view, path.to_owned()))?
        .map(|fork| {
            fork.ops
                .iter()
                .map(|op| ViewForkEdit {
                    operation: op.operation,
                    actor: op.actor.id(),
                    revision: op.revision,
                })
                .collect()
        })
        .unwrap_or_default())
}

/// Lists `path` among view `view`'s masked copies, as the masked
/// materializer does for a marked file (FIX 8965), its copy left as it is.
///
/// # Errors
/// An unknown view, or a store failure.
pub fn hold_masked_copy(vault: &Vault, view: EntityId, path: &str) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let mut receipt = view_receipt_in_txn(vault, txn, view)?.ok_or(Error::EntityNotFound)?;
        let copy = receipt.files.get(path).ok_or(Error::EntityNotFound)?;
        receipt.projections.insert(
            path.to_owned(),
            RepoFileProjectionView {
                kind: RepoFileProjectionKind::Masked,
                source_blob: "0".repeat(40),
                copy_blake3: bytes_to_hex_lower(copy),
                copy_size_bytes: 0,
                way_out: "vault.code.views.read with why".to_owned(),
            },
        );
        crate::code_view::put_view_receipt_in_txn(vault, txn, &receipt)
    })
}

/// The public code of the refusal an ordinary repo edit door answers
/// `actor`, of `class`, with for an edit of `path` on `git_ref` of `repo`;
/// `None` when it admits the edit. The seam is the one every repo edit door
/// calls (`Vault::admit_repo_edit_in_txn`).
///
/// # Errors
/// A store, fold or clock failure.
pub fn repo_edit_refusal(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    repo: EntityId,
    git_ref: &str,
    path: &str,
) -> Result<Option<&'static str>> {
    let txn = vault.store.env.read_txn()?;
    let target = RepoTarget {
        repo,
        git_ref: git_ref.to_owned(),
        paths: std::collections::BTreeSet::from([path.to_owned()]),
    };
    Ok(vault
        .admit_repo_edit_in_txn(&txn, actor, class, repo, &target)?
        .err()
        .map(|refused| refused.public_code()))
}
