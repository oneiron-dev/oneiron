//! `vault.code.views.edit` (row 6 WORKING-VIEW-EDIT, CODECUSTODY-VIEW = A):
//! one whole-file replacement of a file of an owner working view, as one
//! code-document operation on the view's own fork of that file. The shared
//! document, the tested revision and every other view keep their text; the
//! view's copy of the file, which `views.read`, `views.action` and
//! `views.build` read, holds the edit. The owner edits his own view; an agent
//! edits it only under a live Grant bound to that view and account
//! (CODECUSTODY-VIEW-BUILD Q1 = A), and a revoke refuses its next edit.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError};
use super::{CodeViewEdit, CodeViewEditRequest};
use crate::EntityId;
use crate::code_document::{CodeDocumentFrontier, CodeFileEdit, ReceiptActor};
use crate::code_view::{
    CodeViewSet, VIEW_FORK_FILES, VIEW_FORK_REVISIONS, ViewForkFile, ViewForkOp, ViewReceipt,
    view_fork_copies_lock, view_fork_revision_in_txn, view_receipt_in_txn,
};
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::federation::WorkingViewEditBounds;
use crate::memory::MemoryResult;
use crate::memory::repo_doors::refusal_error;
use crate::write_envelope::WriteActor;

/// The refusal of an edit of a file the view holds as a masked copy
/// (CODECUSTODY-VIEW-BUILD-Q3 = A): its copy is the placeholder, its fork's
/// base the stored text, so an edit written against the copy would replace
/// the stored secret.
const MASKED_COPY: &str =
    "this view holds a masked copy of the file; edit it in a view of the stored text";

/// Who calls the view edit door, as its host bound it.
#[derive(Debug, Clone)]
pub enum CodeViewEditProof {
    /// A live Owner's proof, naming this handle's own human actor: he edits
    /// his own view.
    Owner(AuthenticatedOwner),
    /// This handle's own actor, admitted by one live Grant bound to the view
    /// and its account. It carries no actor, Grant id or authority.
    Grant,
}

/// Where the file the edit changes stands before it: the view's fork, the
/// tested revision's document state, or an untouched blob's text.
#[derive(Clone)]
enum EditBase {
    Fork(ViewForkFile),
    Tested(CodeDocumentFrontier),
    Blob { repo: String, text: String },
}

/// What the edit's writer committed.
struct Edited {
    fork: ViewForkFile,
    revision: u64,
    before: String,
    after: String,
}

impl Memory<'_> {
    /// An embedded handle's view edit caller: the vault owner's proof when
    /// the handle is the embedded owner's, else the handle's own actor.
    pub fn code_view_edit_proof(&self, verb: &str) -> CodeViewEditProof {
        self.embedded_owner(verb)
            .map_or(CodeViewEditProof::Grant, CodeViewEditProof::Owner)
    }

    /// `vault.code.views.edit`: replaces the whole text of `input.path` in
    /// the owner working view `input.view`, against the view revision and the
    /// file text the caller read, as one operation on the view's fork of the
    /// file that names this handle's actor.
    ///
    /// # Errors
    /// FORBIDDEN for a view of another base or account, or an owner proof
    /// that is not this handle's; the Grant arm's typed repo refusal
    /// (`repo_no_membership` when no live Grant is bound to this view and
    /// account, `repo_path_outside_scope` for a path outside its editable
    /// globs); NOT_FOUND for an unknown view or a path that is not one of its
    /// files; BAD_REQUEST for a masked copy, a malformed hash or a
    /// replacement equal to the text; INVALID_STATE for another revision or
    /// file text than the caller read.
    pub fn code_view_edit_as(
        &self,
        proof: &CodeViewEditProof,
        input: CodeViewEditRequest,
    ) -> MemoryResult<CodeViewEdit> {
        let view = input.view.view;
        // The Grant arm's bound is the request's view and account: a Grant
        // bound to them is one the owner minted on his own view of them.
        let bound = WorkingViewEditBounds {
            view,
            account: input.view.account,
        };
        let paths = BTreeSet::from([input.path.clone()]);
        let set = match proof {
            CodeViewEditProof::Owner(owner) => self.admitted_view(owner, &input.view)?.0,
            CodeViewEditProof::Grant => {
                // Membership first, before any id the caller named resolves.
                let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
                if let Err(refused) = self.vault.admit_working_view_edit_in_txn(
                    &txn,
                    self.actor,
                    self.actor_class,
                    input.view.repo,
                    &bound,
                    &paths,
                )? {
                    return Err(refusal_error(refused));
                }
                CodeViewSet::open(self.vault)?
            }
        };
        let receipt = set
            .receipt(input.view.view)?
            .ok_or_else(|| MemoryError::not_found("view not found"))?;
        if receipt.run.is_some()
            || receipt.actor != input.view.account
            || receipt.base != Some((input.view.repo, input.view.tested))
        {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "view base or account mismatch",
                &[],
            ));
        }
        let Some(listed) = receipt.files.get(&input.path).copied() else {
            return Err(MemoryError::not_found("path is not an input of this view"));
        };
        if receipt.projections.contains_key(&input.path) {
            return Err(MemoryError::bad_request(MASKED_COPY));
        }
        if input.expected_sha256.len() != 64
            || !input
                .expected_sha256
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(MemoryError::bad_request(
                "expected_sha256 is 64 lower-case hex",
            ));
        }
        let unforked = self.unforked_base(&set, &receipt, &input, listed)?;
        let operation = EntityId::now();
        let actor = WriteActor::new(self.actor, self.actor_class);
        // One writer of fork copies from the row to the copy (fork.rs).
        let _copies = view_fork_copies_lock()?;
        let edited = self.vault.with_write_txn_grouped(
            |txn| -> Result<std::result::Result<Edited, MemoryError>> {
                if view_receipt_in_txn(self.vault, txn, view)?.as_ref() != Some(&receipt) {
                    return Err(Error::ConcurrentWrite("the view changed during its edit"));
                }
                match proof {
                    CodeViewEditProof::Owner(owner) => {
                        if owner.revalidate_in_txn(self.vault, txn)? != self.actor {
                            return Ok(Err(MemoryError::new(
                                MEMORY_CODE_FORBIDDEN,
                                "working views and cache act only within the authenticated owner's account",
                                &[],
                            )));
                        }
                    }
                    CodeViewEditProof::Grant => {
                        if let Err(refused) = self.vault.admit_working_view_edit_in_txn(
                            txn,
                            self.actor,
                            self.actor_class,
                            input.view.repo,
                            &bound,
                            &paths,
                        )? {
                            return Ok(Err(refusal_error(refused)));
                        }
                    }
                }
                let revision = view_fork_revision_in_txn(self.vault, txn, view)?;
                if revision != input.expected_revision {
                    return Ok(Err(MemoryError::new(
                        MEMORY_CODE_INVALID_STATE,
                        format!(
                            "the view is at revision {revision}, not {}: read it again",
                            input.expected_revision
                        ),
                        &[],
                    )));
                }
                let key = (view, input.path.clone());
                let base = match VIEW_FORK_FILES.get(&self.vault.store, txn, &key)? {
                    Some(fork) => EditBase::Fork(fork),
                    None => match &unforked {
                        Some(base) => base.clone(),
                        None => return Err(Error::CorruptedIndex("view fork row disappeared")),
                    },
                };
                let (mut session, fork_base, ops) = match base {
                    EditBase::Fork(fork) => (
                        self.vault
                            .open_view_fork_in_txn(txn, &fork.base, &fork.state, view)?,
                        fork.base,
                        fork.ops,
                    ),
                    EditBase::Tested(tested) => (
                        self.vault.open_view_fork_in_txn(txn, &tested, &tested, view)?,
                        tested,
                        Vec::new(),
                    ),
                    EditBase::Blob { repo, text } => {
                        let session = self.vault.open_code_document_genesis_in_txn(
                            txn,
                            &repo,
                            &input.path,
                            &text,
                            view,
                        )?;
                        let birth = session.frontier()?;
                        (session, birth, Vec::new())
                    }
                };
                let before = session.text();
                if sha256_hex(&before) != input.expected_sha256 {
                    return Ok(Err(MemoryError::new(
                        MEMORY_CODE_INVALID_STATE,
                        "the file changed since it was read: read it again",
                        &[],
                    )));
                }
                if before == input.replacement_text {
                    return Ok(Err(MemoryError::bad_request(
                        "the replacement is the file's current text",
                    )));
                }
                let edit = CodeFileEdit::between(&input.path, &before, &input.replacement_text);
                let step = self
                    .vault
                    .apply_view_fork_edit_in_txn(txn, operation, &mut session, &edit)?;
                let revision = revision + 1;
                let mut ops = ops;
                ops.push(ViewForkOp {
                    operation,
                    session: view,
                    actor: ReceiptActor::Actor(actor.entity_ref()),
                    actor_class: actor.actor_class() as u8,
                    revision,
                    before: step.before,
                    after: step.after.clone(),
                });
                let fork = ViewForkFile {
                    base: fork_base,
                    state: step.after,
                    text_blake3: *blake3::hash(step.text.as_bytes()).as_bytes(),
                    ops,
                };
                VIEW_FORK_FILES.put(&self.vault.store, txn, &key, &fork)?;
                VIEW_FORK_REVISIONS.put(&self.vault.store, txn, &view, &revision)?;
                Ok(Ok(Edited {
                    fork,
                    revision,
                    before,
                    after: step.text,
                }))
            },
        )??;
        // The row stands; a copy this replace leaves stale heals at the
        // next owner read of the view (`CodeViewSet::project_view_forks`).
        if let Err(error) = set.replace_view_file(view, &input.path, edited.after.as_bytes()) {
            tracing::warn!(
                kind = ?error.kind(),
                "a working view's copy of an edited file was not replaced; the next owner read repairs it"
            );
        }
        Ok(CodeViewEdit {
            view,
            path: input.path,
            revision: edited.revision,
            operation,
            before_sha256: sha256_hex(&edited.before),
            after_sha256: sha256_hex(&edited.after),
            frontier: edited.fork.state,
        })
    }

    /// The base of `input.path` before the view's first edit of it: the
    /// tested revision's document state, or, for an untouched blob of a
    /// tested queue revision, the view's own copy, which must still be the
    /// bytes its receipt lists (`listed`). `None` once the view forked it.
    fn unforked_base(
        &self,
        set: &CodeViewSet<'_>,
        receipt: &ViewReceipt,
        input: &CodeViewEditRequest,
        listed: [u8; 32],
    ) -> MemoryResult<Option<EditBase>> {
        let forked = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            VIEW_FORK_FILES.contains(
                &self.vault.store,
                &txn,
                &(receipt.view_id, input.path.clone()),
            )?
        };
        if forked {
            return Ok(None);
        }
        let revision = self
            .vault
            .get_code_revision(&input.view.tested)?
            .ok_or_else(|| MemoryError::not_found("finalized tested revision not found"))?;
        if let Some(tested) = revision
            .file_frontiers
            .values()
            .find(|frontier| frontier.path == input.path)
        {
            let text = self.vault.code_document_at(tested)?;
            if *blake3::hash(text.as_bytes()).as_bytes() != listed {
                return Err(Error::CorruptedIndex("view file is not its tested text").into());
            }
            return Ok(Some(EditBase::Tested(tested.clone())));
        }
        if !revision.blob_frontiers.contains_key(&input.path) {
            return Err(Error::CorruptedIndex("view file has no tested frontier").into());
        }
        let copy = crate::code_view::read_view_file(&set.view_path(receipt.view_id)?, &input.path)?;
        if *blake3::hash(&copy).as_bytes() != listed {
            return Err(Error::CorruptedIndex("view input was modified").into());
        }
        let text = String::from_utf8(copy).map_err(|_| {
            MemoryError::bad_request("a view file that is not UTF-8 text is not edited")
        })?;
        let body = self
            .vault
            .get_code_artifact(&input.view.repo)?
            .ok_or_else(|| MemoryError::not_found("repository not found"))?;
        let repo = self
            .vault
            .resolve_repo_identity(&RepoRef::parse(&body.repo_ref)?)?;
        Ok(Some(EditBase::Blob {
            repo: repo.as_str().to_owned(),
            text,
        }))
    }
}

/// The lower-case hex SHA-256 of `text`.
fn sha256_hex(text: &str) -> String {
    bytes_to_hex_lower(&Sha256::digest(text.as_bytes()))
}
