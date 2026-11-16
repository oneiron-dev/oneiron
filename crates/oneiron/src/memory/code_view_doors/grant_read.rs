//! The view editor's reads (VIEW-BOUND-READ = A): `vault.code.views.get` and
//! `vault.code.views.read` for the caller the view edit door admits (row 6
//! WORKING-VIEW-EDIT). A live Owner reads his own view as before. An agent
//! reads it under the live Grant bound to that view and account, the one the
//! edit door admits through the same seam
//! (`Vault::admit_working_view_edit_in_txn`): only the paths its
//! editable globs and the repository's retained edit ceiling admit, always as
//! a masked reader, so a marked file or a masked copy reads as its
//! projection. A revoke refuses its next read. The read mints nothing.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use super::{
    CodeViewEditProof, CodeViewFileBytes, CodeViewReadRequest, CodeViewRequest, CodeWorkingView,
    working_view,
};
use crate::code_view::{CodeViewSet, ViewReceipt, view_receipt_in_txn};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Error;
use crate::federation::{RepoAccessBounds, RepoAccessIntent, WorkingViewEditBounds};
use crate::memory::repo_doors::refusal_error;

impl Memory<'_> {
    /// `vault.code.views.get` for the view editor `proof` names: the Owner's
    /// view as [`Self::code_view_get_as`] answers it; for the Grant arm, the
    /// view with only the files and edited files the admitting Grant reads.
    ///
    /// # Errors
    /// As [`Self::code_view_get_as`] for the Owner. For the Grant arm, the
    /// typed repo refusal (`repo_no_membership` when no live Grant is bound
    /// to this view and account), then NOT_FOUND for an unknown view and
    /// FORBIDDEN for a view of another base or account.
    pub fn code_view_get_as_editor(
        &self,
        proof: &CodeViewEditProof,
        input: CodeViewRequest,
    ) -> MemoryResult<CodeWorkingView> {
        match proof {
            CodeViewEditProof::Owner(owner) => self.code_view_get_as(owner, input),
            CodeViewEditProof::Grant => self.code_view_get_under_grant(input),
        }
    }

    /// `vault.code.views.read` for the view editor `proof` names: the
    /// Owner's stored bytes as [`Self::code_view_read_as`] reads them; for
    /// the Grant arm, one path its Grant admits, read as a masked reader
    /// reads it ([`Self::code_view_read_projected_as`]'s read, readmitted
    /// under the same Grant before a `why` releases anything).
    ///
    /// # Errors
    /// As [`Self::code_view_read_as`] for the Owner. For the Grant arm, the
    /// typed repo refusal (`repo_no_membership`, or `repo_path_outside_scope`
    /// for a path outside its editable globs), then as the get, then
    /// NOT_FOUND for a path that is not one of the view's files.
    pub fn code_view_read_as_editor(
        &self,
        proof: &CodeViewEditProof,
        input: CodeViewReadRequest,
    ) -> MemoryResult<CodeViewFileBytes> {
        match proof {
            CodeViewEditProof::Owner(owner) => self.code_view_read_as(owner, input),
            CodeViewEditProof::Grant => self.code_view_read_under_grant(input),
        }
    }

    /// The Grant arm's get. One Grant answers it, as Grants are never
    /// unioned: the first one the edit door's seam admits for this view.
    fn code_view_get_under_grant(&self, input: CodeViewRequest) -> MemoryResult<CodeWorkingView> {
        let (mut receipt, readable) = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            let bounds = self.admit_view_grant_in_txn(&txn, &input, &BTreeSet::new())?;
            let receipt = granted_receipt_in_txn(self.vault, &txn, &input)?;
            let mut readable = BTreeSet::new();
            for path in receipt.files.keys() {
                if bounds.admits_path(RepoAccessIntent::Edit, path)
                    && self
                        .vault
                        .admit_registered_edit_in_txn(&txn, input.repo, [path])?
                        .is_ok()
                {
                    readable.insert(path.clone());
                }
            }
            (receipt, readable)
        };
        let set = CodeViewSet::open(self.vault)?;
        // An edit whose copy did not land heals before any read of the view.
        set.project_view_forks(input.view)?;
        receipt.files.retain(|path, _| readable.contains(path));
        let mut view = working_view(
            self.vault,
            &set,
            receipt,
            input.repo,
            input.tested,
            input.account,
        )?;
        view.forks.retain(|fork| readable.contains(&fork.path));
        Ok(view)
    }

    /// The Grant arm's read of one path.
    fn code_view_read_under_grant(
        &self,
        input: CodeViewReadRequest,
    ) -> MemoryResult<CodeViewFileBytes> {
        let CodeViewReadRequest { view, path, why } = input;
        let paths = BTreeSet::from([path.clone()]);
        // Membership first, before any id the caller named resolves.
        let receipt = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            self.admit_view_grant_in_txn(&txn, &view, &paths)?;
            granted_receipt_in_txn(self.vault, &txn, &view)?
        };
        if !receipt.files.contains_key(&path) {
            return Err(MemoryError::not_found("path is not an input of this view"));
        }
        let set = CodeViewSet::open(self.vault)?;
        set.project_view_forks(view.view)?;
        let bytes = crate::code_view::read_view_file(&set.view_path(view.view)?, &path)?;
        let file = CodeViewFileBytes {
            path,
            sha256: bytes_to_hex_lower(&Sha256::digest(&bytes)),
            bytes,
            projection: None,
        };
        self.project_view_file(&view, file, why.as_deref(), || {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            self.admit_view_grant_in_txn(&txn, &view, &paths).map(drop)
        })
    }

    /// The view edit door's own Grant arm admission
    /// (`Vault::admit_working_view_edit_in_txn`) of `paths` of the
    /// view `view` names, for this handle's actor in `txn`: the admitting
    /// Grant's repo bounds, or its typed refusal.
    fn admit_view_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        view: &CodeViewRequest,
        paths: &BTreeSet<String>,
    ) -> MemoryResult<RepoAccessBounds> {
        let bound = WorkingViewEditBounds {
            view: view.view,
            account: view.account,
        };
        match self.vault.admit_working_view_edit_in_txn(
            txn,
            self.actor,
            self.actor_class,
            view.repo,
            &bound,
            paths,
        )? {
            Ok(membership) => Ok(membership.bounds),
            Err(refused) => Err(refusal_error(refused)),
        }
    }
}

/// The receipt of the owner view `view` names, in `txn`, once its Grant is
/// admitted: a view of that base in that account and no run's, as the edit
/// door's Grant arm checks it.
fn granted_receipt_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    view: &CodeViewRequest,
) -> MemoryResult<ViewReceipt> {
    let receipt = view_receipt_in_txn(vault, txn, view.view)?
        .ok_or_else(|| MemoryError::not_found("view not found"))?;
    if receipt.run.is_some()
        || receipt.actor != view.account
        || receipt.base != Some((view.repo, view.tested))
    {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "view base or account mismatch",
            &[],
        ));
    }
    Ok(receipt)
}
