//! The retained edit ceiling of a registered repository (FIX 4299,
//! CODE-CUSTODY-01), judged in each final write admission.
//!
//! A write to a repository folder passes when every registration of that
//! folder admits every path it changes: a rename's old and new name, a
//! delete's removed path, and every file of a bundle or receive. A folder
//! with no registration keeps no ceiling, and the owner's proof or the
//! current Grant's editable globs judge it alone, as before. A miss answers
//! the existing `repo_path_outside_scope`. The ceiling judges admission
//! only: a candidate accepted under it is never revoked by a later change.

use crate::Vault;
use crate::code_artifact::{CodeArtifactBody, decode_code_artifact_body};
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::RepoAccessRefusal;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::store::code_repo_registration::CodeRepoRegistration;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The text an owner or trusted write refuses with: the typed code leads.
fn outside_ceiling(path: &str) -> Error {
    Error::Refused(format!(
        "{}: {path} is outside the registered repository's editable whitelist; \
         the owner changes the whitelist through vault.repo.anchor.bind",
        RepoAccessRefusal::PathOutsideScope.public_code()
    ))
}

impl Vault {
    /// CODE entity `repo`'s body, when it is a live registered repository
    /// in `txn`: a CODE_ARTIFACT whose body carries a registration. `None`
    /// for anything else, an unreadable body included.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn registered_repository_body_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        repo: EntityId,
    ) -> Result<Option<CodeArtifactBody>> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CODE_ARTIFACT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &repo)?
        else {
            return Ok(None);
        };
        Ok(decode_code_artifact_body(&body)
            .ok()
            .filter(|body| body.registration.is_some()))
    }

    /// Whether CODE entity `repo` is a live registered repository now.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn is_registered_repository(&self, repo: EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(self
            .registered_repository_body_in_txn(&txn, repo)?
            .is_some())
    }

    /// Every registered repository whose stored folder is `locator`
    /// ([`RepoRef::locator`]) in `txn`, with its registration. Each
    /// registration writer mints the portable id in its own writer, so the
    /// portable-id index lists every registered anchor.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn registered_repositories_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        locator: &str,
    ) -> Result<Vec<(EntityId, CodeRepoRegistration)>> {
        let mut found = Vec::new();
        for repo in self.repo_manifest_anchors_in_txn(txn)? {
            let Some(body) = self.registered_repository_body_in_txn(txn, repo)? else {
                continue;
            };
            let Some(registration) = body.registration else {
                continue;
            };
            if RepoRef::parse(&body.repo_ref).is_ok_and(|stored| stored.locator() == locator) {
                found.push((repo, registration));
            }
        }
        Ok(found)
    }

    /// Whether every retained edit ceiling of the folder `locator` admits
    /// every path of `paths`, in `txn` (FIX 4299): each registration of the
    /// folder, and `anchor`'s own when it carries one. A folder with no
    /// registration keeps no ceiling. `Ok(Err(PathOutsideScope))` names a
    /// miss; no other refusal is answered here.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn admit_registered_edit_in_txn<'p>(
        &self,
        txn: &heed::RoTxn<'_>,
        anchor: Option<EntityId>,
        locator: &str,
        paths: impl IntoIterator<Item = &'p str>,
    ) -> Result<std::result::Result<(), RepoAccessRefusal>> {
        Ok(
            match self.first_outside_ceiling_in_txn(txn, anchor, locator, paths)? {
                Some(_) => Err(RepoAccessRefusal::PathOutsideScope),
                None => Ok(()),
            },
        )
    }

    /// [`Self::admit_registered_edit_in_txn`] for an owner or trusted
    /// write, which holds no Grant: a miss is an error whose text leads with
    /// `repo_path_outside_scope` and names the path.
    ///
    /// # Errors
    /// A miss, or a store failure.
    pub(crate) fn require_registered_edit_in_txn<'p>(
        &self,
        txn: &heed::RoTxn<'_>,
        anchor: Option<EntityId>,
        locator: &str,
        paths: impl IntoIterator<Item = &'p str>,
    ) -> Result<()> {
        match self.first_outside_ceiling_in_txn(txn, anchor, locator, paths)? {
            Some(path) => Err(outside_ceiling(&path)),
            None => Ok(()),
        }
    }

    /// The first path of `paths` some ceiling of `locator` or `anchor` does
    /// not admit.
    fn first_outside_ceiling_in_txn<'p>(
        &self,
        txn: &heed::RoTxn<'_>,
        anchor: Option<EntityId>,
        locator: &str,
        paths: impl IntoIterator<Item = &'p str>,
    ) -> Result<Option<String>> {
        let mut ceilings = self.registered_repositories_in_txn(txn, locator)?;
        if let Some(anchor) = anchor
            && !ceilings.iter().any(|(repo, _)| *repo == anchor)
            && let Some(registration) = self
                .registered_repository_body_in_txn(txn, anchor)?
                .and_then(|body| body.registration)
        {
            ceilings.push((anchor, registration));
        }
        if ceilings.is_empty() {
            return Ok(None);
        }
        Ok(paths
            .into_iter()
            .find(|path| {
                ceilings
                    .iter()
                    .any(|(_, registration)| !registration.admits_edit(path))
            })
            .map(str::to_owned))
    }
}

impl crate::repo_mutation::proposal::RepoProposal {
    /// Judges this open proposal's changed paths against the retained
    /// whitelist of its repository's folder, and of its run's anchor, in
    /// `txn` (FIX 4299): the acceptance check an owner's Approve and a
    /// critic-eligible landing make. A proposal no longer `Proposed` was
    /// accepted already and is never judged again.
    ///
    /// # Errors
    /// A path outside the whitelist, an unreadable repo pointer, or a store
    /// failure.
    pub(crate) fn require_registered_edit_at_acceptance_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        if self.status != crate::repo_mutation::proposal::RepoProposalStatus::Proposed {
            return Ok(());
        }
        let repo = RepoRef::parse(&self.repo)?;
        let anchor = self.run.as_ref().map(|stamp| stamp.repo);
        vault.require_registered_edit_in_txn(
            txn,
            anchor,
            &repo.locator(),
            proposed_file_paths(&self.files),
        )
    }
}

/// Every path a proposed file changes: its own, and a rename's new name.
pub(crate) fn proposed_file_paths<'f>(
    files: impl IntoIterator<Item = &'f crate::store::repo_proposal_record::RepoProposedFile>,
) -> Vec<&'f str> {
    let mut paths = Vec::new();
    for file in files {
        paths.push(file.path.as_str());
        if let Some(to) = file
            .metadata_edit
            .as_ref()
            .and_then(|edit| edit.new_path.as_deref())
        {
            paths.push(to);
        }
    }
    paths
}
