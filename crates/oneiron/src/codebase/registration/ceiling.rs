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
    /// for anything else. A CODE_ARTIFACT body that does not decode is an
    /// error, never "unregistered": the ceiling fails closed.
    ///
    /// # Errors
    /// A store failure, and a CODE_ARTIFACT body that does not decode.
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
        let body = decode_code_artifact_body(&body)?;
        Ok(body.registration.is_some().then_some(body))
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

    /// Whether the retained edit ceiling of the admitted repository `repo`
    /// admits every path of `paths`, in `txn` (FIX 4299): a Grant edit is
    /// judged by that repository's own registration only, never by a
    /// ceiling found through its folder, its manifest or another anchor
    /// (L02 07:57). An unregistered repository keeps no ceiling.
    /// `Ok(Err(PathOutsideScope))` names a miss of that configured ceiling;
    /// no other refusal is answered here.
    ///
    /// # Errors
    /// A store failure, and a CODE body that does not decode.
    pub(crate) fn admit_registered_edit_in_txn<P>(
        &self,
        txn: &heed::RoTxn<'_>,
        repo: EntityId,
        paths: P,
    ) -> Result<std::result::Result<(), RepoAccessRefusal>>
    where
        P: IntoIterator,
        P::Item: AsRef<str>,
    {
        let Some(registration) = self
            .registered_repository_body_in_txn(txn, repo)?
            .and_then(|body| body.registration)
        else {
            return Ok(Ok(()));
        };
        Ok(
            match paths
                .into_iter()
                .find(|path| !registration.admits_edit(path.as_ref()))
            {
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
    pub(crate) fn require_registered_edit_in_txn<P>(
        &self,
        txn: &heed::RoTxn<'_>,
        anchor: Option<EntityId>,
        locator: &str,
        paths: P,
    ) -> Result<()>
    where
        P: IntoIterator,
        P::Item: AsRef<str>,
    {
        match self.first_outside_ceiling_in_txn(txn, anchor, locator, paths)? {
            Some(path) => Err(outside_ceiling(&path)),
            None => Ok(()),
        }
    }

    /// The first path of `paths` some ceiling of `locator` or `anchor` does
    /// not admit.
    fn first_outside_ceiling_in_txn<P>(
        &self,
        txn: &heed::RoTxn<'_>,
        anchor: Option<EntityId>,
        locator: &str,
        paths: P,
    ) -> Result<Option<String>>
    where
        P: IntoIterator,
        P::Item: AsRef<str>,
    {
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
                    .any(|(_, registration)| !registration.admits_edit(path.as_ref()))
            })
            .map(|path| path.as_ref().to_owned()))
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
