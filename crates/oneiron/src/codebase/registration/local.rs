//! The owner's registration of an external local Git repository (FIX 4299,
//! CODE-CUSTODY-01; `vault.repo.anchor.bind` with a folder).
//!
//! The folder is resolved as the importer resolves it: the root of the Git
//! repository it lies in, canonical. One writer, under the owner's
//! revalidated proof, puts the stable CODE record with its retained
//! registration, its `belongs_to` edge to the live PROJECT he names, and its
//! portable id. The first registration mints the CODE id; a later call that
//! names it, or names the same folder in the same PROJECT, updates that
//! record. The folder is config, never identity: a moved folder keeps its id.

use std::path::Path;

use super::RegisteredRepository;
use crate::TimeRange;
use crate::Vault;
use crate::code_artifact::{CodeArtifactBody, encode_code_artifact_body};
use crate::codebase::{CODEBASE_COMMIT_HASH_HEX_LEN, RepoRef};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EdgeStoreRead;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::store::code_repo_registration::{CodeRepoRegistration, CodeRepoSource};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The folder lies in no local Git repository.
const NOT_A_REPOSITORY: &str =
    "a registered local repository is an absolute folder inside a local Git repository";
/// The project is no live PROJECT of this vault.
const NOT_A_PROJECT: &str = "a registered repository belongs to a live PROJECT of this vault";
/// The anchor named is no registered local repository of that PROJECT.
const NOT_REGISTERED: &str =
    "the anchor named is no registered local repository of the PROJECT named";
/// An editable whitelist entry is no normalized repo-relative path.
const NOT_EDITABLE_PATH: &str =
    "an editable whitelist names exact normalized repo-relative paths, no globs";

/// The canonical root of the Git repository `folder` lies in, as the
/// importer opens it: the work tree, or the store itself when bare.
fn local_repository_root(folder: &Path) -> Result<String> {
    if !folder.is_absolute() {
        return Err(Error::InvalidConfig(NOT_A_REPOSITORY.into()));
    }
    let repo = gix::discover(folder).map_err(|_| Error::InvalidConfig(NOT_A_REPOSITORY.into()))?;
    let root = std::fs::canonicalize(repo.workdir().unwrap_or_else(|| repo.path()))
        .map_err(|_| Error::InvalidConfig(NOT_A_REPOSITORY.into()))?;
    root.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::InvalidConfig(NOT_A_REPOSITORY.into()))
}

impl Vault {
    /// Registers the external local Git repository `folder` in `project` as
    /// the live owner `owner` (FIX 4299). `anchor` names the registration a
    /// config update changes; `editable` replaces its whitelist, and when
    /// omitted keeps the whitelist it holds, empty (read-only) at first.
    ///
    /// # Errors
    /// An owner refusal; `InvalidConfig` for a folder in no Git repository,
    /// a project that is no live PROJECT, an anchor that is no registered
    /// local repository of it, or an editable path that is not normalized;
    /// a store failure.
    pub(crate) fn register_local_repository_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        folder: &Path,
        project: EntityId,
        anchor: Option<EntityId>,
        editable: Option<&[String]>,
    ) -> Result<RegisteredRepository> {
        let path = local_repository_root(folder)?;
        let repo_ref = RepoRef::LocalFolder {
            path: path.clone(),
            commit: "0".repeat(CODEBASE_COMMIT_HASH_HEX_LEN),
        };
        let locator = repo_ref.locator();
        let repo_ref = repo_ref.canonical();
        let source = CodeRepoSource::LocalFolder { path: path.clone() };
        let named = editable
            .map(|paths| {
                CodeRepoRegistration::new(source.clone(), paths.iter().map(String::as_str))
            })
            .transpose()
            .map_err(|_| Error::InvalidConfig(NOT_EDITABLE_PATH.into()))?;
        let (bound, written) = self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            if !live_entity_row_in_txn(&self.store, txn, &project)?.is_live()
                || !crate::workspace_roster::is_project_entity(&self.store, txn, project)?
            {
                return Err(Error::InvalidConfig(NOT_A_PROJECT.into()));
            }
            let in_project = |repo: &EntityId| -> Result<bool> {
                Ok(self
                    .store
                    .port_edge_get(txn, repo, EdgeKind::BelongsTo, &project)?
                    .is_some())
            };
            // The record this call writes: the one named, else the one this
            // folder already has in this PROJECT, else a fresh id.
            let held = match anchor {
                Some(repo) => {
                    let body = self
                        .registered_repository_body_in_txn(txn, repo)?
                        .filter(|body| {
                            body.registration.as_ref().is_some_and(|registration| {
                                matches!(registration.source(), CodeRepoSource::LocalFolder { .. })
                            })
                        });
                    match body {
                        Some(body) if in_project(&repo)? => Some((repo, body)),
                        _ => return Err(Error::InvalidConfig(NOT_REGISTERED.into())),
                    }
                }
                None => {
                    let mut found = None;
                    for (repo, registration) in
                        self.registered_repositories_in_txn(txn, &locator)?
                    {
                        if matches!(registration.source(), CodeRepoSource::LocalFolder { .. })
                            && in_project(&repo)?
                            && let Some(body) = self.registered_repository_body_in_txn(txn, repo)?
                        {
                            found = Some((repo, body));
                            break;
                        }
                    }
                    found
                }
            };
            let (repo, stored) = match held {
                Some((repo, body)) => (repo, Some(body)),
                None => {
                    let repo = EntityId::now();
                    if !matches!(
                        live_entity_row_in_txn(&self.store, txn, &repo)?,
                        LiveEntityRow::Absent
                    ) {
                        return Err(Error::InvariantViolation(
                            "a fresh repository id holds a record",
                        ));
                    }
                    (repo, None)
                }
            };
            let registration = match (
                &named,
                stored.as_ref().and_then(|body| body.registration.clone()),
            ) {
                (Some(named), _) => named.clone(),
                (None, Some(kept)) => kept.with_source(source.clone()),
                (None, None) => CodeRepoRegistration::new(source.clone(), Vec::<String>::new())?,
            };
            let body = CodeArtifactBody::new(
                format!("The registered local repository at {path}."),
                *blake3::hash(repo.as_bytes()).as_bytes(),
                repo_ref.clone(),
            )
            .with_registration(Some(registration.clone()));
            // The edge read ends here: the record time takes the writer.
            let belongs = in_project(&repo)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut batch = self.batch_in();
            let mut changed = false;
            if stored.as_ref() != Some(&body) {
                batch = batch.put(
                    &repo,
                    ENTITY_TYPE_CODE_ARTIFACT,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &encode_code_artifact_body(&body)?,
                );
                changed = true;
            }
            if !belongs {
                batch = batch.edge(&repo, EdgeKind::BelongsTo, &project, 1.0);
                changed = true;
            }
            if changed {
                batch.apply(txn)?;
            }
            // The portable id commits with the record (FIX 4299 with L03).
            let Some((portable, minted)) = self.ensure_repo_manifest_in_txn(txn, repo, None)?
            else {
                return Err(Error::InvariantViolation(
                    "a registered repository is not live in its own writer",
                ));
            };
            Ok((
                RegisteredRepository {
                    repo,
                    project,
                    portable,
                    registration: Some(registration),
                    changed: changed || minted,
                },
                minted,
            ))
        })?;
        if let Err(error) = self.settle_ensured_repo_manifest(bound.repo, bound.portable, written) {
            tracing::warn!(code = %bound.repo.to_hex(), kind = ?error.kind(), "repo manifest not settled");
        }
        Ok(bound)
    }
}
