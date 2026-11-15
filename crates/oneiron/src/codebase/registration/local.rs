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
use crate::authority::owner_delegate_in_txn;
use crate::claim::ScopedReadActorKey;
use crate::code_artifact::{CodeArtifactBody, encode_code_artifact_body};
use crate::codebase::{CODEBASE_COMMIT_HASH_HEX_LEN, RepoRef};
use crate::consent::AuthenticatedOwner;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{MemoryError, MemoryResult};
use crate::ports::EdgeStoreRead;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::store::code_repo_registration::{CodeRepoRegistration, CodeRepoSource};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::verbs::REPO_ANCHOR_BIND_VERB;

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
        let parts = local_registration_parts(folder, editable)?;
        let (bound, written) = self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            self.register_local_in_txn(txn, project, anchor, &parts)
        })?;
        Ok(self.settled_local_registration(bound, written))
    }

    /// Registers the external local Git repository `folder` in `project` as
    /// the owner's delegate: the agent's binding, its live Grant for
    /// `vault.repo.anchor.bind` and the setting
    /// `codebase.registration.agent_may_register` are checked in the writer,
    /// and the agent must read the PROJECT, then the registration writes as
    /// the owner's does. `anchor` and `editable` behave as the owner's.
    ///
    /// # Errors
    /// `FORBIDDEN` when the setting reads false at the agent or no live Grant
    /// lists the verb; `InvalidConfig` for a folder in no Git repository, a
    /// project that is no live PROJECT the agent reads, an anchor that is no
    /// registered local repository of it, or an editable path that is not
    /// normalized; a store failure.
    pub(crate) fn register_local_repository_as_delegate(
        &self,
        agent: EntityId,
        folder: &Path,
        project: EntityId,
        anchor: Option<EntityId>,
        editable: Option<&[String]>,
    ) -> MemoryResult<RegisteredRepository> {
        let parts = local_registration_parts(folder, editable).map_err(MemoryError::from)?;
        let (bound, written) = self.try_with_write_txn_grouped(|txn| {
            owner_delegate_in_txn(self, txn, agent, REPO_ANCHOR_BIND_VERB)?;
            if !delegate_reads_project_in_txn(self, txn, agent, project)
                .map_err(MemoryError::from)?
            {
                return Err(MemoryError::from(Error::InvalidConfig(
                    NOT_A_PROJECT.into(),
                )));
            }
            self.register_local_in_txn(txn, project, anchor, &parts)
                .map_err(MemoryError::from)
        })?;
        Ok(self.settled_local_registration(bound, written))
    }

    /// The registration [`Self::register_local_repository_as_owner`] and
    /// [`Self::register_local_repository_as_delegate`] write, once admitted.
    fn register_local_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        project: EntityId,
        anchor: Option<EntityId>,
        parts: &LocalRegistrationParts,
    ) -> Result<(RegisteredRepository, bool)> {
        let LocalRegistrationParts {
            path,
            locator,
            repo_ref,
            source,
            named,
        } = parts;
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
                for (repo, registration) in self.registered_repositories_in_txn(txn, locator)? {
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
            named,
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
        let Some((portable, minted)) = self.ensure_repo_manifest_in_txn(txn, repo, None)? else {
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
    }

    /// A committed registration's aftermath: the portable id settles
    /// best-effort, never changing the answer.
    fn settled_local_registration(
        &self,
        bound: RegisteredRepository,
        written: bool,
    ) -> RegisteredRepository {
        if let Err(error) = self.settle_ensured_repo_manifest(bound.repo, bound.portable, written) {
            tracing::warn!(code = %bound.repo.to_hex(), kind = ?error.kind(), "repo manifest not settled");
        }
        bound
    }
}

/// What the folder and whitelist resolve to before the writer opens.
struct LocalRegistrationParts {
    path: String,
    locator: String,
    repo_ref: String,
    source: CodeRepoSource,
    named: Option<CodeRepoRegistration>,
}

/// Resolves `folder` to the Git root it lies in and `editable` to the
/// whitelist it names, before the writer opens.
fn local_registration_parts(
    folder: &Path,
    editable: Option<&[String]>,
) -> Result<LocalRegistrationParts> {
    let path = local_repository_root(folder)?;
    let repo_ref = RepoRef::LocalFolder {
        path: path.clone(),
        commit: "0".repeat(CODEBASE_COMMIT_HASH_HEX_LEN),
    };
    let locator = repo_ref.locator();
    let repo_ref = repo_ref.canonical();
    let source = CodeRepoSource::LocalFolder { path: path.clone() };
    let named = editable
        .map(|paths| CodeRepoRegistration::new(source.clone(), paths.iter().map(String::as_str)))
        .transpose()
        .map_err(|_| Error::InvalidConfig(NOT_EDITABLE_PATH.into()))?;
    Ok(LocalRegistrationParts {
        path,
        locator,
        repo_ref,
        source,
        named,
    })
}

/// Whether `agent` reads the PROJECT `project` in `txn`: the delegate's lane
/// under the relationship gate, so the vault's own rows read and a scoped
/// row passes only on the agent's own live grants. A lane that does not
/// build reads nothing.
fn delegate_reads_project_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    project: EntityId,
) -> Result<bool> {
    let Some(key) = ScopedReadActorKey::with_actor_class(
        agent.to_hex(),
        EdgeActorClass::Agent.gate_actor_class(),
    )
    .map(|key| key.require_relationship_grants(Some(agent))) else {
        return Ok(false);
    };
    vault.scoped_read(key).is_entity_readable_in(txn, &project)
}
