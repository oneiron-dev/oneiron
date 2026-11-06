//! The owner's served-repo anchor (FIX 6867, G1 PR3b; `vault.repo.anchor.bind`).
//!
//! A `git_push` Grant, a run's repo bounds and an exact publish all name a
//! repo as a CODE anchor of a PROJECT whose stored repo is the served Git
//! store itself. Registration makes an empty served store and an import
//! stores the folder it read, so nothing made such an anchor. This one
//! owner door does: in one writer, under his revalidated proof, it binds
//! the served repo `repo_name` to the CODE_ARTIFACT whose stored repo is
//! that store's own directory, with a `belongs_to` edge to the live PROJECT
//! he names. The anchor's id is derived from the store's object identity
//! and the PROJECT, so a repeat binds the same row and changes nothing.
//! The mint, the run admission and publish resolve through the stored row
//! as before; register, serve and every owner door are unchanged.
//!
//! FIX 4299 (CODE-CUSTODY-01): the same writer mints the repo's portable id
//! ([`Vault::ensure_repo_manifest_in_txn`]), and, when the owner names an
//! editable whitelist, retains it on the anchor as a served registration.
//! A bind that names none leaves the retained configuration as it stands.

use crate::code_artifact::{CodeArtifactBody, encode_code_artifact_body};
use crate::codebase::{CODEBASE_COMMIT_HASH_HEX_LEN, RegisteredRepository, RepoRef};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EdgeStoreRead;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::store::code_repo_registration::{CodeRepoRegistration, CodeRepoSource};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{TimeRange, Vault};

/// The domain a served repo's anchor id is derived under.
const SERVED_REPO_ANCHOR_DOMAIN: &[u8] = b"oneiron:served-repo-anchor:v1";

/// The project is no live PROJECT of this vault.
const NOT_A_PROJECT: &str = "a served repo anchor belongs to a live PROJECT of this vault";
/// The derived id holds another row.
const ANCHOR_TAKEN: &str = "the served repo anchor's id holds another record";
/// An editable whitelist entry is no normalized repo-relative path.
const NOT_EDITABLE_PATH: &str =
    "an editable whitelist names exact normalized repo-relative paths, no globs";

impl Vault {
    /// The CODE anchor the served store of object identity `identity` has
    /// in `project`, when it stands live (FIX 7608 pre-flip, FIX 9328): the
    /// repo a run's per-file reads name. Read-only, in `txn`; `None` when
    /// the owner bound none.
    ///
    /// # Errors
    /// A failed id derivation, or a store failure.
    pub(crate) fn served_repo_anchor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        identity: &str,
        project: EntityId,
    ) -> Result<Option<EntityId>> {
        let repo = crate::codebase::entity_id_from_hash_material(
            SERVED_REPO_ANCHOR_DOMAIN,
            &[identity.as_bytes(), project.as_bytes()],
        )?;
        Ok(matches!(
            live_entity_row_in_txn(&self.store, txn, &repo)?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_CODE_ARTIFACT,
                ..
            }
        )
        .then_some(repo))
    }

    /// Binds the served repo `repo_name` to its CODE anchor in `project`,
    /// as the live owner `owner`, in one writer: the anchor row and its
    /// `belongs_to` edge, each only when missing, and its portable id.
    ///
    /// # Errors
    /// As [`Self::bind_served_repo_anchor_with`].
    pub(crate) fn bind_served_repo_anchor(
        &self,
        owner: &AuthenticatedOwner,
        repo_name: &str,
        project: EntityId,
    ) -> Result<RegisteredRepository> {
        self.bind_served_repo_anchor_with(owner, repo_name, project, None)
    }

    /// [`Self::bind_served_repo_anchor`], retaining `editable` on the
    /// anchor as its served registration when the owner names one (FIX
    /// 4299): the anchor row, its edge, its configuration and its portable
    /// id commit in one writer, each only when it changes.
    ///
    /// # Errors
    /// An owner refusal; `GitHttpRepoNotFound` for a name this origin does
    /// not serve; `InvalidConfig` for a project that is no live PROJECT, an
    /// id that already holds another record or an editable path that is not
    /// normalized; a store failure.
    pub(crate) fn bind_served_repo_anchor_with(
        &self,
        owner: &AuthenticatedOwner,
        repo_name: &str,
        project: EntityId,
        editable: Option<&[String]>,
    ) -> Result<RegisteredRepository> {
        let dir = crate::origin::smart_http::origin_repo_dir(self, repo_name)?.canonicalize()?;
        let identity = crate::git_wire::GitWire::new(self)?
            .repository_identity(&dir)?
            .as_hex();
        let repo = crate::codebase::entity_id_from_hash_material(
            SERVED_REPO_ANCHOR_DOMAIN,
            &[identity.as_bytes(), project.as_bytes()],
        )?;
        let repo_ref = RepoRef::LocalFolder {
            path: dir.to_string_lossy().into_owned(),
            commit: "0".repeat(CODEBASE_COMMIT_HASH_HEX_LEN),
        }
        .canonical();
        let named = editable
            .map(|paths| {
                CodeRepoRegistration::new(
                    CodeRepoSource::Served {
                        name: repo_name.to_owned(),
                    },
                    paths.iter().map(String::as_str),
                )
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
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let occurred = TimeRange {
                start: now,
                end: now,
            };
            let stored = match live_entity_row_in_txn(&self.store, txn, &repo)? {
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_CODE_ARTIFACT,
                    body,
                } => match crate::code_artifact::decode_code_artifact_body(&body) {
                    Ok(stored) if stored.repo_ref == repo_ref => Some(stored),
                    _ => return Err(Error::InvalidConfig(ANCHOR_TAKEN.into())),
                },
                LiveEntityRow::Live { .. } => {
                    return Err(Error::InvalidConfig(ANCHOR_TAKEN.into()));
                }
                _ => None,
            };
            let held = stored.as_ref().and_then(|body| body.registration.clone());
            let registration = named.clone().or_else(|| held.clone());
            let mut batch = self.batch_in();
            let mut changed = false;
            if stored.is_none() || registration != held {
                let body = stored
                    .unwrap_or_else(|| {
                        CodeArtifactBody::new(
                            format!("The served repository {repo_name}."),
                            *blake3::hash(identity.as_bytes()).as_bytes(),
                            repo_ref.clone(),
                        )
                    })
                    .with_registration(registration.clone());
                batch = batch.put(
                    &repo,
                    ENTITY_TYPE_CODE_ARTIFACT,
                    occurred,
                    now,
                    &encode_code_artifact_body(&body)?,
                );
                changed = true;
            }
            if self
                .store
                .port_edge_get(txn, &repo, EdgeKind::BelongsTo, &project)?
                .is_none()
            {
                batch = batch.edge(&repo, EdgeKind::BelongsTo, &project, 1.0);
                changed = true;
            }
            if changed {
                batch.apply(txn)?;
            }
            // The anchor's portable id commits with it (FIX 4299 with L03).
            let Some((portable, minted)) =
                self.ensure_repo_manifest_in_txn(txn, repo, Some(repo_name))?
            else {
                return Err(Error::InvariantViolation(
                    "a bound served repo anchor is not live in its own writer",
                ));
            };
            Ok((
                RegisteredRepository {
                    repo,
                    project,
                    portable,
                    registration,
                    changed: changed || minted,
                },
                minted,
            ))
        })?;
        // The refs writer refreshes after the commit; a fault only warns.
        if let Err(error) = self.settle_ensured_repo_manifest(repo, bound.portable, written) {
            tracing::warn!(code = %repo.to_hex(), kind = ?error.kind(), "repo manifest not refreshed");
        }
        Ok(bound)
    }
}
