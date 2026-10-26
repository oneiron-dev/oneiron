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

use crate::code_artifact::{CodeArtifactBody, encode_code_artifact_body};
use crate::codebase::{CODEBASE_COMMIT_HASH_HEX_LEN, RepoRef};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EdgeStoreRead;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{TimeRange, Vault};

/// The domain a served repo's anchor id is derived under.
const SERVED_REPO_ANCHOR_DOMAIN: &[u8] = b"oneiron:served-repo-anchor:v1";

/// The project is no live PROJECT of this vault.
const NOT_A_PROJECT: &str = "a served repo anchor belongs to a live PROJECT of this vault";
/// The derived id holds another row.
const ANCHOR_TAKEN: &str = "the served repo anchor's id holds another record";

/// What a binding stands on: the anchor, its PROJECT and whether this call
/// wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServedRepoAnchor {
    pub(crate) repo: EntityId,
    pub(crate) project: EntityId,
    pub(crate) created: bool,
}

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
    /// `belongs_to` edge, each only when missing.
    ///
    /// # Errors
    /// An owner refusal; `GitHttpRepoNotFound` for a name this origin does
    /// not serve; `InvalidConfig` for a project that is no live PROJECT, or
    /// an id that already holds another record; a store failure.
    pub(crate) fn bind_served_repo_anchor(
        &self,
        owner: &AuthenticatedOwner,
        repo_name: &str,
        project: EntityId,
    ) -> Result<ServedRepoAnchor> {
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
        self.with_write_txn_grouped(|txn| {
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
            let mut batch = self.batch_in();
            let mut created = false;
            match live_entity_row_in_txn(&self.store, txn, &repo)? {
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_CODE_ARTIFACT,
                    body,
                } if crate::code_artifact::decode_code_artifact_body(&body)
                    .is_ok_and(|stored| stored.repo_ref == repo_ref) => {}
                LiveEntityRow::Live { .. } => {
                    return Err(Error::InvalidConfig(ANCHOR_TAKEN.into()));
                }
                _ => {
                    let body = CodeArtifactBody::new(
                        format!("The served repository {repo_name}."),
                        *blake3::hash(identity.as_bytes()).as_bytes(),
                        repo_ref.clone(),
                    );
                    batch = batch.put(
                        &repo,
                        ENTITY_TYPE_CODE_ARTIFACT,
                        occurred,
                        now,
                        &encode_code_artifact_body(&body)?,
                    );
                    created = true;
                }
            }
            if self
                .store
                .port_edge_get(txn, &repo, EdgeKind::BelongsTo, &project)?
                .is_none()
            {
                batch = batch.edge(&repo, EdgeKind::BelongsTo, &project, 1.0);
                created = true;
            }
            if created {
                batch.apply(txn)?;
            }
            Ok(ServedRepoAnchor {
                repo,
                project,
                created,
            })
        })
    }
}
