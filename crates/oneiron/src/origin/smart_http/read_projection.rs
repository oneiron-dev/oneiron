//! The read-only backend over a masked Git copy (FIX 7608 slice 2b-i):
//! its constructor only, with no serving sibling, route, dispatch or
//! registration outside this module. Nothing is served masked yet.
//!
//! The copy is admitted again, whole, before a backend is built: its graph
//! claim must still stand under the readable marks it was made under. The
//! backend then carries a frozen Published witness: the canonical store's
//! publication id and each projected ref the canonical publication still
//! names at the original it was frozen at, with its copy tip. A GET and the
//! upload-pack exchange after it read that one frozen witness, so their
//! continuity rests on nothing stock Git would have to echo back. A ref the
//! canonical publication no longer names at its frozen original is left
//! out of the copy's advertisement, never refused.

#![allow(
    dead_code,
    reason = "FIX 7608 slice 2b-i: constructor only; slice 2b-ii selects the copy for fetch"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::advertise::AdvertisedRefGate;
use super::exchange_idle::Progress;
use super::serve::ServeSink;
use super::serve_cmd::ServeCommand;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo};
use crate::origin::lfs::lfs_repo_id;
use crate::origin::secret_projection::git::{RepoGitProjection, admit_repo_git_projection_in_txn};

/// The canonical store's publication, frozen for one copy: its id and
/// each projected ref with the original it is published at and its copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FrozenPublishedWitness {
    repo_id: EntityId,
    refs: Vec<(GitRefName, GitOid, GitOid)>,
}

/// A read-only `http-backend` over one admitted masked copy, with the
/// frozen witness its advertisement is gated by.
#[derive(Debug, Clone)]
pub(crate) struct RepoGitBackend {
    command: ServeCommand,
    copy_dir: PathBuf,
    witness: FrozenPublishedWitness,
}

impl RepoGitBackend {
    /// The frozen read-only serve invocation.
    pub(crate) const fn command(&self) -> &ServeCommand {
        &self.command
    }

    /// The frozen witness.
    pub(crate) const fn witness(&self) -> &FrozenPublishedWitness {
        &self.witness
    }

    /// The advertisement gate over this copy: exactly the witnessed refs,
    /// each at its copy tip.
    pub(super) fn advertisement_gate<'a>(
        &self,
        vault: &Arc<Vault>,
        clock: &'a Progress,
        inner: &'a mut dyn ServeSink,
    ) -> AdvertisedRefGate<'a> {
        let copies = self
            .witness
            .refs
            .iter()
            .map(|(name, _, copy)| (name.clone(), copy.clone()))
            .collect();
        AdvertisedRefGate::frozen_copy(
            vault,
            &self.copy_dir,
            self.witness.repo_id,
            copies,
            clock,
            inner,
        )
    }
}

/// The read-only backend over `projection`, a masked copy of `canonical`;
/// `None` when the copy no longer stands (its graph claim is gone or the
/// readable marks moved), which a later slice answers by making a new copy.
///
/// # Errors
/// A store or publication read failure, or a git executable that cannot be
/// pinned.
pub(crate) fn prepare_projected_read_backend(
    vault: &Vault,
    wire: &GitWire<'_>,
    canonical: &GitWireRepo,
    projection: &RepoGitProjection,
    project_root: &Path,
) -> Result<Option<RepoGitBackend>> {
    {
        let txn = vault.store.env.read_txn()?;
        if !admit_repo_git_projection_in_txn(vault, &txn, projection)? {
            return Ok(None);
        }
    }
    let repo_id = lfs_repo_id(&canonical.identity().as_hex())?;
    let published = vault.published_origin_refs(wire, repo_id, canonical)?;
    let refs = projection
        .refs()
        .iter()
        .filter(|(name, original, _)| {
            published
                .iter()
                .any(|(published, oid)| published == name && oid == original)
        })
        .cloned()
        .collect();
    let command = ServeCommand::http_backend_read_only(projection.store_root(), project_root)?;
    Ok(Some(RepoGitBackend {
        command,
        copy_dir: projection.store_root().clone(),
        witness: FrozenPublishedWitness { repo_id, refs },
    }))
}
