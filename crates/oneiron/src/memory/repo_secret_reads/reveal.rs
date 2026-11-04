//! A Memory handle's per-file repo read that may ask for real bytes (FIX
//! 7608 slice 2b-ii-A, GAP-B / FIX 8960).
//!
//! A handle whose host proved the actual recipient (an agent, never the
//! credential's owner standing in for one) may ask, per file and with a
//! why, for a marked file's stored bytes through the shipped file reveal.
//! Every other handle reads as before: the owner at the owner's own door
//! reads stored bytes with no why, consent or claim walk added, and a
//! masked handle with no why or no proven recipient reads the projection.
//! Bulk and hydration reads never come here: they stay mask-only.

use super::super::{Memory, MemoryResult};
use crate::Vault;
use crate::blob_artifact::ArtifactExport;
use crate::codebase::CodebaseSnapshotMount;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::secret_marks::{RepoBlobMarks, repo_secret_marks_for_hash_in_txn};
use crate::origin::secret_projection::RepoRevealRecipient;
use crate::origin::secret_projection::reveal::{
    RepoFileRevealRead, RepoReadDoor, read_repo_file_with_reveal,
};
use crate::origin::secret_projection::{RepoBodyProjection, RepoSecretAudience, project_repo_blob};
use crate::secret_custody::{RepoFileOriginal, RepoFileReadDisclosure};

/// The ORIGINAL a per-file reveal of the blob `marks` cover binds, as the
/// door `repo` pinned it at `snapshot` and `path` (FIX 7608 2b-ii-B): the
/// one store and blob every readable mark names. `None` when they name
/// more than one, so the read stays masked rather than guess an origin.
/// The import source is not joined here (FIX line), so it is `None`.
///
/// Its repo is the store's CODE anchor in the recipient's PROJECT, the repo
/// a Git read of that store names (CALLS 3262), so a snapshot door's
/// CODE_ARTIFACT and an export's BLOB_ARTIFACT name the same repo as a run
/// door and a Git read, and one repo-wide grant covers them all (FIX
/// 10850). With no recipient PROJECT, or no anchor the owner bound there,
/// it stays the door's `repo`.
///
/// # Errors
/// A failed mark id derivation, or a store failure.
pub(crate) fn repo_file_original(
    vault: &Vault,
    recipient_project: Option<EntityId>,
    repo: EntityId,
    snapshot: Option<EntityId>,
    path: &str,
    marks: &RepoBlobMarks,
) -> Result<Option<RepoFileOriginal>> {
    let Some((store, blob)) = marks.single_origin() else {
        return Ok(None);
    };
    let repo = match recipient_project {
        Some(project) => {
            let txn = vault.store.env.read_txn()?;
            vault
                .served_repo_anchor_in_txn(&txn, store, project)?
                .unwrap_or(repo)
        }
        None => repo,
    };
    Ok(Some(RepoFileOriginal {
        repo,
        store: store.to_owned(),
        snapshot,
        path: path.to_owned(),
        blob: blob.clone(),
        source: None,
        marks: marks.ids()?,
    }))
}

/// A masked or exact read, as a door that asks nothing returns it.
const fn projected(projection: RepoBodyProjection) -> RepoFileRevealRead {
    RepoFileRevealRead {
        projection,
        proof: None,
        byte_route: None,
    }
}

impl Memory<'_> {
    /// Binds this handle to an MCP tool call or run whose actual recipient
    /// the host proved: its repo reads are masked, as
    /// [`Self::for_repo_tool_recipient`]'s, and a per-file read that says
    /// why may ask the owner for that file's real bytes as `recipient`. It
    /// admits nothing: the engine revalidates the recipient and the live
    /// grant at every read. Room and turn handles built from this one keep
    /// it.
    #[must_use]
    pub fn for_repo_reveal_recipient(mut self, recipient: RepoRevealRecipient) -> Self {
        self.repo_tool_recipient.bind(recipient);
        self
    }

    /// The PROJECT the proven recipient of this handle's reads works in, as
    /// its host bound it; `None` with no proven recipient or no project.
    fn repo_reveal_project(&self) -> Option<EntityId> {
        self.repo_tool_recipient
            .actual()
            .and_then(RepoRevealRecipient::project)
    }

    /// CALL 3 for this handle: a per-file read's `why` asks the owner only
    /// when this handle reads masked and its host proved the recipient;
    /// otherwise the read is today's.
    ///
    /// # Errors
    /// A present `why` the file read's own validation refuses.
    pub(crate) fn repo_file_disclosure(&self, why: Option<&str>) -> Result<RepoFileReadDisclosure> {
        // A handle that keeps no record writes no reveal receipt: it reads
        // masked, as with no why, and is never refused for asking.
        if self.keeps_no_record() {
            return Ok(RepoFileReadDisclosure::Masked);
        }
        let asker = self
            .repo_tool_recipient
            .actual()
            .map(RepoRevealRecipient::asker);
        RepoFileReadDisclosure::from_optional_why(why, asker)
    }

    /// One per-file read of the ORIGINAL `original` whose readable marks are
    /// `marks`, through `door`: the stored bytes for a reader of stored
    /// bytes, else the masked reader's read with `why` (CALL 3) through the
    /// file reveal ([`Self::repo_file_read_projected`]). `readmit` re-admits
    /// the door's pins after the reveal's receipts commit.
    ///
    /// # Errors
    /// The read's own, a refused `why`, or a store failure.
    pub(crate) fn repo_file_read_sighted<F, R>(
        &self,
        original: Option<&RepoFileOriginal>,
        marks: &RepoBlobMarks,
        why: Option<&str>,
        door: RepoReadDoor,
        read_exact: F,
        readmit: R,
    ) -> MemoryResult<RepoFileRevealRead>
    where
        F: FnOnce() -> Result<Vec<u8>>,
        R: FnOnce() -> Result<()>,
    {
        if !self.repo_reads_masked()? {
            return Ok(projected(RepoBodyProjection::Exact(read_exact()?)));
        }
        self.repo_file_read_projected(original, marks, why, door, read_exact, readmit)
    }

    /// An artifact version's export for this handle, when the version's
    /// stored bytes are a repo-marked blob (FIX 8960): the masked copy, or,
    /// with a why from a proven recipient, the stored bytes through the file
    /// reveal; the stored bytes for a reader of stored bytes. `None` for a
    /// version no repo mark covers, which exports as before. The version is
    /// pinned once: an ask is never on one version and an export of another.
    ///
    /// # Errors
    /// The export's own, a refused `why`, or a store failure.
    pub(crate) fn export_repo_marked_artifact(
        &self,
        artifact: &EntityId,
        version: Option<u64>,
        why: Option<&str>,
    ) -> MemoryResult<Option<Option<ArtifactExport>>> {
        let vault = self.vault;
        let metadata = match version {
            Some(version) => {
                let txn = vault.store.env.read_txn().map_err(Error::from)?;
                vault.blob_artifact_version_metadata_in_txn(&txn, artifact, version)?
            }
            None => vault.blob_artifact_head(artifact)?,
        };
        let Some(metadata) = metadata else {
            return Ok(None);
        };
        let marks = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            repo_secret_marks_for_hash_in_txn(vault, &txn, &metadata.content_hash)?
        };
        if marks.is_empty() {
            return Ok(None);
        }
        let Some(mut file) = vault.export_blob_artifact_raw(artifact, Some(metadata.version))?
        else {
            return Ok(Some(None));
        };
        let original = match why {
            Some(_) => repo_file_original(
                vault,
                self.repo_reveal_project(),
                *artifact,
                None,
                &file.name,
                &marks,
            )?,
            None => None,
        };
        let stored = std::mem::take(&mut file.bytes);
        let readmit = || -> Result<()> {
            let txn = vault.store.env.read_txn()?;
            let again =
                vault.blob_artifact_version_metadata_in_txn(&txn, artifact, metadata.version)?;
            if again.is_none_or(|again| {
                again.content_hash != metadata.content_hash || again.claim_id != metadata.claim_id
            }) {
                return Err(Error::ConcurrentWrite("the artifact version changed"));
            }
            Ok(())
        };
        let read = self.repo_file_read_sighted(
            original.as_ref(),
            &marks,
            why,
            RepoReadDoor::Bytes,
            || Ok(stored),
            readmit,
        )?;
        file.bytes = vault.resolve_docx_authors(read.projection.into_bytes())?;
        Ok(Some(Some(file)))
    }

    /// One per-file read through a door that chose the projection (a run's
    /// door, or a tool's projected sibling of an owner door), whatever this
    /// handle's own credential reads: no why, no proven recipient or no
    /// pinnable `original` is the masked read; a why from a proven recipient
    /// is the file reveal (CALL 3). `readmit` re-admits the door's pins
    /// after the reveal's receipts commit; the blob's marks are checked
    /// again beside it.
    ///
    /// # Errors
    /// The read's own, a refused `why`, a changed pin, or a store failure.
    pub(crate) fn repo_file_read_projected<F, R>(
        &self,
        original: Option<&RepoFileOriginal>,
        marks: &RepoBlobMarks,
        why: Option<&str>,
        door: RepoReadDoor,
        read_exact: F,
        readmit: R,
    ) -> MemoryResult<RepoFileRevealRead>
    where
        F: FnOnce() -> Result<Vec<u8>>,
        R: FnOnce() -> Result<()>,
    {
        let disclosure = match original {
            Some(_) if !marks.is_empty() => self.repo_file_disclosure(why)?,
            _ => RepoFileReadDisclosure::Masked,
        };
        let Some(original) = original.filter(|_| disclosure != RepoFileReadDisclosure::Masked)
        else {
            let projection =
                project_repo_blob(self.vault, marks, &RepoSecretAudience::Masked, read_exact)?;
            return Ok(projected(projection));
        };
        let vault = self.vault;
        let raw_blake3 = marks.raw_blake3();
        let readmit = || -> Result<()> {
            readmit()?;
            let Some(raw_blake3) = raw_blake3 else {
                return Err(Error::ConcurrentWrite("the repo file's marks changed"));
            };
            let txn = vault.store.env.read_txn()?;
            let fresh = repo_secret_marks_for_hash_in_txn(vault, &txn, &raw_blake3)?;
            if fresh.ids()? != original.marks {
                return Err(Error::ConcurrentWrite("the repo file's marks changed"));
            }
            Ok(())
        };
        Ok(read_repo_file_with_reveal(
            vault, original, marks, disclosure, door, read_exact, readmit,
        )?)
    }

    /// `mount`'s file `path`, of the repo `repo`, through a door that chose
    /// the projection, with the read's optional `why` (FIX 8960): `None`
    /// exactly where [`CodebaseSnapshotMount::read_file_projected`] is. No
    /// why is that read, unchanged.
    ///
    /// # Errors
    /// As [`Self::repo_file_read_projected`].
    pub(crate) fn snapshot_file_read_with_why<R>(
        &self,
        mount: &CodebaseSnapshotMount<'_>,
        repo: EntityId,
        path: &str,
        why: Option<&str>,
        door: RepoReadDoor,
        readmit: R,
    ) -> MemoryResult<Option<RepoFileRevealRead>>
    where
        R: FnOnce() -> Result<()>,
    {
        if why.is_none() {
            return Ok(mount.read_file_projected(path)?.map(projected));
        }
        let Some((_, marks)) = mount.file_marks(path)? else {
            return Ok(None);
        };
        let original = repo_file_original(
            self.vault,
            self.repo_reveal_project(),
            repo,
            Some(mount.code_artifact_id()),
            path,
            &marks,
        )?;
        let read_exact =
            || -> Result<Vec<u8>> { mount.read_file(path)?.ok_or(Error::EntityNotFound) };
        self.repo_file_read_projected(original.as_ref(), &marks, why, door, read_exact, readmit)
            .map(Some)
    }

    /// The stored bytes `bytes` of a working view's file `path`, read by a
    /// door that chose the projection, with its optional `why` (FIX 8960):
    /// the view's file of the repo `repo` at `snapshot` is read as the very
    /// marked blob it holds, else masked. No why is the masked read.
    ///
    /// # Errors
    /// As [`Self::repo_file_read_projected`].
    pub(crate) fn view_file_read_with_why<R>(
        &self,
        repo: EntityId,
        snapshot: Option<EntityId>,
        path: &str,
        bytes: Vec<u8>,
        why: Option<&str>,
        readmit: R,
    ) -> MemoryResult<RepoFileRevealRead>
    where
        R: FnOnce() -> Result<()>,
    {
        let marks = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            repo_secret_marks_for_hash_in_txn(self.vault, &txn, blake3::hash(&bytes).as_bytes())?
        };
        let original = match why {
            Some(_) => repo_file_original(
                self.vault,
                self.repo_reveal_project(),
                repo,
                snapshot,
                path,
                &marks,
            )?,
            None => None,
        };
        self.repo_file_read_projected(
            original.as_ref(),
            &marks,
            why,
            RepoReadDoor::Bytes,
            || Ok(bytes),
            readmit,
        )
    }
}
