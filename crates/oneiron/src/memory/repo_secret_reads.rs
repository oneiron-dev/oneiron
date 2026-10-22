//! Repo bytes a Memory handle's masked reader reads (FIX 7608 slice 2a,
//! ASK 1). The owner reading at the owner's own door reads stored bytes; a
//! handle bound to another credential, and any handle a code run's host
//! origin rides (whatever credential it carries), reads repo bytes masked.
//! The choice changes what is projected only: never the actor, authorship,
//! admission or what is read.
//!
//! A handle the host bound to an MCP tool call (FIX 8961) reads repo bytes
//! masked too, the owner's own credential included: the tool, not the
//! owner, receives them. The marker only masks; it admits nothing, and the
//! owner's HTTP, CLI and SDK doors never carry it.
//!
//! A hydrated row is a repo file only when it is a snapshot ASSET holding
//! its bytes inline: its id is derived from their BLAKE3, which is the hash
//! a repo mark keeps. Every other row, and every row no mark covers, reads
//! as it always has.

use std::borrow::Cow;

use heed::RoTxn;

use super::{Memory, MemoryResult};
use crate::Vault;
use crate::codebase::snapshot_asset_entity_id;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::secret_marks::{
    RepoMarkFacts, RepoSecretMarkLookup, repo_secret_marks_for_hash_in_txn,
};
use crate::origin::secret_projection::{RepoBodyProjection, project_repo_bytes_in_txn};
use crate::registry::ENTITY_TYPE_ASSET;

mod reveal;

/// The body a masked reader reads of the hydrated row `id`, in `txn`:
/// `None` unless the row is a repo snapshot ASSET whose inline bytes a repo
/// mark covers, and then their projection.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(crate) fn repo_asset_body_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<Option<Vec<u8>>> {
    if entity_type != ENTITY_TYPE_ASSET {
        return Ok(None);
    }
    let hash = *blake3::hash(body).as_bytes();
    if snapshot_asset_entity_id(&hash)? != *id {
        return Ok(None);
    }
    let marks = repo_secret_marks_for_hash_in_txn(vault, txn, &hash)?;
    if marks.is_empty() {
        return Ok(None);
    }
    project_repo_bytes_in_txn(vault, txn, &marks, body.to_vec())
        .map(|projected| Some(projected.into_bytes()))
}

/// [`repo_asset_body_in_txn`] in its own snapshot, for a reader that holds
/// none; no snapshot is opened for a row that is no ASSET.
///
/// # Errors
/// As [`repo_asset_body_in_txn`].
pub(crate) fn repo_asset_body(
    vault: &Vault,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<Option<Vec<u8>>> {
    if entity_type != ENTITY_TYPE_ASSET {
        return Ok(None);
    }
    let txn = vault.store.env.read_txn()?;
    repo_asset_body_in_txn(vault, &txn, id, entity_type, body)
}

/// `body`, a hydrated row's, as a masked reader reads it: a repo ASSET's
/// projection when a mark covers its inline bytes, else `body` as read.
///
/// # Errors
/// As [`repo_asset_body_in_txn`].
pub(crate) fn masked_asset_body(
    vault: &Vault,
    id: &EntityId,
    entity_type: u8,
    body: Vec<u8>,
) -> Result<Vec<u8>> {
    Ok(repo_asset_body(vault, id, entity_type, &body)?.unwrap_or(body))
}

/// `bytes`, one stored file's, as a masked reader reads them, the marks
/// found in one walk: the stored bytes when no mark covers them.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(crate) fn project_repo_file(vault: &Vault, bytes: Vec<u8>) -> Result<RepoBodyProjection> {
    let txn = vault.store.env.read_txn()?;
    let marks = repo_secret_marks_for_hash_in_txn(vault, &txn, blake3::hash(&bytes).as_bytes())?;
    project_repo_bytes_in_txn(vault, &txn, &marks, bytes)
}

/// The repo marks one view's masked reader reads its file texts under,
/// found once for that view; none for a reader of stored bytes.
pub(crate) struct RepoReadMasks {
    facts: Option<RepoMarkFacts>,
}

impl RepoReadMasks {
    /// `bytes`, one file's stored bytes, as this view's reader reads them:
    /// as they are when no mark covers them.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn bytes<'b>(&self, vault: &Vault, bytes: &'b [u8]) -> Result<Cow<'b, [u8]>> {
        let Some(facts) = &self.facts else {
            return Ok(Cow::Borrowed(bytes));
        };
        let marks = facts.for_hash(blake3::hash(bytes).as_bytes());
        if marks.is_empty() {
            return Ok(Cow::Borrowed(bytes));
        }
        let txn = vault.store.env.read_txn()?;
        project_repo_bytes_in_txn(vault, &txn, &marks, bytes.to_vec())
            .map(|projected| Cow::Owned(projected.into_bytes()))
    }
}

impl Memory<'_> {
    /// Binds this handle to an MCP tool call (FIX 8961, GAP-A): its repo
    /// reads are masked whatever credential rides it, the owner's included.
    /// Mask-only and off by default; the host sets it once where it builds
    /// the MCP handle, and room or turn handles built from this one keep it.
    /// It never turns a recipient into a reveal, and never changes the
    /// actor, admission or anything but which repo bytes are returned.
    #[must_use]
    pub fn for_repo_tool_recipient(mut self) -> Self {
        self.repo_tool_recipient.mask();
        self
    }

    /// Whether this handle reads repo bytes masked: an MCP tool call, a
    /// credential other than the owner's, or a call a code run's host
    /// origin rides.
    pub(crate) fn repo_reads_masked(&self) -> MemoryResult<bool> {
        Ok(self.repo_tool_recipient.masked()
            || self.host_origin.is_some()
            || self.reads_lifted_keys_masked()?)
    }

    /// The marks this handle's view reads file texts under: found in one
    /// walk for a masked reader, none for a reader of stored bytes.
    pub(crate) fn repo_read_masks(&self) -> MemoryResult<RepoReadMasks> {
        if !self.repo_reads_masked()? {
            return Ok(RepoReadMasks { facts: None });
        }
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let facts =
            RepoMarkFacts::read_in_txn(self.vault, &txn, RepoSecretMarkLookup::ReadableClaims)?;
        Ok(RepoReadMasks { facts: Some(facts) })
    }

    /// The body the read lane decodes for the admitted row `id`, in `txn`:
    /// a repo ASSET's projection for a masked reader, else `body` as read.
    pub(super) fn repo_lane_body_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        entity_type: u8,
        body: Vec<u8>,
    ) -> MemoryResult<Vec<u8>> {
        if entity_type != ENTITY_TYPE_ASSET
            || !(self.repo_tool_recipient.masked()
                || self.host_origin.is_some()
                || self.reads_lifted_keys_masked_in_txn(txn)?)
        {
            return Ok(body);
        }
        Ok(repo_asset_body_in_txn(self.vault, txn, id, entity_type, &body)?.unwrap_or(body))
    }
}
