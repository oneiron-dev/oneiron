//! The repository a capture belongs to (FIX 4299, CODE-CUSTODY-01), judged
//! again in the import's final writer.
//!
//! The owner's capture of a registered repository, a run's capture of its
//! admitted anchor and the owner's served import each name the stable CODE
//! anchor. The final writer reads that anchor, never a caller's whitelist:
//! it must stand live with the folder the import read, and, where the caller
//! has not proved it, belong to the live PROJECT named. The capture stays
//! immutable and content-addressed with its source revision.

use crate::Vault;
use crate::code_artifact::decode_code_artifact_body;
use crate::codebase::RepoRef;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EdgeStoreRead;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The anchor no longer names the folder the import read.
const NOT_THE_ANCHOR: &str =
    "the capture's repository is no live CODE anchor of the folder the import read";
/// The anchor does not belong to the PROJECT the capture names.
const NOT_IN_PROJECT: &str =
    "the capture's repository does not belong to the live PROJECT it names";

/// The repository a capture belongs to (FIX 4299).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CaptureRepository {
    /// The stable CODE anchor.
    pub(crate) anchor: EntityId,
    /// The live PROJECT the anchor must belong to, where the caller has not
    /// proved it; a run's Grant admission already has.
    pub(crate) project: Option<EntityId>,
}

impl Vault {
    /// Judges `capture` in the import's final writer `txn` against the
    /// source revision `repo_ref` the import read: the anchor is a live
    /// CODE_ARTIFACT whose stored folder is that same folder, and it belongs
    /// to `capture.project` when one is named.
    ///
    /// # Errors
    /// `InvalidConfig` naming the rule the capture breaks; a store failure.
    pub(crate) fn require_capture_repository_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        capture: &CaptureRepository,
        repo_ref: &RepoRef,
    ) -> Result<()> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CODE_ARTIFACT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &capture.anchor)?
        else {
            return Err(Error::InvalidConfig(NOT_THE_ANCHOR.into()));
        };
        let same_folder = decode_code_artifact_body(&body)
            .ok()
            .and_then(|stored| RepoRef::parse(&stored.repo_ref).ok())
            .is_some_and(|stored| stored.locator() == repo_ref.locator());
        if !same_folder {
            return Err(Error::InvalidConfig(NOT_THE_ANCHOR.into()));
        }
        if let Some(project) = capture.project
            && (!live_entity_row_in_txn(&self.store, txn, &project)?.is_live()
                || !crate::workspace_roster::is_project_entity(&self.store, txn, project)?
                || self
                    .store
                    .port_edge_get(txn, &capture.anchor, EdgeKind::BelongsTo, &project)?
                    .is_none())
        {
            return Err(Error::InvalidConfig(NOT_IN_PROJECT.into()));
        }
        Ok(())
    }
}
