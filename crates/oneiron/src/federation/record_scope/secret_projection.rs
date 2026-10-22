//! The masked copy a scoped export carries of a marked repo row (FIX 7608
//! slice 4, LEAF 4.2; L02 ack 17:2x and 20:2x).
//!
//! The export's own admission stays the ceiling: a row reaches this leaf
//! only after every conjunct the export judges it by (scope, causal,
//! epoch, text) admitted it, and only its bytes and, for a marked snapshot
//! ASSET, its id change. A marked repo source that today's masked-key
//! exclusion drops is carried as its copy instead (the copy masks the
//! custody spans with the marks', so no key leaves). Every other row keeps
//! its admitted bytes, its id and its place in the export's order. Custody
//! rows, unpublished LFS chunks and masked-key rows that are not marked
//! repo sources still drop.
//!
//! The copies are read once per export, in its transaction. A read that
//! fails leaves the export exactly as before this leaf: the masked-key
//! rows drop and nothing is carried as a copy, never as raw bytes.

use heed::RoTxn;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::provenance::birth::RowBirth;
use crate::sync::selector::secret_projection::{CopyRow, SyncSecretProjection};

/// One export's marked repo copies.
pub(super) struct ExportProjection(Option<SyncSecretProjection>);

impl ExportProjection {
    /// The copies `txn` reads; none when the read fails.
    pub(super) fn read_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Self {
        match SyncSecretProjection::read_in_txn(vault, txn) {
            Ok(projection) if !projection.is_empty() => Self(Some(projection)),
            Ok(_) => Self(None),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "scoped export: marked repo copies unreadable; masked-key rows drop as before"
                );
                Self(None)
            }
        }
    }

    /// Whether row `raw`, stored under `id`, is a marked repo item this
    /// export carries as its copy: the one case today's masked-key
    /// exclusion no longer drops.
    pub(super) fn carries_copy(&self, id: &EntityId, raw: &[u8]) -> bool {
        self.0
            .as_ref()
            .is_some_and(|projection| projection.project_row(id, raw) != CopyRow::Keep)
    }

    /// Row `id`'s admitted bytes as the export carries them: a marked item's
    /// copy, under its copy id for a marked snapshot ASSET; any other row as
    /// admitted.
    pub(super) fn released(&self, id: EntityId, bytes: Vec<u8>) -> (EntityId, Vec<u8>) {
        match self
            .0
            .as_ref()
            .map(|projection| projection.project_row(&id, &bytes))
        {
            Some(CopyRow::Copy { key, row }) => (key, row),
            _ => (id, bytes),
        }
    }

    /// The stored row a carried record id stands for: its source for a copy.
    pub(super) fn source_of(&self, id: &EntityId) -> EntityId {
        self.0
            .as_ref()
            .and_then(|projection| projection.source_of_copy(id))
            .unwrap_or(*id)
    }

    /// `birth`, already masked for this export, with each input naming a
    /// marked source naming the copy the export carries instead: no
    /// recipient learns a source id from it.
    pub(super) fn translated_birth(&self, mut birth: RowBirth) -> RowBirth {
        if let Some(projection) = &self.0 {
            for input in &mut birth.made_by.inputs {
                if let Some(copy) = projection.copy_of(&input.row) {
                    input.row = copy;
                }
            }
        }
        birth
    }
}
