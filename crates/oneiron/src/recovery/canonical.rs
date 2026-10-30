//! CRDT-independent, byte-exact Layer-1 snapshot and fresh-window construction.

use std::collections::BTreeMap;

use loro::{LoroDoc, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

use super::document::{self, CanonicalDocument, CanonicalHead, CanonicalHeadMove};
use super::validation;
use super::{decode_recovery_artifact, seal_recovery_artifact};
use crate::error::{ArtifactError, Error, Result};
use crate::ports::{
    DeletionMarker, EntityStoreRead, TombstoneStoreRead, WindowAddress, WindowDeletionRows,
};
use crate::{EntityId, Vault};

mod asset_body_refs;
mod budget;
mod capture;
mod peer_origins;
mod rebuild;
mod row_births;
mod snapshot_ops;
mod vocabulary;
mod withdrawn_cutoffs;
pub use asset_body_refs::CanonicalAssetBodyRef;
pub(super) use budget::ByteBudget;
pub use budget::RecoveryBudgetOverrun;
#[cfg(test)]
pub(super) use budget::held_bytes;
pub use capture::capture_canonical_window;
pub(crate) use capture::{capture_canonical_window_within, prepare_artifact_pads};
pub use peer_origins::CanonicalPeerOrigin;
pub use rebuild::rebuild_vault_window_from_canonical;
#[cfg(feature = "sync")]
pub(crate) use rebuild::{RebuildAt, rebuild_page, rebuild_start};
pub use row_births::CanonicalRowBirth;
pub use vocabulary::{
    CanonicalBaseEdge, CanonicalContainerManifest, CanonicalCustodyTransition,
    CanonicalDocumentFork, CanonicalDocumentPin, CanonicalDocumentPurge, CanonicalDocumentReceipt,
    CanonicalDocumentVersion, CanonicalEntity, CanonicalEntityDocument,
    CanonicalEntityDocumentHistory, CanonicalForkStatus, CanonicalPinCarrier, CanonicalRoomFact,
    CanonicalRoomTurn, CanonicalSchemaManifest, CanonicalSettleVerb, CanonicalShellWorld,
    CanonicalSnapshot, CanonicalTombstone,
};
pub use withdrawn_cutoffs::CanonicalCutoff;

/// Canonical Layer-1 artifact discriminator (not a Loro snapshot).
pub const CANONICAL_SNAPSHOT_ARTIFACT_TYPE: u16 = 1;
/// Maximum decoded artifact size. Recovery is off the hot path but remains bounded.
pub const CANONICAL_SNAPSHOT_MAX_BYTES: usize = 64 * 1024 * 1024;

impl CanonicalBaseEdge {
    pub(super) fn key(&self) -> Result<String> {
        Ok(format!(
            "{}:{:02}:{}",
            id(self.source)?.to_hex(),
            self.kind,
            id(self.target)?.to_hex()
        ))
    }
}

impl CanonicalEntityDocument {
    /// The bytes this row holds: its ids, text and causal history.
    pub(super) fn held(&self) -> usize {
        self.entity_id.len()
            + self.document_id.len()
            + self.field.as_ref().map_or(0, String::len)
            + self.text.len()
            + metadata_size(&self.metadata)
            + self.record_fields.iter().map(String::len).sum::<usize>()
            + self.birth_actor.map_or(0, |actor| actor.len())
            + self.history.as_ref().map_or(0, |history| {
                let versions = history.versions.iter().map(|version| {
                    16 + 4 * version.parents.len()
                        + version.middle.len()
                        + metadata_size(&version.metadata)
                });
                let pins = history.pins.iter().map(|pin| 96 + pin.quote.len());
                // Ids, times, flags and the u64 place in its bundle.
                let forks = history.forks.iter().map(|fork| {
                    108 + fork.output.as_ref().map_or(0, String::len)
                        + fork.output_metadata.as_ref().map_or(0, metadata_size)
                        + 16 * fork.read_refs.len()
                        + fork.keep.as_ref().map_or(0, String::len)
                });
                versions.sum::<usize>()
                    + pins.sum::<usize>()
                    + forks.sum::<usize>()
                    + 96 * (history.receipts.len() + history.purges.len())
                    + history
                        .receipts
                        .iter()
                        .map(|receipt| 16 * receipt.read_refs.len())
                        .sum::<usize>()
            })
    }
}

fn metadata_size(fields: &BTreeMap<String, Vec<u8>>) -> usize {
    fields
        .iter()
        .map(|(field, value)| field.len() + value.len())
        .sum()
}

impl CanonicalSnapshot {
    /// [`Self::encode`], refused with [`ArtifactError::OverlayLimit`] once the
    /// artifact would pass `limit` bytes. The payload is written straight
    /// into the artifact's one buffer, which stops growing at the limit, so
    /// an artifact too large is never held whole before it is refused.
    pub(crate) fn encode_within(&self, limit: usize) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = BoundedWriter {
            bytes: Vec::new(),
            budget: ByteBudget::new(limit.min(CANONICAL_SNAPSHOT_MAX_BYTES)),
            refused: None,
        };
        // Room for the envelope header, sealed once the payload is written.
        std::io::Write::write_all(&mut out, &[0; super::HEADER_LEN]).map_err(|_| out.refusal())?;
        rmp_serde::encode::write_named(&mut out, self).map_err(|_| out.refusal())?;
        seal_recovery_artifact(CANONICAL_SNAPSHOT_ARTIFACT_TYPE, &mut out.bytes);
        Ok(out.bytes)
    }

    pub(super) fn refresh_containers(&mut self) {
        self.container_manifests = self.expected_containers();
    }
    pub(super) fn expected_containers(&self) -> Vec<CanonicalContainerManifest> {
        let mut rows = Vec::new();
        for name in [
            "entities",
            "edges",
            "tombstones",
            "retained_claim_worlds",
            "documents",
            "entity_documents",
            "document_heads",
            "head_move_receipts",
            "note_forks",
            "note_proposals",
            "custody",
            "room_turns",
            "room_facts",
            "document_pins",
            "peer_origins",
            "row_births",
            "withdrawn_cutoffs",
            "asset_body_refs",
        ] {
            rows.push(CanonicalContainerManifest {
                container_id: name.to_owned(),
                container_kind: "map".to_owned(),
                schema_version: 1,
                source_entity_id: None,
            });
        }
        for doc in &self.entity_documents {
            for (name, kind) in [("body", "text"), ("meta", "map")] {
                rows.push(CanonicalContainerManifest {
                    container_id: format!(
                        "entity_doc/{}/{name}",
                        crate::entity_id::bytes_to_hex_lower(&doc.entity_id)
                    ),
                    container_kind: kind.to_owned(),
                    schema_version: 1,
                    source_entity_id: Some(doc.entity_id),
                });
            }
        }
        for doc in &self.doc_snapshots {
            for (name, kind) in [("body", "text"), ("note", "map"), ("authorship", "map")] {
                rows.push(CanonicalContainerManifest {
                    container_id: format!("{}/{name}", doc.key()),
                    container_kind: kind.to_owned(),
                    schema_version: 1,
                    source_entity_id: Some(doc.entity_id),
                });
            }
        }
        rows.sort_by(|a, b| a.container_id.cmp(&b.container_id));
        rows
    }
}

/// Marks first, as every local removal does, the task of an authority fact
/// this vault never admitted that a deleted id's carrier holds: the capture
/// below leaves that carrier out of the artifact or keeps only its shell, and
/// the mark is what then carries the refusal in `suppressed_tasks`. An id is
/// deleted here when the window or a pending marker holds its tombstone, or a
/// global hard marker names it, as the capture reads them. A build without
/// sync captures too, so it marks through the same writer.
fn mark_deleted_carriers_first(
    vault: &Vault,
    window: &str,
    snapshot: &CanonicalSnapshot,
) -> Result<()> {
    let mut deleted: std::collections::BTreeSet<_> =
        snapshot.tombstones.iter().map(|row| row.id).collect();
    {
        let txn = vault.store.env.read_txn()?;
        for row in vault
            .store
            .port_pending_tombstones_in_window(&txn, WindowAddress::new(window))?
        {
            deleted.insert(*row?.id.as_bytes());
        }
        for row in &snapshot.entity_blobs {
            if vault
                .store
                .port_deletion_marked(&txn, DeletionMarker::HardDelete, &id(row.id)?)?
            {
                deleted.insert(row.id);
            }
        }
    }
    let carriers = snapshot
        .entity_blobs
        .iter()
        .filter(|row| {
            deleted.contains(&row.id)
                && crate::batch::EntityMetadataHeader::parse(&row.blob)
                    .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_TASK)
        })
        .map(|row| Ok((id(row.id)?, row.blob.clone())))
        .collect::<Result<Vec<_>>>()?;
    #[cfg(feature = "sync")]
    crate::sync::window::mark_removed_carriers_first(
        vault,
        crate::sync::window::CarrierRemoval::CanonicalCapture,
        &carriers,
    )?;
    #[cfg(not(feature = "sync"))]
    crate::task_authority::mark_removed_carriers(vault, &carriers)?;
    Ok(())
}

#[cfg(feature = "sync")]
pub(super) fn binary_rows(doc: &LoroDoc, name: &str) -> Result<BTreeMap<String, Vec<u8>>> {
    binary_rows_within(doc, name, &mut ByteBudget::new(usize::MAX))
}

/// The shortest key a Layer-1 window map holds: one hex entity id.
const ROW_KEY_BYTES: usize = 32;

/// The binary rows of the window map `name`, copying no row past `budget`.
fn binary_rows_within(
    doc: &LoroDoc,
    name: &str,
    budget: &mut ByteBudget,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut rows = BTreeMap::new();
    let LoroValue::Map(containers) = doc.get_value() else {
        return Err(invalid("window root"));
    };
    // Looking up a root by name creates it in Loro, even without an op. Readers
    // must inspect the existing root IDs so validation cannot change the document.
    let map = match containers.get(name) {
        None => return Ok(rows),
        Some(LoroValue::Container(id)) => doc
            .try_get_map(id)
            .ok_or(invalid("nonmap Layer-1 carrier"))?,
        Some(_) => return Err(invalid("nonmap Layer-1 carrier")),
    };
    // The map walk lists every key before its first row, so the keys are
    // admitted first, each at the shortest key a Layer-1 map holds.
    budget.take(map.len().saturating_mul(ROW_KEY_BYTES))?;
    let mut failed = false;
    let mut refused = None;
    map.for_each(|key, value| match value {
        _ if refused.is_some() => {}
        ValueOrContainer::Value(LoroValue::Binary(value)) => {
            match budget.take(key.len().saturating_sub(ROW_KEY_BYTES) + value.len()) {
                Ok(()) => {
                    rows.insert(key.to_owned(), value.to_vec());
                }
                Err(error) => refused = Some(error),
            }
        }
        _ => failed = true,
    });
    if failed {
        return Err(invalid("nonbinary Layer-1 carrier"));
    }
    match refused {
        Some(error) => Err(error),
        None => Ok(rows),
    }
}
pub(super) fn insert(doc: &LoroDoc, map: &str, key: &str, bytes: &[u8]) -> Result<()> {
    doc.get_map(map)
        .insert(key, bytes)
        .map_err(|_| invalid("rebuild map"))
}
pub(super) fn id(bytes: [u8; 16]) -> Result<EntityId> {
    EntityId::from_bytes(bytes)
}
pub(super) fn parse_id(value: &str) -> Result<[u8; 16]> {
    let parsed = EntityId::from_hex(value)?;
    if parsed.to_hex() != value {
        return Err(invalid("noncanonical entity id"));
    }
    Ok(*parsed.as_bytes())
}
pub(super) fn pack<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| invalid("canonical encoding"))
}
pub(super) fn invalid(reason: &'static str) -> Error {
    ArtifactError::InvalidRecoveryArtifact(reason).into()
}

/// The artifact's one buffer: a write past its budget is refused, and the
/// buffer never reserves past the budget either.
struct BoundedWriter {
    bytes: Vec<u8>,
    budget: ByteBudget,
    refused: Option<Error>,
}

impl BoundedWriter {
    /// Why a write failed: the budget it would pass, else the encoder.
    fn refusal(&mut self) -> Error {
        self.refused
            .take()
            .unwrap_or_else(|| invalid("canonical encoding"))
    }
}

impl std::io::Write for BoundedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Err(error) = self.budget.take(buf.len()) {
            self.refused = Some(error);
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        let need = self.bytes.len() + buf.len();
        if need > self.bytes.capacity() {
            let grown = need
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.budget.limit);
            self.bytes.reserve_exact(grown - self.bytes.len());
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn check_size(size: usize) -> Result<()> {
    if size > CANONICAL_SNAPSHOT_MAX_BYTES {
        return Err(ArtifactError::OverlayLimit {
            required: size,
            limit: CANONICAL_SNAPSHOT_MAX_BYTES,
        }
        .into());
    }
    Ok(())
}
