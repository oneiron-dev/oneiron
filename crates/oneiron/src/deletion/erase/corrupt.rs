//! The audited escape for a corrupt CLAIM's hard erase (FIX 7800, ARCH-0038).
//!
//! A CLAIM whose non-empty body fails its strict capture decode cannot be
//! erased: neither its world nor its provenance subject reads, so the delete
//! fails closed. An owner's maintenance pass may select it
//! (`MaintenanceBuilder::reclassify_corrupt_claims`). The writer re-reads the
//! record and, when its capture really fails, classifies it: its bytes stay,
//! one signed repair event is appended and the marker below binds the exact
//! header it saw, in one commit. A later hard erase of that same version takes
//! the exception: its world is unknown, so its tombstone also goes to every
//! world window of its month this vault holds; the cached provenance stamps it
//! may have supported are derived again from the surviving Claims; and its
//! receipt and sweep record `capture_failed`, the sweep then taking every
//! carrier. The marker goes in the commit that writes that receipt and sweep.
//! An unclassified corrupt CLAIM, a soft delete and a healthy body keep the
//! strict path.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::super::receipt::{CaptureFailure, encode_corrupt_claim_repair_event};
use super::super::sweep_queue::HardEraseSweepExtras;
use super::super::tombstone::{
    DeleteReason, PENDING_TOMBSTONE, PendingTombstoneKey, TombstoneValueV2,
};
use super::provenance::decode_provenance_capture;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, WindowDeletionRows};
use crate::provenance::EdgeRef;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// Whether a SoftErase has scrubbed the classified body since.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum CorruptCapturePhase {
    /// Classified; the body is as it was seen.
    Classified,
    /// A hard erase's SoftErase scrubbed it: the purge still owes its
    /// `capture_failed`, whenever it runs.
    SoftScrubbed,
}

/// One classification: the exact 25-byte header seen, the id of its signed
/// repair event and its phase. No content, no actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CorruptCaptureMark {
    header: [u8; 25],
    repair_receipt: [u8; 16],
    phase: CorruptCapturePhase,
}

/// The classifications awaiting their hard erase, by CLAIM id.
const CORRUPT_CAPTURE: SideTable<EntityId, CorruptCaptureMark, Named> =
    SideTable::new(&side_table::DELETION_CORRUPT_CAPTURE);

/// One record a maintenance pass selected for the audited corrupt-CLAIM
/// repair (FIX 7800).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorruptClaimRepair {
    /// Classified by this pass: `repair_receipt` is its signed REDACTION_AUDIT
    /// repair event. Its hard erase can now finish.
    Reclassified {
        id: EntityId,
        repair_receipt: EntityId,
    },
    /// Classified already, at the header it has now, by `repair_receipt`.
    AlreadyClassified {
        id: EntityId,
        repair_receipt: EntityId,
    },
    /// No stored CLAIM whose non-empty body fails its capture decode: left as
    /// it is.
    NotCorrupt { id: EntityId },
}

/// A hard erase's capture of a classified corrupt CLAIM: the classification
/// it rests on, and the sources of the subjects its structural `claim_of`
/// rows name, read before any scrub.
pub(in crate::deletion) struct CorruptCapture {
    id: EntityId,
    mark: CorruptCaptureMark,
    repair_receipt: EntityId,
    sources: Vec<EntityId>,
}

impl CorruptCapture {
    /// The failure record the erase's receipt and sweep carry.
    pub(in crate::deletion) fn failure(&self) -> CaptureFailure {
        CaptureFailure::new(&self.id, &self.repair_receipt)
    }
}

/// The classification a hard erase's capture of `id`, whose stored row is
/// `raw`, takes: one whose marker binds this exact header. `None` leaves the
/// strict decoder's error standing: a different version, or none classified.
pub(super) fn corrupt_capture_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<Option<CorruptCapture>> {
    let Some(mark) = CORRUPT_CAPTURE.get(store, txn, id)? else {
        return Ok(None);
    };
    if raw.get(..ENTITY_METADATA_HEADER_LEN) != Some(mark.header.as_slice()) {
        return Ok(None);
    }
    let repair_receipt = EntityId::from_bytes(mark.repair_receipt)?;
    let mut sources = Vec::new();
    for edge in store.port_edges(txn, id, EdgeDirection::Out, Some(EdgeKind::ClaimOf), None)? {
        sources.push(edge?.target);
    }
    Ok(Some(CorruptCapture {
        id: *id,
        mark,
        repair_receipt,
        sources,
    }))
}

/// Moves `id`'s classification into the sweep being queued when this erase
/// took its exception: its capture failed in this call, or a SoftErase
/// before it scrubbed the corrupt body. The marker goes in the commit that
/// writes the receipt and the sweep; one this erase did not use stays.
pub(in crate::deletion) fn take_corrupt_capture_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    extras: &mut HardEraseSweepExtras,
) -> Result<()> {
    let Some(mark) = CORRUPT_CAPTURE.get(&vault.store, wtxn, id)? else {
        return Ok(());
    };
    let hex = id.to_hex();
    let failed = extras
        .capture_failures
        .iter()
        .any(|failure| failure.entity_id == hex);
    if !failed {
        if mark.phase != CorruptCapturePhase::SoftScrubbed {
            return Ok(());
        }
        let repair_receipt = EntityId::from_bytes(mark.repair_receipt)?;
        extras
            .capture_failures
            .push(CaptureFailure::new(id, &repair_receipt));
    }
    CORRUPT_CAPTURE.delete(&vault.store, wtxn, id)?;
    Ok(())
}

impl Vault {
    /// Classifies each selected record that is a stored CLAIM whose non-empty
    /// body fails its strict capture decode, each in its own transaction. Its
    /// bytes stay; one signed repair event and the marker binding the header
    /// seen commit together. A repeat at the same header reports the earlier
    /// event; a different header is its own version, classified anew. Any
    /// other record is reported and left as it is. Classifying authorizes no
    /// erase and reads no body to anyone.
    pub(crate) fn reclassify_corrupt_claims(
        &self,
        ids: &[EntityId],
    ) -> Result<Vec<CorruptClaimRepair>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        // The repair event is signed in its transaction: the device key
        // loads first (P6c).
        self.prepare_install_signing()?;
        let mut outcomes = Vec::with_capacity(ids.len());
        for id in ids {
            let outcome = self.with_write_txn_grouped(|wtxn| self.reclassify_in_txn(wtxn, id))?;
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    /// One selected record's classification, in its own transaction.
    fn reclassify_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<CorruptClaimRepair> {
        let not_corrupt = CorruptClaimRepair::NotCorrupt { id: *id };
        let Some(raw) = self.store.port_entity_raw(wtxn, id)? else {
            return Ok(not_corrupt);
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Ok(not_corrupt);
        };
        let seen: [u8; 25] = raw[..ENTITY_METADATA_HEADER_LEN]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("entity header"))?;
        if let Some(mark) = CORRUPT_CAPTURE.get(&self.store, wtxn, id)?
            && mark.header == seen
        {
            return Ok(CorruptClaimRepair::AlreadyClassified {
                id: *id,
                repair_receipt: EntityId::from_bytes(mark.repair_receipt)?,
            });
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        if header.entity_type != ENTITY_TYPE_CLAIM
            || body.is_empty()
            || decode_provenance_capture(body).is_ok()
        {
            return Ok(not_corrupt);
        }
        let repair_receipt = self.store.clock.entity_id()?;
        let request_id = uuid::Uuid::from_bytes(self.store.clock.ulid()?).to_string();
        let recorded_at = self.store.clock.now_recorded_at();
        let identity = crate::identity::ensure_device_identity_in_txn(self, wtxn)?;
        let event = encode_corrupt_claim_repair_event(
            id,
            header.learned_at,
            request_id,
            recorded_at,
            &repair_receipt,
            &identity,
        )?;
        crate::off_record::FloorWrites::new(&self.store).append_redaction_audit(
            wtxn,
            &repair_receipt,
            recorded_at,
            &event,
        )?;
        let mark = CorruptCaptureMark {
            header: seen,
            repair_receipt: *repair_receipt.as_bytes(),
            phase: CorruptCapturePhase::Classified,
        };
        CORRUPT_CAPTURE.put(&self.store, wtxn, id, &mark)?;
        Ok(CorruptClaimRepair::Reclassified {
            id: *id,
            repair_receipt,
        })
    }

    /// The world the CLAIM `id`, stored as `raw` with a body, rides for its
    /// delete. A body that does not decode keeps the decoder's error, unless a
    /// hard erase meets the version a maintenance pass classified: its world
    /// is unknown, so it is addressed by its base month, where sync places a
    /// body that does not decode, and its month's world windows take its
    /// tombstone as well ([`Self::stage_corrupt_world_tombstones_in_txn`]).
    pub(in crate::deletion) fn erase_claim_world(
        &self,
        id: &EntityId,
        raw: &[u8],
        reason: DeleteReason,
    ) -> Result<Option<EntityId>> {
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        let error = match crate::claim::decode_claim_body(body, true) {
            Ok(claim) => return Ok(claim.world),
            Err(error) => error,
        };
        if !reason.active_store_hard_purge_v1() {
            return Err(error);
        }
        let txn = self.store.env.read_txn()?;
        let header = raw.get(..ENTITY_METADATA_HEADER_LEN);
        match CORRUPT_CAPTURE.get(&self.store, &txn, id)? {
            Some(mark) if header == Some(mark.header.as_slice()) => Ok(None),
            _ => Err(error),
        }
    }

    /// The audited exception's part of the scrub or purge of the CLAIM
    /// `corrupt` captured, in that transaction, its classification still
    /// standing as captured. A SoftErase keeps it as `SoftScrubbed` debt, so a
    /// purge retried after it still records `capture_failed`. The CLAIM's own
    /// subject does not read, so each cached provenance stamp on an edge out of
    /// a source its `claim_of` rows name is derived again from the surviving
    /// Claims (D16), as a healthy capture's subject edge is: an active winner,
    /// else a retracted one, else a bare edge. Returns the endpoints whose
    /// edges changed.
    pub(in crate::deletion) fn scrub_corrupt_capture_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        corrupt: &CorruptCapture,
        soft: bool,
    ) -> Result<Vec<EntityId>> {
        let stands = CORRUPT_CAPTURE
            .get(&self.store, wtxn, &corrupt.id)?
            .is_some_and(|mark| {
                mark.header == corrupt.mark.header
                    && mark.repair_receipt == corrupt.mark.repair_receipt
            });
        if !stands {
            return Err(Error::InvariantViolation(
                "a corrupt CLAIM's classification changed during its erase",
            ));
        }
        if soft {
            let mark = CorruptCaptureMark {
                phase: CorruptCapturePhase::SoftScrubbed,
                ..corrupt.mark.clone()
            };
            CORRUPT_CAPTURE.put(&self.store, wtxn, &corrupt.id, &mark)?;
        }
        let mut changed = Vec::new();
        for source in &corrupt.sources {
            let mut subjects = Vec::new();
            for edge in self
                .store
                .port_edges(wtxn, source, EdgeDirection::Out, None, None)?
            {
                let edge = edge?;
                if edge.provenance.is_some() {
                    subjects.push(EdgeRef::new(*source, edge.kind, edge.target));
                }
            }
            for subject in &subjects {
                changed.extend(self.refresh_subject_edge_after_claim_delete_in_txn(
                    wtxn,
                    &corrupt.id,
                    subject,
                )?);
            }
        }
        Ok(changed)
    }

    /// Stages `tombstone`'s pending marker for `id` in every world window of
    /// the month `window_label` names that this vault holds persisted state
    /// for, when `id` is a classified corrupt CLAIM of this exact version: a
    /// CLAIM of a world rides that world's windows, and this one's world does
    /// not read. Returns those windows, for the caller to publish once its
    /// purge commits, as it does an erased world's pad tombstones; empty for
    /// every other erase.
    pub(in crate::deletion) fn stage_corrupt_world_tombstones_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        window_label: &str,
        tombstone: &TombstoneValueV2,
    ) -> Result<BTreeSet<String>> {
        let mut windows = BTreeSet::new();
        if window_label.contains('@') {
            return Ok(windows);
        }
        let Some(mark) = CORRUPT_CAPTURE.get(&self.store, wtxn, id)? else {
            return Ok(windows);
        };
        let raw = self.store.port_entity_raw(wtxn, id)?;
        let header = raw
            .as_deref()
            .and_then(|raw| raw.get(..ENTITY_METADATA_HEADER_LEN));
        if header != Some(mark.header.as_slice()) {
            return Ok(windows);
        }
        let prefix = format!("{window_label}@");
        let snapshots = self
            .store
            .port_window_doc_rows_raw(wtxn, |window, _| window.as_str().to_owned())?
            .collect::<Result<Vec<_>>>()?;
        let updates = self
            .store
            .port_window_update_keys(wtxn, None, str::to_owned)?
            .collect::<Result<Vec<_>>>()?;
        for label in snapshots {
            if label.starts_with(&prefix) {
                windows.insert(label);
            }
        }
        for key in &updates {
            if let Some(label) = update_window(key)
                && label.starts_with(&prefix)
            {
                windows.insert(label.to_owned());
            }
        }
        let value = tombstone.encode().to_vec();
        for window in &windows {
            let key = PendingTombstoneKey {
                window: window.clone(),
                id: *id,
            };
            PENDING_TOMBSTONE.put(&self.store, wtxn, &key, &value)?;
        }
        Ok(windows)
    }
}

/// The window label a `u:w:{label}:{seq}` key names.
fn update_window(key: &str) -> Option<&str> {
    let (label, _seq) = key.strip_prefix("u:w:")?.rsplit_once(':')?;
    Some(label)
}
