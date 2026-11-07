//! The scoped export door.
use std::collections::BTreeSet;

use super::{Scope, ScopedRecord, disclosure_scope_for_stored_row, note_world};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::CallerLocality;
use crate::provenance::birth::{WithheldKey, row_birth_in_txn};
use crate::settings::ReadDestination;
use crate::{
    EntityId, Vault,
    error::{Error, Result},
};

impl Vault {
    /// Export never has a debug mode and requires the export verb class, and
    /// never carries a SECRET_CUSTODY row or an unpublished LFS chunk. Every
    /// body it carries passes the export release filter: a credential the
    /// write scan would refuse never leaves, whether the scan was on when
    /// it was stored or not, nor a row secret exhaust tainted (FIX 8742).
    /// A row a device-only world keeps on this device is never exported, nor
    /// a text written from one, nor a row whose own words are withdrawn.
    /// The export goes to a recipient nobody proved; see
    /// [`Self::export_records_in_scope_for`].
    pub(crate) fn export_records_in_scope(
        &self,
        selector: &Scope,
        slip: &Scope,
        channel: &Scope,
    ) -> Result<Vec<ScopedRecord>> {
        self.export_records_in_scope_for(selector, slip, channel, &CallerLocality::OffDevice.into())
    }

    /// [`Self::export_records_in_scope`] to the recipient `destination`
    /// names: a row, and a text written from one, is judged by the world
    /// settings for each machine it goes to, its proof revalidated in this
    /// snapshot (mesh PR2b). An export always leaves this device, so an
    /// on-device destination is read as one nobody proved. Selector, slip,
    /// channel, epoch and text fences stay conjuncts.
    ///
    /// A scoped door: neither it nor [`Self::export_records_in_scope`] is an
    /// Owner's copy of the vault, whatever scopes it is given. The Owner's
    /// own copy of every record is [`Self::export_owner_records`], which
    /// also judges each row by the members' mailbox rule (fix list row
    /// 15416).
    pub(crate) fn export_records_in_scope_for(
        &self,
        selector: &Scope,
        slip: &Scope,
        channel: &Scope,
        destination: &ReadDestination,
    ) -> Result<Vec<ScopedRecord>> {
        let txn = self.store.env.read_txn()?;
        self.export_records_in_txn(&txn, [selector, slip, channel], destination, |_, _, _| {
            Ok(true)
        })
        .map(|(records, _)| records)
    }

    /// [`Self::export_records_in_scope_for`] in the snapshot `txn`, through
    /// the door `[selector, slip, channel]`: `carries` judges each row every
    /// other check admits, by its id, its type and its stored bytes, before
    /// its body is read, and a row it refuses stays home. An Owner's own copy
    /// judges by the members' mailbox rule there (fix list row 15416); a
    /// scoped export carries every such row. Answers the records, and the
    /// stored row each stands for (a marked item's copy by its source).
    pub(crate) fn export_records_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        [selector, slip, channel]: [&Scope; 3],
        destination: &ReadDestination,
        mut carries: impl FnMut(EntityId, u8, &[u8]) -> Result<bool>,
    ) -> Result<(Vec<ScopedRecord>, BTreeSet<EntityId>)> {
        let recipient = if destination.is_off_device() {
            destination.clone()
        } else {
            ReadDestination::from(CallerLocality::OffDevice)
        };
        // FIX 7608 slice 4: a marked repo row leaves as its masked copy.
        let copies = super::secret_projection::ExportProjection::read_in_txn(self, txn)?;
        let device_only = crate::settings::device_local_worlds_for(self, txn, &recipient)?;
        let withheld = |source: &EntityId| {
            crate::settings::device_only_withholds(&self.store, txn, &device_only, source)
        };
        let mut out = Vec::new();
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, txn)? {
            let (id, raw) = row?;
            if withheld(&id)? || !crate::ports::raw_readable_in_txn(&self.store, txn, &id, &raw)? {
                continue;
            }
            let h =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("record header"))?;
            if h.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
                || (crate::secret_custody::holds_masked_keys_in_txn(
                    &self.store,
                    txn,
                    &id,
                    h.entity_type,
                    &raw[ENTITY_METADATA_HEADER_LEN..],
                )? && !copies.carries_copy(&id, &raw))
                || crate::origin::lfs::unpublished_lfs_chunk_in_txn(
                    &self.store,
                    txn,
                    &id,
                    h.entity_type,
                )?
            {
                continue;
            }
            // A row secret exhaust tainted stays home, as a whole-vault
            // export nulls its body (FIX 8742).
            if !crate::secret_rotation::exhaust_taint_refs_in_txn(&self.store, txn, &id)?.is_empty()
            {
                continue;
            }
            if let Some(scope) = disclosure_scope_for_stored_row(
                &self.store,
                txn,
                id,
                h.entity_type,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )? && note_world::admits_at(
                &self.store,
                txn,
                id,
                h.entity_type,
                &scope,
                [selector, slip, channel],
                "export",
            ) && crate::authority::row_causal_admitted(self, txn, &id, &raw)?
                && self.epoch_fence_in(txn, id, &raw, [selector, slip, channel], "export")?
                && self.text_fence_in(
                    txn,
                    id,
                    &raw,
                    [selector, slip, channel],
                    "export",
                    &withheld,
                )?
                && carries(id, h.entity_type, raw.as_slice())?
            {
                // A pad row is key material, never memory text: a reference
                // leaves as the carrier the world-key door builds and a pad
                // body that decodes leaves whole, since the memory filter
                // would break its key. Every other body leaves as the release
                // filter reads it, after its marked copy is chosen (FIX 8742).
                let pad = h.entity_type == crate::registry::ENTITY_TYPE_WORLD_KEY_PAD
                    && raw.get(ENTITY_METADATA_HEADER_LEN..).is_some_and(|body| {
                        oneiron_store::world_pad_codec::decode_pad_body(body).is_ok()
                    });
                let carrier = crate::world_keys::image_pad_row(&self.store, &raw);
                let filtered = carrier.is_none() && !pad;
                let bytes = match carrier {
                    Some(carrier) => carrier,
                    None => self.materialized_row_in_txn(txn, &id, raw)?,
                };
                let (id, bytes) = copies.released(id, bytes);
                let bytes = if filtered {
                    match crate::batch::export::export_released_record(h.entity_type, bytes)? {
                        Some(bytes) => bytes,
                        None => continue,
                    }
                } else {
                    bytes
                };
                out.push(ScopedRecord {
                    id,
                    bytes,
                    scope: Some(scope),
                    suppressed: false,
                    birth: None,
                });
            }
        }
        // A birth leaves naming only the rows this export carries; one key
        // per export, so its handles link to no other copy.
        let ships: BTreeSet<EntityId> = out
            .iter()
            .map(|record| copies.source_of(&record.id))
            .collect();
        let key = WithheldKey::for_export();
        for record in &mut out {
            record.birth =
                row_birth_in_txn(&self.store, txn, &copies.source_of(&record.id))?.map(|birth| {
                    copies.translated_birth(birth.masked(|row| ships.contains(row), &key))
                });
        }
        Ok((out, ships))
    }

    /// The position each of `ids`, records an export carries, stands at in
    /// `txn`, read as [`Self::export_records_in_scope_for`] reads it: off
    /// the stored row the record stands for (a marked item's copy by its
    /// source). `None` for one whose row is gone or holds no position. An
    /// export-first removal reads them in its archive's own snapshot
    /// (FIX-LIST 8224), so each frozen position labels the bytes archived.
    pub(crate) fn export_positions_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        ids: &std::collections::BTreeSet<crate::EntityId>,
    ) -> Result<Vec<(crate::EntityId, Option<Scope>)>> {
        let copies = super::secret_projection::ExportProjection::read_in_txn(self, txn)?;
        let mut positions = Vec::with_capacity(ids.len());
        for &id in ids {
            let source = copies.source_of(&id);
            let scope =
                match crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &source)? {
                    Some(raw) => {
                        let h = EntityMetadataHeader::parse(&raw)
                            .ok_or(Error::CorruptedIndex("record header"))?;
                        disclosure_scope_for_stored_row(
                            &self.store,
                            txn,
                            source,
                            h.entity_type,
                            &raw[ENTITY_METADATA_HEADER_LEN..],
                        )?
                    }
                    None => None,
                };
            positions.push((id, scope));
        }
        Ok(positions)
    }
}
