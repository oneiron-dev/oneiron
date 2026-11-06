//! Archive receipt I/O through ordinary ASSET admission, not terminal ledgers.
use super::{
    body::decode_stored,
    codec::{ReceiptArchive, invalid, is_inert_holder},
    custody::{read_source, receipt_archives_for_holder},
    prepared::ReceiptArchivePreparation,
    reader::{decode_reader, id_of_reader},
};
use crate::{
    Vault,
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, export::ExportReceiptSource},
    entity_id::EntityId,
    error::{Error, Result},
    registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM},
    store::Store,
    temporal::TimeRange,
};
use std::collections::BTreeMap;

pub(crate) fn archived_receipt_sources_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<BTreeMap<String, ExportReceiptSource>> {
    let mut sources = BTreeMap::new();
    for id in receipt_archives_for_holder(store, txn, holder)? {
        let Some(source) = read_source(store, txn, &id)? else {
            continue;
        };
        if source.holder()? != *holder {
            return Err(invalid());
        }
        let reference = source.source.receipt_id().to_owned();
        if let Some(previous) = sources.insert(reference, source.source.clone())
            && previous != source.source
        {
            return Err(invalid());
        }
    }
    Ok(sources)
}

/// [`archived_receipt_sources_in_txn`] for an export (SCAN C022): a source
/// whose carrier row `withholds` keeps out is not folded, and the carriers
/// folded come back beside the sources, for the export to name among the
/// rows it read.
pub(crate) fn archived_receipt_carriers_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
    mut withholds: impl FnMut(&EntityId) -> Result<bool>,
) -> Result<(BTreeMap<String, ExportReceiptSource>, Vec<EntityId>)> {
    let mut sources = BTreeMap::new();
    let mut carriers = Vec::new();
    for id in receipt_archives_for_holder(store, txn, holder)? {
        let Some(source) = read_source(store, txn, &id)? else {
            continue;
        };
        if source.holder()? != *holder {
            return Err(invalid());
        }
        if withholds(&id)? {
            continue;
        }
        let reference = source.source.receipt_id().to_owned();
        if let Some(previous) = sources.insert(reference, source.source.clone())
            && previous != source.source
        {
            return Err(invalid());
        }
        carriers.push(id);
    }
    Ok((sources, carriers))
}

impl Vault {
    pub(crate) fn restore_claim_receipt_sources_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        holder: &EntityId,
        sources: &[ExportReceiptSource],
    ) -> Result<usize> {
        if sources.is_empty() {
            return Ok(0);
        }
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, holder)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("receipt source import holder"))?;
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(invalid());
        }
        // Re-import into a vault already holding this exact native head does
        // not attach foreign evidence or downgrade that head.
        if !is_inert_holder(body) {
            return Ok(0);
        }
        let mut existing = archived_receipt_sources_in_txn(&self.store, txn, holder)?;
        let mut prepared = Vec::new();
        let mut preparation = None;
        for source in sources {
            let source = source.as_imported_archive();
            source.validate()?;
            if let Some(previous) = existing.get(source.receipt_id()) {
                if previous != &source {
                    return Err(invalid());
                }
                continue;
            }
            let archive = ReceiptArchive::new(holder, body, source.clone())?;
            if preparation.is_none() {
                preparation = Some(ReceiptArchivePreparation::new(self.store.body_dir()?)?);
            }
            let encoded = preparation
                .as_mut()
                .expect("receipt preparation opened")
                .push(&archive)?;
            prepared.push((None, encoded));
            existing.insert(source.receipt_id().to_owned(), source);
        }
        let Some(preparation) = preparation else {
            return Ok(0);
        };
        let bytes = preparation.finish()?;
        let mut count = 0;
        // Resolve every identity and existing row against the frozen bytes
        // before admitting the first put. No encoder is replayed for an id.
        for (id, encoded) in &mut prepared {
            let actual = id_of_reader(bytes.reader(encoded))?;
            if let Some(raw) =
                crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &actual)?
            {
                let head = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("receipt source existing header"))?;
                if head.entity_type != ENTITY_TYPE_ASSET {
                    return Err(invalid());
                }
                let expected = decode_reader(bytes.reader(encoded))?.ok_or_else(invalid)?;
                let existing = decode_stored(
                    &self.store,
                    txn,
                    &actual,
                    &raw[ENTITY_METADATA_HEADER_LEN..],
                )?
                .ok_or_else(invalid)?;
                if existing.id != actual || existing.row != expected {
                    return Err(invalid());
                }
            } else {
                *id = Some(actual);
                count += 1;
            }
        }
        for (id, encoded) in prepared {
            let Some(id) = id else {
                continue;
            };
            // Receipt archives remain owning-adapter rows. No file manifest
            // or persistent instance is introduced: the native stager reads
            // this one frozen archive back for the ordinary ASSET put.
            let staged = self.stage_asset_body(bytes.reader(&encoded), None, None, None)?;
            encoded.check_facts(staged.facts())?;
            self.put_asset_body_in_txn(
                txn,
                &id,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
                &staged,
            )?;
        }
        Ok(count)
    }
}
