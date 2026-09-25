//! Archive receipt I/O through ordinary ASSET admission, not terminal ledgers.
use super::{
    codec::{ReceiptArchive, decode, invalid, is_inert_holder},
    custody::{read_source, receipt_archives_for_holder},
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
        let raw = self
            .store
            .entities
            .get(txn, holder.as_bytes())?
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
            let bytes = archive.bytes()?;
            let id = archive.id()?;
            if let Some(raw) = self.store.entities.get(txn, id.as_bytes())? {
                let head = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("receipt source existing header"))?;
                if head.entity_type != ENTITY_TYPE_ASSET
                    || decode(&raw[ENTITY_METADATA_HEADER_LEN..])? != Some(archive)
                {
                    return Err(invalid());
                }
            } else {
                prepared.push((id, bytes));
            }
            existing.insert(source.receipt_id().to_owned(), source);
        }
        for (id, bytes) in &prepared {
            self.batch_in()
                .put(
                    id,
                    ENTITY_TYPE_ASSET,
                    TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    header.learned_at,
                    bytes,
                )
                .apply(txn)?;
        }
        Ok(prepared.len())
    }
}
