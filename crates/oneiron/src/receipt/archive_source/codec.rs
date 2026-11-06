//! Canonical claim-bound archived receipt data, never a native terminal stamp.
pub(super) use crate::store::receipt_identity::MAGIC;
use crate::{
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, export::ExportReceiptSource},
    entity_id::EntityId,
    error::{Error, Result},
    registry::ENTITY_TYPE_CLAIM,
    store::Store,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
/// The domain an archived source's id hashes its canonical bytes under.
pub(super) const ID_DOMAIN: &[u8] = b"oneiron.receipt-archive.asset.v1";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReceiptArchive {
    pub(super) holder: String,
    pub(super) body_sha256: String,
    pub(super) source: ExportReceiptSource,
}
impl ReceiptArchive {
    pub(super) fn new(holder: &EntityId, body: &[u8], source: ExportReceiptSource) -> Result<Self> {
        let row = Self {
            holder: holder.to_hex(),
            body_sha256: digest(body),
            source,
        };
        row.validate()?;
        if !row.matches_body(body) {
            return Err(invalid());
        }
        Ok(row)
    }
    pub(super) fn holder(&self) -> Result<EntityId> {
        let id = EntityId::from_hex(&self.holder)?;
        if id.to_hex() != self.holder {
            return Err(invalid());
        }
        Ok(id)
    }
    pub(super) fn validate(&self) -> Result<()> {
        self.holder()?;
        if self.body_sha256.len() != 64
            || !self
                .body_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(invalid());
        }
        self.source.validate()?;
        if matches!(&self.source, ExportReceiptSource::Preserved { origin, .. } if *origin != crate::batch::export::ReceiptSourceOrigin::ImportedArchive)
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// The canonical stored bytes: the magic, then the named MessagePack
    /// payload. Any size: a source carries whole (FIX 10059).
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.write_canonical(&mut bytes)?;
        Ok(bytes)
    }
    /// [`Self::bytes`] written into `out` as it is encoded, never held whole
    /// here.
    pub(super) fn write_canonical(&self, out: &mut impl std::io::Write) -> Result<()> {
        self.validate()?;
        out.write_all(MAGIC).map_err(|_| invalid())?;
        rmp_serde::encode::write_named(out, self).map_err(|_| invalid())
    }
    pub(super) fn matches_body(&self, body: &[u8]) -> bool {
        is_inert_holder(body)
            && digest(body) == self.body_sha256
            && crate::claim::decode_claim_body(body, true).is_ok_and(|claim| {
                crate::batch::export::task_receipt_refs(&claim).contains(self.source.receipt_id())
            })
    }
    pub(super) fn matches_holder(&self, store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
        let holder = self.holder()?;
        if store.off_record_sessions.contains_entity(&holder)?
            || !crate::vault::live_entity_row_in_txn(store, txn, &holder)?.is_live()
        {
            return Ok(false);
        }
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &holder)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("archived receipt holder"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Ok(false);
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        Ok(self.matches_body(body))
    }
}
pub(crate) use crate::store::receipt_identity::is_receipt_archive_source;
pub(super) fn decode(bytes: &[u8]) -> Result<Option<ReceiptArchive>> {
    if !is_receipt_archive_source(bytes) {
        return Ok(None);
    }
    super::reader::decode_reader(std::io::Cursor::new(bytes))
}
/// The id of the archived source whose canonical stored bytes are `bytes`.
pub(super) fn id_of_bytes(bytes: &[u8]) -> Result<EntityId> {
    super::reader::id_of_reader(std::io::Cursor::new(bytes))
}
pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn invalid() -> Error {
    Error::InvalidConfig("archived receipt source is malformed, mismatched or retired".into())
}

pub(super) fn is_inert_holder(bytes: &[u8]) -> bool {
    crate::claim::decode_claim_body(bytes, true).is_ok_and(|body| {
        body.source == Some(crate::claim::ClaimSource::Imported)
            && matches!(
                body.approval,
                crate::claim::ClaimApprovalStatus::Proposed
                    | crate::claim::ClaimApprovalStatus::Rejected
            )
    })
}

#[cfg(feature = "sync")]
pub(crate) fn receipt_archive_holder(bytes: &[u8]) -> Option<EntityId> {
    decode(bytes).ok().flatten()?.holder().ok()
}
#[cfg(feature = "sync")]
pub(crate) fn receipt_archive_matches_id(bytes: &[u8], id: &EntityId) -> bool {
    decode(bytes)
        .ok()
        .flatten()
        .is_some_and(|_| id_of_bytes(bytes).is_ok_and(|actual| actual == *id))
}
