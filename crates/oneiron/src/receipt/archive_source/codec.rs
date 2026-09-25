//! Canonical claim-bound archived receipt data, never a native terminal stamp.
use crate::{
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, export::ExportReceiptSource},
    entity_id::EntityId,
    error::{Error, Result},
    registry::ENTITY_TYPE_CLAIM,
    store::Store,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
// Invalid UTF-8 and a non-container MessagePack first byte prevent opaque
// carriers from falling through a text serializer. Whole export uses the
// credential-safe source facet, never these bytes as another escape channel.
pub(super) const MAGIC: &[u8] = b"\xf5oneiron.receipt-archive.v1\0";
const MAX_BYTES: usize = 4 * 1024 * 1024;
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
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let payload = rmp_serde::to_vec_named(self).map_err(|_| invalid())?;
        if payload.len() > MAX_BYTES {
            return Err(invalid());
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend(payload);
        Ok(bytes)
    }
    pub(super) fn id(&self) -> Result<EntityId> {
        crate::codebase::entity_id_from_hash_material(
            b"oneiron.receipt-archive.asset.v1",
            &[&self.bytes()?],
        )
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
        let raw = store
            .entities
            .get(txn, holder.as_bytes())?
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
pub(crate) fn is_receipt_archive_source(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}
pub(super) fn decode(bytes: &[u8]) -> Result<Option<ReceiptArchive>> {
    let Some(payload) = bytes.strip_prefix(MAGIC) else {
        return Ok(None);
    };
    if payload.len() > MAX_BYTES {
        return Err(invalid());
    }
    let row: ReceiptArchive = rmp_serde::from_slice(payload).map_err(|_| invalid())?;
    if row.bytes()? != bytes {
        return Err(invalid());
    }
    Ok(Some(row))
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
        .is_some_and(|source| source.id().is_ok_and(|actual| actual == *id))
}
