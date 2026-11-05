//! Native federation delivery history, not current grant or content authority.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::ManifestDbs;

const DELIVERED: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::FEDERATION_DELIVERED_RECORD);

/// The local admission that delivered one exact record image. These facts
/// describe that delivery, not today's grant standing or today's record bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationDeliveryRecord {
    pub source_ref: EntityId,
    pub delivering_pact: [u8; 32],
    pub consent_epoch: u64,
    pub grant_ref: EntityId,
    pub source_vault: [u8; 32],
    /// BLAKE3 of the full landed row, including its metadata header.
    pub delivered_row_hash: [u8; 32],
    pub world: Option<EntityId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeliveryOrigin {
    pub grant_ref: EntityId,
    pub source_vault: [u8; 32],
}

pub(crate) struct DeliveredRecord {
    pub origin: DeliveryOrigin,
    pub row_hash: [u8; 32],
    pub world: Option<EntityId>,
}

fn corrupt() -> Error {
    Error::CorruptedIndex("federation delivered record")
}

/// Current delivery-value codec. Keys still carry pact, consent epoch and id.
pub(crate) fn encode_delivered_record(record: &DeliveredRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(80 + record.world.map_or(0, |_| 16));
    bytes.extend_from_slice(record.origin.grant_ref.as_bytes());
    bytes.extend_from_slice(&record.origin.source_vault);
    bytes.extend_from_slice(&record.row_hash);
    if let Some(world) = record.world {
        bytes.extend_from_slice(world.as_bytes());
    }
    bytes
}

pub(crate) fn decode_delivered_record(bytes: &[u8]) -> Result<DeliveredRecord> {
    let (grant, rest) = bytes.split_first_chunk::<16>().ok_or_else(corrupt)?;
    let (source_vault, rest) = rest.split_first_chunk::<32>().ok_or_else(corrupt)?;
    let (row_hash, place) = rest.split_first_chunk::<32>().ok_or_else(corrupt)?;
    let grant_ref = EntityId::from_bytes(*grant).map_err(|_| corrupt())?;
    let world = if place.is_empty() {
        None
    } else {
        Some(
            EntityId::from_bytes(place.try_into().map_err(|_| corrupt())?)
                .map_err(|_| corrupt())?,
        )
    };
    Ok(DeliveredRecord {
        origin: DeliveryOrigin {
            grant_ref,
            source_vault: *source_vault,
        },
        row_hash: *row_hash,
        world,
    })
}

/// Reads only locally retained delivery facts, never a peer's evidence fields
/// or a reconstruction from the current authority fold.
pub(crate) fn delivery_history_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    sources: &BTreeSet<EntityId>,
) -> Result<BTreeMap<EntityId, Vec<FederationDeliveryRecord>>> {
    let mut history = BTreeMap::<EntityId, Vec<FederationDeliveryRecord>>::new();
    if sources.is_empty() {
        return Ok(history);
    }
    for row in DELIVERED.iter_from(store, txn, b"")? {
        let (key, value) = row?;
        let (pact_epoch, record) = key.rsplit_once(':').ok_or_else(corrupt)?;
        let source = EntityId::from_hex(record).map_err(|_| corrupt())?;
        if source.to_hex() != record {
            return Err(corrupt());
        }
        if !sources.contains(&source) {
            continue;
        }
        let (pact, epoch) = pact_epoch.split_once(':').ok_or_else(corrupt)?;
        let delivering_pact = blake3::Hash::from_hex(pact).map_err(|_| corrupt())?;
        let consent_epoch = u64::from_str_radix(epoch, 16)
            .ok()
            .filter(|_| epoch.len() == 16)
            .ok_or_else(corrupt)?;
        let record = decode_delivered_record(&value)?;
        history
            .entry(source)
            .or_default()
            .push(FederationDeliveryRecord {
                source_ref: source,
                delivering_pact: *delivering_pact.as_bytes(),
                consent_epoch,
                grant_ref: record.origin.grant_ref,
                source_vault: record.origin.source_vault,
                delivered_row_hash: record.row_hash,
                world: record.world,
            });
    }
    Ok(history)
}

impl Vault {
    /// The local delivery history of `records`, retained when their exact
    /// images landed. No current authority or current-byte match is implied.
    /// A later landing at the same pact/epoch/id replaces that key's image.
    ///
    /// # Errors
    /// Storage errors or malformed locally stored delivery metadata.
    pub fn federation_delivery_history(
        &self,
        records: &[EntityId],
    ) -> Result<Vec<FederationDeliveryRecord>> {
        let txn = self.store.env.read_txn()?;
        Ok(
            delivery_history_in_txn(&self.store, &txn, &records.iter().copied().collect())?
                .into_values()
                .flatten()
                .collect(),
        )
    }
}
