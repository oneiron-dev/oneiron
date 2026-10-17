//! Integrity reads compose ports without opening a transaction.
use super::{EntityStore, TombstoneStore};
use crate::{EntityId, error::Result};
pub fn safe_read_text<P: EntityStore + TombstoneStore>(
    ports: &P,
    txn: &P::Read<'_>,
    id: &EntityId,
) -> Result<Option<Vec<u8>>> {
    let row = ports.port_entity_get(txn, id)?;
    if ports.port_tombstone_is_deleted(txn, id)? {
        return Ok(None);
    }
    Ok(row
        .filter(|row| !body_is_stale(&row.body))
        .map(|row| row.body))
}
pub fn safe_read_asset_text<P: EntityStore + TombstoneStore>(
    ports: &P,
    txn: &P::Read<'_>,
    id: &EntityId,
    derived_hash: &[u8; 32],
    source_hash: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    if derived_hash != source_hash {
        return Ok(None);
    }
    safe_read_text(ports, txn, id)
}

/// Whether `id`'s own words are withdrawn in this snapshot: deleted, marked
/// stale, covered by a pending source walk (I1, I2), or kept only under a
/// legal-hold use limit after a refused privacy erasure (OF-470 C6). A door
/// that returns a stored body refuses such a row; maintenance and
/// capture-before-purge read the raw ports instead.
pub(crate) fn withdrawn_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(
        super::TombstoneStoreRead::port_deletion_state(store, txn, id)?.deleted
            || super::stale_in_txn(store, txn, id)?
            || crate::store::legal_hold::use_limit_in_txn(store, txn, id)?.is_some(),
    )
}

/// What a door makes of a stored body's own `stale: true`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyStale {
    /// Withdrawn words, whatever the kind.
    Withdrawn,
    /// A deliberate CLAIM status-history read: a CLAIM's `stale` is a
    /// Recorded status, kept as `port_claim_get` keeps it.
    ClaimStatus,
}

impl BodyStale {
    /// The raw doors' rule: a CLAIM keeps its Recorded status, and any other
    /// kind's stale body is withdrawn derived text.
    pub(crate) fn for_kind(entity_type: u8) -> Self {
        if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            Self::ClaimStatus
        } else {
            Self::Withdrawn
        }
    }

    /// Whether this rule admits `body`'s own flag.
    pub(crate) fn admits(self, body: &[u8]) -> bool {
        self == Self::ClaimStatus || !body_is_stale(body)
    }
}

/// Whether `id`'s stored `body` may serve in this snapshot: its own words are
/// not withdrawn ([`withdrawn_in_txn`]), `stale` admits its own flag, and
/// every source it is recorded as derived from still stands (I1, I2). Only
/// `id`'s own rows are read. Maintenance, capture-before-purge and
/// checkpoints read the raw ports instead.
pub(crate) fn body_readable_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
    stale: BodyStale,
) -> Result<bool> {
    Ok(!withdrawn_in_txn(store, txn, id)?
        && stale.admits(body)
        && !super::integrity::source_withdrawn_in(store, txn, id)?)
}

/// [`body_readable_in_txn`] for a stored envelope, header and body, by the
/// raw doors' rule ([`BodyStale::for_kind`]).
pub(crate) fn raw_readable_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<bool> {
    let stale = match crate::batch::EntityMetadataHeader::parse(raw) {
        Some(header) => BodyStale::for_kind(header.entity_type),
        None => BodyStale::Withdrawn,
    };
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .unwrap_or_default();
    body_readable_in_txn(store, txn, id, body, stale)
}

pub(crate) fn body_is_stale(bytes: &[u8]) -> bool {
    let Ok(body) = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)) else {
        return false;
    };
    body.as_map().is_some_and(|fields| {
        fields
            .iter()
            .any(|(key, value)| key.as_str() == Some("stale") && value.as_bool() == Some(true))
    })
}
