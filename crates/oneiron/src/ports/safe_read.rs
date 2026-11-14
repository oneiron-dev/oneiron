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

/// The validity flag bag of one asset-text read (ARCH-0005a, Read patterns:
/// canon's `_validity`): each flag names one reason the strict read
/// [`safe_read_asset_text`] gives no text, for a UI badge or a monitor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AssetTextValidity {
    /// The derived hash the caller holds is not the source hash: the asset
    /// changed after its text was derived.
    pub hash_mismatch: bool,
    /// The row is deleted (its tombstone stands).
    pub deleted: bool,
    /// The row is marked stale (its source was withdrawn, or a walk is
    /// pending), or its served body carries `stale: true`.
    pub stale: bool,
    /// The store serves no live row under the id: none was written, or the
    /// store's own read gate withholds it.
    pub absent: bool,
}

impl AssetTextValidity {
    /// Whether every check passed, so the read serves the text.
    pub fn is_valid(&self) -> bool {
        !(self.hash_mismatch || self.deleted || self.stale || self.absent)
    }
}

/// The diagnostic record of one asset-text read: the text the strict read
/// serves, with the flags that explain its absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetTextRead {
    /// The body bytes, present only when [`AssetTextValidity::is_valid`]:
    /// the record never serves words the strict read withholds.
    pub body: Option<Vec<u8>>,
    /// Why the body is absent, if it is.
    pub validity: AssetTextValidity,
}

/// [`safe_read_asset_text`] as a diagnostic record (ARCH-0005a, Read patterns):
/// every check runs, even after one fails, and each sets its flag. The body is
/// present only when no flag is set, and then it is the strict read's text.
pub fn safe_read_asset_text_diagnostic<P: EntityStore + TombstoneStore>(
    ports: &P,
    txn: &P::Read<'_>,
    id: &EntityId,
    derived_hash: &[u8; 32],
    source_hash: &[u8; 32],
) -> Result<AssetTextRead> {
    let row = ports.port_entity_get(txn, id)?;
    let deleted = ports.port_tombstone_is_deleted(txn, id)?;
    let marked_stale = super::TombstoneStoreRead::port_deletion_state(ports, txn, id)?.stale;
    let validity = AssetTextValidity {
        hash_mismatch: derived_hash != source_hash,
        deleted,
        stale: marked_stale || row.as_ref().is_some_and(|row| body_is_stale(&row.body)),
        absent: row.is_none(),
    };
    let body = row.filter(|_| validity.is_valid()).map(|row| row.body);
    Ok(AssetTextRead { body, validity })
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
    Ok(lapsed_in_txn(store, txn, id)?
        || crate::store::legal_hold::use_limit_in_txn(store, txn, id)?.is_some())
}

/// [`withdrawn_in_txn`] less a legal-hold use limit: deleted or stale.
fn lapsed_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    // The deletion state already walks the staleness sources once.
    let state = super::TombstoneStoreRead::port_deletion_state(store, txn, id)?;
    Ok(state.deleted || state.stale)
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
    let (body, stale) = stored_body(raw);
    body_readable_in_txn(store, txn, id, body, stale)
}

/// [`raw_readable_in_txn`] with a legal-hold use limit left out, for a named
/// read that asks that conjunct on its own once every other gate admits the
/// row (FIX 5226): deleted, stale or source-withdrawn words still refuse.
pub(crate) fn raw_readable_apart_from_use_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<bool> {
    let (body, stale) = stored_body(raw);
    Ok(!lapsed_in_txn(store, txn, id)?
        && stale.admits(body)
        && !super::integrity::source_withdrawn_in(store, txn, id)?)
}

/// [`raw_readable_in_txn`] for the owner's whole-vault export, which carries a
/// record a cleanup archive filed away, with its retained body: a cleanup
/// archive is not a removal (ARCH-0073 §2, FIX 21912). A removal, a stale
/// mark, a legal-hold use limit, a stale body or a withdrawn source still
/// refuses the row.
pub(crate) fn raw_exportable_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<bool> {
    let state = super::TombstoneStoreRead::port_deletion_state(store, txn, id)?;
    if !state.archived {
        return raw_readable_in_txn(store, txn, id, raw);
    }
    let (body, stale) = stored_body(raw);
    Ok(!state.stale
        && !super::removed_in_txn(store, txn, id)?
        && crate::store::legal_hold::use_limit_in_txn(store, txn, id)?.is_none()
        && stale.admits(body)
        && !super::integrity::source_withdrawn_in(store, txn, id)?)
}

/// A stored envelope's body and the raw doors' stale rule for its kind.
fn stored_body(raw: &[u8]) -> (&[u8], BodyStale) {
    let stale = match crate::batch::EntityMetadataHeader::parse(raw) {
        Some(header) => BodyStale::for_kind(header.entity_type),
        None => BodyStale::Withdrawn,
    };
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .unwrap_or_default();
    (body, stale)
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
