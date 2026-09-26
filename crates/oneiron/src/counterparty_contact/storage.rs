//! Counterparty contact lookup and party-channel index keys and helpers.

use super::codec::{decode_counterparty_contact_body, normalize_counterparty};
use super::types::CounterpartyContactRecord;
use crate::channel_identity::decode_channel_identity_body;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_COUNTERPARTY_CONTACT};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;
use sha2::Digest;

use sha2::Sha256;

/// Lookup index from (identity ref, normalized counterparty) to the contact
/// entity id. Key: id16 + hash32(sha256).
pub(super) const CONTACT_INDEX: SideTable<(EntityId, [u8; 32]), EntityId, Raw> =
    SideTable::new(&side_table::COUNTERPARTY_CONTACT_INDEX);

/// Deduplicated set of contact refs reachable for a (party, channel class)
/// pair. Key: hash32(sha256).
const PARTY_CHANNEL_INDEX: SideTable<[u8; 32], ContactRefs, Raw> =
    SideTable::new(&side_table::COUNTERPARTY_CONTACT_PARTY_CHANNEL_INDEX);

pub(super) fn counterparty_contact_index_key_parts(
    identity_ref: &EntityId,
    counterparty: &str,
) -> Result<(EntityId, [u8; 32])> {
    let counterparty = normalize_counterparty(counterparty.to_owned())?;
    let digest: [u8; 32] = Sha256::digest(counterparty.as_bytes()).into();
    Ok((*identity_ref, digest))
}

pub(super) fn counterparty_contact_index_key_for_record(
    record: &CounterpartyContactRecord,
) -> Result<(EntityId, [u8; 32])> {
    counterparty_contact_index_key_parts(&record.identity_ref, &record.counterparty)
}

/// The contact id the (identity, counterparty) lookup row names, if any.
pub(crate) fn counterparty_contact_by_index_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: &EntityId,
    counterparty: &str,
) -> Result<Option<EntityId>> {
    CONTACT_INDEX.get(
        store,
        txn,
        &counterparty_contact_index_key_parts(identity_ref, counterparty)?,
    )
}

/// Canonical channel-class normalization for the party-channel index.
///
/// Shared by the index writer, the record-class resolver, and the
/// external-effect gate so a stored class and a queried class can never
/// disagree over case or padding. Mirrors `campaign::claims`'s token rule, the
/// one CA-01's `comm.do_not_contact` matching already uses.
#[must_use]
pub fn normalize_channel_class(channel: &str) -> String {
    channel.trim().to_ascii_lowercase()
}

fn party_channel_digest(party_ref: &str, channel_class: &str) -> Result<[u8; 32]> {
    let party = normalize_counterparty(party_ref.to_owned())?;
    let channel_class = normalize_channel_class(channel_class);
    let mut hasher = Sha256::new();
    hasher.update((party.len() as u64).to_be_bytes());
    hasher.update(party.as_bytes());
    hasher.update(channel_class.as_bytes());
    Ok(hasher.finalize().into())
}

/// Vault-meta key of the `(party_ref, channel_class)` contact index.
///
/// The party is length-prefixed before the class so no `(party, class)` pair
/// can collide with a different split of the same bytes.
pub fn counterparty_contact_party_channel_index_key(
    party_ref: &str,
    channel_class: &str,
) -> Result<Vec<u8>> {
    Ok(PARTY_CHANNEL_INDEX.key_bytes(&party_channel_digest(party_ref, channel_class)?))
}

/// A de-duplicated, sorted set of contact refs, stored as concatenated
/// 16-byte ids — the module's pre-existing byte layout.
struct ContactRefs(Vec<EntityId>);

impl RawValue for ContactRefs {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut sorted: Vec<[u8; ENTITY_ID_LEN]> = self.0.iter().map(|id| *id.as_bytes()).collect();
        sorted.sort_unstable();
        sorted.dedup();
        Ok(sorted.concat())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if !bytes.len().is_multiple_of(ENTITY_ID_LEN) {
            return Err(
                Error::CorruptedIndex("counterparty contact party/channel index value").into(),
            );
        }
        let refs = bytes
            .chunks_exact(ENTITY_ID_LEN)
            .map(|chunk| {
                let raw: [u8; ENTITY_ID_LEN] = chunk.try_into().map_err(|_| {
                    Error::CorruptedIndex("counterparty contact party/channel index value")
                })?;
                EntityId::from_bytes(raw).map_err(|_| {
                    Error::CorruptedIndex("counterparty contact party/channel index value")
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self(refs))
    }
}

/// Appends `contact_ref` to the canonical de-duplicated set for this pair.
pub(super) fn put_counterparty_contact_party_channel_index(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    contact_ref: EntityId,
) -> Result<()> {
    let digest = party_channel_digest(party_ref, channel_class)?;
    let mut refs = match PARTY_CHANNEL_INDEX.get(store, &*wtxn, &digest)? {
        Some(ContactRefs(refs)) => refs,
        None => Vec::new(),
    };
    refs.push(contact_ref);
    PARTY_CHANNEL_INDEX.put(store, wtxn, &digest, &ContactRefs(refs))?;
    Ok(())
}

/// Removes `contact_ref` from the canonical de-duplicated set for this pair,
/// deleting the entry entirely when nothing is left in it.
pub(super) fn remove_counterparty_contact_party_channel_index(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    contact_ref: EntityId,
) -> Result<()> {
    let digest = party_channel_digest(party_ref, channel_class)?;
    let Some(ContactRefs(mut refs)) = PARTY_CHANNEL_INDEX.get(store, &*wtxn, &digest)? else {
        return Ok(());
    };
    refs.retain(|id| *id != contact_ref);
    if refs.is_empty() {
        PARTY_CHANNEL_INDEX.delete(store, wtxn, &digest)?;
    } else {
        PARTY_CHANNEL_INDEX.put(store, wtxn, &digest, &ContactRefs(refs))?;
    }
    Ok(())
}

/// Resolves the channel class a contact record belongs to, or `None` when the
/// record's sending identity does not resolve to a ChannelIdentity row.
///
/// `None` means UNKNOWN, never "no class": see
/// [`counterparty_contact_matches_channel_class`].
pub(super) fn counterparty_contact_channel_class(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &CounterpartyContactRecord,
) -> Result<Option<String>> {
    let Some(raw) = store.port_entity_record(txn, &record.identity_ref)? else {
        return Ok(None);
    };

    if raw.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Ok(None);
    }
    let identity = decode_channel_identity_body(&raw.body)?;
    Ok(Some(normalize_channel_class(&identity.channel)))
}

/// Whether a record participates in the `(party_ref, channel_class)` aggregate.
///
/// A record whose class is UNKNOWN matches EVERY class. This is the same
/// uncertainty rule CA-01 pins in `campaign::claims::do_not_contact_applies`: a
/// reader who cannot prove the suppression is irrelevant must treat it as
/// relevant. Resolving the other way would turn every unresolvable identity
/// into a false negative — the exact failure this index exists to prevent.
pub(crate) fn counterparty_contact_matches_channel_class(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &CounterpartyContactRecord,
    channel_class: &str,
) -> Result<bool> {
    Ok(counterparty_contact_channel_class(store, txn, record)?
        .is_none_or(|stored| stored == normalize_channel_class(channel_class)))
}

/// The contact records the party-channel index names for this party/class pair.
///
/// The index is a CANDIDATE source, never a verdict source: a hit is re-validated
/// against the party, so an entry left behind by a record that later changed
/// identity is filtered rather than mis-attributed. Channel scope is NOT applied
/// here — every candidate source funnels through the single class predicate in
/// `gate::counterparty_contacts_for_send`, so no source can ship a row into the
/// aggregate that skipped it.
pub(crate) fn counterparty_contacts_by_party_channel(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
    channel_class: &str,
) -> Result<Vec<(EntityId, CounterpartyContactRecord)>> {
    let digest = party_channel_digest(party_ref, channel_class)?;
    let Some(ContactRefs(refs)) = PARTY_CHANNEL_INDEX.get(store, txn, &digest)? else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    for id in refs {
        let Some(record) = read_counterparty_contact_in_txn(store, txn, &id)? else {
            return Err(Error::CorruptedIndex(
                "counterparty contact party/channel index entity row",
            ));
        };
        if record.matches_party(party_ref) {
            records.push((id, record));
        }
    }
    Ok(records)
}

/// Every contact record for this party, found by scanning ALL COUNTERPARTY_CONTACT rows.
///
/// Unbounded and mandatory: the party-channel index cannot prove its own
/// completeness at HEAD (rows written before it existed are absent, and so is
/// any row whose identity had no resolvable channel class at write time), and a
/// bounded lookup that missed one opted-out row would answer a false "no".
/// ONE-1752's cutover owns retiring this scan.
pub(crate) fn counterparty_contacts_by_party_full_scan(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
) -> Result<Vec<(EntityId, CounterpartyContactRecord)>> {
    let mut records = Vec::new();
    for entry in store.port_entity_ids_by_type(txn, ENTITY_TYPE_COUNTERPARTY_CONTACT, None)? {
        let id = entry?;
        let Some(record) = read_counterparty_contact_in_txn(store, txn, &id)? else {
            return Err(Error::CorruptedIndex("counterparty contact entity row"));
        };
        if record.matches_party(party_ref) {
            records.push((id, record));
        }
    }
    Ok(records)
}

/// Reads one contact record inside a caller-owned transaction.
pub(crate) fn read_counterparty_contact_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<CounterpartyContactRecord>> {
    let Some(raw) = store.port_entity_record(txn, id)? else {
        return Ok(None);
    };

    if raw.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
        return Err(Error::CorruptedIndex("counterparty contact entity type"));
    }
    decode_counterparty_contact_body(&raw.body).map(Some)
}

pub(crate) fn rebuild_checkpoint_contact_index(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &[u8],
) -> Result<()> {
    let record = decode_counterparty_contact_body(body)?;
    let key = counterparty_contact_index_key_for_record(&record)?;
    if let Some(previous) = CONTACT_INDEX.get(store, txn, &key)?
        && previous != id
    {
        return Err(Error::CorruptedIndex("ambiguous restored contact index"));
    }
    CONTACT_INDEX.put(store, txn, &key, &id)?;
    if let Some(class) = counterparty_contact_channel_class(store, txn, &record)? {
        put_counterparty_contact_party_channel_index(store, txn, &record.counterparty, &class, id)?;
    }
    Ok(())
}
