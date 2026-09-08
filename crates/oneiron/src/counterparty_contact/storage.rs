//! Counterparty contact lookup and party-channel index keys and helpers.

use super::codec::{decode_counterparty_contact_body, normalize_counterparty};
use super::types::CounterpartyContactRecord;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity::decode_channel_identity_body;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_COUNTERPARTY_CONTACT};
use crate::store::Store;
use crate::vault::entity_id_from_type_index_key;
use sha2::{Digest, Sha256};

const COUNTERPARTY_CONTACT_INDEX_KEY_PREFIX: &[u8] = b"counterparty_contact.index.v1:";

/// Vault-meta prefix of the identity-INDEPENDENT `(party_ref, channel_class)`
/// contact index (ONE-1868 / ARCH-0057 §3).
///
/// Index only: no entity, no type byte, no second copy of opt-out truth. Its
/// value is the canonical de-duplicated set of every contact ref recorded for
/// the pair, because one party can be reachable on one channel class through
/// several sending identities and the send-time aggregate is RESTRICTIVE.
pub const COUNTERPARTY_CONTACT_PARTY_CHANNEL_INDEX_PREFIX: &[u8] =
    b"counterparty.contact.party_channel.v1:";

pub(crate) fn counterparty_contact_index_key(
    identity_ref: &EntityId,
    counterparty: &str,
) -> Result<Vec<u8>> {
    let counterparty = normalize_counterparty(counterparty.to_owned())?;
    let counterparty_hash = Sha256::digest(counterparty.as_bytes());
    let mut key = Vec::with_capacity(
        COUNTERPARTY_CONTACT_INDEX_KEY_PREFIX.len() + ENTITY_ID_LEN + counterparty_hash.len(),
    );
    key.extend_from_slice(COUNTERPARTY_CONTACT_INDEX_KEY_PREFIX);
    key.extend_from_slice(identity_ref.as_bytes());
    key.extend_from_slice(&counterparty_hash);
    Ok(key)
}

pub(crate) fn counterparty_contact_index_key_for_record(
    record: &CounterpartyContactRecord,
) -> Result<Vec<u8>> {
    counterparty_contact_index_key(&record.identity_ref, &record.counterparty)
}

pub(crate) fn encode_counterparty_contact_index_value(id: &EntityId) -> [u8; ENTITY_ID_LEN] {
    *id.as_bytes()
}

pub(crate) fn decode_counterparty_contact_index_value(raw: &[u8]) -> Result<EntityId> {
    if raw.len() != ENTITY_ID_LEN {
        return Err(Error::CorruptedIndex(
            "counterparty contact lookup index value",
        ));
    }
    EntityId::from_bytes(
        raw.try_into()
            .map_err(|_| Error::CorruptedIndex("counterparty contact lookup index value"))?,
    )
    .map_err(|_| Error::CorruptedIndex("counterparty contact lookup index value"))
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

/// Vault-meta key of the `(party_ref, channel_class)` contact index.
///
/// The party is length-prefixed before the class so no `(party, class)` pair
/// can collide with a different split of the same bytes.
pub fn counterparty_contact_party_channel_index_key(
    party_ref: &str,
    channel_class: &str,
) -> Result<Vec<u8>> {
    let party = normalize_counterparty(party_ref.to_owned())?;
    let channel_class = normalize_channel_class(channel_class);
    let mut hasher = Sha256::new();
    hasher.update((party.len() as u64).to_be_bytes());
    hasher.update(party.as_bytes());
    hasher.update(channel_class.as_bytes());
    let digest = hasher.finalize();
    let mut key =
        Vec::with_capacity(COUNTERPARTY_CONTACT_PARTY_CHANNEL_INDEX_PREFIX.len() + digest.len());
    key.extend_from_slice(COUNTERPARTY_CONTACT_PARTY_CHANNEL_INDEX_PREFIX);
    key.extend_from_slice(&digest);
    Ok(key)
}

fn encode_party_channel_index_value(refs: &[EntityId]) -> Vec<u8> {
    let mut sorted: Vec<[u8; ENTITY_ID_LEN]> = refs.iter().map(|id| *id.as_bytes()).collect();
    sorted.sort_unstable();
    sorted.dedup();
    sorted.concat()
}

fn decode_party_channel_index_value(raw: &[u8]) -> Result<Vec<EntityId>> {
    if !raw.len().is_multiple_of(ENTITY_ID_LEN) {
        return Err(Error::CorruptedIndex(
            "counterparty contact party/channel index value",
        ));
    }
    raw.chunks_exact(ENTITY_ID_LEN)
        .map(|chunk| {
            let bytes: [u8; ENTITY_ID_LEN] = chunk.try_into().map_err(|_| {
                Error::CorruptedIndex("counterparty contact party/channel index value")
            })?;
            EntityId::from_bytes(bytes).map_err(|_| {
                Error::CorruptedIndex("counterparty contact party/channel index value")
            })
        })
        .collect()
}

/// Appends `contact_ref` to the canonical de-duplicated set for this pair.
pub(crate) fn put_counterparty_contact_party_channel_index(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    contact_ref: EntityId,
) -> Result<()> {
    let key = counterparty_contact_party_channel_index_key(party_ref, channel_class)?;
    let mut refs = match store.vault_meta.get(&*wtxn, &key)? {
        Some(raw) => decode_party_channel_index_value(&raw)?,
        None => Vec::new(),
    };
    refs.push(contact_ref);
    let value = encode_party_channel_index_value(&refs);
    store.vault_meta.put(wtxn, &key, &value)?;
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
    let key = counterparty_contact_party_channel_index_key(party_ref, channel_class)?;
    let Some(raw) = store.vault_meta.get(&*wtxn, &key)? else {
        return Ok(());
    };
    let mut refs = decode_party_channel_index_value(&raw)?;
    refs.retain(|id| *id != contact_ref);
    if refs.is_empty() {
        store.vault_meta.delete(wtxn, &key)?;
    } else {
        let value = encode_party_channel_index_value(&refs);
        store.vault_meta.put(wtxn, &key, &value)?;
    }
    Ok(())
}

/// Resolves the channel class a contact record belongs to, or `None` when the
/// record's sending identity does not resolve to a ChannelIdentity row.
///
/// `None` means UNKNOWN, never "no class": see
/// [`counterparty_contact_matches_channel_class`].
pub(crate) fn counterparty_contact_channel_class(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &CounterpartyContactRecord,
) -> Result<Option<String>> {
    let Some(raw) = store.entities.get(txn, record.identity_ref.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Ok(None);
    }
    let identity = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
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
    let key = counterparty_contact_party_channel_index_key(party_ref, channel_class)?;
    let Some(raw) = store.vault_meta.get(txn, &key)? else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    for id in decode_party_channel_index_value(&raw)? {
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
    for entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_COUNTERPARTY_CONTACT])?
    {
        let (key, _) = entry?;
        let id = entity_id_from_type_index_key(&key)?;
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
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
        return Err(Error::CorruptedIndex("counterparty contact entity type"));
    }
    decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}
