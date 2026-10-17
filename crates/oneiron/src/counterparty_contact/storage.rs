//! Counterparty contact lookup and party-channel index keys and helpers.

use super::codec::{decode_counterparty_contact_body, normalize_counterparty};
use super::types::{
    CounterpartyContactRecord, PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY,
    PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF,
};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_COUNTERPARTY_CONTACT};
use crate::scan_check::{EngineScan, ScanCount};
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

/// Canonical channel-class normalization for the party-channel index.
///
/// Shared by index writers, the contact/comm gate, campaign compliance, and
/// outbound sender/window handling. Provider-specific email rails are one
/// recipient-facing class, not aliases for connector authorization: grants,
/// transport routing and intent ledgers still use each exact connector key.
#[must_use]
pub fn normalize_channel_class(channel: &str) -> String {
    let channel = channel.trim().to_ascii_lowercase();
    if matches!(
        channel.as_str(),
        "email_resend" | "email_ses" | "email_postmark"
    ) {
        "email".to_owned()
    } else {
        channel
    }
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

/// Removes `contact_ref` from every pair that lists it. A contact's own row
/// cannot name the pair its leg was filed under (see the caller).
pub(super) fn remove_counterparty_contact_from_every_party_channel(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    contact_ref: EntityId,
) -> Result<()> {
    let mut listed = Vec::new();
    for item in PARTY_CHANNEL_INDEX.iter_from(store, &*wtxn, &[])? {
        let (digest, ContactRefs(refs)) = item?;
        if refs.contains(&contact_ref) {
            listed.push((digest, refs));
        }
    }
    for (digest, mut refs) in listed {
        refs.retain(|id| *id != contact_ref);
        if refs.is_empty() {
            PARTY_CHANNEL_INDEX.delete(store, wtxn, &digest)?;
        } else {
            PARTY_CHANNEL_INDEX.put(store, wtxn, &digest, &ContactRefs(refs))?;
        }
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
    identity_channel_class(store, txn, &record.identity_ref)
}

/// The class the identity's `channel_identity.channel` head names (OF-272);
/// an identity with no heads is UNKNOWN.
fn identity_channel_class(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: &EntityId,
) -> Result<Option<String>> {
    Ok(
        crate::channel_identity::channel_identity_facts_in_txn(store, txn, identity_ref)?
            .map(|facts| normalize_channel_class(&facts.channel)),
    )
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
/// here. The gate reads contact claims now (OF-272); this row reader stays for
/// the index's own checks.
#[cfg(test)]
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

/// Whether the `counterparty_contact.*` claims name a contact of `party_ref`
/// on `channel_class`, or on a class its identity does not resolve to: UNKNOWN
/// matches every class, as above.
///
/// Read from the claims, the contact's truth, and not from the type-132 rows:
/// a supported cache drop removes a row and both its index legs, and a row
/// reader would lose a contact a party-wide opt-out still covers (F06 R2-F5).
/// Every lifecycle counts, so the read holds more, never less. It walks every
/// `counterparty_contact.counterparty` posting, under the scan-check door.
pub(crate) fn party_has_contact_on_class_in_claims_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
    channel_class: &str,
) -> Result<bool> {
    const PAGE: usize = 256;
    let party_ref = party_ref.trim();
    let channel_class = normalize_channel_class(channel_class);
    let mut count = ScanCount::start(store, txn, EngineScan::PartyContactClaims, &[])?;
    let mut after = None;
    let found = 'pages: loop {
        let page = crate::claim::claim_ids_for_predicate_page_in_txn(
            store,
            txn,
            PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY,
            after,
            PAGE,
        )?;
        count.rows(page.len());
        for claim_id in &page {
            let Some(body) = claim_body_in_txn(store, txn, claim_id)? else {
                continue;
            };
            if body.predicate != PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY
                || body.value.as_str() != Some(party_ref)
            {
                continue;
            }
            let ClaimSubject::Entity(contact_id) = body.subject else {
                continue;
            };
            if contact_claims_match_class(store, txn, &contact_id, &channel_class)? {
                break 'pages true;
            }
        }
        if page.len() < PAGE {
            break false;
        }
        after = page.last().copied();
    };
    count.defer(store);
    Ok(found)
}

/// Every contact of `party_ref` that a send on `channel_class` reaches, each
/// rebuilt from its live `counterparty_contact.*` heads: the external-effect
/// gate's contact facts (OF-272, ARCH-0057 §3). First-touch, status and the
/// contact's own opt-out come from claims, never from type-132 rows or their
/// indexes; a cache drop removes nothing the gate reads. A contact is found
/// through its live `counterparty_contact.counterparty` head, ordered by id so
/// the gate's fold is deterministic, and scoped by the class rule above:
/// UNKNOWN matches every class.
pub(crate) fn counterparty_contacts_for_send_in_claims_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
    channel_class: &str,
) -> Result<Vec<CounterpartyContactRecord>> {
    let contacts = contact_ids_with_live_head_in_txn(
        store,
        txn,
        PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY,
        party_ref.trim(),
    )?;
    let mut records = Vec::with_capacity(contacts.len());
    for contact in contacts {
        let Some(record) = super::lifecycle::counterparty_contact_record_from_store_claims_in_txn(
            store, txn, &contact,
        )?
        else {
            continue;
        };
        if counterparty_contact_matches_channel_class(store, txn, &record, channel_class)? {
            records.push(record);
        }
    }
    Ok(records)
}

/// Every contact whose live `predicate` head holds exactly `value`, in id
/// order: the claim-posting lookup behind the contact read doors (OF-272). It
/// walks the predicate's whole posting list under the scan-check door, so a
/// contact whose type-132 row a cache drop removed is still found, and one a
/// hard delete or soft erase marked is skipped. A batch delete leaves the
/// postings but tears the `claim_of` edges, so the readers find no heads.
pub(super) fn contact_ids_with_live_head_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    predicate: &str,
    value: &str,
) -> Result<Vec<EntityId>> {
    const PAGE: usize = 256;
    let mut contacts = std::collections::BTreeSet::new();
    let mut count = ScanCount::start(store, txn, EngineScan::PartyContactClaims, &[])?;
    let mut after = None;
    loop {
        let page =
            crate::claim::claim_ids_for_predicate_page_in_txn(store, txn, predicate, after, PAGE)?;
        count.rows(page.len());
        for claim_id in &page {
            let Some(body) = claim_body_in_txn(store, txn, claim_id)? else {
                continue;
            };
            if body.predicate != predicate
                || body.value.as_str() != Some(value)
                || body.lifecycle != crate::claim::ClaimLifecycleStatus::Active
                || body.stale
            {
                continue;
            }
            if let ClaimSubject::Entity(contact_id) = body.subject {
                contacts.insert(*contact_id.as_bytes());
            }
        }
        if page.len() < PAGE {
            break;
        }
        after = page.last().copied();
    }
    count.defer(store);
    let mut ids = Vec::with_capacity(contacts.len());
    for contact in contacts {
        let id = EntityId::from_bytes(contact)?;
        if !contact_deleted_in_txn(store, txn, &id)? {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// Whether one of the contact's `identity_ref` claims names an identity on
/// `channel_class` or on no resolvable class. A contact with no such claim is
/// UNKNOWN too.
fn contact_claims_match_class(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    contact_id: &EntityId,
    channel_class: &str,
) -> Result<bool> {
    let mut any_identity = false;
    for entry in store.port_edges(
        txn,
        contact_id,
        EdgeDirection::In,
        Some(EdgeKind::ClaimOf),
        None,
    )? {
        let Some(body) = claim_body_in_txn(store, txn, &entry?.target)? else {
            continue;
        };
        if body.predicate != PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF {
            continue;
        }
        any_identity = true;
        let class = match body.value.as_str().map(EntityId::from_hex) {
            Some(Ok(identity_ref)) => identity_channel_class(store, txn, &identity_ref)?,
            _ => None,
        };
        if class.is_none_or(|class| class == channel_class) {
            return Ok(true);
        }
    }
    Ok(!any_identity)
}

/// Whether `contact_id` was hard-deleted or soft-erased, by the deletion state
/// those doors record (OF-272). A supported cache drop records none: it
/// removes the row and keeps the contact, so row presence can never be the
/// deletion question.
pub(super) fn contact_deleted_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    contact_id: &EntityId,
) -> Result<bool> {
    Ok(crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, contact_id)?.deleted)
}

fn claim_body_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ClaimBody>> {
    let Some(raw) = store.port_entity_record(txn, id)? else {
        return Ok(None);
    };
    if raw.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    crate::claim::decode_claim_body(&raw.body, true).map(Some)
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
