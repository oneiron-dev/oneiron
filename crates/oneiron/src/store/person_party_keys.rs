//! The PERSON party-key index (L6-22, ARCH-0057 H174): each PERSON whose
//! synced body carries a `party_key`, under that key.
//!
//! Each replica derives it from the PERSON bodies it holds, in the
//! transaction that writes or removes the body, so it is never synced and
//! never imaged. It is a prefilter: the do-not-contact scan re-reads every
//! PERSON it names, so a row a removal left behind never adds a subject.
//! Only a whole rebuild marks it complete; until one has committed, the scan
//! reads every PERSON, as it did before the index.

use std::collections::BTreeSet;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::side_table::{self, Raw, SideTable};
use crate::store::{ManifestDbs, Store};
use crate::write_envelope::communication::KEY_PARTY_KEY;

/// Key `(sha256(party_key), person)`; the value is an empty presence marker.
const PERSON_PARTY_KEY: SideTable<([u8; 32], EntityId), (), Raw> =
    SideTable::new(&side_table::PERSON_PARTY_KEY_INDEX);

/// `Some(INDEX_VERSION)` once a whole rebuild of the index has committed.
const PERSON_PARTY_KEY_STATE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::PERSON_PARTY_KEY_INDEX_STATE);

const INDEX_VERSION: u64 = 1;

fn party_key_digest(party_key: &str) -> [u8; 32] {
    Sha256::digest(party_key.as_bytes()).into()
}

/// The party keys a PERSON body carries: the value of each `party_key`
/// entry of its top-level map that is a string, exactly as stored (a map
/// may repeat the entry). A body that does not decode to a map carries
/// none. The index and the do-not-contact scan both read keys through this.
pub(crate) fn person_body_party_keys(body: &[u8]) -> BTreeSet<String> {
    let mut cursor = std::io::Cursor::new(body);
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return BTreeSet::new();
    };
    entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(KEY_PARTY_KEY))
        .filter_map(|(_, value)| value.as_str().map(str::to_owned))
        .collect()
}

/// Keeps the index in the transaction that writes or removes one entity
/// row: drops the keys the stored PERSON row carries, then adds the keys
/// `replacement` carries when it is a PERSON body. `None` is a removal.
/// Runs beside `reindex_identity_hints`, before the row changes; a put of
/// another type reads nothing.
pub(crate) fn reindex_person_party_keys(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    replacement: Option<(u8, &[u8])>,
) -> Result<()> {
    if replacement.is_some_and(|(kind, _)| kind != ENTITY_TYPE_PERSON) {
        return Ok(());
    }
    if let Some(raw) = EntityStoreRead::port_entity_raw_wiped(store, txn, id)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
        && header.entity_type == ENTITY_TYPE_PERSON
    {
        for party_key in person_body_party_keys(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]) {
            PERSON_PARTY_KEY.delete(store, txn, &(party_key_digest(&party_key), *id))?;
        }
    }
    if let Some((_, body)) = replacement {
        for party_key in person_body_party_keys(body) {
            PERSON_PARTY_KEY.put(store, txn, &(party_key_digest(&party_key), *id), &())?;
        }
    }
    Ok(())
}

fn index_complete_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> bool {
    matches!(
        PERSON_PARTY_KEY_STATE.get(store, txn, &()),
        Ok(Some(INDEX_VERSION))
    )
}

/// The PERSONs the index names under `party_key`, in id order. `None` when
/// no whole rebuild has committed or the index does not read: the caller
/// then reads every PERSON. A name is a candidate only; the caller re-reads
/// its row.
pub(crate) fn person_party_key_candidates_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_key: &str,
) -> Option<Vec<EntityId>> {
    if !index_complete_in_txn(store, txn) {
        return None;
    }
    let digest = party_key_digest(party_key);
    let rows = PERSON_PARTY_KEY.scan_from(store, txn, &digest).ok()?;
    Some(rows.into_iter().map(|((_, person), ())| person).collect())
}

/// Rebuilds the index from every PERSON row when no whole rebuild has
/// committed, or always with `force`, in one write transaction (a crash
/// leaves nothing or everything). Runs at writable open and after a
/// checkpoint restore (`force`), whose rows came back without a put.
pub(crate) fn backfill_person_party_key_index(vault: &Vault, force: bool) -> Result<()> {
    // At open (`force` false) a failed rebuild of this derived index never
    // refuses the open: the flag stays unset and the scan keeps reading every
    // PERSON. The restore rebuild propagates its errors like its siblings.
    match rebuild_person_party_key_index(&vault.store, force) {
        Err(error) if !force => {
            tracing::warn!(
                %error,
                "person party-key index rebuild failed; the do-not-contact scan keeps reading every PERSON"
            );
            Ok(())
        }
        other => other,
    }
}

fn rebuild_person_party_key_index(store: &Store, force: bool) -> Result<()> {
    let mut wtxn = store.env.write_txn()?;
    if !force && index_complete_in_txn(store, &wtxn) {
        return Ok(());
    }
    let mut rows = Vec::new();
    for entry in store.port_entity_ids_by_type(&wtxn, ENTITY_TYPE_PERSON, None)? {
        let id = entry?;
        let Some(record) = store.port_entity_record(&wtxn, &id)? else {
            continue;
        };
        if record.entity_type != ENTITY_TYPE_PERSON {
            continue;
        }
        for party_key in person_body_party_keys(&record.body) {
            rows.push((party_key_digest(&party_key), id));
        }
    }
    PERSON_PARTY_KEY.delete_from(store, &mut wtxn, &[])?;
    for key in &rows {
        PERSON_PARTY_KEY.put(store, &mut wtxn, key, &())?;
    }
    PERSON_PARTY_KEY_STATE.put(store, &mut wtxn, &(), &INDEX_VERSION)?;
    wtxn.commit()?;
    Ok(())
}

/// Test door (`test_doors::do_not_contact_subject_reads`): drops the whole
/// index and its flag, as a vault file older than the index holds neither.
#[cfg(oneiron_test_support)]
pub(crate) fn forget_person_party_key_index(vault: &Vault) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    PERSON_PARTY_KEY.delete_from(&vault.store, &mut wtxn, &[])?;
    PERSON_PARTY_KEY_STATE.delete(&vault.store, &mut wtxn, &())?;
    wtxn.commit()?;
    Ok(())
}
