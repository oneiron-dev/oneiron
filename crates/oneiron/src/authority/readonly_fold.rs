//! One read-snapshot authority evaluator shared by Vault and the batch write door.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::store::Store;
use crate::vault::entity_id_from_type_index_key;
use crate::{
    HostingPrivacyPosture,
    error::{Error, Result},
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn authority_fold_readonly_for_store_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityFold> {
    let mut entries = Vec::new();
    let mut first_seen_at_secs = BTreeMap::new();
    let mut indeterminate = BTreeSet::new();
    let persisted_floor = store
        .sync_state
        .get(txn, authority_first_seen_clock_sync_key())?
        .and_then(|raw| decode_authority_first_seen_secs(&raw))
        .unwrap_or(0);
    // Read ONCE, before the row scan: the synthesized-first-seen rule below
    // must be the same for every entry in one fold, and this also decides
    // whether an absent sidecar is a pre-migration gap or genuine corruption.
    let backfilled = store
        .sync_state
        .get(txn, authority_first_seen_backfill_sync_key())?
        .is_some();
    let now_secs = authority_observation_secs(store, persisted_floor, crate::unix_seconds_now());
    for row in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_AUTHORITY_LOG])?
    {
        let (key, _) = row?;
        let id = entity_id_from_type_index_key(&key)?;
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("type index row without entity"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
            return Err(Error::CorruptedIndex("type index row kind mismatch"));
        }
        let entry = decode_authority_log_entry_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let hash = authority_entry_hash(&entry)?;
        let (first_seen, observed_locally) =
            readonly_first_seen_for(store, txn, &hash, backfilled, now_secs)?;
        if !observed_locally {
            indeterminate.insert(hash);
        }
        first_seen_at_secs.insert(hash, first_seen);
        entries.push(entry);
    }
    // Peer consent roots ride BOTH folds. This one authorizes, and a fold
    // used for authorization must never be weaker OR stronger than the one
    // used for truth: omitting them here would silently reject a lifecycle
    // entry the full fold accepts.
    let peer_consent_roots =
        crate::federation::admitted_peer_consent_roots_for_store_in_txn(store, txn)?;
    let fold = fold_authority_log_for_posture(
        &entries,
        &first_seen_at_secs,
        now_secs,
        &peer_consent_roots,
        posture,
    );
    // An indeterminate row is only a problem where its delay actually
    // decides something. `now_secs` is the maximum-delay assumption, so any
    // affected DELAYABLE widen lands in `pending_widens` — and pending is
    // fail-OPEN for `RotateKey`/`ReRoot`, which revoke as they
    // grant. Refuse there rather than authorize against a roster still
    // holding a key a matured rotation may already have retired. Rows whose
    // first-seen time the fold never consults (every non-delayable op, and
    // widens a veto already killed) are unaffected, so a legacy vault whose
    // log carries no live delayable widen keeps working untouched.
    if fold
        .pending_widens
        .keys()
        .any(|hash| indeterminate.contains(hash))
    {
        return Err(Error::CorruptedIndex(AUTHORITY_FIRST_SEEN_INDETERMINATE));
    }
    Ok(fold)
}

fn readonly_first_seen_for(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    hash: &AuthorityEntryHash,
    backfilled: bool,
    now_secs: u64,
) -> Result<(u64, bool)> {
    let corrupt = || Error::CorruptedIndex(AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT);
    match store
        .sync_state
        .get(txn, authority_first_seen_sync_key(hash).as_str())?
    {
        Some(raw) => decode_authority_first_seen_secs(&raw)
            .ok_or_else(corrupt)
            .map(|secs| (secs, true)),
        None if backfilled => Err(corrupt()),
        None => Ok((now_secs, false)),
    }
}
