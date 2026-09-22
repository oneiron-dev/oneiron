//! One read-snapshot authority evaluator shared by Vault and the batch write door.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::store::Store;
use crate::{
    HostingPrivacyPosture,
    error::{Error, Result},
};
use std::collections::{BTreeMap, BTreeSet};

/// Folds the stored AUTHORITY_LOG inside a CALLER-OWNED read transaction.
///
/// [`Vault::authority_fold`] opens its own transactions — including a WRITE
/// txn for the first-seen clock and the sidecar backfill — so it cannot be
/// called from inside an open transaction under LMDB's single-writer rule.
/// This variant writes nothing at all: no persisted clock write, no
/// backfill, no transaction of its own. It reproduces both write-side
/// effects in its snapshot instead.
///
/// The observation time is deliberately NOT the raw wall clock. Widen
/// maturity is an AUTHORIZATION decision here — the facade's owner-verb
/// gate consumes this fold — so it runs on the same monotonic clock
/// [`Vault::authority_fold`] uses: the persisted floor read through `txn`,
/// raised through [`authority_observation_secs`]. On the raw
/// wall clock a forward jump would mature a pending owner enrollment early
/// and expose an Active human binding INSIDE the veto window, while a jump
/// backward below the persisted floor would un-apply an elapsed rotation
/// and resurrect the retired key's binding. The derived value is not
/// written back — the floor advances only on write paths, and a lagging
/// floor can delay a widen but never skip the delay.
///
/// The other divergence the full fold hides is a MISSING sidecar, and
/// omitting it here is not the conservative default it looks like — see
/// [`readonly_first_seen_for`] for why an omitted sidecar can leave a
/// retired owner key live, and what this fold does instead. Where that
/// leaves a delayable widen resting on an UNOBSERVED first-seen time, this
/// fold refuses with [`AUTHORITY_FIRST_SEEN_INDETERMINATE`] rather than pick
/// a roster; the refusal clears the moment one write-path fold records the
/// observation.
pub(crate) fn authority_fold_readonly_for_store_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityFold> {
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
    let now_secs =
        authority_observation_secs(store, persisted_floor, store.clock.now_recorded_at());
    let entries = authority_log_rows_in_txn(store, txn)?
        .into_iter()
        .map(|(_, body)| decode_authority_log_entry_body(&body))
        .collect::<Result<Vec<_>>>()?;
    for entry in &entries {
        let hash = authority_entry_hash(entry)?;
        let (first_seen, observed_locally) =
            readonly_first_seen_for(store, txn, &hash, backfilled, now_secs)?;
        if !observed_locally {
            indeterminate.insert(hash);
        }
        first_seen_at_secs.insert(hash, first_seen);
    }
    // Peer consent roots ride BOTH folds. This one authorizes, and a fold
    // used for authorization must never be weaker OR stronger than the one
    // used for truth: omitting them here would silently reject a lifecycle
    // entry the full fold accepts.
    let peer_consent_roots =
        crate::federation::admitted_peer_consent_roots_for_store_in_txn(store, txn)?;
    let observations = authority_local_observations_in_txn(store, txn, &entries)?;
    let fold = fold_authority_log_with_local_observations_and_posture(
        &entries,
        &first_seen_at_secs,
        now_secs,
        &peer_consent_roots,
        &observations,
        posture,
    );
    // An indeterminate row is only a problem where its delay actually
    // decides something. `now_secs` is the maximum-delay assumption, so any
    // affected DELAYABLE widen lands in `pending_widens` — and pending is
    // fail-OPEN for `RotateKey`/`RecoveryReboot`, which revoke as they
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

/// First-seen seconds for ONE entry inside a readonly fold, reproducing the
/// one-shot migration's semantics without writing anything.
///
/// Returns `(first_seen_secs, observed_locally)`. `observed_locally` is
/// false when the value is an ASSUMPTION rather than a record of local
/// observation; the caller escalates that to a refusal only where the value
/// actually decided a pending widen.
///
/// Omitting an entry from `first_seen_at_secs` is NOT fail-closed, which is
/// what the naive version got wrong. A sidecar-less delayable widen folds to
/// `eligible_at_secs: None`, which pins it PENDING forever — and "pending"
/// is only conservative for widens that GRANT (EnrollDevice, SetTierFloor).
/// `RotateKey` and `RecoveryReboot` also REVOKE: an un-applied rotation
/// leaves the retired owner key in the roster with its actor binding Active.
/// On a legacy vault whose matured rotation K→K2 never got a sidecar, an
/// attacker still holding K could file a sibling `BindActor(K, …, "human")`
/// parented before the rotation, and this fold would hand them every owner
/// verb — while [`Vault::authority_fold`] (which backfills first) revokes K.
/// A fold used for AUTHORIZATION must not be weaker than the one used for
/// truth.
///
/// Two states, two answers:
///
/// - backfill marker ABSENT — the migration has not run in a write txn yet,
///   so this vault has NO local record of when it first saw the row. The
///   header's `learned_at` is not a substitute: it is peer-written entity
///   metadata, and a legacy `EnrollDevice` shipped with `learned_at = 0`
///   would read as first seen in 1970, i.e. matured before it ever arrived.
///   The answer is `now_secs` — the same value
///   [`Vault::backfill_authority_first_seen_sidecars`] will persist when it
///   next runs, and the maximum remaining delay — flagged indeterminate.
/// - marker PRESENT and the sidecar still missing, or the row present but
///   undecodable under EITHER marker state — the one-shot pass can never
///   regenerate it (it is gated by the marker, and it skips keys that
///   already hold a row), so the entry's delay clock is unrecoverable in
///   place. Refuse the fold with [`AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT`];
///   the facade turns that into an invalid-state suspension of owner verbs
///   rather than authorizing on a fold it cannot compute.
///
/// The assumed value never MATURES anything: it equals the `now_secs` the
/// maturity comparison uses, so `now + delay > now` holds for every positive
/// delay and the widen stays pending until a real observation is recorded.
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

pub(super) fn authority_log_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(crate::EntityId, Vec<u8>)>> {
    let mut rows = Vec::new();
    for row in store.port_entity_ids_by_type(txn, ENTITY_TYPE_AUTHORITY_LOG, None)? {
        let id = row?;
        let raw = store
            .port_entity_record(txn, &id)?
            .map(|row| row.encode())
            .ok_or(Error::CorruptedIndex("type index row without entity"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
            return Err(Error::CorruptedIndex("type index row kind mismatch"));
        }
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        rows.push((id, body.to_vec()));
    }
    Ok(rows)
}
