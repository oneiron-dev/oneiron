//! `impl Vault` — the AUTHORITY_LOG read/write door.
//!
//! The engine-authored put/get doors for signed entries plus the
//! readonly/backfilling fold entry points.

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::batch::BatchOp;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::apply_ops;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::temporal::TimeRange;
use crate::unix_seconds_now;
use crate::vault::entity_id_from_type_index_key;

use super::*;

impl Vault {
    /// Engine-authored write door for signed AUTHORITY_LOG entries.
    ///
    /// The entity id is DERIVED from the entry's content hash (ONE-1604-D1;
    /// never caller-chosen) and returned. Generic public puts for
    /// `ENTITY_TYPE_AUTHORITY_LOG` stay rejected with
    /// `MaintenanceKindNotWritable`; this method validates canonical bytes and
    /// the origin signature before using the internal maintenance path.
    ///
    /// A stored terminal `FederationLifecycle` entry additionally triggers the
    /// ONE-1411 stale-stamp sweep (see below). Fold semantics are untouched:
    /// the sweep only reads the fold this door's own append produced.
    pub fn put_authority_log_entry(
        &self,
        entry: &AuthorityLogEntry,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let ids = self.put_authority_log_entries(&[(entry.clone(), occurred, learned_at)])?;
        let id = ids.into_iter().next().ok_or(Error::EntityNotFound)?;
        // ONE-1411: a terminal federation transition marks the worlds that pact
        // delivered as no longer refreshing. The trigger is a SHAPE test and the
        // sweep is global: it stamps exactly what the FOLD reports terminal, so
        // a fold-REJECTED entry can never justify a stamp of its own (though the
        // sweep it triggers still writes any stamp the fold already justifies,
        // e.g. a world registered late to an already-terminal pact). The write
        // path therefore never duplicates the transition table.
        if is_terminal_federation_lifecycle(entry) {
            crate::federation::apply_federation_stale_stamps(self)?;
        }
        Ok(id)
    }

    /// Appends N AUTHORITY_LOG entries in ONE transaction, all-or-nothing.
    ///
    /// Every id is derived from entry content (ONE-1604-D1), exactly as the
    /// single-entry door does. Encoding, validation, and derivation all happen
    /// BEFORE the write transaction opens, so a bad entry anywhere in the
    /// batch stores nothing at all.
    ///
    /// This is what makes a genesis owner-binding a single ceremony: a host
    /// composes `[genesis, bind]` and either both land or neither does. The
    /// door does NOT require a binding to accompany a genesis — enforcement
    /// lives at the facade, where a rooted vault without an owner binding
    /// fail-closes owner verbs.
    pub fn put_authority_log_entries(
        &self,
        entries: &[(AuthorityLogEntry, TimeRange, u64)],
    ) -> Result<Vec<EntityId>> {
        let mut wtxn = self.store.env.write_txn()?;
        let ids = self.put_authority_log_entries_in_txn(&mut wtxn, entries)?;
        wtxn.commit()?;
        Ok(ids)
    }

    /// [`Self::put_authority_log_entries`] against a CALLER-OWNED write
    /// transaction, for composing an authority append with other writes that
    /// must land atomically with it — and for tests that need to commit an
    /// authority change at a precise instant relative to another thread.
    pub(crate) fn put_authority_log_entries_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entries: &[(AuthorityLogEntry, TimeRange, u64)],
    ) -> Result<Vec<EntityId>> {
        let mut ids = Vec::with_capacity(entries.len());
        let mut ops = Vec::with_capacity(entries.len());
        for (entry, occurred, learned_at) in entries {
            let data = encode_authority_log_entry_body(entry)?;
            crate::authority::validate_authority_log_entry_body_bytes(&data)?;
            let id = authority_log_entity_id(entry)?;
            ids.push(id);
            ops.push(BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_AUTHORITY_LOG,
                occurred: *occurred,
                learned_at: *learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            });
        }
        if ops.is_empty() {
            return Ok(ids);
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(ids)
    }

    /// Reads and decodes one AUTHORITY_LOG entry by entity id.
    pub fn get_authority_log_entry(&self, id: &EntityId) -> Result<Option<AuthorityLogEntry>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_authority_log_entry_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    fn backfill_authority_first_seen_sidecars(&self) -> Result<()> {
        let rtxn = self.store.env.read_txn()?;
        let already_backfilled = self
            .store
            .sync_state
            .get(&rtxn, authority_first_seen_backfill_sync_key())?
            .is_some();
        drop(rtxn);
        if already_backfilled {
            return Ok(());
        }

        self.with_write_txn(|wtxn| {
            if self
                .store
                .sync_state
                .get(wtxn, authority_first_seen_backfill_sync_key())?
                .is_some()
            {
                return Ok(());
            }

            let floor_key = authority_first_seen_clock_sync_key();
            let previous_floor = self
                .store
                .sync_state
                .get(wtxn, floor_key)?
                .and_then(|raw| decode_authority_first_seen_secs(&raw))
                .unwrap_or(0);
            let observed_floor = authority_observation_secs_for_domain(
                self.store.authority_clock_domain,
                previous_floor,
                unix_seconds_now(),
            );
            if observed_floor != previous_floor {
                let encoded = encode_authority_first_seen_secs(observed_floor);
                self.store.sync_state.put(wtxn, floor_key, &encoded)?;
            }

            let mut missing_sidecars = Vec::new();
            for entry in self
                .store
                .type_index
                .prefix_iter(wtxn, &[ENTITY_TYPE_AUTHORITY_LOG])?
            {
                let (key, _) = entry?;
                let id = entity_id_from_type_index_key(&key)?;
                let raw = self
                    .store
                    .entities
                    .get(wtxn, id.as_bytes())?
                    .ok_or(Error::CorruptedIndex("type index row without entity"))?;
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("entity header"))?;
                if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
                    return Err(Error::CorruptedIndex("type index row kind mismatch"));
                }
                let authority_entry =
                    decode_authority_log_entry_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
                let hash = authority_entry_hash(&authority_entry)?;
                let sidecar_key = authority_first_seen_sync_key(&hash);
                if self
                    .store
                    .sync_state
                    .get(wtxn, sidecar_key.as_str())?
                    .is_none()
                {
                    // fix-leg 4: the persisted value is THIS vault's local
                    // observation time, never `header.learned_at`. The header
                    // field is entity metadata written by whichever peer
                    // shipped the row, so trusting it lets a legacy
                    // sidecar-less `EnrollDevice(learned_at = 0)` claim it was
                    // first seen in 1970 — instantly past its veto delay, with
                    // a child `BindActor` on the freshly owner-capable key
                    // folding ACTIVE on arrival. `observed_floor` clamps
                    // FUTURE claims only; the whole past is unclamped, and the
                    // past is the dangerous direction.
                    //
                    // Migrating at the observation time means an
                    // already-imported widen serves its full delay from HERE
                    // rather than from a claim, which delays a legitimate
                    // legacy widen once and never skips one.
                    missing_sidecars.push((
                        sidecar_key,
                        encode_authority_first_seen_secs(observed_floor),
                    ));
                }
            }
            for (sidecar_key, first_seen) in missing_sidecars {
                self.store
                    .sync_state
                    .put(wtxn, sidecar_key.as_str(), &first_seen)?;
            }

            self.store
                .sync_state
                .put(wtxn, authority_first_seen_backfill_sync_key(), &[1])?;
            Ok(())
        })
    }

    /// Folds all stored AUTHORITY_LOG entries into the current authority roster.
    ///
    /// The fold is the authority boundary: replay doors only admit canonical,
    /// origin-signed records; signer ancestry, sequence, quorum, and roster
    /// semantics are recomputed here from the stored log. Software-tier widens
    /// are evaluated against this device's local first-seen timestamps.
    ///
    /// Admitted PEER authority logs (FED-03) are refolded alongside, and their
    /// consent roots enter as gesture evidence only: they never join the local
    /// roster, hold local quorum, or change this vault's id.
    pub fn authority_fold(&self) -> Result<AuthorityFold> {
        self.backfill_authority_first_seen_sidecars()?;
        let rtxn = self.store.env.read_txn()?;
        let mut entries = Vec::new();
        let mut first_seen_at_secs = std::collections::BTreeMap::new();
        let previous_floor = self
            .store
            .sync_state
            .get(&rtxn, authority_first_seen_clock_sync_key())?
            .and_then(|raw| decode_authority_first_seen_secs(&raw))
            .unwrap_or(0);
        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_AUTHORITY_LOG])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
                return Err(Error::CorruptedIndex("type index row kind mismatch"));
            }
            let entry = decode_authority_log_entry_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            let hash = authority_entry_hash(&entry)?;
            if let Some(first_seen) = self
                .store
                .sync_state
                .get(&rtxn, authority_first_seen_sync_key(&hash).as_str())?
                .and_then(|raw| decode_authority_first_seen_secs(&raw))
            {
                first_seen_at_secs.insert(hash, first_seen);
            }
            entries.push(entry);
        }
        let peer_consent_roots =
            crate::federation::admitted_peer_consent_roots_in_txn(self, &rtxn)?;
        drop(rtxn);
        let now_secs = self.with_write_txn(|wtxn| {
            let previous_floor = self
                .store
                .sync_state
                .get(wtxn, authority_first_seen_clock_sync_key())?
                .and_then(|raw| decode_authority_first_seen_secs(&raw))
                .unwrap_or(previous_floor);
            let now_secs = authority_observation_secs_for_domain(
                self.store.authority_clock_domain,
                previous_floor,
                unix_seconds_now(),
            );
            if now_secs != previous_floor {
                let encoded = encode_authority_first_seen_secs(now_secs);
                self.store
                    .sync_state
                    .put(wtxn, authority_first_seen_clock_sync_key(), &encoded)?;
            }
            Ok(now_secs)
        })?;
        Ok(fold_authority_log_with_peer_consent_roots(
            &entries,
            &first_seen_at_secs,
            now_secs,
            &peer_consent_roots,
        ))
    }

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
    /// raised through [`authority_observation_secs_for_domain`]. On the raw
    /// wall clock a forward jump would mature a pending owner enrollment early
    /// and expose an Active human binding INSIDE the veto window, while a jump
    /// backward below the persisted floor would un-apply an elapsed rotation
    /// and resurrect the retired key's binding. The derived value is not
    /// written back — the floor advances only on write paths, and a lagging
    /// floor can delay a widen but never skip the delay.
    ///
    /// The other divergence the full fold hides is a MISSING sidecar, and
    /// omitting it here is not the conservative default it looks like — see
    /// [`Self::readonly_first_seen_for`] for why an omitted sidecar can leave a
    /// retired owner key live, and what this fold does instead. Where that
    /// leaves a delayable widen resting on an UNOBSERVED first-seen time, this
    /// fold refuses with [`AUTHORITY_FIRST_SEEN_INDETERMINATE`] rather than pick
    /// a roster; the refusal clears the moment one write-path fold records the
    /// observation.
    pub(crate) fn authority_fold_readonly_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<AuthorityFold> {
        let mut entries = Vec::new();
        let mut first_seen_at_secs = BTreeMap::new();
        let mut indeterminate = BTreeSet::new();
        let persisted_floor = self
            .store
            .sync_state
            .get(txn, authority_first_seen_clock_sync_key())?
            .and_then(|raw| decode_authority_first_seen_secs(&raw))
            .unwrap_or(0);
        // Read ONCE, before the row scan: the synthesized-first-seen rule below
        // must be the same for every entry in one fold, and this also decides
        // whether an absent sidecar is a pre-migration gap or genuine corruption.
        let backfilled = self
            .store
            .sync_state
            .get(txn, authority_first_seen_backfill_sync_key())?
            .is_some();
        let now_secs = authority_observation_secs_for_domain(
            self.store.authority_clock_domain,
            persisted_floor,
            unix_seconds_now(),
        );
        for row in self
            .store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_AUTHORITY_LOG])?
        {
            let (key, _) = row?;
            let id = entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
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
                self.readonly_first_seen_for(txn, &hash, backfilled, now_secs)?;
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
        let peer_consent_roots = crate::federation::admitted_peer_consent_roots_in_txn(self, txn)?;
        let fold = fold_authority_log_with_peer_consent_roots(
            &entries,
            &first_seen_at_secs,
            now_secs,
            &peer_consent_roots,
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
        &self,
        txn: &heed::RoTxn<'_>,
        hash: &AuthorityEntryHash,
        backfilled: bool,
        now_secs: u64,
    ) -> Result<(u64, bool)> {
        let corrupt = || Error::CorruptedIndex(AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT);
        match self
            .store
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
}
