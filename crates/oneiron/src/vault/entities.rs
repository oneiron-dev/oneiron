//! Vault entity, vector, short-id and type-index reads and writes.

use super::Vault;
use crate::batch::{
    ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, encode_short_id_forward_key,
    parse_short_id_value,
};
use crate::deletion::{HydratedShortIdDeletion, HydratedShortIdDeletionSource};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::pipeline::{RetrievalWithTelemetry, ScoredEntity};
use crate::store::{RetrievalSignal, ShortIdAliasTarget, Store};
use crate::temporal::TimeRange;
use crate::{hnsw, le_bytes_to_f32_vec, unix_seconds_now};
use std::time::Instant;

/// Cap for `entities_by_type` to prevent unbounded allocation on large indexes.
pub(crate) const MAX_TYPE_QUERY_RESULTS: usize = 100_000;

/// Cap for `entities_in_learned_range` to prevent unbounded allocation on
/// wide time-range queries. Distinct from `MAX_TYPE_QUERY_RESULTS` so the two
/// APIs can be tuned independently.
pub(super) const MAX_LEARNED_RANGE_RESULTS: usize = 100_000;

pub(crate) fn entity_id_from_type_index_key(key: &[u8]) -> Result<EntityId> {
    require_key_len(key, 17, "type index key")?;
    EntityId::from_bytes(
        key[1..17]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("type index key"))?,
    )
    .map_err(|_| Error::CorruptedIndex("type index key"))
}

/// Result of resolving a context-pack short reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydratedShortId {
    /// Entity id referenced by the short-id row.
    pub id: EntityId,
    /// Numeric entity type from the entity header, or zero for a dangling row.
    pub entity_type: u8,
    /// Entity learned-at timestamp from the header, or zero for a dangling row.
    pub learned_at: u64,
    /// Deletion metadata when the short-id row resolves to deleted state.
    pub deletion: Option<HydratedShortIdDeletion>,
    /// Entity body bytes. `None` means a deleted shell or dangling row.
    pub body: Option<Vec<u8>>,
}

/// What one entity id resolves to inside ONE transaction.
///
/// "The row parses" and "the entity is live" are DIFFERENT questions: the
/// ARCH-0038 soft delete keeps the 25-byte metadata header of the entity it
/// erases (`deletion/erase.rs`), so a deleted shell still parses and still
/// carries its original entity-type byte. This enum is the one shared answer
/// for callers that must not confuse the two — the GATE-12 evidence resolver
/// and the Free-lane admission-record reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LiveEntityRow {
    /// No row exists under the id.
    Absent,
    /// A LIVE entity: a body-bearing row, or a header-only row with NO
    /// deletion metadata (a live zero-byte payload).
    Live {
        /// Entity-type byte read off the row's metadata header.
        entity_type: u8,
        /// The row's body bytes; empty for a live zero-byte payload.
        body: Vec<u8>,
    },
    /// A header-only row carrying pending or published deletion metadata: the
    /// soft-delete shell. Never evidence, never a reusable record.
    DeletedShell,
}

/// Resolves `id` to its [`LiveEntityRow`] through the CALLER'S transaction.
///
/// Transaction-composable on purpose, in both directions: a row written
/// earlier in the same write transaction (the miner's mined-evidence record,
/// `edit_distance/miner.rs`) is visible here, and the deletion metadata is
/// read through that same transaction, so the `pt:` pending tombstone
/// `deletion/delete.rs` commits BESIDE the shell scrub is visible too.
/// Opening a fresh read transaction would lose both.
///
/// Fails CLOSED: an entity-row read error, an unparseable header, or a
/// deletion-metadata read/parse error is an `Err`, never a live answer. The
/// shell rule is the canonical [`Vault::is_deleted_shell`] one — header-only
/// PLUS deletion metadata — so a live zero-byte payload stays live.
pub(crate) fn live_entity_row_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<LiveEntityRow> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(LiveEntityRow::Absent);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if store
        .sync_state
        .get(txn, crate::deletion::archive_tombstone_key(id).as_str())?
        .is_some()
        || (raw.len() == ENTITY_METADATA_HEADER_LEN
            && store.entity_deletion_present_in_txn(txn, id, header.learned_at)?)
    {
        return Ok(LiveEntityRow::DeletedShell);
    }
    Ok(LiveEntityRow::Live {
        entity_type: header.entity_type,
        body: raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
    })
}

impl LiveEntityRow {
    /// True only for a live entity row.
    pub(crate) const fn is_live(&self) -> bool {
        matches!(self, Self::Live { .. })
    }
}

pub(crate) fn require_key_len(key: &[u8], expected: usize, context: &'static str) -> Result<()> {
    if key.len() != expected {
        return Err(Error::CorruptedIndex(context));
    }
    Ok(())
}

impl Vault {
    // NOTE (ONE-1133): the bare non-txn `purge_entity_active_store` wrapper
    // was removed — both sync replay surfaces now route through the
    // reason-aware `apply_replayed_tombstone`, and a bare purge entry point
    // would be an invitation to bypass the ARCH-0038 reason semantics.

    // -----------------------------------------------------------------
    // ARCH-0050 R6 L2 code-memory doors (ONE-1608).
    //
    // Every wrapper here opens ONE transaction, delegates to the internal
    // `crate::code_memory` implementation, and commits exactly once on
    // success. None exposes `Store`, `RoTxn`, or `RwTxn`; the public
    // contract suite reaches only these methods.
    // -----------------------------------------------------------------

    // Read/write/list helpers intentionally remain behind `feature = "sync"`
    // instead of `cfg(test)` because the sync bridge regression suite is an
    // integration test crate. Production bridge code still uses direct
    // transactional `sync_state` access when multiple keys must update
    // atomically.

    // ─── Tree Query API ───────────────────────────────────────

    /// Stores an entity blob.
    pub fn put_entity(
        &self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Result<()> {
        self.batch()
            .put(id, entity_type, occurred, learned_at, data)
            .commit()
    }

    /// Retrieves an entity blob by ID.
    ///
    /// SECRET_CUSTODY (byte 77) is denied: the custody body carries the secret
    /// value in the clear, and the ONLY sanctioned value read is the bound door
    /// `Vault::get_secret_value_in_txn`. The value-less projection is
    /// [`Vault::get_secret_metadata`].
    pub fn get(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        let value = self.store.entities.get(&rtxn, id.as_bytes())?;
        let Some(bytes) = value else {
            return Ok(None);
        };

        let Some(header) = EntityMetadataHeader::parse(&bytes) else {
            return Err(Error::CorruptedIndex("entity header"));
        };
        if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
            return Err(crate::secret_custody::reject_secret_custody_byte());
        }

        if self.archive_tombstone_in_txn(&rtxn, id)?.is_some() {
            return Ok(None);
        }
        Ok(Some(bytes[ENTITY_METADATA_HEADER_LEN..].to_vec()))
    }

    pub(crate) fn read_entity_header(&self, id: &EntityId) -> Result<Option<EntityMetadataHeader>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity metadata"))
            .map(Some)
    }

    /// Stores a vector for an entity.
    pub fn put_vector(&self, id: &EntityId, vector: &[f32]) -> Result<()> {
        self.batch().vector(id, vector).commit()
    }

    /// Retrieves a vector for an entity.
    pub fn get_vector(&self, id: &EntityId) -> Result<Option<Vec<f32>>> {
        let rtxn = self.store.env.read_txn()?;
        if crate::vault_cleanup::is_archived_in_txn(&self.store, &rtxn, id)? {
            return Ok(None);
        }
        let Some(bytes) = self.store.vectors.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };

        let vector = le_bytes_to_f32_vec(&bytes, self.config.dimensions)?;
        if vector.len() != self.config.dimensions {
            // Persisted-data corruption — the LMDB row decoded to a vector
            // whose length does not match the configured dimensionality.
            // Distinct from `DimensionMismatch`, which is reserved for
            // caller input validation in `search_vector` / `index_vector`.
            return Err(Error::CorruptedIndex("vector value"));
        }

        Ok(Some(vector))
    }

    /// Searches nearest neighbors by cosine similarity using the HNSW index.
    pub fn search_vector(&self, query: &[f32], limit: usize) -> Result<Vec<ScoredEntity>> {
        Ok(self.search_vector_with_telemetry(query, limit)?.value)
    }

    /// Searches nearest neighbors by cosine similarity and returns the
    /// retrieval telemetry run id when the best-effort telemetry row was
    /// persisted.
    pub fn search_vector_with_telemetry(
        &self,
        query: &[f32],
        limit: usize,
    ) -> Result<RetrievalWithTelemetry<Vec<ScoredEntity>>> {
        // EMB-2: a `fast_dims`-length query is a first-class prefix query.
        if query.len() != self.config.dimensions
            && self.config.fast_dims.map(usize::from) != Some(query.len())
        {
            return Err(Error::DimensionMismatch {
                expected: self.config.dimensions,
                got: query.len(),
            });
        }
        if let Some(error) = Error::invalid_vector_component(query) {
            return Err(error);
        }

        let started_at = unix_seconds_now();
        let started = Instant::now();
        let results = {
            let rtxn = self.store.env.read_txn()?;
            // The direct vault path stays the exact-quality path for
            // full-length queries; the skip-rescore hot lane is a pipeline
            // feature (a `fast_dims`-length query is inherently prefix-only
            // on every path — no full query exists to rescore).
            hnsw::hnsw_search(
                &self.store,
                &self.config,
                &rtxn,
                query,
                limit,
                /* skip_rescore = */ false,
            )?
        };
        let run_id = self.record_vault_search_retrieval_run(
            RetrievalSignal::Vector,
            started_at,
            started,
            &results,
            limit,
        );
        Ok(RetrievalWithTelemetry {
            retrieval_quality: crate::retrieval_quality::classify_retrieval_quality(
                &crate::retrieval_quality::RetrievalDiagnostics {
                    attempted: vec![RetrievalSignal::Vector],
                    succeeded: vec![RetrievalSignal::Vector],
                    ..Default::default()
                },
            ),
            value: results,
            run_id,
        })
    }

    /// Returns the raw entity blob (header + data) for an entity.
    ///
    /// Unlike `get()` which strips the header, this returns the full LMDB
    /// value. SECRET_CUSTODY (byte 77) is denied for the same reason `get()`
    /// denies it: the body carries the secret value in the clear.
    pub fn get_raw(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let Some(bytes) = self.get_raw_unsealed(id)? else {
            return Ok(None);
        };
        if EntityMetadataHeader::parse(&bytes)
            .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY)
        {
            return Err(crate::secret_custody::reject_secret_custody_byte());
        }
        Ok(Some(bytes))
    }

    /// Raw entity bytes WITHOUT the custody seal.
    ///
    /// Crate-internal, for the passes whose whole job is to read the type byte
    /// and then refuse, skip, or scrub a custody row (`sync::window`'s mirror,
    /// scrub and rematerialization passes). Sealing this reader would make
    /// those passes fail closed on the very row they exist to remove, and
    /// would turn one custody carrier into a wedged window. `get_raw_in` is
    /// unsealed for the same reason. Everything outside those passes uses the
    /// sealed public [`Vault::get_raw`].
    pub(crate) fn get_raw_unsealed(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        self.get_raw_in(&rtxn, id)
    }

    pub(crate) fn get_raw_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .store
            .entities
            .get(rtxn, id.as_bytes())?
            .map(|bytes| bytes.to_vec()))
    }

    /// Installs `legacy_id` as a one-hop alias for `target`'s current canonical
    /// short-id row (ONE-1930).
    ///
    /// The forward key is read from the target's own `short_ids_reverse` row
    /// rather than taken from the caller, so an alias can only ever be minted
    /// against a short id that actually exists. `EntityNotFound` when the
    /// target has no short id yet.
    pub fn alias_short_id_to_entity(&self, legacy_id: &str, target: &EntityId) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let forward_key = self
            .store
            .short_ids_reverse
            .get(&wtxn, target.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec();
        self.store.insert_short_id_alias(
            &mut wtxn,
            legacy_id,
            &ShortIdAliasTarget::EntityForwardKey(forward_key),
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Installs `legacy_id` as a one-hop alias for a vault identity.
    ///
    /// `vtN` is a presentation slug; the durable identity is the 32-byte
    /// [`crate::authority::AuthorityVaultId`] it resolves to.
    pub fn alias_short_id_to_vault(
        &self,
        legacy_id: &str,
        vault_id: crate::authority::AuthorityVaultId,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        self.store.insert_short_id_alias(
            &mut wtxn,
            legacy_id,
            &ShortIdAliasTarget::Vault(vault_id),
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Reads the alias row a retired presentation id resolves through, if any.
    pub fn short_id_alias(&self, legacy_id: &str) -> Result<Option<ShortIdAliasTarget>> {
        let rtxn = self.store.env.read_txn()?;
        self.store.resolve_short_id_alias(&rtxn, legacy_id)
    }

    /// Resolves a context-pack short reference to a live or soft-deleted entity.
    ///
    /// The caller supplies the parsed short id and one-byte content hash from
    /// the public `short_id:hash` form. `Ok(None)` means no short-id row exists.
    /// `Ok(Some(result))` with `result.body == None` means the short id resolves
    /// to a deleted shell or dangling row; a live entity returns its body bytes.
    ///
    /// A canonical miss falls back to ONE alias hop (ONE-1930), which is how a
    /// retired presentation id keeps resolving after its kind's prefix moves.
    /// A live forward row always wins, so an alias can never shadow an entity.
    pub fn hydrate_short_id(
        &self,
        short_id: &str,
        content_hash: u8,
    ) -> Result<Option<HydratedShortId>> {
        let rtxn = self.store.env.read_txn()?;
        let forward_key = encode_short_id_forward_key(short_id, content_hash);
        let raw_id = match self.store.short_ids.get(&rtxn, &forward_key)? {
            Some(raw_id) => raw_id.to_vec(),
            None => {
                let Some(ShortIdAliasTarget::EntityForwardKey(canonical_key)) =
                    self.store.resolve_short_id_alias(&rtxn, short_id)?
                else {
                    // No alias, or one naming a vault — neither resolves to an
                    // entity here.
                    return Ok(None);
                };
                // An alias relocates a NAME; it does not waive the content-hash
                // check that makes a short ref a versioned reference.
                let (_, target_hash) = parse_short_id_value(&canonical_key)?;
                if target_hash != content_hash {
                    return Ok(None);
                }
                let Some(raw_id) = self.store.short_ids.get(&rtxn, &canonical_key)? else {
                    return Ok(None);
                };
                raw_id.to_vec()
            }
        };
        require_key_len(&raw_id, ENTITY_ID_LEN, "short id entity id")?;
        let id = EntityId::from_bytes(
            raw_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("short id entity id"))?,
        )
        .map_err(|_| Error::CorruptedIndex("short id entity id"))?;

        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(Some(HydratedShortId {
                id,
                entity_type: 0,
                learned_at: 0,
                deletion: Some(HydratedShortIdDeletion {
                    source: HydratedShortIdDeletionSource::DanglingShortId,
                    reason: None,
                    deleted_at: None,
                    request_id: None,
                    // No entity row remains to inspect, so hydrate treats this
                    // as an effectively hard deletion and keeps the source explicit.
                    hard: true,
                }),
                body: None,
            }));
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let entity_type = header.entity_type;
        let learned_at = header.learned_at;
        let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
        if self.archive_tombstone_in_txn(&rtxn, &id)?.is_some() {
            return Ok(Some(HydratedShortId {
                id,
                entity_type,
                learned_at,
                deletion: None,
                body: None,
            }));
        }
        drop(rtxn);

        if body.is_empty()
            && let Some(deletion) = self.entity_deletion_metadata(&id, learned_at)?
        {
            return Ok(Some(HydratedShortId {
                id,
                entity_type,
                learned_at,
                deletion: Some(deletion),
                body: None,
            }));
        }

        Ok(Some(HydratedShortId {
            id,
            entity_type,
            learned_at,
            deletion: None,
            body: Some(body),
        }))
    }

    /// Returns true when an entity row is a soft-delete shell, not a live
    /// zero-byte payload.
    ///
    /// An ARCHIVED row (ONE-1931) answers `true` here as well: the archive is
    /// a soft tombstone, and the shell it leaves behind is the same 25 B
    /// shell `user_delete` leaves. Which of the two it is — and therefore
    /// whether [`Self::restore_archived`] will undo it — is
    /// [`Self::archived_entity`]'s question, not this one's.
    pub fn is_deleted_shell(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        // Checked inside the SAME read txn as the row, and before the
        // window-doc path below, exactly as `entity_deletion_present_in_txn`
        // orders its own three sources.
        if self.archive_tombstone_in_txn(&rtxn, id)?.is_some() {
            return Ok(true);
        }
        if raw.len() != ENTITY_METADATA_HEADER_LEN {
            return Ok(false);
        }
        drop(rtxn);

        Ok(self
            .entity_deletion_metadata(id, header.learned_at)?
            .is_some())
    }

    /// Resolves one entity id to its [`LiveEntityRow`] in a read transaction
    /// of this call's own.
    ///
    /// The cross-transaction wrapper over [`live_entity_row_in_txn`], for the
    /// callers that hold no transaction: the Free-lane admission record is
    /// minted and committed in its own transaction before the door that cites
    /// it opens, so it asks this question outside any write txn. Callers that
    /// DO hold one (the GATE-12 evidence resolver) must use the in-txn body
    /// directly — a fresh read transaction cannot see same-transaction writes.
    pub(crate) fn live_entity_row(&self, id: &EntityId) -> Result<LiveEntityRow> {
        let rtxn = self.store.env.read_txn()?;
        live_entity_row_in_txn(&self.store, &rtxn, id)
    }

    /// Returns all entity IDs of a given type via prefix scan on type_index.
    ///
    /// Returns all matching entity IDs, or `Err(IndexOverflow("entities_by_type"))`
    /// if the scan would exceed `MAX_TYPE_QUERY_RESULTS`.
    pub fn entities_by_type(&self, entity_type: u8) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let mut ids = Vec::new();
        for entry in self.store.type_index.prefix_iter(&rtxn, &[entity_type])? {
            if ids.len() >= MAX_TYPE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("entities_by_type"));
            }
            let (key, _) = entry?;
            ids.push(entity_id_from_type_index_key(&key)?);
        }
        Ok(ids)
    }

    /// Returns at most `limit` entity IDs of a given type after `after`.
    ///
    /// This is the bounded counterpart to [`Self::entities_by_type`] for
    /// callers that must walk large type indexes incrementally. Results follow
    /// the same LMDB type-index key order as `entities_by_type`; `after` is an
    /// exclusive lower bound.
    pub fn entities_by_type_page(
        &self,
        entity_type: u8,
        after: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let limit = limit.min(MAX_TYPE_QUERY_RESULTS);
        let rtxn = self.store.env.read_txn()?;
        let start_key = match after {
            Some(id) => Store::encode_type_key(entity_type, id).to_vec(),
            None => vec![entity_type],
        };
        let start_bound: std::ops::Bound<&[u8]> = match after {
            Some(_) => std::ops::Bound::Excluded(&start_key[..]),
            None => std::ops::Bound::Included(&start_key[..]),
        };
        let end_bound: std::ops::Bound<&[u8]> = std::ops::Bound::Unbounded;

        let mut ids = Vec::with_capacity(limit.min(1024));
        for entry in self
            .store
            .type_index
            .range(&rtxn, &(start_bound, end_bound))?
        {
            let (key, _) = entry?;
            if key.first() != Some(&entity_type) {
                break;
            }
            ids.push(entity_id_from_type_index_key(&key)?);
            if ids.len() >= limit {
                break;
            }
        }
        Ok(ids)
    }

    /// Returns up to `limit` latest entity bodies of a given type.
    ///
    /// Scans at most `scan_limit` rows from the `temporal_learned` index in
    /// newest-first order and reads matching entity bodies from the same LMDB
    /// snapshot, returning `(id, learned_at, body)` tuples.
    pub fn latest_entity_bodies_by_type(
        &self,
        entity_type: u8,
        limit: usize,
        scan_limit: usize,
    ) -> Result<Vec<(EntityId, u64, Vec<u8>)>> {
        if limit == 0 || scan_limit == 0 {
            return Ok(Vec::new());
        }

        let rtxn = self.store.env.read_txn()?;
        let lower: std::ops::Bound<&[u8]> = std::ops::Bound::Unbounded;
        let upper: std::ops::Bound<&[u8]> = std::ops::Bound::Unbounded;
        let mut rows = Vec::with_capacity(limit.min(1024));
        for (scanned, entry) in self
            .store
            .temporal_learned
            .rev_range(&rtxn, &(lower, upper))?
            .enumerate()
        {
            if scanned >= scan_limit {
                break;
            }

            let (key, _) = entry?;
            require_key_len(&key, 24, "temporal learned key")?;
            let learned_at = u64::from_be_bytes(
                key[..8]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
            );
            let id = EntityId::from_bytes(
                key[8..24]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("temporal learned key"))?;

            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                continue;
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != entity_type {
                continue;
            }
            if header.learned_at != learned_at {
                return Err(Error::CorruptedIndex("temporal learned key"));
            }
            rows.push((
                id,
                header.learned_at,
                raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
            ));
            if rows.len() >= limit {
                break;
            }
        }
        Ok(rows)
    }

    /// Counts entity IDs of a given type via the `type_index` prefix path.
    ///
    /// This is the exact count primitive for deterministic paginated list
    /// metadata. It does not materialize entity IDs or read entity bodies.
    pub fn count_entities_by_type(&self, entity_type: u8) -> Result<u64> {
        let rtxn = self.store.env.read_txn()?;
        let mut total = 0_u64;
        for entry in self.store.type_index.prefix_iter(&rtxn, &[entity_type])? {
            let (key, _) = entry?;
            entity_id_from_type_index_key(&key)?;
            total = total
                .checked_add(1)
                .ok_or(Error::IndexOverflow("count_entities_by_type"))?;
        }
        Ok(total)
    }

    /// Returns the entity type byte for a stored entity, or None if not found.
    pub fn get_entity_type(&self, id: &EntityId) -> Result<Option<u8>> {
        let rtxn = self.store.env.read_txn()?;
        self.get_entity_type_in_txn(&rtxn, id)
    }

    /// Transaction-composable body of [`Vault::get_entity_type`].
    pub(crate) fn get_entity_type_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<u8>> {
        let Some(raw) = self.store.entities.get(txn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(Some(header.entity_type))
    }
}
