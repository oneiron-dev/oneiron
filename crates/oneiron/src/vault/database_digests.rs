//! One BLAKE3 digest per named database: the comparison two vaults given the
//! same writes can be held to, database by database.

use crate::error::{Error, Result};
use crate::vault::Vault;

impl Vault {
    /// One digest per named ARCH-0019 database, in manifest order, read from
    /// one snapshot: BLAKE3 over every row, each written as key length, key,
    /// value length, value (lengths little-endian u64), rows in byte order.
    ///
    /// The digest is of what the writes stored. Two row families carry bytes
    /// that are not a function of the writes, and are masked the way the
    /// engine's own row-dump comparison masks them before they are hashed:
    /// the wall-clock and random-peer stamps of entity-revision rows in
    /// `vault_meta`, and the wall-clock queue time of embed jobs in
    /// `sync_queue`.
    pub fn database_digests(&self) -> Result<Vec<(&'static str, [u8; 32])>> {
        let store = &self.store;
        let txn = store.env.read_txn()?;
        let mut digests: Vec<(&'static str, [u8; 32])> = Vec::new();
        macro_rules! digest {
            ($($name:literal => $field:ident),* $(,)?) => {$(
                let mut rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                for row in store.$field.iter(&txn)? {
                    let (key, value) = row?;
                    rows.push((
                        AsRef::<[u8]>::as_ref(&*key).to_vec(),
                        AsRef::<[u8]>::as_ref(&*value).to_vec(),
                    ));
                }
                digests.push(($name, digest_rows($name, rows)?));
            )*};
        }
        digest!(
            "entities" => entities,
            "type_index" => type_index,
            "short_ids" => short_ids,
            "short_ids_reverse" => short_ids_reverse,
            "vault_meta" => vault_meta,
            "vectors" => vectors,
            "hnsw_neighbors" => hnsw_neighbors,
            "hnsw_meta" => hnsw_meta,
            "text_postings" => text_postings,
            "text_meta" => text_meta,
            "text_forward" => text_forward,
            "text_bm25_field_stats" => text_bm25_field_stats,
            "text_doc_field_lengths" => text_doc_field_lengths,
            "edges_out" => edges_out,
            "edges_in" => edges_in,
            "ppr_cache" => ppr_cache,
            "ppr_cache_deps" => ppr_cache_deps,
            "temporal_occurred_start" => temporal_occurred_start,
            "temporal_occurred_end" => temporal_occurred_end,
            "temporal_learned" => temporal_learned,
            "temporal_long_intervals" => temporal_long_intervals,
            "phonetic_index" => phonetic_index,
            "phonetic_forward" => phonetic_forward,
            "sync_state" => sync_state,
            "sync_queue" => sync_queue,
            "job_records" => attempt_records,
            "job_ready" => attempt_ready,
            "job_dedupe" => attempt_dedupe,
        );
        let mut ordered = Vec::with_capacity(digests.len());
        for entry in &crate::store::DB_MANIFEST {
            let position = digests
                .iter()
                .position(|(name, _)| *name == entry.name)
                .ok_or(Error::InvariantViolation(
                    "database digests miss a manifest database",
                ))?;
            ordered.push(digests.swap_remove(position));
        }
        if !digests.is_empty() {
            return Err(Error::InvariantViolation(
                "database digests name a database outside the manifest",
            ));
        }
        Ok(ordered)
    }
}

fn digest_rows(name: &str, mut rows: Vec<(Vec<u8>, Vec<u8>)>) -> Result<[u8; 32]> {
    match name {
        "vault_meta" => mask_unrepeatable_stamps(&mut rows)?,
        "sync_queue" => mask_embed_job_stamps(&mut rows),
        _ => {}
    }
    rows.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    for (key, value) in &rows {
        hasher.update(&(key.len() as u64).to_le_bytes());
        hasher.update(key);
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// An embed job row (`e:` + entity id) carries its priority and the wall-clock
/// millisecond it was queued at. The queue time is masked to zero.
pub(crate) fn mask_embed_job_stamps(rows: &mut [(Vec<u8>, Vec<u8>)]) {
    const EMBED_KEY_LEN: usize = 2 + crate::entity_id::ENTITY_ID_LEN;
    for (key, value) in rows.iter_mut() {
        if key.starts_with(b"e:") && key.len() == EMBED_KEY_LEN && value.len() == 9 {
            value[1..].fill(0);
        }
    }
}

/// Masks the two `vault_meta` row families whose bytes differ between two
/// opens given the same writes:
///
/// - the entity-revision state row stamps `changed_at_ms` from the wall
///   clock, not the store clock;
/// - an overwritten entity's revision history is a Loro document, whose peer
///   id is random per document. The document, the frontiers retained from
///   it, and the frontier references hashed from those (in the frontier and
///   identity keys and the state row's `live`/`indexed`) all carry it.
///
/// What stays: which entity holds a document, how many frontiers it retains,
/// which entity each identity row names, whether its live revision is the
/// indexed one, and whether it has a document.
pub(crate) fn mask_unrepeatable_stamps(rows: &mut [(Vec<u8>, Vec<u8>)]) -> Result<()> {
    const DOC: &[u8] = b"entity_revision:doc:";
    const FRONTIER: &[u8] = b"entity_revision:frontier:";
    const IDENTITY: &[u8] = b"entity_revision:identity:";
    const STATE: &[u8] = b"entity_revision:state:";
    const MASK: &[u8] = b"<loro>";
    const ID_LEN: usize = crate::entity_id::ENTITY_ID_LEN;
    for (key, value) in rows.iter_mut() {
        if key.starts_with(DOC) {
            *value = MASK.to_vec();
        } else if key.starts_with(FRONTIER) {
            key.truncate(FRONTIER.len() + ID_LEN);
            key.extend_from_slice(MASK);
            *value = MASK.to_vec();
        } else if key.starts_with(IDENTITY) {
            key.truncate(IDENTITY.len());
            key.extend_from_slice(MASK);
        } else if key.starts_with(STATE) {
            let corrupt = || Error::CorruptedIndex("entity revision state");
            let mut state =
                rmpv::decode::read_value(&mut value.as_slice()).map_err(|_| corrupt())?;
            let rmpv::Value::Map(entries) = &mut state else {
                return Err(corrupt());
            };
            let field = |entries: &[(rmpv::Value, rmpv::Value)], name: &str| {
                entries
                    .iter()
                    .find(|(field, _)| field.as_str() == Some(name))
                    .map(|(_, value)| value.clone())
            };
            let published = field(entries, "live") == field(entries, "indexed");
            for (field, stamp) in entries.iter_mut() {
                match field.as_str() {
                    Some("changed_at_ms") => *stamp = rmpv::Value::from(0_u64),
                    Some("live") => *stamp = rmpv::Value::Nil,
                    Some("indexed") => *stamp = rmpv::Value::Boolean(published),
                    _ => {}
                }
            }
            value.clear();
            rmpv::encode::write_value(value, &state).map_err(|_| corrupt())?;
        }
    }
    Ok(())
}
