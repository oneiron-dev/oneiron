//! Byte dump of every named LMDB database a vault holds, and the rows a write
//! changed between two dumps.
//!
//! The strongest "these two writes stored the same thing" comparison: every
//! database in [`crate::store::DB_MANIFEST`], every key and value, in LMDB
//! order. DUP_SORT duplicates (`text_postings`) appear as repeated keys in
//! iteration order.
//!
//! A few row families are not a function of the writes alone, and are masked
//! so two opens given the same writes dump the same bytes (see
//! [`mask_unrepeatable_stamps`] and [`mask_embed_job_stamps`]). Every other
//! byte is compared as stored.

use std::collections::BTreeMap;

use crate::vault::Vault;

/// Database name -> ordered `(key, value)` rows.
pub(crate) type RowDump = BTreeMap<&'static str, Vec<(Vec<u8>, Vec<u8>)>>;

/// Dumps every named database of `vault`. Panics if the dump misses a name
/// the pinned manifest carries, so a new database cannot fall out of it.
pub(crate) fn dump_rows(vault: &Vault) -> RowDump {
    let store = &vault.store;
    let rtxn = store.env.read_txn().expect("read txn");
    let mut out = RowDump::new();
    macro_rules! dump {
        ($($name:literal => $field:ident),* $(,)?) => {$(
            let rows = store
                .$field
                .iter(&rtxn)
                .expect("iterate database")
                .map(|row| {
                    let (key, value) = row.expect("database row");
                    (AsRef::<[u8]>::as_ref(&*key).to_vec(), value.to_vec())
                })
                .collect();
            out.insert($name, rows);
        )*};
    }
    dump!(
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
    let mut dumped: Vec<&str> = out.keys().copied().collect();
    let mut manifest: Vec<&str> = crate::store::DB_MANIFEST
        .iter()
        .map(|entry| entry.name)
        .collect();
    dumped.sort_unstable();
    manifest.sort_unstable();
    assert_eq!(dumped, manifest, "the row dump covers every named database");
    if let Some(rows) = out.get_mut("vault_meta") {
        mask_unrepeatable_stamps(rows);
    }
    if let Some(rows) = out.get_mut("sync_queue") {
        mask_embed_job_stamps(rows);
    }
    out
}

/// An embed job row (`e:` + entity id) carries its priority and the wall-clock
/// millisecond it was queued at. The queue time is masked to zero.
fn mask_embed_job_stamps(rows: &mut [(Vec<u8>, Vec<u8>)]) {
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
fn mask_unrepeatable_stamps(rows: &mut [(Vec<u8>, Vec<u8>)]) {
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
            let mut state =
                rmpv::decode::read_value(&mut value.as_slice()).expect("revision state decodes");
            let rmpv::Value::Map(entries) = &mut state else {
                panic!("revision state is a map");
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
            rmpv::encode::write_value(value, &state).expect("revision state encodes");
        }
    }
}

/// One row a write changed: its database, key and value, and whether the
/// write added it (`true`) or removed it (`false`). A rewritten value is one
/// removal and one addition.
pub(crate) type RowChange = (&'static str, Vec<u8>, Vec<u8>, bool);

/// The rows that differ between `before` and `after`, compared as multisets
/// (a duplicate row counts once per copy), in database, key, value order,
/// removals before additions.
pub(crate) fn changed_rows(before: &RowDump, after: &RowDump) -> Vec<RowChange> {
    let mut changes = Vec::new();
    for (name, after_rows) in after {
        let mut counts: BTreeMap<(&[u8], &[u8]), i64> = BTreeMap::new();
        for (key, value) in before.get(name).into_iter().flatten() {
            *counts.entry((key, value)).or_default() -= 1;
        }
        for (key, value) in after_rows {
            *counts.entry((key, value)).or_default() += 1;
        }
        let mut rows: Vec<(&[u8], &[u8], bool)> = Vec::new();
        for ((key, value), count) in counts {
            for _ in 0..count.unsigned_abs() {
                rows.push((key, value, count > 0));
            }
        }
        rows.sort_unstable();
        changes.extend(
            rows.into_iter()
                .map(|(key, value, added)| (*name, key.to_vec(), value.to_vec(), added)),
        );
    }
    changes
}

/// A blake3 digest of `changes`, hex-encoded. Every field is length-prefixed
/// so no two change sets share an encoding.
pub(crate) fn digest_changes(changes: &[RowChange]) -> String {
    let mut hasher = blake3::Hasher::new();
    for (name, key, value, added) in changes {
        hasher.update(&[u8::from(*added)]);
        for part in [name.as_bytes(), key.as_slice(), value.as_slice()] {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
    }
    hasher.finalize().to_hex().to_string()
}
