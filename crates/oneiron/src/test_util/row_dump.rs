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
//! `crate::vault::mask_unrepeatable_stamps` and
//! `crate::vault::mask_embed_job_stamps`). Every other byte is compared as
//! stored.

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
        crate::vault::mask_unrepeatable_stamps(rows).expect("revision state decodes");
    }
    if let Some(rows) = out.get_mut("sync_queue") {
        crate::vault::mask_embed_job_stamps(rows);
    }
    out
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
