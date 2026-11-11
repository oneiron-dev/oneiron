//! Snapshot classification. Index pages and process coordination never enter the image. A side
//! table's tier is on its declaration row (`[tier: ..]`, core split slice 1).
use crate::side_table::SideDb;
pub use crate::side_table::row_classes::StorageTier;
use StorageTier::*;
/// Host orders and the host-only log (OF-470 C2): a restore carries them from
/// the live vault, never from an image (`host_holds`).
pub(super) const HOST_HOLD_PREFIX: &[u8] = b"legal_hold:host:";
pub fn storage_tier(database: &str, key: &[u8]) -> StorageTier {
    match database {
        "entities" | "edges_out" | "edges_in" | "short_ids" | "short_ids_reverse"
        | "job_records" => Canonical,
        "vault_meta" => side_tier(SideDb::VaultMeta, key),
        "hnsw_meta" => {
            if [
                b"model_id".as_slice(),
                b"embedding_transform",
                b"hnsw_config",
                b"embedding_model_epoch",
                b"vector_version",
                b"graph_version",
                b"temporal_long_intervals_schema_version",
            ]
            .contains(&key)
            {
                Canonical
            } else {
                Derived
            }
        }
        "sync_state" => side_tier(SideDb::SyncState, key),
        "sync_queue" => {
            if key.starts_with(b"m:maintenance_ingest_quota:v1:") {
                Runtime
            } else if key.starts_with(b"e:") {
                Derived
            } else {
                Canonical
            }
        }
        _ => Derived,
    }
}

/// A side-table row's tier: its declared table's, for the key range it falls in. A key no table
/// declares is canonical, so an image keeps an undeclared row and the payload receipt names it.
fn side_tier(db: SideDb, key: &[u8]) -> StorageTier {
    crate::side_table::declared_for(db, key).map_or(Canonical, |decl| decl.tier_of(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The run and group indexes of pending Gate consents are rebuilt on restore
    /// (`rebuild_pending_gate_consent_sidecars`), so they never enter an image. Their
    /// prefixes moved to v2 (#5369) while this classifier still named v1, so v2 rows
    /// were imaged as canonical and refused as an undeclared family on restore.
    #[test]
    fn gate_pending_run_and_group_indexes_are_derived() {
        for prefix in [
            crate::side_table::PENDING_GATE_CONSENT_RUN_INDEX.prefix,
            crate::side_table::PENDING_GATE_CONSENT_GROUP_INDEX.prefix,
        ] {
            assert_eq!(storage_tier("vault_meta", prefix), StorageTier::Derived);
        }
    }
}
