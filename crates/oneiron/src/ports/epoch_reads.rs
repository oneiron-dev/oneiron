//! Original epoch-summary reads with borrowed physical input observations.
//! No document load, retention permission or complete staleness certificate.
use super::{DocumentRead, StaleRead, StaleReadObserver, StaleReadTable};
use crate::EntityId;
use crate::error::Result;
use crate::side_table::SideDb;
use crate::store::ManifestDbs;
use heed::RoTxn;

pub(super) fn epoch_summary_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    observer: &mut Option<&mut StaleReadObserver<'_>>,
) -> Result<bool> {
    match super::stale_reads::entity_record(store, txn, id, observer)? {
        Some(row) if row.entity_type == crate::registry::ENTITY_TYPE_SUMMARY => {
            let epoch = if observer.is_none() {
                crate::compaction::stored_epoch_in(store, txn, id, &row.body)?
            } else {
                let mut head = |read: DocumentRead<'_>| {
                    if let DocumentRead::Row { table, key, value } = read {
                        super::stale_reads::observe(
                            observer,
                            StaleRead::Row {
                                table: match table.db {
                                    SideDb::VaultMeta => StaleReadTable::VaultMeta,
                                    SideDb::SyncState => StaleReadTable::SyncState,
                                },
                                key,
                                value,
                            },
                        );
                    }
                };
                crate::compaction::stored_epoch_in_observed(
                    store,
                    txn,
                    id,
                    &row.body,
                    Some(&mut head),
                )?
            };
            Ok(epoch.may_be())
        }
        _ => Ok(false),
    }
}
