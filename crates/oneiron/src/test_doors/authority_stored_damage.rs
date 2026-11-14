//! L9-50 (ARCH-0006a #list-read-built): damage one stored authority row in
//! place, past every write door, so a test reads how the authority readers
//! report store damage. Census L7-19: store rows as a vault did before every
//! store door held a stranger's row (#1449, H72).

use crate::authority::{
    AuthorityLogEntry, AuthorityObservationPolicy, advance_authority_cache_generation,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Error, Result, TimeRange, Vault};

/// Overwrites the signed body of the first stored AUTHORITY_LOG row with
/// bytes of the same length that decode as no entry, keeps its header, and
/// drops the cached fold, so the next fold reads every stored row again.
/// Returns the damaged row's id.
///
/// # Errors
///
/// The vault stores no AUTHORITY_LOG row, or the store refuses the write.
pub fn damage_first_stored_authority_log_body(vault: &Vault) -> Result<EntityId> {
    let id = vault.with_write_txn(|txn| {
        let id = vault
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_AUTHORITY_LOG, None)?
            .next()
            .transpose()?
            .ok_or(Error::InvariantViolation(
                "the vault stores no authority row",
            ))?;
        let mut raw = vault
            .store
            .port_entity_record(txn, &id)?
            .map(|row| row.encode())
            .ok_or(Error::InvariantViolation(
                "the type index names no stored row",
            ))?;
        // 0xc1 is the one byte MessagePack never uses.
        raw[ENTITY_METADATA_HEADER_LEN..].fill(0xc1);
        vault.store.entities.put(txn, id.as_bytes(), &raw)?;
        advance_authority_cache_generation(&vault.store, txn)?;
        Ok(id)
    })?;
    drop_cached_authority_fold(vault);
    Ok(id)
}

/// Stores `raw` as this vault's authority observation policy row, past the
/// write door's check, and drops the cached fold.
///
/// # Errors
///
/// The store refuses the write.
pub fn put_raw_authority_observation_policy(vault: &Vault, raw: &[u8]) -> Result<()> {
    let table: SideTable<(), AuthorityObservationPolicy, Raw> =
        SideTable::new(&side_table::AUTHLOG_OBSERVATION_POLICY);
    let key = table.key_bytes(&());
    let key = std::str::from_utf8(&key)
        .map_err(|_| Error::InvariantViolation("the policy row key is not UTF-8"))?;
    vault.with_write_txn(|txn| {
        vault.store.sync_state.put(txn, key, raw)?;
        advance_authority_cache_generation(&vault.store, txn)?;
        Ok(())
    })?;
    drop_cached_authority_fold(vault);
    Ok(())
}

/// Stores `entries` through the authority write door with this thread's
/// store doors open, as a vault did before every store door held a row no
/// key that may vouch for signed (#1449, H72), so a test holds a stranger's
/// row such a vault kept. Returns the rows' ids.
///
/// # Errors
///
/// The write door refuses a row for anything but its signer's standing.
pub fn put_authority_log_entries_past_the_store_door(
    vault: &Vault,
    entries: &[(AuthorityLogEntry, TimeRange, u64)],
) -> Result<Vec<EntityId>> {
    crate::authority::with_authority_doors_open_for_test(|| {
        vault.put_authority_log_entries(entries)
    })
}

fn drop_cached_authority_fold(vault: &Vault) {
    if let Ok(mut cache) = vault.store.authority_fold_cache.lock() {
        *cache = None;
    }
}
