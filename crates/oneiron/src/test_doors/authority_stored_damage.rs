//! L9-50 (ARCH-0006a #list-read-built): damage one stored authority row in
//! place, past every write door, so a test reads how the authority readers
//! report store damage.

use crate::authority::{AuthorityObservationPolicy, advance_authority_cache_generation};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Error, Result, Vault};

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

fn drop_cached_authority_fold(vault: &Vault) {
    if let Ok(mut cache) = vault.store.authority_fold_cache.lock() {
        *cache = None;
    }
}
