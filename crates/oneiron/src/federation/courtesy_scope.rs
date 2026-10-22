//! Which records a courtesy deletion ask covers here, read in the caller's
//! own transaction (FIX 2927): this pact's recipient copies, by the delivery
//! ledger the pact's imports write (`FEDERATION_DELIVERED_RECORD`). The
//! same rule the owner's candidate list reads (FIX 321, 3497): a record the
//! pact delivered at a consent epoch at or before the ask's cutoff, in one
//! of the worlds the ask names as they land here, or in any world the pact
//! delivered when it names none. Base reality and a guest's foreign WORLD
//! row count as they are delivered. World registration alone proves no
//! record. Compiled with or without `sync`, so a vault that holds delivered
//! rows reads them whichever build opens it.

use std::collections::BTreeSet;

use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};

/// Each record one pact delivered at one epoch, with the world it sits in
/// (16 raw bytes; empty for base reality). Key: hex64 (pact) ":" hex16
/// (epoch) ":" hex32 (record). Read only here.
const DELIVERED: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::FEDERATION_DELIVERED_RECORD);

fn corrupt() -> Error {
    Error::CorruptedIndex("federation delivered record")
}

/// Splits `records` into the ones a courtesy ask under pact `pact_id`
/// covers here, naming the requester's own `worlds` and `epoch_cutoff`, and
/// the rest, each in `records`' order. Every persisted delivery row of the
/// pact is read, however many.
///
/// # Errors
///
/// Storage errors, and a delivery row whose key or world does not decode.
pub(crate) fn split_recipient_copies_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pact_id: &[u8; 32],
    worlds: &[EntityId],
    epoch_cutoff: u64,
    records: &[EntityId],
) -> Result<(Vec<EntityId>, Vec<EntityId>)> {
    let wanted: BTreeSet<EntityId> = records.iter().copied().collect();
    if wanted.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let worlds = super::foreign_world::courtesy_ask_worlds_here(&fold, pact_id, worlds)?;
    let prefix = format!("{}:", bytes_to_hex_lower(pact_id));
    let base = crate::claim::base_world_id();
    let mut delivered = BTreeSet::new();
    for (key, place) in DELIVERED.scan_from(&vault.store, txn, prefix.as_bytes())? {
        let (epoch, record) = key
            .strip_prefix(&prefix)
            .and_then(|rest| rest.split_once(':'))
            .ok_or_else(corrupt)?;
        let epoch = u64::from_str_radix(epoch, 16)
            .ok()
            .filter(|_| epoch.len() == 16)
            .ok_or_else(corrupt)?;
        let record = EntityId::from_hex(record)
            .ok()
            .filter(|id| id.to_hex() == record)
            .ok_or_else(corrupt)?;
        let world = match <[u8; 16]>::try_from(place.as_slice()) {
            Ok(bytes) => EntityId::from_bytes(bytes).map_err(|_| corrupt())?,
            Err(_) if place.is_empty() => base,
            Err(_) => return Err(corrupt()),
        };
        if epoch > epoch_cutoff
            || !wanted.contains(&record)
            || worlds
                .as_ref()
                .is_some_and(|worlds| !worlds.contains(&world))
        {
            continue;
        }
        delivered.insert(record);
    }
    Ok(records
        .iter()
        .copied()
        .partition(|record| delivered.contains(record)))
}
