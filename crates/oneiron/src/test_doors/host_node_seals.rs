//! Doors for the host node's engine seals on a paired replica (L7-34;
//! ARCH-0055 `#seal-standing-open`): another install of a vault takes the
//! vault's authority log, and a peer's identity-topology rows reach it through
//! the replicated identity-topology door, as sync delivers them.

use crate::authority::{authority_entry_hash, decode_authority_log_entry_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT};
use crate::temporal::TimeRange;
use crate::{EntityId, Error, Result, Vault};

/// The lease stream a peer's identity-topology rows arrive on.
const PEER_LEASE_VAULT_ID: u64 = 7;

/// Row `id` as `vault` stores it, with its parsed header.
fn stored_row(vault: &Vault, id: &EntityId) -> Result<(Vec<u8>, EntityMetadataHeader)> {
    let raw = vault
        .get_raw(id)?
        .ok_or(Error::CorruptedIndex("host node seal door: no stored row"))?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("host node seal door: row header"))?;
    Ok((raw, header))
}

/// Stages every authority-log row `from` holds into `to`, each row's log
/// parents first, as sync and import do: the door judges each row against
/// the rows staged before it (H72). Afterwards `to` folds `from`'s vault.
pub fn copy_authority_log(from: &Vault, to: &Vault) -> Result<()> {
    let mut rest = Vec::new();
    for id in from.entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)? {
        let (raw, header) = stored_row(from, &id)?;
        let entry = decode_authority_log_entry_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let occurred = TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        };
        rest.push((entry, occurred, header.learned_at));
    }
    let mut staged = std::collections::BTreeSet::new();
    let mut ordered = Vec::with_capacity(rest.len());
    while !rest.is_empty() {
        let (ready, waiting): (Vec<_>, Vec<_>) = rest.into_iter().partition(|(entry, ..)| {
            entry
                .parent_hashes
                .iter()
                .all(|parent| staged.contains(parent))
        });
        if ready.is_empty() {
            return Err(Error::CorruptedIndex(
                "host node seal door: the log names a missing parent",
            ));
        }
        for (entry, ..) in &ready {
            staged.insert(authority_entry_hash(entry)?);
        }
        ordered.extend(ready);
        rest = waiting;
    }
    to.put_authority_log_entries(&ordered)?;
    Ok(())
}

/// Delivers every identity-topology row `from` holds (each decision and its
/// seal) to `to` through the replicated identity-topology door, with the
/// bytes `from` stores, as Observer B's entity pass does for a row of a
/// peer's stream. Returns how many landed fresh.
pub fn deliver_identity_topology_rows(from: &Vault, to: &Vault) -> Result<usize> {
    let mut landed = 0;
    for id in from.entities_by_type(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)? {
        let (raw, header) = stored_row(from, &id)?;
        // The window a row's learned stamp names (`sync::types::entity_belongs_to_window`).
        let window_key = crate::sync::types::WindowKey::from_timestamp(header.learned_at);
        let fresh = to.with_write_txn(|wtxn| {
            crate::sync::bridge::ingest_replicated_identity_topology_event_in_txn(
                to,
                wtxn,
                &id,
                &header,
                (&raw, window_key.0.as_str()),
                &raw[ENTITY_METADATA_HEADER_LEN..],
                PEER_LEASE_VAULT_ID,
            )
        })?;
        landed += usize::from(fresh);
    }
    Ok(landed)
}
