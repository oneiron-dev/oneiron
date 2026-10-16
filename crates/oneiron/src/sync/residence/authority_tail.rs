//! Authority history for a machine that syncs what it opened (OF-469, the
//! delivery half). Window sync carries AUTHORITY_LOG rows only inside the
//! windows a machine holds, so an opened machine lacks the history its grants,
//! machines and world settings fold from. The home serves it apart from any
//! content: the signed entries the machine lacks, parents first, a page at a
//! time, which the machine imports through the signed-history door and folds
//! itself. The whole log is kept for now (identity, tiered authority history),
//! so the hot tail is everything the home holds; a checkpoint and a cold
//! archive come with L02's checkpoint v2.

use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::{
    AuthorityEntryHash, PeerMachine, authority_entry_hash, decode_authority_log_entry_body,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;

/// The most entries one authority tail page carries.
pub const AUTHORITY_TAIL_PAGE_MAX: usize = 512;

/// The hash of every authority entry this replica holds, read from the rows
/// themselves: a history this replica cannot yet close still names what it
/// holds.
///
/// # Errors
///
/// A row that does not decode; storage errors.
pub fn held_authority_entries(vault: &Vault) -> Result<BTreeSet<AuthorityEntryHash>> {
    let txn = vault.store.env.read_txn()?;
    let mut held = BTreeSet::new();
    for id in vault
        .store
        .port_entity_ids_by_type(&txn, ENTITY_TYPE_AUTHORITY_LOG, None)?
    {
        let id = id?;
        let Some(raw) = vault.store.port_entity_raw(&txn, &id)? else {
            continue;
        };
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("authority row header"))?;
        held.insert(authority_entry_hash(&decode_authority_log_entry_body(
            body,
        )?)?);
    }
    Ok(held)
}

/// The signed entries this home holds and `held` lacks, parents first, at most
/// `limit`, for a machine of the owner's whose proof stands here. Each entry's
/// parents are in `held` or earlier in the page, so the page imports whole.
/// Refused for any other peer: the log names grants, machines and settings.
///
/// # Errors
///
/// A refused peer; a history this home cannot order; storage errors.
pub fn authority_tail_for(
    vault: &Vault,
    peer: PeerMachine,
    held: &BTreeSet<AuthorityEntryHash>,
    limit: usize,
) -> Result<Vec<Vec<u8>>> {
    {
        let txn = vault.store.env.read_txn()?;
        let fold = vault.authority_fold_readonly_in_txn(&txn)?;
        let mine = match peer {
            PeerMachine::Proven { machine, key } => {
                fold.machine_proof_key(machine) == Some(key)
                    && fold.trusted_machine(machine).is_some()
            }
            PeerMachine::Unknown => false,
        };
        if !mine {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::DocumentAdmissionDenied,
            ));
        }
    }
    let limit = limit.clamp(1, AUTHORITY_TAIL_PAGE_MAX);
    let mut page = Vec::new();
    for bytes in vault.export_signed_authority_history()? {
        let hash = authority_entry_hash(&decode_authority_log_entry_body(&bytes)?)?;
        if !held.contains(&hash) {
            page.push(bytes);
            if page.len() == limit {
                break;
            }
        }
    }
    Ok(page)
}
