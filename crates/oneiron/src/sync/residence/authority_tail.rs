//! Authority history for a machine that syncs what it opened (OF-469, the
//! delivery half). Window sync carries AUTHORITY_LOG rows only inside the
//! windows a machine holds, so an opened machine lacks the history its grants,
//! machines and world settings fold from. The home serves it apart from any
//! content: the signed entries the machine lacks, parents first, a page at a
//! time, which the machine imports through the signed-history door and folds
//! itself. The whole log is kept for now (identity, tiered authority history),
//! so the hot tail is everything the home holds; a cold archive comes with
//! L02's checkpoint v2. A machine whose pairing pinned a checkpoint adopts
//! its image before the tail folds: the home serves the image it keeps a
//! part at a time, with the attestations kept for it, and nothing the home
//! serves is trusted until it verifies against the machine's own pin.
//!
//! The append half runs the other way: the home names, on the tail's last
//! page, the entries the machine holds that it lacks, and the machine sends
//! them back through the same door, so an entry an opened machine wrote
//! reaches the home without the window it rides.

use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::{
    AuthorityCheckpointAttestation, AuthorityEntryHash, AuthorityHistoryFetch,
    AuthorityHistoryPage, PeerMachine, authority_entry_hash, decode_authority_log_entry_body,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::sync::quarantine::remote_rejection_reason;

/// The most entries one authority tail page carries.
pub const AUTHORITY_TAIL_PAGE_MAX: usize = 512;

/// The most image bytes one checkpoint part carries, as a sealed packet's
/// part does: inside the RPC reply once base64 is added.
pub const AUTHORITY_CHECKPOINT_PART_MAX: usize = 16 * 1024 * 1024;

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
    require_owner_machine(vault, peer)?;
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

/// The page of `fetch` this home serves a machine of the owner's whose proof
/// stands here ([`Vault::authority_history_page`]): the exact rows it names
/// and, with parent closure, their ancestors down to what the machine holds,
/// parents first. Refused for any other peer, as the tail is.
///
/// # Errors
///
/// A refused peer; a fetch naming another vault; storage errors.
pub fn authority_range_for(
    vault: &Vault,
    peer: PeerMachine,
    fetch: &AuthorityHistoryFetch,
) -> Result<AuthorityHistoryPage> {
    require_owner_machine(vault, peer)?;
    vault.authority_history_page(fetch)
}

/// One slice of a kept checkpoint image ([`authority_checkpoint_part_for`]).
#[derive(Debug)]
pub struct AuthorityCheckpointPart {
    /// The image's whole length.
    pub total: u64,
    /// The image's bytes from the slice's offset.
    pub part: Vec<u8>,
    /// The attestations kept for the image, on the slice at offset zero only.
    pub attestations: Vec<AuthorityCheckpointAttestation>,
}

/// One slice of the checkpoint image this home keeps at `id`, at most
/// [`AUTHORITY_CHECKPOINT_PART_MAX`] bytes from `offset`, with the image's
/// whole length and, on the slice at offset zero, the attestations kept for
/// it under its own root policy ([`Vault::authority_checkpoint_bundle`]),
/// for a machine of the owner's whose proof stands here. The machine adopts
/// the image only once it verifies against the pin its pairing returned.
/// `None` for an image not kept here and an offset at or past its end.
/// Refused for any other peer, as the tail is.
///
/// # Errors
///
/// A refused peer; a kept image that is not what its id names; storage
/// errors.
pub fn authority_checkpoint_part_for(
    vault: &Vault,
    peer: PeerMachine,
    id: &[u8; 32],
    offset: u64,
) -> Result<Option<AuthorityCheckpointPart>> {
    require_owner_machine(vault, peer)?;
    let Some(bundle) = vault.authority_checkpoint_bundle(id)? else {
        return Ok(None);
    };
    let Some(rest) = usize::try_from(offset)
        .ok()
        .and_then(|offset| bundle.image.get(offset..))
        .filter(|rest| !rest.is_empty())
    else {
        return Ok(None);
    };
    let part = rest[..rest.len().min(AUTHORITY_CHECKPOINT_PART_MAX)].to_vec();
    let attestations = if offset == 0 {
        bundle.attestations
    } else {
        Vec::new()
    };
    Ok(Some(AuthorityCheckpointPart {
        total: bundle.image.len() as u64,
        part,
        attestations,
    }))
}

/// Whether `peer` is a machine of the owner's whose proof stands here on the
/// key it proved.
fn owner_machine(vault: &Vault, peer: PeerMachine) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    Ok(match peer {
        PeerMachine::Proven { machine, key } => {
            fold.machine_proof_key(machine) == Some(key) && fold.trusted_machine(machine).is_some()
        }
        PeerMachine::Unknown => false,
    })
}

/// Refuses every peer but a machine of the owner's ([`owner_machine`]).
fn require_owner_machine(vault: &Vault, peer: PeerMachine) -> Result<()> {
    if !owner_machine(vault, peer)? {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::DocumentAdmissionDenied,
        ));
    }
    Ok(())
}

/// The entries of `offered` this home does not hold: what the machine that
/// named them should append. The caller has already admitted the machine.
///
/// # Errors
///
/// A row that does not decode; storage errors.
pub fn authority_wanted(
    vault: &Vault,
    offered: &BTreeSet<AuthorityEntryHash>,
) -> Result<Vec<AuthorityEntryHash>> {
    let held = held_authority_entries(vault)?;
    Ok(offered.difference(&held).copied().collect())
}

/// Imports the signed entries a machine of the owner's appends, at most
/// [`AUTHORITY_TAIL_PAGE_MAX`], through the signed-history door
/// ([`import_authority_page`]): every signature, parent and standing is
/// checked and the log refolds here, so nothing the machine asserts is
/// trusted beyond the signed bytes. Each entry's parents are held here or
/// earlier in `entries`; an entry the door refuses holds back only itself and
/// what stands on it. Returns how many rows the import wrote, or `None` for a
/// peer that is not a machine of the owner's.
///
/// # Errors
///
/// An oversized page; an entry or history the door refuses; storage errors.
pub fn authority_append_for(
    vault: &Vault,
    peer: PeerMachine,
    entries: &[Vec<u8>],
) -> Result<Option<usize>> {
    if !owner_machine(vault, peer)? {
        return Ok(None);
    }
    if entries.len() > AUTHORITY_TAIL_PAGE_MAX {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::DocumentAdmissionDenied,
        ));
    }
    Ok(Some(import_authority_page(vault, entries)?.written))
}

/// What one authority page import did ([`import_authority_page`]).
#[derive(Debug, Default)]
pub struct AuthorityPageImport {
    /// How many rows the import wrote.
    pub written: usize,
    /// The entries the signed-history door refused, by hash.
    pub refused: BTreeSet<AuthorityEntryHash>,
}

/// Imports one page of signed authority entries, parents first, through the
/// door for a history held in part ([`Vault::import_signed_authority_page`]).
/// When the door refuses the page whole, each entry is tried alone in order,
/// so one refused entry (a fork on a retired key, say) holds back only itself
/// and the entries that stand on it.
///
/// # Errors
///
/// An entry that does not decode; an error that judges no entry, such as
/// storage.
pub fn import_authority_page(vault: &Vault, entries: &[Vec<u8>]) -> Result<AuthorityPageImport> {
    if entries.is_empty() {
        return Ok(AuthorityPageImport::default());
    }
    match vault.import_signed_authority_page(entries) {
        Ok(ids) => {
            return Ok(AuthorityPageImport {
                written: ids.len(),
                refused: BTreeSet::new(),
            });
        }
        Err(error) if remote_rejection_reason(&error).is_none() => return Err(error),
        Err(_) => {}
    }
    let mut outcome = AuthorityPageImport::default();
    for entry in entries {
        let hash = authority_entry_hash(&decode_authority_log_entry_body(entry)?)?;
        match vault.import_signed_authority_page(std::slice::from_ref(entry)) {
            Ok(ids) => outcome.written += ids.len(),
            Err(error) if remote_rejection_reason(&error).is_some() => {
                outcome.refused.insert(hash);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(outcome)
}
