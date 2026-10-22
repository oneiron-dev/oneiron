//! Who one world's pads go to, and what this machine holds of them, for pad
//! hydration (KS-5, FIX 6706, L04 leaf): the world's current recipients, the
//! pads its rows hold here, and the keys its authority names whose pad is not
//! here. What a capsule seals and installs is the store's
//! (`store::world_pad_custody::current`).
//!
//! The recipients read is featureless (FIX 10326): a custody head's world
//! compartments are wrapped to them in every build. The rest serves sync's
//! pad hydration alone.

use std::collections::BTreeSet;

use heed::RoTxn;
#[cfg(feature = "sync")]
use zeroize::Zeroizing;

use super::super::pads::world_keys_destroyed_in_txn;
#[cfg(feature = "sync")]
use super::super::pads::{pad_in_txn, pad_row_in_txn};
use super::super::recipients;
#[cfg(feature = "sync")]
use super::{decode_pad_body, key_of_id, pad_item, pad_row_erased_in_txn};
use crate::Vault;
#[cfg(feature = "sync")]
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
#[cfg(feature = "sync")]
use crate::ports::EntityStoreRead;
#[cfg(feature = "sync")]
use crate::registry::ENTITY_TYPE_WORLD_KEY_PAD;
use crate::store::PadRecipients;
#[cfg(feature = "sync")]
use crate::store::Store;
use crate::world_keys::{RecoveryRootId, WrapRecipient};

/// Who a world's pads go to (CALLS: WORLD_PAD_RECIPIENT_RULE, FIX 6706).
enum RecipientRule {
    /// Each machine of the owner's whose trusted identity stands under this
    /// install's pin, that the world's read setting admits, with the
    /// encryption key of that identity; and each recovery root the world's
    /// current key is wrapped to, by the record this install holds of it.
    /// Never every linked machine or every pinned root.
    AdmittedReadersAndTheWorldKeysRoots,
}

const WORLD_PAD_RECIPIENT_RULE: RecipientRule = RecipientRule::AdmittedReadersAndTheWorldKeysRoots;

/// `world`'s pad recipients now, by [`WORLD_PAD_RECIPIENT_RULE`], from the
/// authority `txn` reads. None for a world whose keys were destroyed here: no
/// pad of it goes anywhere.
///
/// # Errors
///
/// Authority and storage faults.
pub(crate) fn world_pad_recipients_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    world: EntityId,
) -> Result<PadRecipients> {
    let mut out = PadRecipients::new();
    if world_keys_destroyed_in_txn(&vault.store, txn, world)? {
        return Ok(out);
    }
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    match WORLD_PAD_RECIPIENT_RULE {
        RecipientRule::AdmittedReadersAndTheWorldKeysRoots => {}
    }
    out.extend(recipients(&fold, world, None));
    let roots: BTreeSet<RecoveryRootId> = fold
        .current_world_key(world)
        .into_iter()
        .flat_map(|key| key.wraps.keys())
        .filter_map(|recipient| match recipient {
            WrapRecipient::RecoveryRoot(root) => Some(*root),
            WrapRecipient::Machine(_) => None,
        })
        .collect();
    for root in roots {
        // A root this install holds no valid record of gets no wrap here.
        if let Some(root) = vault.root_recipient_in_txn(txn, &fold, root)? {
            out.insert(WrapRecipient::RecoveryRoot(root.id), root.key);
        }
    }
    Ok(out)
}

/// The full id of each key of `world` whose pad row is here, a bare
/// reference included: a source's candidates beside what its custody names.
/// A soft-erased shell or a row that does not decode names none.
///
/// # Errors
///
/// Storage faults.
#[cfg(feature = "sync")]
pub(crate) fn world_pad_row_items_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    world: EntityId,
) -> Result<BTreeSet<[u8; 40]>> {
    let mut out = BTreeSet::new();
    for id in store.port_entity_ids_by_type(txn, ENTITY_TYPE_WORLD_KEY_PAD, None)? {
        let Some(raw) = store.port_entity_raw(txn, &id?)?.map(Zeroizing::new) else {
            continue;
        };
        let Some(Ok(body)) = raw.get(ENTITY_METADATA_HEADER_LEN..).map(decode_pad_body) else {
            continue;
        };
        if body.key().world == world {
            out.insert(pad_item(body.key()));
        }
    }
    Ok(out)
}

/// The pad the row of the key `item` names holds here: its own, a carrier's
/// or the one it rests beside, or current custody's for a bare reference.
/// `None` with no row, or an item that names no key.
///
/// # Errors
///
/// A row of another kind or key; storage faults.
#[cfg(feature = "sync")]
pub(crate) fn row_pad_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    item: &[u8; 40],
) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let Some(key) = key_of_id(item) else {
        return Ok(None);
    };
    Ok(pad_row_in_txn(store, txn, &key)?.map(|(pad, _)| Zeroizing::new(*pad.bytes())))
}

/// The full id of each key of `world` this vault's authority names whose pad
/// is not here, ascending: what a first open or an exact repair asks for.
/// None for a world whose keys were destroyed here; a key whose pad row was
/// hard-erased here is never asked for.
///
/// # Errors
///
/// Authority and storage faults.
#[cfg(feature = "sync")]
pub(crate) fn missing_world_pads_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    world: EntityId,
) -> Result<Vec<[u8; 40]>> {
    if world_keys_destroyed_in_txn(&vault.store, txn, world)? {
        return Ok(Vec::new());
    }
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let mut out = Vec::new();
    for key in fold.world_keys(world) {
        let item = pad_item(&key.id);
        if pad_in_txn(&vault.store, txn, &key.id)?.is_none()
            && !pad_row_erased_in_txn(&vault.store, txn, &item)?
        {
            out.push(item);
        }
    }
    out.sort_unstable();
    Ok(out)
}
