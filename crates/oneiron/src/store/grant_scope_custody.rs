//! A federation grant's scope opening keys (FIX 7907, 7958, L04's half):
//! the secret each pact epoch's scope commitment is keyed by
//! (`authority::federation_scope_digest`), held as an erasable key
//! (`key_custody::erasable`) whose parent is the grant and whose incarnation
//! is the pact and its epoch.
//!
//! A key enters custody in the writer that logs the Connect or re-pact it
//! keys, synced and journaled before that commits. A revoke stages every
//! epoch's key of the grant, an aborted writer's orphans included, in its
//! own transaction, and custody's finisher retires them after commit: the
//! signed commitment left in the log then no longer lets anyone test a
//! guessed scope. Nothing here does network I/O; the offer carries the key
//! between the two hosts, outside every signed record.

use heed::RwTxn;
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result, StoreError};
use crate::store::Store;
use crate::store::key_custody::{
    CustodyKind, CustodySecret, EntryState, ErasableItem, ErasablePurpose, erasable_refs_of_in_txn,
    put_erasable_ref_in_txn, stage_erasable_retirement_in_txn,
};

/// The context a pact id and epoch derive a key incarnation under.
const GRANT_INCARNATION_CONTEXT: &str = "oneiron/grant-scope/erasable-incarnation/v1";

/// The incarnation of the key that keys pact `pact_id` at `epoch`.
fn incarnation(pact_id: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(pact_id);
    material[32..].copy_from_slice(&epoch.to_be_bytes());
    blake3::derive_key(GRANT_INCARNATION_CONTEXT, &material)
}

fn unknown_key() -> Error {
    CustodyKind::ErasableKey.corrupt()
}

fn archived() -> Error {
    Error::Store(StoreError::ArchivedVault)
}

/// A fresh opening key for a pact epoch no custody holds yet: it enters
/// custody when this vault's owner accepts the terms it keys.
///
/// # Errors
/// The random source failed.
pub(crate) fn new_scope_key() -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    crate::world_keys::os_fill(&mut key[..])?;
    Ok(key)
}

/// Installs `key` as the opening of `grant`'s pact `pact_id` at `epoch` in
/// `w`, the writer that logs what it keys, with the custody binding pinned
/// there: synced and journaled before this returns. The same key already
/// held is kept (a retry). A key for the epoch that no committed writer
/// named, an aborted accept's orphan, never blocks a retry: one with the
/// same bytes is taken up, another is staged to retire. Only a committed
/// key with other bytes, or a retired one, is refused.
///
/// # Errors
/// An archived vault, whose custody is its replacement's; another or a
/// retired committed key for the epoch; custody faults.
pub(crate) fn install_scope_key(
    s: &Store,
    w: &mut RwTxn<'_>,
    grant: &EntityId,
    pact_id: &[u8; 32],
    epoch: u64,
    key: &[u8; 32],
) -> Result<()> {
    if s.core.gate_custody_archived() {
        return Err(archived());
    }
    s.core.key_custody.pin_in_txn(s, w)?;
    let custody = s.core.key_custody.bind_in_txn(s, &*w)?;
    let incarnation = incarnation(pact_id, epoch);
    let committed = erasable_refs_of_in_txn(s, &*w, ErasablePurpose::GrantScope, grant.as_bytes())?;
    let secret = CustodySecret::from_bytes(Zeroizing::new(key.to_vec()));
    let mut held = None;
    for item in custody.erasable_keys_of(ErasablePurpose::GrantScope, grant.as_bytes())? {
        if item.incarnation != incarnation {
            continue;
        }
        let state = custody.erasable_state(&item)?;
        let same =
            state == EntryState::Live && custody.read_erasable(&item)?.expose() == secret.expose();
        if committed.contains(&item) {
            match state {
                EntryState::Live if !same => return Err(unknown_key()),
                EntryState::Retired => return Err(unknown_key()),
                _ => held = Some(item),
            }
        } else if same && held.is_none() {
            held = Some(item);
        } else if state == EntryState::Live {
            stage_erasable_retirement_in_txn(s, w, &custody, &item)?;
        }
    }
    let item = match held {
        Some(item) => {
            if custody.erasable_state(&item)? == EntryState::Missing {
                custody.install_erasable(&item, &secret)?;
            }
            item
        }
        None => {
            let mut key_ref = [0u8; 32];
            crate::world_keys::os_fill(&mut key_ref)?;
            let item = ErasableItem {
                purpose: ErasablePurpose::GrantScope,
                parent: *grant.as_bytes(),
                incarnation,
                key_ref,
            };
            custody.install_erasable(&item, &secret)?;
            item
        }
    };
    put_erasable_ref_in_txn(s, w, &item)
}

/// Stages the retirement of every opening key custody holds for `grant`,
/// every epoch's and an aborted writer's orphans, in `w`, the transaction
/// that revokes its pact; custody's finisher retires them after commit. An
/// archived vault, or one with no custody yet, stages nothing.
///
/// # Errors
/// Storage and custody faults.
pub(crate) fn retire_scope_keys(s: &Store, w: &mut RwTxn<'_>, grant: &EntityId) -> Result<()> {
    if s.core.gate_custody_archived() {
        return Ok(());
    }
    let Some(custody) = s.core.key_custody.local() else {
        return Ok(());
    };
    for item in custody.erasable_keys_of(ErasablePurpose::GrantScope, grant.as_bytes())? {
        stage_erasable_retirement_in_txn(s, w, &custody, &item)?;
    }
    Ok(())
}
