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

use crate::key_custody::files::EntryState;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySecret;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::StoreError;
use oneiron_contracts::entity_id::EntityId;

/// The context a pact id and epoch derive a key incarnation under.
const GRANT_INCARNATION_CONTEXT: &str = "oneiron/grant-scope/erasable-incarnation/v1";

/// The incarnation of the key that keys pact `pact_id` at `epoch`.
pub fn incarnation(pact_id: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(pact_id);
    material[32..].copy_from_slice(&epoch.to_be_bytes());
    blake3::derive_key(GRANT_INCARNATION_CONTEXT, &material)
}

pub fn unknown_key() -> Error {
    CustodyKind::ErasableKey.corrupt()
}

pub fn archived() -> Error {
    Error::Store(StoreError::ArchivedVault)
}

/// A fresh opening key for a pact epoch no custody holds yet: it enters
/// custody when this vault's owner accepts the terms it keys.
///
/// # Errors
/// The random source failed.
pub fn new_scope_key() -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    crate::key_material::os_fill(&mut key[..])?;
    Ok(key)
}
