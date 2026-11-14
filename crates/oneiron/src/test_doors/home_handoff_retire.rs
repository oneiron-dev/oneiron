//! Fixture doors for the home handoff retire purpose test (FIX 23943):
//! erasable keys of two purposes in one vault's custody, the holder's
//! retire half that a peer's `home_handoff_retire` request reaches once the
//! peer is proven an owner machine, and where each key stands after.

use crate::error::{Error, Result};
use crate::store::grant_scope_custody;
use crate::store::home_handoff_custody::{self, Incarnation, KeyRef, KeyState};
use crate::{EntityId, Vault};

/// The export incarnation the fixture's home handoff key is minted for.
const HANDOFF_INCARNATION: [u8; 32] = [0x48; 32];

/// The pact the fixture's scope opening key opens, at epoch 1.
const PACT_ID: [u8; 32] = [0x47; 32];

/// Where one erasable key stands in this vault's custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErasableKeyState {
    Live,
    /// An erase staged its retirement; the finisher has not run yet.
    Staged,
    Retired,
    /// No entry here.
    Missing,
}

/// Mints a home handoff key for `actor` in its own writer, as an export
/// does, and returns its ref as 64 lowercase hex digits.
///
/// # Errors
///
/// Custody and storage faults.
pub fn mint_home_handoff_key(vault: &Vault, actor: EntityId) -> Result<String> {
    let key = vault.with_write_txn(|txn| {
        home_handoff_custody::mint(
            &vault.store,
            txn,
            Incarnation::from_bytes(HANDOFF_INCARNATION),
            actor,
        )
    })?;
    Ok(key.to_hex())
}

/// Installs a fresh scope opening key for `grant`'s pact in its own writer,
/// as an accepted Connect does, and returns its ref as 64 lowercase hex
/// digits.
///
/// # Errors
///
/// Custody and storage faults; custody holding other than exactly one
/// opening key for `grant` after the install.
pub fn install_grant_scope_key(vault: &Vault, grant: EntityId) -> Result<String> {
    let key = grant_scope_custody::new_scope_key()?;
    vault.with_write_txn(|txn| {
        grant_scope_custody::install_scope_key(&vault.store, txn, &grant, &PACT_ID, 1, &key)
    })?;
    match home_handoff_custody::grant_scope_refs_for_test(&vault.store, &grant)?.as_slice() {
        [only] => Ok(only.to_hex()),
        _ => Err(Error::InvariantViolation(
            "the fixture's grant holds other than one scope opening key",
        )),
    }
}

/// The holder's retire half of the home handoff, at `requester`'s word, for
/// `keys`: what `oneiron::sync::residence::home_handoff_retire` runs after
/// it proves the peer an owner machine.
///
/// # Errors
///
/// Whatever the retire half refuses, and storage and custody faults.
pub fn retire_held(vault: &Vault, requester: EntityId, keys: &[String]) -> Result<u32> {
    crate::sync::home_handoff::retire_held(vault, requester, keys)
}

/// Where the key `key` (64 lowercase hex digits) stands in this vault's
/// custody, whatever its purpose.
///
/// # Errors
///
/// A ref in another spelling; custody faults.
pub fn erasable_key_state(vault: &Vault, key: &str) -> Result<ErasableKeyState> {
    Ok(
        match home_handoff_custody::key_state(&vault.store, KeyRef::from_hex(key)?)? {
            KeyState::Live => ErasableKeyState::Live,
            KeyState::Staged => ErasableKeyState::Staged,
            KeyState::Retired => ErasableKeyState::Retired,
            KeyState::Missing => ErasableKeyState::Missing,
        },
    )
}
