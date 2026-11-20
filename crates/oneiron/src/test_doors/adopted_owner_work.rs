//! The adopted owner-work door (FIX [OWNER-RESERVE-ADOPTED-OWNER-WORK]): an
//! install's machine on a fresh install of the same vault that holds none of
//! its rows, so a test shows the reserve take a request this machine
//! carried, held there only through an adopted checkpoint image, as the
//! owner's work. Compiled only under `--cfg oneiron_test_support`; never API.

use ed25519_dalek::SigningKey;

use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// This install's machine signing key, loaded from its keystore slot (its
/// machine identity minted first when it has none), so a test signs a row
/// under it as this install's doors sign the rows it carries.
///
/// # Errors
///
/// No keystore, or a slot the keys do not load from; storage errors.
pub fn this_install_machine_key(vault: &Vault) -> Result<SigningKey> {
    vault.prepare_install_signing()?;
    let txn = vault.store.env.read_txn()?;
    crate::identity::read_machine_signing_key_in_txn(vault, &txn)?.ok_or(Error::InvariantViolation(
        "this install holds no machine key",
    ))
}

/// Gives `vault`, a fresh install that holds no machine identity yet, the
/// machine `machine`, before its signing keys load. Opened under the storage
/// id of the install that is `machine`, with that install's keystore, it
/// loads the same keys: the same machine, holding none of its rows.
///
/// # Errors
///
/// An install that already holds a machine identity; storage errors.
pub fn take_machine_identity(vault: &Vault, machine: EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    if crate::identity::read_machine_id_in_txn(vault, &wtxn)?.is_some() {
        return Err(Error::InvariantViolation(
            "this install already holds a machine identity",
        ));
    }
    crate::store::install_identity::MACHINE_ID.put(
        &vault.store,
        &mut wtxn,
        &(),
        &machine.as_bytes().to_vec(),
    )?;
    wtxn.commit()?;
    Ok(())
}
