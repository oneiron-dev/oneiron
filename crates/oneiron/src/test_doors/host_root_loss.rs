//! Door for a lost host root (L1-07; OF-570): a stopped vault whose install
//! lost its host issuer seed and whose key custody can give none back, the
//! one state `oneiron host recover-root` exists for.

use crate::{Result, Vault};

/// Empties this install's host issuer seed slot for `vault` and retires every
/// escrowed generation of the seed. The vault must have its keystore
/// installed and this install's signing keys loaded
/// (`Vault::prepare_install_signing`). After it, no seed of the live root is
/// held here or escrowed: only a root move signed by another live owner key
/// gives the vault a root this install holds.
pub fn lose_host_issuer_seed(vault: &Vault) -> Result<()> {
    vault.lose_host_issuer_seed_for_test()
}
