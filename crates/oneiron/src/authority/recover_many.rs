//! M-vault recovery (OF-169): each vault recovers on its own chain. No share
//! spans vaults, since one would be a person root by another name; recover-all
//! is M independent recoveries, run here one after another, each judged and
//! committed by its own vault's door, with one outcome per vault. A refusal on
//! one vault never stops another. The UI chains its ceremony over this.
use std::collections::{BTreeMap, BTreeSet};

use super::{AuthorityVaultId, HostReRoot, HostSlipIssuer};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::world_keys::{KitConfirmation, RecoveryRootSeed, RootRestore};

/// One vault's own recovery proof.
#[non_exhaustive]
pub enum VaultRecoveryProof<'a> {
    /// The in-chain host re-root ([`Vault::re_root_host`]).
    HostReRoot {
        current: &'a HostSlipIssuer,
        next: &'a HostSlipIssuer,
    },
    /// The vault's own printed kit ([`Vault::restore_world_keys`]), on this
    /// machine.
    KitRestore {
        owner: &'a AuthenticatedOwner,
        seed: &'a RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
    },
}

/// One step of a recover-many run: a vault and its own proof. A vault may
/// take several steps, a re-root and then its kit, in the order given.
pub struct VaultRecoveryStep<'a> {
    pub vault: &'a Vault,
    pub proof: VaultRecoveryProof<'a>,
}

/// What one vault's own door did.
#[derive(Debug)]
#[non_exhaustive]
pub enum VaultRecovered {
    ReRooted(HostReRoot),
    KeysRestored(RootRestore),
}

/// One step's outcome, in step order.
#[derive(Debug)]
#[non_exhaustive]
pub struct VaultRecoveryOutcome {
    /// The vault's id, where its authority log names one.
    pub vault_id: Option<AuthorityVaultId>,
    pub result: Result<VaultRecovered>,
}

/// Runs each step through its vault's own door and reports every vault. A
/// kit seed offered for more than one vault is refused on each of them
/// before any door runs: kits are per vault, so a seed two vaults share is
/// the master share M-vault recovery forbids.
pub fn recover_vaults(steps: Vec<VaultRecoveryStep<'_>>) -> Vec<VaultRecoveryOutcome> {
    let vault_ids: Vec<Option<AuthorityVaultId>> = steps
        .iter()
        .map(|step| step.vault.recovery_vault_id().ok().flatten())
        .collect();
    let mut seed_vaults = BTreeMap::<[u8; 32], BTreeSet<Option<AuthorityVaultId>>>::new();
    for (step, vault_id) in steps.iter().zip(&vault_ids) {
        if let VaultRecoveryProof::KitRestore { seed, .. } = &step.proof {
            seed_vaults
                .entry(seed_fingerprint(seed))
                .or_default()
                .insert(*vault_id);
        }
    }
    steps
        .into_iter()
        .zip(vault_ids)
        .map(|(step, vault_id)| {
            let result = match step.proof {
                VaultRecoveryProof::KitRestore { seed, .. }
                    if seed_vaults
                        .get(&seed_fingerprint(seed))
                        .is_some_and(|vaults| vaults.len() > 1) =>
                {
                    Err(crate::world_keys::refused(
                        "one recovery kit is offered for more than one vault",
                    ))
                }
                VaultRecoveryProof::KitRestore {
                    owner,
                    seed,
                    confirm,
                } => step
                    .vault
                    .restore_world_keys(owner, seed, confirm)
                    .map(VaultRecovered::KeysRestored),
                VaultRecoveryProof::HostReRoot { current, next } => step
                    .vault
                    .re_root_host(current, next)
                    .map(VaultRecovered::ReRooted),
            };
            VaultRecoveryOutcome { vault_id, result }
        })
        .collect()
}

/// A seed's identity across a run, never its bytes.
fn seed_fingerprint(seed: &RecoveryRootSeed) -> [u8; 32] {
    blake3::derive_key(
        "oneiron/recover-many/seed-fingerprint/v1",
        &seed.kit_bytes()[..],
    )
}

impl Vault {
    /// The id this vault's authority log names, read for a recovery report.
    fn recovery_vault_id(&self) -> Result<Option<AuthorityVaultId>> {
        let txn = self.store.env.read_txn()?;
        Ok(self.authority_fold_readonly_in_txn(&txn)?.vault_id)
    }
}
