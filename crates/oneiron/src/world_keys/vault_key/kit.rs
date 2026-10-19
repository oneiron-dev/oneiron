//! The data-key kit (FIX 4532): the owner's 2-of-3 copy of the vault data key
//! this handle holds, issued on his proof.
//!
//! The key is split by [`issue_vault_key_kit`] over the homes the owner names,
//! at the passphrase cost he asks, on any custody: his will to keep a copy
//! counts wherever the vault runs, a hosted vault's included, and the kit is
//! a copy, never a claim of host-blindness. Nothing is written: no key is
//! minted, rotated or wrapped, no raw key leaves this handle except split
//! into the pieces, and the world kit and its `world-kit` escrow wrap stay as
//! they are.

use super::STATE;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::recovery::{KitIssue, KitManifest, KitPiece, issue_vault_key_kit};
use crate::world_keys::kit::{kit_refused, resolve_homes};
use crate::world_keys::refused;

/// A data-key kit just issued: its pieces for the owner to place, and its
/// public facts. Nothing is stored or published.
#[derive(Debug)]
pub struct IssuedVaultKeyKit {
    /// The vault id the data key, its wraps and the kit are bound to
    /// ([`Vault::vault_key_vault_id`]): a restore names it.
    pub vault_id: [u8; 32],
    pub manifest: KitManifest,
    /// The stored pieces in x order. A passphrase home has none.
    pub pieces: Vec<KitPiece>,
}

impl Vault {
    /// Issues a kit of the vault data key this handle holds, on `owner`'s
    /// request. The owner proof, the key's commitment and the machine roster
    /// are read in one snapshot: the proof must still hold, and the
    /// commitment must name the held key. The vault id `issue` names must be
    /// the one the key is bound to. `only_machine` comes from the roster,
    /// never the caller, and a home naming this machine's own id is read as
    /// this machine, as a world kit's homes are. The homes and the cost are
    /// the owner's as `issue` names them.
    ///
    /// # Errors
    ///
    /// A key this handle does not hold (unlock it first) or the vault does
    /// not have; an owner proof that no longer holds; another vault's id; a
    /// held key the commitment does not name; and every kit refusal by its
    /// fixed reason, never piece bytes.
    pub fn issue_vault_key_recovery_kit_as(
        &self,
        owner: &AuthenticatedOwner,
        issue: &KitIssue<'_>,
    ) -> Result<IssuedVaultKeyKit> {
        let key = self
            .held_vault_key()
            .ok_or_else(|| refused("the vault key is not held on this handle: unlock it first"))?;
        let vault_id = self.vault_key_vault_id();
        let (only_machine, me) = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            let state = STATE
                .get(&self.store, &txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?;
            if key.commitment(&vault_id) != state.commitment {
                return Err(refused(
                    "the held key is not the one this vault's commitment names",
                ));
            }
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let me = crate::identity::read_machine_id_in_txn(self, &txn)?;
            let others = fold
                .machines
                .keys()
                .any(|machine| Some(*machine) != me && fold.trusted_machine(*machine).is_some());
            (!others, me)
        };
        if issue.vault_id != vault_id {
            return Err(refused("the kit names another vault"));
        }
        let homes = resolve_homes(&issue.homes, me)?;
        let kit = issue_vault_key_kit(
            &self.config.privacy,
            &KitIssue {
                vault_id,
                homes,
                passphrase: issue.passphrase,
                cost: issue.cost,
                only_machine,
            },
            &key.0,
        )
        .map_err(kit_refused)?;
        Ok(IssuedVaultKeyKit {
            vault_id,
            manifest: kit.manifest().clone(),
            pieces: kit.into_pieces(),
        })
    }
}
