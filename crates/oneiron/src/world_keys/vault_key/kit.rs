//! The data-key kit (FIX 4532): the owner's 2-of-3 copy of the vault data key
//! this handle holds, issued on his proof, and the door that takes its pieces
//! back (FIX 5614).
//!
//! The key is split by [`issue_vault_key_kit`] over the homes the owner names,
//! at the passphrase cost he asks, on any custody: his will to keep a copy
//! counts wherever the vault runs, a hosted vault's included, and the kit is
//! a copy, never a claim of host-blindness. No key is minted, rotated or
//! wrapped, no raw key leaves this handle except split into the pieces, and
//! the world kit and its `world-kit` escrow wrap stay as they are. The kit's
//! public facts go into the kit inventory with no root
//! ([`StoredKit`](crate::world_keys::StoredKit)): it is issued and stays so,
//! never pending, current or replaced.
//!
//! Its pieces come back as
//! [`VaultKeyUnlock::Kit`](super::VaultKeyUnlock::Kit): two, or one and the
//! kit passphrase, rebuild the key bound to the vault id the owner names. It
//! opens only when that id is the vault's and the key is the one the vault's
//! commitment names, so a restore on a new host, `vault-key add-device` and
//! a sealed vault's pages open on it with no wrap carried. The commitment is
//! what authenticates a key one piece and the passphrase rebuilt. No
//! inventory row is read for it: a fresh host lists nothing.
//!
//! A `ThisMachine` home's piece stays in this install's key slots, replacing
//! the piece an earlier data-key kit kept there, and the unlock here reads it
//! back as one of the pieces (FIX 2063).

use super::{STATE, VaultDataKey};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::recovery::{
    KitIssue, KitManifest, KitPassphrase, KitPiece, KitSecretKind, RestoredKitSecret,
    issue_vault_key_kit, restore_kit,
};
use crate::world_keys::kit::{kit_refused, resolve_homes};
use crate::world_keys::kit_piece::keep_this_machine_piece;
use crate::world_keys::refused;

/// A data-key kit just issued: its pieces for the owner to place, and its
/// public facts. Nothing secret is stored or published.
#[derive(Debug)]
pub struct IssuedVaultKeyKit {
    /// The vault id the data key, its wraps and the kit are bound to
    /// ([`Vault::vault_key_vault_id`]): a restore names it.
    pub vault_id: [u8; 32],
    pub manifest: KitManifest,
    /// The pieces to hand out, in x order. A passphrase home has none, and a
    /// `ThisMachine` home's piece is in this install's key slots (FIX 2063).
    pub pieces: Vec<KitPiece>,
    /// Whether the kit's public facts went into the kit inventory. The
    /// pieces open the key either way; a vault that took no write keeps no
    /// row of it.
    pub listed: bool,
}

/// The vault data key the data-key kit's `pieces` rebuild for the vault
/// `vault_id`, checked against `commitment`, its key's. `named` is the id the
/// owner names the kit by: another vault's is refused before any passphrase
/// work. Every kit refusal names its fixed reason, never piece bytes.
pub(super) fn open_kit(
    vault_id: &[u8; 32],
    commitment: &[u8; 32],
    named: &[u8; 32],
    pieces: &[KitPiece],
    passphrase: Option<&KitPassphrase>,
) -> Result<VaultDataKey> {
    if named != vault_id {
        return Err(refused("the kit names another vault"));
    }
    let pieces: Vec<&KitPiece> = pieces.iter().collect();
    let secret = restore_kit(*vault_id, KitSecretKind::VaultKey, &pieces, passphrase)
        .map_err(kit_refused)?;
    committed_key(vault_id, commitment, secret)
}

/// The data key a kit rebuilt for the vault `vault_id`, held only when it is
/// the key `commitment` names.
fn committed_key(
    vault_id: &[u8; 32],
    commitment: &[u8; 32],
    secret: RestoredKitSecret,
) -> Result<VaultDataKey> {
    let key = VaultDataKey(secret.into_bytes());
    if key.commitment(vault_id) != *commitment {
        return Err(refused(
            "the kit opens to another key than the one this vault's commitment names",
        ));
    }
    Ok(key)
}

impl Vault {
    /// Issues a kit of the vault data key this handle holds, on `owner`'s
    /// request. The owner proof, the key's commitment and the machine roster
    /// are read in one snapshot: the proof must still hold, and the
    /// commitment must name the held key. The vault id `issue` names must be
    /// the one the key is bound to. `only_machine` comes from the roster,
    /// never the caller, and a home naming this machine's own id is read as
    /// this machine, as a world kit's homes are. The homes and the cost are
    /// the owner's as `issue` names them. A `ThisMachine` home's piece goes
    /// to this install's key slots before the listing, and the other homes'
    /// pieces are returned (FIX 2063). The kit's public facts are then
    /// listed in the inventory, the owner rechecked in that write; a write
    /// that does not go through leaves the kit issued and unlisted.
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
        let store = self.this_machine_piece_store(&issue.homes)?;
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
        let manifest = kit.manifest().clone();
        let pieces = keep_this_machine_piece(store.as_ref(), kit.into_pieces())?;
        // The pieces never depend on the row: a write refused here (a vault
        // that takes none, a proof gone since the snapshot) is said, and the
        // kit is handed over all the same.
        let listed = match self
            .with_write_txn(|txn| self.list_vault_key_kit_in_txn(txn, owner, &manifest))
        {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "the data-key kit was issued and not listed in the kit inventory"
                );
                false
            }
        };
        Ok(IssuedVaultKeyKit {
            vault_id,
            manifest,
            pieces,
            listed,
        })
    }

    /// Unlocks the vault data key with the data-key kit's pieces: two, or one
    /// and the kit passphrase, bound to `vault_id`, the id the owner names.
    /// The key they rebuild is held only when `vault_id` is this vault's and
    /// the key is the one the vault's commitment names. No wrap opens and
    /// none is needed: a vault restored from an artifact opens on the kit as
    /// on a wrap it carries. This machine's own piece of the kit, when it
    /// keeps one, joins `pieces` (FIX 2063).
    ///
    /// # Errors
    ///
    /// A vault with no data key; another vault's id; every kit refusal by its
    /// fixed reason, never piece bytes; and a key the commitment does not
    /// name.
    pub fn unlock_vault_key_with_kit(
        &self,
        vault_id: &[u8; 32],
        pieces: &[KitPiece],
        passphrase: Option<&KitPassphrase>,
    ) -> Result<()> {
        let commitment = {
            let txn = self.store.env.read_txn()?;
            STATE
                .get(&self.store, &txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?
                .commitment
        };
        let own = self.vault_key_vault_id();
        if *vault_id != own {
            return Err(refused("the kit names another vault"));
        }
        let pieces: Vec<&KitPiece> = pieces.iter().collect();
        let secret = self
            .restore_kit_here(own, KitSecretKind::VaultKey, &pieces, passphrase)
            .map_err(kit_refused)?;
        let key = committed_key(&own, &commitment, secret)?;
        self.hold_vault_key(key);
        Ok(())
    }
}
