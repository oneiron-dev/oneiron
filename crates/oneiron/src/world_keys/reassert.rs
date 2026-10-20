//! The owner's re-assertion of one world after a pin change (contract §4).
//!
//! A pin door only reports a world whose settings the change made differ;
//! it never edits one. The owner signs the world's settings again from any
//! surface where he is authenticated, carried by any live linked install
//! (mesh contract §3; the surface is audit only), and the same transaction
//! does the world's key work or records it for a holder:
//! - an install that holds the world wraps its own keys of it again under
//!   the current pin, so each key id survives, and only then ensures the
//!   world's key ([`holder`]);
//! - any other install, or a holder whose own records left the work
//!   incomplete, records an owner work request in Reassert mode naming one
//!   that holds it, on the same receipt. It never mints in a holder's place
//!   (CALLS WORLD_KEY_REASSERT_MODE), and the receipt says "awaiting a
//!   holder" (CALLS WORLD_KEY_REASSERT_INCOMPLETE).
//!
//! No location rule reads anything here. What stays is real: only an
//! eligible reader opens or wraps a key, and every wrap stays within the
//! owner's read choice.

mod holder;

use super::refused;
use crate::authority::{
    ActSurface, AuthorityFold, Destination, EffectiveRead, KeyWork, OwnerWorkBody, PolicyRevision,
    WorldKeyMode, WorldPrivacy,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::policy_model::WorldPrivacyReceipt;
use crate::{EntityId, Vault};

pub(super) use self::holder::{
    HeldKey, HolderRead, ReassertIncomplete, WORLD_KEY_REASSERT_INCOMPLETE,
};

impl Vault {
    /// Re-asserts one world's complete settings, which the owner chose, from
    /// `surface`, recorded for audit only. The world must keep its live
    /// WORLD row here and `expected` must be its current settings revision.
    /// This install carries the act under any live profile of the vault; it
    /// needs neither the world nor a key of it, and a missing machine secret
    /// is no refusal. One settings edit with its receipt, and either the
    /// re-wraps and the world's key (this install holds the world) or an
    /// owner work request naming a holder (it does not), in one transaction.
    /// The engine never calls it on its own.
    pub fn reassert_world_privacy(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        world: EntityId,
        settings: WorldPrivacy,
        expected: PolicyRevision,
    ) -> Result<WorldPrivacyReceipt> {
        // The install signer is prepared before the writer. The machine
        // secret is a holder's alone: without one this install records the
        // work for a holder.
        self.load_install_signing_if_minted()?;
        let secret = self.machine_secret_outside_txn().ok();
        let (_release, receipt) = self.with_write_txn(|txn| {
            let release = self
                .store
                .device_only_flag_lock
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Key possession: this install signs with its own install key,
            // under the machine its secret was read for when it has one.
            let signer = match &secret {
                Some(secret) => Some(self.door_signing_key_in_txn(txn, secret.machine)?),
                None => crate::identity::read_machine_signing_key_in_txn(self, txn)?,
            }
            .ok_or_else(|| refused("this install has no machine key"))?;
            let my_key = signer.verifying_key().to_bytes();
            if !self.world_row_live_in_txn(txn, world)? {
                return Err(refused("the world has no live WORLD row here"));
            }
            let fold = self.authority_view_readonly_in_txn(txn)?;
            if fold.world_policy_revision(world) != expected {
                return Err(refused("the world's settings changed since they were read"));
            }
            let receipt = self.set_world_privacy_in_txn(
                txn,
                owner,
                surface,
                world,
                settings,
                Some(expected),
            )?;
            let after = self.authority_view_readonly_in_txn(txn)?;
            let holder = secret
                .as_ref()
                .filter(|secret| holds(&after, world, secret.machine, &my_key));
            let done = match holder {
                Some(secret) => self
                    .reassert_held_world_keys_in_txn(txn, world, secret, None)?
                    .ensures()
                    .then_some(secret),
                None => None,
            };
            let receipt = match done {
                Some(secret) => {
                    let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
                    let status = self.world_key_for_edit_in_txn(txn, actor, world, Ok(secret))?;
                    self.settle_world_key_work_in_txn(txn, owner, receipt, status)?
                }
                None => self.record_reassert_work_in_txn(txn, owner, world, receipt)?,
            };
            Ok((release, receipt))
        })?;
        Ok(receipt)
    }

    /// The re-assertion's key work, recorded for a holder on `receipt` in the
    /// same transaction: an owner work request in Reassert mode for the
    /// settings revision right after the edit, signed by this install as the
    /// carrier of `owner`'s act, and where it stands. A world read everywhere
    /// needs no key work. The key work awaits a holder, never enacted here
    /// (CALLS WORLD_KEY_REASSERT_INCOMPLETE).
    fn record_reassert_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        world: EntityId,
        mut receipt: WorldPrivacyReceipt,
    ) -> Result<WorldPrivacyReceipt> {
        if receipt.next.read == EffectiveRead::Everywhere {
            return Ok(receipt);
        }
        let seen = self
            .authority_view_readonly_in_txn(txn)?
            .world_policy_revision(world);
        receipt.key_work = KeyWork::AwaitingHolder;
        receipt.owner_work = Some(self.record_owner_work_in_txn(
            txn,
            owner,
            receipt.surface,
            world,
            seen.0,
            OwnerWorkBody::WorldKey {
                mode: WorldKeyMode::Reassert,
            },
        )?);
        self.put_world_privacy_receipt_in_txn(txn, &receipt)?;
        Ok(receipt)
    }
}

/// This install may hold `world`'s key after the edit: the world is private
/// and readable on this machine, mine here under the key it signs with. The
/// owner's recipient choice, never a rule on who decides.
fn holds(fold: &AuthorityFold, world: EntityId, machine: EntityId, key: &[u8; 32]) -> bool {
    fold.world_privacy(world).read != EffectiveRead::Everywhere
        && fold
            .trusted_machine(machine)
            .is_some_and(|trusted| trusted.profile.machine_key == *key)
        && fold.world_readable_on(world, Destination::Machine(machine))
}
