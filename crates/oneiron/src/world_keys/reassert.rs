//! The owner's re-assertion of one world after a pin change (contract §4).
//!
//! A pin door only reports a world whose settings the change made differ;
//! it never edits one. The owner signs the world's settings again from a
//! machine that holds it, and the same transaction opens that world's keys
//! from this machine's own records (a pin door's pre-wraps among them) and
//! wraps each again under the current pin, so the key id survives. Only
//! then may `ensure_world_key` mint a fresh one.

use std::collections::BTreeSet;

use super::pads::pad_in_txn;
use super::{
    PolicyRevision, SequenceCounter, WorldKeyBinding, WorldKeyId, WrapRecipient, open_world_key,
    recipients, refused,
};
use crate::authority::{
    ActSurface, Destination, EditOrigin, EffectiveRead, WorldPrivacy, own_world_key_records_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::policy_model::WorldPrivacyReceipt;
use crate::{EntityId, Vault};

impl Vault {
    /// Re-asserts one world's complete settings, which the owner chose, on
    /// this machine only. This machine must be mine under the pin and hold
    /// the world's live WORLD row, and `expected` must be the world's current
    /// settings revision; the settings edit itself needs no standing (mesh
    /// contract §3).
    /// One settings edit with its receipt, the re-wraps and the world's key,
    /// in one transaction. The engine never calls it on its own.
    pub fn reassert_world_privacy(
        &self,
        owner: &AuthenticatedOwner,
        origin: EditOrigin,
        world: EntityId,
        settings: WorldPrivacy,
        expected: PolicyRevision,
    ) -> Result<WorldPrivacyReceipt> {
        if origin != EditOrigin::ThisMachine {
            return Err(refused("only this machine re-asserts its worlds"));
        }
        let secret = self.machine_secret_outside_txn()?;
        let (_release, receipt) = self.with_write_txn(|txn| {
            let release = self
                .store
                .device_only_flag_lock
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let signing = self.door_signing_key_in_txn(txn, secret.machine)?;
            let my_key = signing.verifying_key().to_bytes();
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let mine = |fold: &crate::authority::AuthorityFold| {
                fold.trusted_machine(secret.machine)
                    .is_some_and(|trusted| trusted.profile.machine_key == my_key)
            };
            if !mine(&fold) {
                return Err(refused("this machine is not one of the owner's here"));
            }
            if !self.world_row_live_in_txn(txn, world)? {
                return Err(refused("the world has no live WORLD row here"));
            }
            let current = PolicyRevision::of(
                fold.worlds
                    .get(&world)
                    .into_iter()
                    .flat_map(|folded| folded.live.keys().copied()),
            );
            if current != expected {
                return Err(refused("the world's settings changed since they were read"));
            }
            let receipt = self.set_world_privacy_in_txn(
                txn,
                owner,
                ActSurface::ThisInstall,
                world,
                settings,
                Some(expected),
            )?;
            // The world's keys this machine wrapped itself, wrapped again
            // under the current pin and the settings after the edit.
            let after = self.authority_view_readonly_in_txn(txn)?;
            let reads = mine(&after)
                && after.world_privacy(world).read != EffectiveRead::Everywhere
                && after.world_readable_on(world, Destination::Machine(secret.machine));
            if reads {
                let vault_id = after
                    .vault_id
                    .ok_or_else(crate::authority::invalid_authority)?;
                let own =
                    own_world_key_records_in_txn(&self.store, txn, &after, secret.machine, my_key)?;
                let root = self.pinned_root_recipient_in_txn(txn, &after)?;
                let me = WrapRecipient::Machine(secret.machine);
                let ids: BTreeSet<WorldKeyId> = own
                    .iter()
                    .map(|(_, record)| record.key)
                    .filter(|id| id.world == world)
                    .collect();
                let mut seq = SequenceCounter::new();
                let mut appended = Vec::new();
                for id in ids {
                    let held = after.world_key(&id);
                    if held.is_some_and(|held| held.conflicted) {
                        continue;
                    }
                    let Some(pad) = pad_in_txn(&self.store, txn, &id)? else {
                        continue;
                    };
                    let opened = own
                        .iter()
                        .map(|(_, record)| record)
                        .filter(|record| {
                            record.key == id
                                && held.is_none_or(|held| held.commitment == record.commitment)
                        })
                        .find_map(|record| {
                            let (_, bytes) = record.wraps.iter().find(|(to, _)| *to == me)?;
                            let envelope = oneiron_crypto::Envelope::parse(bytes).ok()?;
                            let binding = WorldKeyBinding {
                                vault_id,
                                key: id,
                                owner: record.owner,
                                policy: record.policy,
                                commitment: record.commitment,
                            };
                            open_world_key(&binding, me, &secret.secret, &envelope, &pad)
                                .ok()
                                .map(|key| (key, record.owner))
                        });
                    let Some((key, key_owner)) = opened else {
                        continue;
                    };
                    let missing: Vec<_> = recipients(&after, world, root.clone())
                        .into_iter()
                        .filter(|(to, _)| !held.is_some_and(|held| held.wraps.contains_key(to)))
                        .collect();
                    appended.extend(
                        self.append_world_key_wraps_in_txn(
                            txn,
                            &after,
                            &signing,
                            secret.machine,
                            &key,
                            key_owner,
                            &missing,
                            &mut seq,
                        )?
                        .map_err(super::doors::FrontierWide::refused)?,
                    );
                }
                self.require_counted_in_txn(txn, &appended)?;
            }
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let status = self.world_key_for_edit_in_txn(txn, actor, world, Ok(&secret))?;
            let receipt = self.settle_world_key_work_in_txn(txn, owner, receipt, status)?;
            Ok((release, receipt))
        })?;
        Ok(receipt)
    }
}
