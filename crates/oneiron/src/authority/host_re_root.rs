//! A self-host root move to a new host secret, in-chain (OF-455).
//!
//! The current root signs one ReRoot for the new secret's key, so the vault
//! keeps its genesis and its id. A ReRoot retires every key on the roster, so
//! the same transaction carries what the vault needs to keep working under the
//! new root: its host root slip, the engine writers that were live, and the
//! MACHINE claim histories that were readable. Every slip the old root minted
//! stops verifying (OF-455: "existing slips on the old host fail verification
//! against the new root"); the holders get new ones from the new root.
use super::slip_vault::require_host;
use super::*;
use crate::claim::history_projection::{
    PIN_PREFIX, trusted_machine_handoff, verified_handoff_chain,
};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::{EntityId, Vault};
use rand_core::{OsRng, RngCore};

/// What a host re-root changed, for the owner's report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HostReRoot {
    pub vault_id: AuthorityVaultId,
    /// Engine writers enrolled again under keys the new secret derives.
    pub writers_enrolled: usize,
    /// MACHINE claim histories the new root carried.
    pub histories_carried: usize,
    /// Pinned histories that were not readable before the move and stay so.
    pub histories_left: usize,
    /// Live slips the old root minted, other than its own root slip. None of
    /// them verifies now.
    pub retired_slips: Vec<RetiredSlip>,
}

/// A credential the re-root retired: its holder needs a new one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetiredSlip {
    pub slip_id: [u8; 32],
    pub holder_ref: String,
    pub actor_class: Option<String>,
}

impl Vault {
    /// Moves the host root from `current` to `next` in one transaction, on a
    /// vault no server holds. `current` must be the live root and `next` a
    /// key the vault has never seen. Engine writers whose binding an owner
    /// revoked, and histories that were quarantined, are left as they were.
    pub fn re_root_host(
        &self,
        current: &HostSlipIssuer,
        next: &HostSlipIssuer,
    ) -> Result<HostReRoot> {
        if self.privacy_posture() == crate::HostingPrivacyPosture::Relay {
            return Err(invalid_authority());
        }
        // Writer rows are created in their own transactions, before this one.
        let engine_writers = self.engine_machine_actors()?;
        let mut txn = self.store.env.write_txn()?;
        let before = self.authority_fold_readonly_in_txn(&txn)?;
        require_host(&before, current)?;
        if before.roster.contains_key(&next.public_key()) {
            return Err(invalid_authority());
        }
        let vault_id = before.vault_id.ok_or_else(invalid_authority)?;
        let writers: Vec<EntityId> = engine_writers
            .into_iter()
            .filter(|machine| {
                before.actor_bindings.iter().any(|(key, binding)| {
                    binding.actor_ref == *machine
                        && binding.actor_class == "system"
                        && binding.status == ActorBindingStatus::Active
                        && before.roster.get(key).is_some_and(|device| !device.revoked)
                })
            })
            .collect();
        let mut carried = Vec::new();
        let mut histories_left = 0;
        for target in pinned_machine_history_targets(&self.store, &txn)? {
            if self.machine_target_admitted_in_txn(&txn, &before, target)? {
                carried.push(target);
            } else {
                histories_left += 1;
            }
        }
        let now = self.instant_in_txn(&txn)?;
        let retired_slips = before
            .slips
            .mints
            .iter()
            .filter(|(id, mint)| {
                mint.signer == current.public_key()
                    && mint.action.claims.holder_ref != "host"
                    && before.slip_is_live_at(id, now)
            })
            .map(|(id, mint)| RetiredSlip {
                slip_id: *id,
                holder_ref: mint.action.claims.holder_ref.clone(),
                actor_class: mint.action.claims.actor_class.clone(),
            })
            .collect();

        self.re_root_authority_in_txn(
            &mut txn,
            next.root_device(),
            current.public_key(),
            |transcript| Ok(current.sign_slip(transcript)),
        )?;
        // The new root's first entry: its sequence is what enrollment extends.
        self.ensure_host_root_slip_in_txn(&mut txn, next)?;
        for machine in &writers {
            self.enroll_engine_machine_in_txn(&mut txn, next, &vault_id, *machine)?;
        }
        for target in &carried {
            let mut challenge = [0; 32];
            OsRng.fill_bytes(&mut challenge);
            self.carry_machine_history_in_txn(&mut txn, *target, next, challenge)?;
        }
        txn.commit()?;
        Ok(HostReRoot {
            vault_id,
            writers_enrolled: writers.len(),
            histories_carried: carried.len(),
            histories_left,
            retired_slips,
        })
    }

    /// Whether the claim a pinned history projects is readable now.
    fn machine_target_admitted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        target: EntityId,
    ) -> Result<bool> {
        let Some(raw) = self.store.entities.get(txn, target.as_bytes())? else {
            return Ok(false);
        };
        if crate::batch::EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_CLAIM)
        {
            return Ok(false);
        }
        let Ok(body) =
            crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
        else {
            return Ok(false);
        };
        super::claim_write::claim_causal_admitted(&self.store, txn, fold, &target, &body)
    }
}

/// Whether a MACHINE birth whose signing key a ReRoot retired still reads:
/// the key stayed bound to `actor` as a writer and was never revoked as an
/// actor, and a live root carried the birth's history at the very ReRoot
/// that made it root. A writer's actor revoke stays terminal across a move.
pub(super) fn origin_carried_past_re_root(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
    key: &AuthorityKey,
    actor: EntityId,
) -> bool {
    fold.actor_bindings
        .get(key)
        .is_some_and(|binding| binding.actor_ref == actor && binding.actor_class == "system")
        && fold.roster.get(key).is_some_and(|device| {
            device.revoked
                && device.tier == AuthorityTier::Software
                && device.roles & ROLE_AGENT != 0
        })
        && !fold.revoked_actor_keys.contains(key)
        && carried_by_live_root(store, txn, fold, target).unwrap_or(false)
}

fn carried_by_live_root(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
) -> Result<bool> {
    let tip = trusted_machine_handoff(store, txn, target)?;
    for packet in verified_handoff_chain(store, txn, &tip, fold)? {
        if packet.previous_handoff_hash.is_some()
            && fold.valid_entries.contains(&packet.authority_head)
            && fold
                .roster
                .get(&packet.signer)
                .is_some_and(|root| !root.revoked && root.roles & ROLE_OWNER != 0)
            && head_re_roots_to(store, txn, &packet.authority_head, &packet.signer)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the logged entry `head` is the ReRoot that made `key` the root.
fn head_re_roots_to(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    head: &AuthorityEntryHash,
    key: &AuthorityKey,
) -> Result<bool> {
    let id = authority_log_entity_id_from_hash(head)?;
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .ok_or(Error::CorruptedIndex("authority head header"))?;
    let entry = decode_authority_log_entry_body(body)?;
    Ok(authority_entry_hash(&entry)? == *head
        && matches!(&entry.op, AuthorityOp::ReRoot { new_device } if new_device.key == *key))
}

/// Every target with a trusted history pin, readable or not.
fn pinned_machine_history_targets(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Vec<EntityId>> {
    let mut targets = Vec::new();
    for row in store.vault_meta.prefix_iter(txn, PIN_PREFIX)? {
        let (key, _) = row?;
        let bytes: [u8; 16] = key[PIN_PREFIX.len()..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("machine history pin"))?;
        targets.push(EntityId::from_bytes(bytes)?);
    }
    Ok(targets)
}
