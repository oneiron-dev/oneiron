//! The owner's doors over the cloud registration's slots: each rechecks the
//! owner proof and live ownership in the writer that commits, and checks the
//! binding's fence there, so a request queued behind a logout, an erase, a
//! replacement or a removed owner changes nothing.
//!
//! A refresh is three commits around one send (L14 lead call, 08:3x): the
//! reservation (`InFlight`) commits before the slot's token leaves the T0
//! door, the door releases its writer before the send, and the successor
//! replaces the token in place, its generation advanced, with the binding
//! back to `Linked` in one commit after. A reservation is never undone into
//! a send: whatever did not commit its successor stays `InFlight` or goes to
//! `NeedsLogin`, and the owner logs in again.

use heed::{RoTxn, RwTxn};
use zeroize::Zeroize;

use super::super::doors::{NAME_INDEX, register_secret_in_txn};
use super::super::read_secret_custody_meta_in_txn;
use super::super::types::{
    CustodyClass, SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyFloor, SecretCustodyRecord,
    SecretCustodyStatus,
};
use super::{
    CloudRegistrationBinding, CloudRegistrationErased, CloudRegistrationFence,
    CloudRegistrationLink, CloudRegistrationLinked, CloudRegistrationPhase,
    CloudRegistrationTokenUse, ROWS, Row, slot_bindings, slot_name,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::secret_lease::DoorInjectionReceipt;
use crate::store::Store;

/// The live owner `owner` proves in `txn`: the actor every act binds.
fn owner_actor_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> Result<EntityId> {
    let actor = owner.revalidate_in_txn(vault, txn)?;
    if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)? {
        return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            "only the vault owner acts on its cloud registration",
        )));
    }
    Ok(actor)
}

/// Every binding row in `txn`, in slot order. A row that does not read is
/// warned and left.
pub(super) fn rows_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<Vec<(EntityId, Row)>> {
    let mut rows = Vec::new();
    for row in ROWS.iter_from(store, txn, &[])? {
        match row {
            Ok(row) => rows.push(row),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "a cloud registration binding row did not read; it is left"
            ),
        }
    }
    Ok(rows)
}

/// `actor`'s current link for `issuer`, the newest when more than one
/// stands.
fn current_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    actor: &EntityId,
    issuer: &str,
) -> Result<Option<(EntityId, Row)>> {
    Ok(rows_in_txn(store, txn)?
        .into_iter()
        .filter(|(_, row)| row.owner == *actor && row.issuer == issuer && row.phase.current())
        .max_by_key(|(_, row)| row.linked_at))
}

/// The row `fence` names, when `actor` linked it, it stands at the fenced
/// generation, and its phase is one of `phases`.
fn fenced_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    actor: &EntityId,
    fence: &CloudRegistrationFence,
    phases: &[CloudRegistrationPhase],
) -> Result<Option<Row>> {
    Ok(ROWS.get(store, txn, &fence.slot)?.filter(|row| {
        row.owner == *actor && row.generation == fence.generation && phases.contains(&row.phase)
    }))
}

/// Stops slot `slot`'s binding at `phase`: its record revoked, its value
/// emptied at rest, its row kept for the owner's erase. A record already
/// gone keeps only its row.
fn retire_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    slot: &EntityId,
    row: &mut Row,
    phase: CloudRegistrationPhase,
    at: u64,
) -> Result<()> {
    if read_secret_custody_meta_in_txn(&vault.store, &*wtxn, slot)?.is_some() {
        crate::secret_rotation::revoke_custody_in_txn(
            vault,
            wtxn,
            slot,
            crate::secret_rotation::RevokeCause::Revoked,
            at,
        )?;
    }
    row.phase = phase;
    row.changed_at = at;
    ROWS.put(&vault.store, wtxn, slot, row)
}

/// Hard-erases slot `slot` in `wtxn`, as a run-bound record's end does:
/// fenced and every key its id names staged to retire before its record,
/// its name and its row go (KS-6 part 2). The finisher retires the keys
/// after the commit.
pub(super) fn erase_slot_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    slot: &EntityId,
) -> Result<()> {
    vault.fence_credential_in_txn(wtxn, slot);
    crate::batch::deindex_entity(&vault.store, wtxn, slot)?;
    let name = slot_name(slot);
    if NAME_INDEX
        .get(&vault.store, &*wtxn, &name)?
        .is_some_and(|entry| entry.id == *slot)
    {
        NAME_INDEX.delete(&vault.store, wtxn, &name)?;
    }
    ROWS.delete(&vault.store, wtxn, slot)?;
    Ok(())
}

/// The record a link stores. Its value is wiped on every path.
struct Held(SecretCustodyRecord);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.value_bytes.zeroize();
    }
}

impl Vault {
    /// The owner's current cloud registration link for `issuer`, value-free;
    /// `None` when the owner has none.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] for a proof that is no
    /// longer the live owner's; storage faults.
    pub fn cloud_registration_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &str,
    ) -> Result<Option<CloudRegistrationBinding>> {
        let txn = self.store.env.read_txn()?;
        let actor = owner_actor_in_txn(self, &txn, owner)?;
        Ok(current_in_txn(&self.store, &txn, &actor, issuer)?
            .map(|(slot, row)| CloudRegistrationBinding::of(slot, &row)))
    }

    /// Links the owner's cloud registration: the owner's explicit login is
    /// the act that maps the verified cloud subject to this owner. In one
    /// commit a new slot takes `tokens` and its binding lands `Linked`; the
    /// owner's current link for the issuer, if any, is replaced and kept for
    /// the owner's erase. A
    /// current link naming another subject is replaced only with `replace`;
    /// without it nothing is stored (CALLS G7_LINK_REPLACEMENT).
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`]; an empty token set;
    /// custody and storage faults.
    pub fn link_cloud_registration_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        link: &CloudRegistrationLink<'_>,
        tokens: &[u8],
        replace: bool,
        at: u64,
    ) -> Result<CloudRegistrationLinked> {
        if tokens.is_empty() {
            return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
                "a cloud registration slot holds its tokens",
            )));
        }
        let slot = self.store.clock.entity_id()?;
        let mut wtxn = self.store.env.write_txn()?;
        let actor = owner_actor_in_txn(self, &wtxn, owner)?;
        let current = current_in_txn(&self.store, &wtxn, &actor, link.issuer)?;
        if let Some((held, row)) = &current
            && row.subject != link.subject
            && !replace
        {
            return Ok(CloudRegistrationLinked::ReplaceRequired {
                current: CloudRegistrationBinding::of(*held, row),
            });
        }
        let replaced = match current {
            Some((held, mut row)) => {
                retire_in_txn(
                    self,
                    &mut wtxn,
                    &held,
                    &mut row,
                    CloudRegistrationPhase::Replaced,
                    at,
                )?;
                Some(CloudRegistrationBinding::of(held, &row))
            }
            None => None,
        };
        let mut rec = Held(SecretCustodyRecord {
            schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
            name: slot_name(&slot),
            class: CustodyClass::CustodyDeviceBound,
            device_only: true,
            value_bytes: tokens.to_vec(),
            status: SecretCustodyStatus::Active,
            registered_at: at,
            rotated_at: None,
            rotation_generation: 0,
            bindings: slot_bindings(),
            manifest_ref: String::new(),
            declared_paths: Vec::new(),
            policy_floor_snapshot: SecretCustodyFloor::resolve(&self.store, &wtxn)?,
        });
        register_secret_in_txn(self, &mut wtxn, &slot, &mut rec.0)?;
        let row = Row {
            owner: actor,
            issuer: link.issuer.to_owned(),
            audience: link.audience.to_owned(),
            subject: link.subject.to_owned(),
            phase: CloudRegistrationPhase::Linked,
            generation: rec.0.rotation_generation,
            linked_at: at,
            changed_at: at,
        };
        ROWS.put(&self.store, &mut wtxn, &slot, &row)?;
        wtxn.commit()?;
        Ok(CloudRegistrationLinked::Linked {
            binding: CloudRegistrationBinding::of(slot, &row),
            replaced,
        })
    }

    /// Reserves a refresh of the link `fence` names: `Linked` becomes
    /// `InFlight`, committed before any token leaves. `None` when the fence
    /// moved: nothing changed.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`]; storage faults.
    pub fn reserve_cloud_registration_refresh_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        fence: &CloudRegistrationFence,
        at: u64,
    ) -> Result<Option<CloudRegistrationBinding>> {
        let mut wtxn = self.store.env.write_txn()?;
        let actor = owner_actor_in_txn(self, &wtxn, owner)?;
        let linked = [CloudRegistrationPhase::Linked];
        let Some(mut row) = fenced_in_txn(&self.store, &wtxn, &actor, fence, &linked)? else {
            return Ok(None);
        };
        row.phase = CloudRegistrationPhase::InFlight;
        row.changed_at = at;
        ROWS.put(&self.store, &mut wtxn, &fence.slot, &row)?;
        wtxn.commit()?;
        Ok(Some(CloudRegistrationBinding::of(fence.slot, &row)))
    }

    /// Hands the slot's token set to `apply` at the T0 door, for `token_use`
    /// alone, once the owner proof, live ownership and the fence (`Linked`
    /// or `InFlight`) hold in the door's own writer. The door releases its
    /// writer before `apply` runs; `apply` returns nothing, and the receipt
    /// carries no value. `None` when the fence moved: nothing was sent.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`]; the door's refusals (a
    /// revoked slot, a value its custody key does not open); `apply`'s own.
    pub fn send_cloud_registration_token_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        fence: &CloudRegistrationFence,
        token_use: CloudRegistrationTokenUse,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Option<DoorInjectionReceipt>> {
        let wtxn = self.store.env.write_txn()?;
        let actor = owner_actor_in_txn(self, &wtxn, owner)?;
        let usable = [
            CloudRegistrationPhase::Linked,
            CloudRegistrationPhase::InFlight,
        ];
        if fenced_in_txn(&self.store, &wtxn, &actor, fence, &usable)?.is_none() {
            return Ok(None);
        }
        let name = slot_name(&fence.slot);
        self.inject_secret_at_door_in_txn(wtxn, &name, token_use.effector(), apply)
            .map(Some)
    }

    /// Replaces the reserved link's tokens with their successor `tokens`:
    /// the slot rotates in place, its generation one up, and the binding is
    /// `Linked` at it, in one commit. `None` when the fence moved (an erase,
    /// a logout, a replacement): nothing is stored, and the caller wipes and
    /// revokes the successor.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`]; custody and storage
    /// faults.
    pub fn replace_cloud_registration_tokens_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        fence: &CloudRegistrationFence,
        tokens: &[u8],
        at: u64,
    ) -> Result<Option<CloudRegistrationBinding>> {
        let mut wtxn = self.store.env.write_txn()?;
        let actor = owner_actor_in_txn(self, &wtxn, owner)?;
        let reserved = [CloudRegistrationPhase::InFlight];
        let Some(mut row) = fenced_in_txn(&self.store, &wtxn, &actor, fence, &reserved)? else {
            return Ok(None);
        };
        let receipt = self.rotate_secret_in_txn(&mut wtxn, &slot_name(&fence.slot), tokens, at)?;
        row.generation = receipt.to_generation;
        row.phase = CloudRegistrationPhase::Linked;
        row.changed_at = at;
        ROWS.put(&self.store, &mut wtxn, &fence.slot, &row)?;
        wtxn.commit()?;
        Ok(Some(CloudRegistrationBinding::of(fence.slot, &row)))
    }

    /// Stops the current link `fence` names at `phase`, `NeedsLogin` or
    /// `LoggedOut`: its slot revoked and its value emptied at rest, its row
    /// kept for the owner's erase. Not an erase: older generations' keys stay
    /// until one. `None` when the fence moved.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`]; another phase; storage
    /// faults.
    pub fn retire_cloud_registration_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        fence: &CloudRegistrationFence,
        phase: CloudRegistrationPhase,
        at: u64,
    ) -> Result<Option<CloudRegistrationBinding>> {
        if !matches!(
            phase,
            CloudRegistrationPhase::NeedsLogin | CloudRegistrationPhase::LoggedOut
        ) {
            return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
                "a cloud registration link stops at needs-login or logged-out",
            )));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let actor = owner_actor_in_txn(self, &wtxn, owner)?;
        let current = [
            CloudRegistrationPhase::Linked,
            CloudRegistrationPhase::InFlight,
            CloudRegistrationPhase::NeedsLogin,
        ];
        let Some(mut row) = fenced_in_txn(&self.store, &wtxn, &actor, fence, &current)? else {
            return Ok(None);
        };
        retire_in_txn(self, &mut wtxn, &fence.slot, &mut row, phase, at)?;
        wtxn.commit()?;
        Ok(Some(CloudRegistrationBinding::of(fence.slot, &row)))
    }

    /// The owner's erase of the cloud registration for `issuer`, or for every
    /// issuer with `None`: every slot the owner linked for it, current,
    /// replaced or logged out, is fenced,
    /// every generation's and carrier's key staged to retire, and its
    /// record, name and row erased, in one commit (KS-6 part 2); then the
    /// keys are retired. Completion is read from custody, never from the
    /// commit: `complete` false is pending, and the finisher retries.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`]; a legal hold on a slot
    /// (nothing is erased then); storage faults.
    pub fn erase_cloud_registration_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        issuer: Option<&str>,
    ) -> Result<CloudRegistrationErased> {
        let slots = self.with_write_txn(|wtxn| {
            let actor = owner_actor_in_txn(self, &*wtxn, owner)?;
            let slots: Vec<EntityId> = rows_in_txn(&self.store, &*wtxn)?
                .into_iter()
                .filter(|(_, row)| {
                    row.owner == actor && issuer.is_none_or(|issuer| row.issuer == issuer)
                })
                .map(|(slot, _)| slot)
                .collect();
            for slot in &slots {
                erase_slot_in_txn(self, wtxn, slot)?;
            }
            Ok(slots)
        })?;
        if !slots.is_empty() {
            self.finish_credential_retirements_after_commit();
        }
        let complete = self.cloud_registration_erase_finished(&slots)?;
        Ok(CloudRegistrationErased { slots, complete })
    }

    /// Whether the erase of every one of `slots` has finished here: each
    /// one's fence and discovery complete, every key it names retired and
    /// its journal obligations complete (KS-6 part 2).
    ///
    /// # Errors
    /// Storage and custody faults: the caller reads them pending.
    pub fn cloud_registration_erase_finished(&self, slots: &[EntityId]) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        for slot in slots {
            if !self.store.credential_erase_finished_in_txn(&txn, slot)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
