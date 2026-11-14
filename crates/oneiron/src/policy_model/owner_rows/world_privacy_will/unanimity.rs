//! "Widen needs every owner" (FIX 4480, the several-holders ruling): one
//! per-vault policy row with a per-world override, default off. The owner's
//! words: "too much consensus can be bad. an admin should be able to just
//! do". When the row is on for a world, any widen of it (a holder's own, or an
//! agent's ask) lands only once every live Owner of the vault said yes; the
//! author's own act counts as his yes, and Admins alone cannot satisfy it.
//! Tightening stays any one holder (CALLS "FIX 4480 unanimity scope").
//!
//! Any one live Owner turns it on. Turning it off while it is on takes every
//! live Owner, the same bar as the widen it guards, or one owner could switch
//! it off and then widen (CALLS "FIX 4480 unanimity setter", the Engine's
//! amendment of 10-19 05:0x). Such a change waits as a
//! [`WidenUnanimityOffRequest`] that collects the yeses, and the last one
//! lands it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::super::ledger::{PolicyChangedEvent, put_event_in_txn};
use super::record::WorldPrivacyRequestStatus;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::gate::PolicyRowScope;
use crate::inbox::NotificationKind;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Event kind on the shared owner-policy stream for a change of the row.
const UNANIMITY_CHANGED: &str = "policy.world_privacy.unanimity.changed";
/// The notice every live Owner gets for a pending turn-off.
const OFF_NOTICE: &str = "an owner asks to turn off \"widen needs every owner\"; it lands once \
                          every owner said yes: confirm or decline it at the world-privacy door";
/// A turn-off already settled.
const OFF_SETTLED: &str = "this \"widen needs every owner\" turn-off was already settled";

#[doc(hidden)]
pub use oneiron_verb_wire::policy_model::owner_rows::world_privacy_will::unanimity::{
    WidenUnanimity, WidenUnanimityOffRequest, WidenUnanimityOutcome,
};

const UNANIMITY: SideTable<(), WidenUnanimity, Named> =
    SideTable::new(&side_table::OWNER_POLICY_WORLD_PRIVACY_UNANIMITY);
const OFF_REQUESTS: SideTable<EntityId, WidenUnanimityOffRequest, Named> =
    SideTable::new(&side_table::OWNER_POLICY_WORLD_PRIVACY_UNANIMITY_OFF);

/// The live Owners every one of whose yes a widen of `world` needs; empty
/// while the row is off for it, so any one holder's yes applies a widen.
pub(super) fn widen_needs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
) -> Result<Vec<EntityId>> {
    let row = UNANIMITY.get(&vault.store, txn, &())?.unwrap_or_default();
    if !row.applies_to(world) {
        return Ok(Vec::new());
    }
    super::super::authority::owners_in_txn(vault, txn)
}

/// Policy hook (CALLS "FIX 4480 unanimity turn-off request", open): the live
/// Owners whose yes a turn-off needs, by the same live-owner set a widen's
/// unanimity uses. It is read again at each answer, so an owner who left no
/// longer holds it up and one who joined must say yes too.
fn off_needs_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<EntityId>> {
    super::super::authority::owners_in_txn(vault, txn)
}

/// Policy hook (CALLS "FIX 4480 widen ask live owners", open): the live
/// Owners whose yes a pending widen ask opened under "widen needs every
/// owner" needs, by the same live-owner set. It is read again at each
/// answer, as a turn-off's is: an owner who left no longer holds it up, and
/// his yes no longer counts; one who joined must say yes too, and may answer
/// it though it did not go to him.
pub(super) fn ask_needs_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<EntityId>> {
    super::super::authority::owners_in_txn(vault, txn)
}

impl Vault {
    /// The "widen needs every owner" row as it stands.
    pub fn widen_needs_every_owner(&self) -> Result<WidenUnanimity> {
        let txn = self.store.env.read_txn()?;
        Ok(UNANIMITY.get(&self.store, &txn, &())?.unwrap_or_default())
    }

    /// A live Owner sets the row: the vault's setting when `world` is
    /// `None`, else that world's override, which `on: None` clears. A change
    /// that turns no effective scope from on to off (turning it on, among
    /// others) lands at once with an event on the owner-policy stream. One
    /// that turns any scope from on to off waits for every live Owner's yes:
    /// it opens a turn-off request with his yes counted (or counts it on the
    /// pending one for the same change), and tells every live Owner. With one
    /// live Owner his yes alone lands it.
    ///
    /// # Errors
    /// [`crate::error::GateError::ConsentOwnerNotAuthenticated`] unless
    /// `owner` is a live Owner of this vault; [`Error::InvalidConfig`] for a
    /// vault setting of `None`.
    pub fn set_widen_needs_every_owner(
        &self,
        owner: &AuthenticatedOwner,
        world: Option<EntityId>,
        on: Option<bool>,
    ) -> Result<WidenUnanimityOutcome> {
        self.with_write_txn(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let row = UNANIMITY.get(&self.store, txn, &())?.unwrap_or_default();
            let after = row.changed(world, on)?;
            if !row.turns_off(&after) {
                self.put_unanimity_in_txn(txn, actor, world, &after)?;
                return Ok(WidenUnanimityOutcome::Set(after));
            }
            let pending = self.pending_off_in_txn(txn, world, on)?;
            let opened = pending.is_none();
            let mut request = match pending {
                Some(request) => request,
                None => WidenUnanimityOffRequest {
                    request_id: self.store.clock.entity_id()?.to_hex(),
                    world: world.as_ref().map(EntityId::to_hex),
                    on,
                    author: actor.to_hex(),
                    needs: Vec::new(),
                    yes: Vec::new(),
                    status: WorldPrivacyRequestStatus::Pending,
                    at: self.instant_in_txn(txn)?.secs(),
                },
            };
            push_yes(&mut request, actor);
            let needs = off_needs_in_txn(self, txn)?;
            let outcome = self.land_or_wait_in_txn(txn, actor, &needs, request)?;
            if let (true, WidenUnanimityOutcome::Pending(request)) = (opened, &outcome) {
                let subjects: Vec<EntityId> = world.into_iter().collect();
                self.notify_holders_in_txn(
                    txn,
                    NotificationKind::Ask,
                    &request.request_id,
                    &subjects,
                    &needs,
                    OFF_NOTICE,
                )?;
            }
            Ok(outcome)
        })
    }

    /// A live Owner's answer to the pending turn-off `request`: `yes` counts
    /// his yes, and the yes that completes every live Owner's lands it; a no
    /// declines it, and the row stays as it is.
    ///
    /// # Errors
    /// [`crate::error::GateError::ConsentOwnerNotAuthenticated`] unless
    /// `owner` is a live Owner of this vault; [`Error::EntityNotFound`] for
    /// no such request; [`Error::InvalidConfig`] for one already settled.
    pub fn answer_widen_unanimity_off(
        &self,
        owner: &AuthenticatedOwner,
        request: EntityId,
        yes: bool,
    ) -> Result<WidenUnanimityOutcome> {
        self.with_write_txn(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let mut stored = OFF_REQUESTS
                .get(&self.store, txn, &request)?
                .ok_or(Error::EntityNotFound)?;
            if stored.status != WorldPrivacyRequestStatus::Pending {
                return Err(Error::InvalidConfig(OFF_SETTLED.to_owned()));
            }
            if !yes {
                stored.status = WorldPrivacyRequestStatus::Declined {
                    holder: actor.to_hex(),
                };
                OFF_REQUESTS.put(&self.store, txn, &request, &stored)?;
                return Ok(WidenUnanimityOutcome::Declined(stored));
            }
            push_yes(&mut stored, actor);
            let needs = off_needs_in_txn(self, txn)?;
            self.land_or_wait_in_txn(txn, actor, &needs, stored)
        })
    }

    /// Every turn-off of the row, newest first; only the pending ones when
    /// `pending_only`.
    pub fn widen_unanimity_off_requests(
        &self,
        pending_only: bool,
    ) -> Result<Vec<WidenUnanimityOffRequest>> {
        let txn = self.store.env.read_txn()?;
        let mut requests: Vec<WidenUnanimityOffRequest> = OFF_REQUESTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, request)| request)
            .filter(|request| !pending_only || request.status == WorldPrivacyRequestStatus::Pending)
            .collect();
        requests.sort_by_key(|request| std::cmp::Reverse(request.at));
        Ok(requests)
    }

    /// The pending turn-off of the same change, when there is one.
    fn pending_off_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        world: Option<EntityId>,
        on: Option<bool>,
    ) -> Result<Option<WidenUnanimityOffRequest>> {
        let world = world.as_ref().map(EntityId::to_hex);
        Ok(OFF_REQUESTS
            .scan(&self.store, txn)?
            .into_iter()
            .map(|(_, request)| request)
            .find(|request| {
                request.status == WorldPrivacyRequestStatus::Pending
                    && request.world == world
                    && request.on == on
            }))
    }

    /// Lands `request` once every one of `needs` said yes, `actor`'s yes the
    /// last; else keeps it waiting with the yeses so far.
    fn land_or_wait_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        needs: &[EntityId],
        mut request: WidenUnanimityOffRequest,
    ) -> Result<WidenUnanimityOutcome> {
        request.needs = needs.iter().map(EntityId::to_hex).collect();
        let id = request.id()?;
        if !request
            .needs
            .iter()
            .all(|needed| request.yes.contains(needed))
        {
            OFF_REQUESTS.put(&self.store, txn, &id, &request)?;
            return Ok(WidenUnanimityOutcome::Pending(request));
        }
        let world = request.world_id()?;
        let row = UNANIMITY
            .get(&self.store, txn, &())?
            .unwrap_or_default()
            .changed(world, request.on)?;
        let receipt_id = self.put_unanimity_in_txn(txn, actor, world, &row)?;
        request.status = WorldPrivacyRequestStatus::Applied {
            receipt_id,
            holder: actor.to_hex(),
        };
        OFF_REQUESTS.put(&self.store, txn, &id, &request)?;
        Ok(WidenUnanimityOutcome::Set(row))
    }

    /// Writes `row` with its event on the owner-policy stream, `actor` its
    /// author; returns the event's receipt id.
    fn put_unanimity_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        world: Option<EntityId>,
        row: &WidenUnanimity,
    ) -> Result<String> {
        UNANIMITY.put(&self.store, txn, &(), row)?;
        let receipt_id = self.store.clock.entity_id()?.to_hex();
        put_event_in_txn(
            self,
            txn,
            &PolicyChangedEvent {
                kind: UNANIMITY_CHANGED.to_owned(),
                receipt_id: receipt_id.clone(),
                author: actor.to_hex(),
                scope: Some(world.map_or(PolicyRowScope::Vault, |world| {
                    PolicyRowScope::World(world.to_hex())
                })),
                target: None,
                at: self.instant_in_txn(txn)?.secs(),
            },
        )?;
        Ok(receipt_id)
    }
}

/// Counts `actor`'s yes on `request`, once.
fn push_yes(request: &mut WidenUnanimityOffRequest, actor: EntityId) {
    let me = actor.to_hex();
    if !request.yes.contains(&me) {
        request.yes.push(me);
    }
}
