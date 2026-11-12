//! Where an off-device read's rows go, and the one verdict every door asks
//! about them (mesh PR2b, CALLS `mesh PR2-destination`).
//!
//! A read off this device carries the machine its connection proved
//! ([`PeerMachine`]) beside its locality. Every snapshot that serves or
//! releases rows judges that proof again, in the same snapshot as the world
//! settings, and asks the shared world judge
//! ([`WorldPrivacyView::withheld_for_peer`]) for the machine it names. Only a
//! destination no live machine proof names is [`Destination::Unknown`]: an
//! Everywhere world with a valid scope never fails for it, and a OneMachine
//! or MyMachines world is the owner's recipient choice, read for that machine
//! and named when it withholds ([`RecipientLimit`], L11-B (B)). The mine test
//! stays the judge's own (a machine the owner marked his); carrying the
//! owner's will (`owner_act_signer_admits`) never makes a machine a
//! recipient.

use std::collections::BTreeSet;

use heed::RoTxn;

use crate::Vault;
use crate::authority::WorldPrivacyView;
use oneiron_base::machine_destination::{Destination, EffectiveRead, PeerMachine};
#[doc(hidden)]
pub use oneiron_verb_wire::settings::destination::{
    CallerLocality, RecipientChoice, RecipientLimit, RecipientWhy, ReleaseHold,
};

use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};

#[doc(hidden)]
pub use oneiron_wake_contract::settings::destination::ReadDestination;

/// A caller at `locality` on a connection that proved `peer`: on this
/// device nothing leaves, whatever it proved; off it the rows go to
/// `peer`. A TCP address or an owner principal alone is no machine proof.
#[must_use]
pub fn read_destination_at(locality: CallerLocality, peer: PeerMachine) -> ReadDestination {
    match locality {
        CallerLocality::OnDevice => ReadDestination::on_device(),
        CallerLocality::OffDevice => ReadDestination::toward(peer),
    }
}

/// The locality alone, for a door that judges only that.
#[must_use]
pub fn read_destination_locality(read_destination: &ReadDestination) -> CallerLocality {
    if read_destination.off_device {
        CallerLocality::OffDevice
    } else {
        CallerLocality::OnDevice
    }
}

/// A locality alone names no machine: off this device it is an unproved
/// destination.
impl From<CallerLocality> for ReadDestination {
    fn from(locality: CallerLocality) -> Self {
        Self {
            off_device: locality == CallerLocality::OffDevice,
            proved: Vec::new(),
        }
    }
}

/// The worlds whose rows a read toward `destination` never carries: every
/// world the shared judge withholds from one of its machines, each proof
/// revalidated in `txn`'s snapshot. None on this device.
pub(crate) fn withheld_worlds_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    destination: &ReadDestination,
) -> Result<BTreeSet<EntityId>> {
    let peers = destination.peers();
    if peers.is_empty() {
        return Ok(BTreeSet::new());
    }
    let view = WorldPrivacyView::load_in(vault, txn)?;
    let mut withheld = BTreeSet::new();
    for peer in peers {
        withheld.extend(view.withheld_for_peer(peer)?);
    }
    Ok(withheld)
}

/// The first limit `world`'s settings put on one of `destination`'s
/// machines, in `view`'s snapshot.
fn recipient_limit_in(
    view: &WorldPrivacyView,
    world: EntityId,
    destination: &ReadDestination,
) -> Option<RecipientLimit> {
    let read = view.world_read(world);
    destination.peers().into_iter().find_map(|peer| {
        RecipientLimit::of(&read, view.destination_for_peer(peer), |machine| {
            view.marked_mine(machine)
        })
    })
}

/// Each of `worlds` the owner's recipient choice keeps from `destination`,
/// with why, judged in `txn`'s snapshot by the same rule as
/// [`Vault::world_recipient_limit`] (FIX 5493: what his own export carries
/// that his choice would have kept from where it goes). Every world may be
/// read on this device; under a conflicted vault root no world's choice can
/// be judged, so none is named.
pub(crate) fn recipient_limits_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    worlds: &BTreeSet<EntityId>,
    destination: &ReadDestination,
) -> Result<Vec<(EntityId, RecipientLimit)>> {
    if worlds.is_empty() || !destination.is_off_device() {
        return Ok(Vec::new());
    }
    let Some(view) = WorldPrivacyView::load_unless_conflicted_in(vault, txn)? else {
        return Ok(Vec::new());
    };
    Ok(worlds
        .iter()
        .filter_map(|world| {
            recipient_limit_in(&view, *world, destination).map(|limit| (*world, limit))
        })
        .collect())
}

/// Why one of `worlds`, which a verdict read in `txn` already keeps from
/// `destination`, stays (FIX 4939): the owner's recipient choice for the
/// first of them his choice limits there, by the same rule as
/// [`recipient_limits_in`], else an integrity hold. Under a conflicted vault
/// root no choice can be judged, and it says so. Naming the reason never
/// changes the verdict.
pub(crate) fn worlds_hold_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    worlds: &BTreeSet<EntityId>,
    destination: &ReadDestination,
) -> ReleaseHold {
    match WorldPrivacyView::load_unless_conflicted_in(vault, txn) {
        Ok(Some(view)) => worlds
            .iter()
            .find_map(|world| recipient_limit_in(&view, *world, destination))
            .map_or(ReleaseHold::Placement, ReleaseHold::Recipient),
        Ok(None) => ReleaseHold::ConflictedRoot,
        Err(_) => ReleaseHold::Placement,
    }
}

/// Why `row`, which a verdict read in `txn` already withheld from
/// `destination` by the `withheld` worlds, stays (FIX 4939):
/// [`Vault::release_hold_for`]'s reason for it in that same snapshot. A
/// reason that cannot be read is an integrity hold.
pub(crate) fn withheld_row_hold_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    withheld: &BTreeSet<EntityId>,
    row: &EntityId,
    destination: &ReadDestination,
) -> ReleaseHold {
    match WorldPrivacyView::load_unless_conflicted_in(vault, txn) {
        Ok(Some(view)) => row_hold(vault, txn, &view, withheld, row, destination)
            .unwrap_or(ReleaseHold::Placement),
        Ok(None) => ReleaseHold::ConflictedRoot,
        Err(_) => ReleaseHold::Placement,
    }
}

/// Why `world`'s current settings keep it from `machine`, named directly
/// rather than proved by a connection, in `txn`'s snapshot (FIX 5493: an
/// import judged for the install it lands on), or `None` when it may be
/// read there. A conflicted vault root judges no world, and says so.
pub(crate) fn machine_recipient_hold_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    world: EntityId,
    machine: Destination,
) -> Result<Option<ReleaseHold>> {
    let Some(view) = WorldPrivacyView::load_unless_conflicted_in(vault, txn)? else {
        return Ok(Some(ReleaseHold::ConflictedRoot));
    };
    Ok(
        RecipientLimit::of(&view.world_read(world), machine, |id| view.marked_mine(id))
            .map(ReleaseHold::Recipient),
    )
}

impl Vault {
    /// Why the owner's recipient choice keeps `world` from `destination`
    /// now, or `None` when it may be read there. Refused under a conflicted
    /// vault root, whose fold judges no world.
    pub fn world_recipient_limit(
        &self,
        world: EntityId,
        destination: &ReadDestination,
    ) -> Result<Option<RecipientLimit>> {
        if !destination.is_off_device() {
            return Ok(None);
        }
        let txn = self.store.env.read_txn()?;
        let view = WorldPrivacyView::load_in(self, &txn)?;
        Ok(recipient_limit_in(&view, world, destination))
    }

    /// Why `rows` may not all leave for `destination` now, judged in one
    /// snapshot, or `None` when every one may: the same verdict as
    /// [`Vault::off_device_readable_for`], with its reason. A row a withheld
    /// world keeps names the owner's choice for that world; a row whose
    /// world cannot be placed is an integrity hold.
    pub fn release_hold_for(
        &self,
        rows: &[EntityId],
        destination: &ReadDestination,
    ) -> Result<Option<ReleaseHold>> {
        self.release_hold_judged(rows, destination, false)
    }

    /// [`Self::release_hold_for`] for the owner's own whole-vault export
    /// (owner ruling 1-EXPORT = B), whose release mode its door chose from
    /// its trusted route and the owner's fresh proof: his recipient choice
    /// keeps none of its rows from where it goes, so a row a withheld world
    /// keeps by that choice alone goes, and every row after it is judged
    /// on. Every integrity hold still keeps the rows here: a row whose world
    /// cannot be placed, and a conflicted vault root.
    pub fn owner_export_release_hold_for(
        &self,
        rows: &[EntityId],
        destination: &ReadDestination,
    ) -> Result<Option<ReleaseHold>> {
        self.release_hold_judged(rows, destination, true)
    }

    /// The one release verdict of [`Self::release_hold_for`] and, with
    /// `owner_export`, of [`Self::owner_export_release_hold_for`].
    fn release_hold_judged(
        &self,
        rows: &[EntityId],
        destination: &ReadDestination,
        owner_export: bool,
    ) -> Result<Option<ReleaseHold>> {
        if !destination.is_off_device() || rows.is_empty() {
            return Ok(None);
        }
        let txn = self.store.env.read_txn()?;
        let Some(view) = WorldPrivacyView::load_unless_conflicted_in(self, &txn)? else {
            return Ok(Some(ReleaseHold::ConflictedRoot));
        };
        let mut withheld = BTreeSet::new();
        for peer in destination.peers() {
            withheld.extend(view.withheld_for_peer(peer)?);
        }
        for row in rows {
            match super::device_only_withholds(&self.store, &txn, &withheld, row) {
                Ok(false) => {}
                // Naming the reason never changes the verdict: a reason that
                // cannot be read is an integrity hold.
                Ok(true) => {
                    let hold = row_hold(self, &txn, &view, &withheld, row, destination)
                        .unwrap_or(ReleaseHold::Placement);
                    if owner_export && hold.is_owner_choice() {
                        continue;
                    }
                    return Ok(Some(hold));
                }
                Err(Error::CorruptedIndex(_)) => return Ok(Some(ReleaseHold::Placement)),
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }
}

/// Why a withheld world keeps `row`: the owner's choice for the first
/// withheld world its words lie in, or an integrity hold when none of them
/// can be named.
fn row_hold(
    vault: &Vault,
    txn: &RoTxn<'_>,
    view: &WorldPrivacyView,
    withheld: &BTreeSet<EntityId>,
    row: &EntityId,
    destination: &ReadDestination,
) -> Result<ReleaseHold> {
    let carried = if withheld.contains(row) {
        BTreeSet::from([*row])
    } else {
        let carried = super::carried_worlds_in(&vault.store, txn, row)?;
        if carried.unknown {
            return Ok(ReleaseHold::Placement);
        }
        carried.worlds
    };
    Ok(carried
        .intersection(withheld)
        .find_map(|world| recipient_limit_in(view, *world, destination))
        .map_or(ReleaseHold::Placement, ReleaseHold::Recipient))
}
