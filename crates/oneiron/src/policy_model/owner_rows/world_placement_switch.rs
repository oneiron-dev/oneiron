//! "This Mac only": one switch over a world's two placement settings, for a
//! surface that shows a single toggle (CLIP-SYNC = A, owner 2026-11-03,
//! FIX 12586).
//!
//! On, the world is read only on this install and keeps no sealed copy
//! anywhere: `OneMachine(this install)` with sealed copies `Off`. Off, the
//! world syncs sealed to the owner's machines and the cloud: read on the
//! machines marked "yours", sealed copies on the cloud and on those machines
//! (DEC-0005: the cloud stores and relays only sealed bytes). The world's
//! model order stays as it is.
//!
//! The switch is the ordinary holder door ([`Vault::set_world_privacy_as`]):
//! the same signed edit, receipt, event and key work, and the same `seen`
//! rule, so a toggle shown on a stale revision is refused, never applied
//! over a newer choice.

use serde::{Deserialize, Serialize};

use super::world_privacy_switch::WorldPrivacyReceipt;
use crate::authority::{
    ActSurface, EffectiveModelOrder, EffectiveRead, EffectiveWorldPrivacy, ModelOrder,
    PolicyRevision, ReadLocation, SealedCopies, WorldPrivacy,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// Where one world's copies live, as a single switch reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorldMachinePlacement {
    /// The WORLD row, as hex.
    pub world: String,
    /// This install's machine, as hex; `None` while it has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// The world is read only on this install and keeps no sealed copy.
    pub this_machine_only: bool,
    /// The world syncs sealed: read on the machines marked "yours", sealed
    /// copies on the cloud and on those machines.
    pub synced_sealed: bool,
    /// The world's settings as this install folds them.
    pub settings: EffectiveWorldPrivacy,
    /// The settings revision, as 64 hex: a switch names it as its `seen`.
    pub revision: String,
}

/// The settings the switch writes: on, this install only and no sealed copy;
/// off, the owner's machines with sealed copies on the cloud and on them.
/// `models` is the world's current order, kept.
#[must_use]
pub fn machine_placement_settings(
    this_machine_only: bool,
    machine: EntityId,
    models: ModelOrder,
) -> WorldPrivacy {
    if this_machine_only {
        WorldPrivacy {
            read: ReadLocation::OneMachine(machine),
            sealed: SealedCopies::Off,
            models,
        }
    } else {
        WorldPrivacy {
            read: ReadLocation::MyMachines,
            sealed: SealedCopies::CloudAndMyMachines,
            models,
        }
    }
}

fn revision_hex(revision: &PolicyRevision) -> String {
    revision
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Vault {
    /// Reads where `world`'s copies live as one switch: whether it is read
    /// only on this install with no sealed copy, whether it syncs sealed to
    /// the owner's machines and the cloud, the folded settings and the
    /// revision a switch names as its `seen`.
    ///
    /// # Errors
    /// Store errors from the settings reads.
    pub fn world_machine_placement(&self, world: EntityId) -> Result<WorldMachinePlacement> {
        // The revision first: a change landing between the reads leaves a
        // revision older than the settings shown, which the switch's `seen`
        // refuses as stale, never the other way round.
        let revision = self.world_privacy_revision(world)?;
        let settings = self.world_privacy(world)?;
        let machine = self.local_machine()?.map(|local| local.id);
        let this_machine_only = matches!(
            (&settings.read, machine),
            (EffectiveRead::OneMachine(only), Some(local)) if *only == local
        ) && settings.sealed == SealedCopies::Off;
        let synced_sealed = settings.read == EffectiveRead::MyMachines
            && settings.sealed == SealedCopies::CloudAndMyMachines;
        Ok(WorldMachinePlacement {
            world: world.to_hex(),
            machine: machine.map(|id| id.to_hex()),
            this_machine_only,
            synced_sealed,
            settings,
            revision: revision_hex(&revision),
        })
    }

    /// Turns "this Mac only" on or off for `world`, as the holder's own act
    /// through [`Self::set_world_privacy_as`]. On reads the world only on
    /// this install's machine and keeps no sealed copy; off reads it on the
    /// owner's machines with sealed copies on the cloud and on them. The
    /// world's model order is kept. `seen` is the revision the surface showed
    /// ([`Self::world_machine_placement`]); `None` takes the current one.
    /// Either way this install's revision is read before the model order the
    /// switch keeps, and is the one the edit names.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] when this install has no machine yet, or when
    /// concurrent edits left the world's model order conflicted (the full
    /// settings door picks one); every error of
    /// [`Self::set_world_privacy_as`], among them a one-machine target this
    /// install's owner has not marked "yours" and a stale `seen`.
    pub fn set_world_this_machine_only(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        world: EntityId,
        this_machine_only: bool,
        seen: Option<PolicyRevision>,
    ) -> Result<WorldPrivacyReceipt> {
        let machine = self
            .local_machine()?
            .map(|local| local.id)
            .ok_or(Error::InvalidConfig(
                "this install has no machine yet, so no world can be kept on it alone".to_owned(),
            ))?;
        // This install's revision before the model order it keeps, and always
        // named to the writer: a change landing after this read makes the edit
        // stale and refused, so the kept order is never one a newer edit
        // replaced. A `seen` read elsewhere must be this same revision.
        let current = self.world_privacy_revision(world)?;
        if seen.is_some_and(|seen| seen != current) {
            return Err(Error::ConcurrentWrite(
                "the world's settings changed since they were read",
            ));
        }
        let seen = current;
        let models = match self.world_privacy(world)?.models {
            EffectiveModelOrder::Inherit => ModelOrder::Inherit,
            EffectiveModelOrder::Ordered(routes) => ModelOrder::Ordered(routes),
            EffectiveModelOrder::Conflicted => {
                return Err(Error::InvalidConfig(
                    "the world's model order is conflicted: set the full settings, with one order"
                        .to_owned(),
                ));
            }
        };
        let settings = machine_placement_settings(this_machine_only, machine, models);
        self.set_world_privacy_as(owner, surface, world, settings, Some(seen))
    }
}
