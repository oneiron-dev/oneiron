//! A private world's own text space (DEC-0005 #private-world-vectors; census L5-26).
//!
//! A world's model order may name a declared embedding space whose model runs on the device
//! (`model@revision@device`) and accepts text: that space is the world's text space. Every row
//! the world carries embeds into it alone. The vault's pending-text reconciler leaves such a row
//! pending, unleased and unsent ([`super::PendingEmbeddingReconcileReport::world_space`]), so it
//! never reaches the vault's text index, its primary or a remote rung. The media pass for the
//! space takes it instead, as it takes any document of a kind it fills. A row of a world that
//! inherits, or whose order names no such space, takes the vault's index as before. One world,
//! one space: the world's vectors stay comparable inside one list (ARCH-0004 MERGE-RULE = B),
//! and a row two worlds carry embeds into each world's space.
//!
//! Nothing here is a new door. The owner declares the space and names it in the world's order
//! with the two owner acts that already exist; the space and the order are both synced rows,
//! so every machine that may read the world routes its rows the same way.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use super::space::{EmbeddingSpace, InputKind, embedding_space_in_txn};
use super::space_move::space_fill_kinds_in_txn;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

#[cfg(feature = "sync")]
mod sweep;
#[cfg(feature = "sync")]
pub(crate) use sweep::sweep_world_text_spaces;

/// The place of a space whose model runs in-process on the device that embeds: the last
/// `@`-part of its `model@revision@where` id.
pub const DEVICE_PLACE: &str = "device";

/// Whether the space `space_id` names the device as its model's place.
#[must_use]
pub fn space_runs_on_device(space_id: &str) -> bool {
    space_id
        .rsplit_once('@')
        .is_some_and(|(_, place)| place == DEVICE_PLACE)
}

/// Each world's text space, as the authority fold and the declared spaces read in one
/// transaction.
#[derive(Debug, Default, Clone)]
pub(crate) struct WorldTextSpaces {
    by_world: BTreeMap<EntityId, EmbeddingSpace>,
}

impl WorldTextSpaces {
    /// Every world whose own model order names a text space: the first route of the order
    /// that is a space declared here, accepting text, whose model runs on the device. A world
    /// that inherits, or a vault root in conflict (no world's order is known), names none.
    pub(crate) fn read_in(vault: &Vault, txn: &RoTxn<'_>) -> Result<Self> {
        let fold = vault.authority_view_readonly_in_txn(txn)?;
        let mut by_world = BTreeMap::new();
        for (world, routes) in fold.ordered_world_model_routes() {
            for route in routes.iter().filter(|route| space_runs_on_device(route)) {
                if let Some(space) = embedding_space_in_txn(&vault.store, txn, route)?
                    && space.accepts.contains(&InputKind::Text)
                {
                    by_world.insert(world, space);
                    break;
                }
            }
        }
        Ok(Self { by_world })
    }

    /// `world`'s text space, if it names one.
    pub(crate) fn of_world(&self, world: &EntityId) -> Option<&EmbeddingSpace> {
        self.by_world.get(world)
    }

    /// Whether some world names `space_id` as its text space.
    pub(crate) fn names(&self, space_id: &str) -> bool {
        self.by_world.values().any(|space| space.id == space_id)
    }

    /// The text spaces of the worlds the row `id` carries: empty when none of them names one,
    /// and at once when no world does.
    pub(crate) fn of_row(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<BTreeSet<&str>> {
        if self.by_world.is_empty() {
            return Ok(BTreeSet::new());
        }
        let carried = crate::settings::carried_worlds_in(store, txn, id)?;
        Ok(carried
            .worlds
            .iter()
            .filter_map(|world| self.by_world.get(world))
            .map(|space| space.id.as_str())
            .collect())
    }

    /// Adds text to `kinds`, the kinds a media pass for `space` fills
    /// ([`space_fill_kinds_in_txn`]), when `space` is some world's text space.
    pub(crate) fn add_world_text(&self, space: &EmbeddingSpace, kinds: &mut BTreeSet<InputKind>) {
        if self.names(&space.id) {
            kinds.insert(InputKind::Text);
        }
    }
}

/// Which text documents one media pass for a space takes: a row a world with its own text
/// space carries goes to that space alone; any other row to the space a kind slot binds for
/// text, or an open move carries text to.
#[derive(Debug)]
pub(crate) struct TextDocumentRoute {
    world_spaces: WorldTextSpaces,
    space_id: String,
    slot_text: bool,
}

impl TextDocumentRoute {
    /// The route for `space` as `txn` reads it.
    pub(crate) fn read_in(vault: &Vault, txn: &RoTxn<'_>, space: &EmbeddingSpace) -> Result<Self> {
        let world_spaces = WorldTextSpaces::read_in(vault, txn)?;
        let slot_text = !world_spaces.by_world.is_empty()
            && space_fill_kinds_in_txn(&vault.store, txn, space)?.contains(&InputKind::Text);
        Ok(Self {
            world_spaces,
            space_id: space.id.clone(),
            slot_text,
        })
    }

    /// [`WorldTextSpaces::add_world_text`] as this route read the worlds.
    pub(crate) fn add_world_text(&self, space: &EmbeddingSpace, kinds: &mut BTreeSet<InputKind>) {
        self.world_spaces.add_world_text(space, kinds);
    }

    /// Whether the pass takes the text document `id`. With no world text space anywhere,
    /// every document the pass scanned, as before.
    pub(crate) fn takes(&self, store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        if self.world_spaces.by_world.is_empty() {
            return Ok(true);
        }
        let own = self.world_spaces.of_row(store, txn, id)?;
        Ok(if own.is_empty() {
            self.slot_text
        } else {
            own.contains(self.space_id.as_str())
        })
    }
}
