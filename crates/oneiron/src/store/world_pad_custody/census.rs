//! Which worlds a custody head's pad compartments are sealed for (FIX 9178):
//! a world whose pads custody holds here, live or retired, whose pad rows are
//! here, or whose keys the authority names. Only ids; no pad is read.

use std::collections::BTreeSet;

use heed::RoTxn;

use super::item_world;
use crate::authority::AuthorityFold;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_WORLD_KEY_PAD;
use crate::store::Store;
use crate::store::key_custody::{CustodyKind, custody_present};

impl Store {
    /// Every world a custody head's pads may belong to: the world of each pad
    /// custody holds here, live or retired (an erased world's included), of
    /// each pad row `txn` reads here, and of each key the authority `fold`
    /// names. A custody item or pad row that names no world adds none.
    ///
    /// # Errors
    ///
    /// Custody and storage faults.
    pub(crate) fn world_pad_worlds(
        &self,
        txn: &RoTxn<'_>,
        fold: &AuthorityFold,
    ) -> Result<BTreeSet<EntityId>> {
        let mut worlds: BTreeSet<EntityId> =
            fold.all_world_keys().map(|key| key.id.world).collect();
        if let Some(custody) = self.core.key_custody.local()
            && custody_present(custody.binding().root())?
        {
            for subject in custody.subjects_with_prefix(CustodyKind::WorldPad, &[])? {
                worlds.extend(item_world(subject.item()).ok());
            }
        }
        for id in self.port_entity_ids_by_type(txn, ENTITY_TYPE_WORLD_KEY_PAD, None)? {
            let world = self.port_entity_with_raw(txn, &id?, |raw| {
                Ok(crate::world_keys::pad_body_world(raw).and_then(|world| world.ok()))
            })?;
            worlds.extend(world.flatten());
        }
        Ok(worlds)
    }
}
