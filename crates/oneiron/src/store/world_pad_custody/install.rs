//! Core half of `store::world_pad_custody::install`: its store-layer items live in `oneiron_store::world_pad_custody::install` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::world_pad_custody::install::*;

use super::{WorldPadCustody, WorldPadItem};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::key_custody::CustodyKind;
use heed::RwTxn;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

impl Store {
    /// Publishes each pad of `world` in `live` that current custody here
    /// lacks, in `wtxn`'s writer, each synced and its Mint journaled before
    /// the commit (`publish_world_pad_in_txn`). Every check comes before the
    /// first publication: a pad custody holds other bytes for refuses them
    /// all. A pad retired here, whose row was hard-erased here, or of a world
    /// whose keys were destroyed here is never published, nor is any in a
    /// custody that takes none (an archived vault). `retired` counts the pads
    /// the source named retired: evidence only, nothing here is retired for
    /// them. The caller commits, then reads back
    /// ([`Self::read_back_world_pads`]).
    ///
    /// # Errors
    ///
    /// A pad custody holds other bytes for; custody and storage faults.
    pub(crate) fn install_world_pads_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        world: EntityId,
        live: &BTreeMap<WorldPadItem, Zeroizing<[u8; 32]>>,
        retired: usize,
    ) -> Result<InstalledWorldPads> {
        let mut installed = InstalledWorldPads {
            held: Vec::new(),
            skipped: retired,
        };
        if self.core.gate_custody_archived()
            || crate::store::world_pad_rows::world_keys_destroyed_in_txn(self, wtxn, world)?
        {
            installed.skipped += live.len();
            return Ok(installed);
        }
        let mut publish = Vec::new();
        for (item, pad) in live {
            if crate::store::world_pad_rows::pad_row_erased_in_txn(self, wtxn, item)? {
                installed.skipped += 1;
                continue;
            }
            match self.world_pad_custody_entry(item)? {
                WorldPadCustody::Live(held) if *held == **pad => installed.held.push(*item),
                // A pad never changes.
                WorldPadCustody::Live(_) => return Err(CustodyKind::WorldPad.corrupt()),
                WorldPadCustody::Retired | WorldPadCustody::Closed => installed.skipped += 1,
                WorldPadCustody::Missing => publish.push((item, pad)),
            }
        }
        for (item, pad) in publish {
            self.publish_world_pad_in_txn(wtxn, item, pad)?;
            installed.held.push(*item);
        }
        Ok(installed)
    }

    /// Whether current custody here holds every pad `installed` names, each
    /// with the bytes `live` brought: an install's read back, after its
    /// commit.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn read_back_world_pads(
        &self,
        live: &BTreeMap<WorldPadItem, Zeroizing<[u8; 32]>>,
        installed: &InstalledWorldPads,
    ) -> Result<bool> {
        for item in &installed.held {
            let Some(pad) = live.get(item) else {
                return Ok(false);
            };
            if !self
                .world_pad_in_custody(item)?
                .is_some_and(|held| *held == **pad)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
