//! One world's pads installed into current custody and read back (KS-5, FIX
//! 6706; PAD-2, FIX 10470): the core a hydrated capsule's install and a
//! custody head's reopen share (`current`, and the restore's
//! `recovery::checkpoint` pad reopen). It takes the pads as their full ids and
//! bytes, so neither adapter forges the other's recipient.

use std::collections::BTreeMap;

use heed::RwTxn;
use zeroize::Zeroizing;

use super::{WorldPadCustody, WorldPadItem};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::key_custody::CustodyKind;

/// What an install did, for its read back.
pub(crate) struct InstalledWorldPads {
    /// Each pad it published into custody here, or found there already with
    /// the same bytes.
    pub(crate) held: Vec<WorldPadItem>,
    /// Each pad its source named that it left out: retired at the source or
    /// here, erased here, or a custody that takes none.
    pub(crate) skipped: usize,
}

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
            || crate::world_keys::world_keys_destroyed_in_txn(self, wtxn, world)?
        {
            installed.skipped += live.len();
            return Ok(installed);
        }
        let mut publish = Vec::new();
        for (item, pad) in live {
            if crate::world_keys::pad_row_erased_in_txn(self, wtxn, item)? {
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
