//! One world's current pads, moved between the owner's machines (KS-5, FIX
//! 6706, L04 leaf): what pad hydration seals at its source and installs where
//! it lands.
//!
//! A source seals what current custody holds here for the pads asked, live
//! and retired, and takes a pad its row carries when custody cannot supply
//! it; a pad whose world or row an erase reached here goes as retired, never
//! live. The capsule is wrapped to the recipients named alone
//! ([`seal_world_pad_compartment`]) and bound to this custody's position. A
//! machine that opened it publishes each pad it lacks into its own custody
//! (`publish_world_pad_in_txn`), checked first and all at once, and reads
//! them back once committed. No pad is kept anywhere else, nothing is wrapped
//! to a host or data key, and no lineage control secret moves.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use super::{WorldPadCustody, WorldPadItem, item_world};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::custody_protocol::CustodyPosition;
use crate::store::key_custody::{CustodyKind, custody_present};
use crate::store::{
    OpenedWorldPads, PadRecipients, SealedWorldPads, Store, seal_world_pad_compartment,
};

/// What an export sealed: the capsule, and each pad it holds that is retired
/// at the source, the retirement evidence a hydration's reply names.
pub(crate) struct ExportedWorldPads {
    pub(crate) sealed: SealedWorldPads,
    pub(crate) retired: BTreeSet<WorldPadItem>,
}

/// What an install did, for its read back.
pub(crate) struct InstalledWorldPads {
    /// Each pad it published into custody here, or found there already with
    /// the same bytes.
    pub(crate) held: Vec<WorldPadItem>,
    /// Each pad of the capsule it left out: retired at the source or here,
    /// erased here, or a custody that takes none.
    pub(crate) skipped: usize,
}

impl Store {
    /// Where this store's custody stands now: the position a capsule sealed
    /// here is bound to. `None` when no custody is bound here.
    fn custody_position(&self) -> Result<Option<CustodyPosition>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(None);
        };
        if !custody_present(custody.binding().root())? {
            return Ok(None);
        }
        if let Some(requirement) = self.custody_requirement()? {
            return requirement.position().map(Some);
        }
        // Nothing published under the binding yet: its empty log.
        let mut empty = [0u8; 96];
        empty[..32].copy_from_slice(custody.binding().vault().as_bytes());
        empty[32..48].copy_from_slice(custody.binding().namespace().as_bytes());
        Ok(CustodyPosition::from_bytes(&empty))
    }

    /// Every pad of `world` current custody here names, live or retired: a
    /// source's candidates beside the pads its rows hold. None when no
    /// custody is bound.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn world_pad_items(&self, world: &EntityId) -> Result<BTreeSet<WorldPadItem>> {
        Ok(self
            .world_pad_subjects(world.as_bytes())?
            .into_iter()
            .filter_map(|(subject, _)| <[u8; 40]>::try_from(subject.item()).ok())
            .collect())
    }

    /// Seals the current pads of `world` among `items` for `recipients`
    /// alone, at this custody's position. Each comes from current custody,
    /// else from `row_pad`, the pad its row holds here; a pad custody retired,
    /// or whose world's keys were destroyed or whose row was hard-erased here,
    /// goes as retired. An item no source holds is left out. `None` when no
    /// custody is bound here, or nothing is left to seal.
    ///
    /// # Errors
    ///
    /// An item of another world; no recipient; sealing and storage faults.
    pub(crate) fn export_current_world_pads(
        &self,
        txn: &RoTxn<'_>,
        world: EntityId,
        items: &BTreeSet<WorldPadItem>,
        row_pad: &dyn Fn(&WorldPadItem) -> Result<Option<Zeroizing<[u8; 32]>>>,
        recipients: &PadRecipients,
    ) -> Result<Option<ExportedWorldPads>> {
        if items.is_empty() || recipients.is_empty() {
            return Ok(None);
        }
        let Some(position) = self.custody_position()? else {
            return Ok(None);
        };
        let destroyed = crate::world_keys::world_keys_destroyed_in_txn(self, txn, world)?;
        let mut live = BTreeMap::new();
        let mut retired = BTreeSet::new();
        for item in items {
            if item_world(item)? != world {
                return Err(CustodyKind::WorldPad.corrupt());
            }
            // An erase standing here retires the pad, whatever custody holds
            // while its retirement finishes.
            if destroyed || crate::world_keys::pad_row_erased_in_txn(self, txn, item)? {
                retired.insert(*item);
                continue;
            }
            let held = match self.world_pad_custody_entry(item) {
                Ok(WorldPadCustody::Retired) => {
                    retired.insert(*item);
                    continue;
                }
                Ok(WorldPadCustody::Live(pad)) => Some(pad),
                Ok(WorldPadCustody::Missing | WorldPadCustody::Closed) => None,
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "a world pad custody could not read is taken from its row"
                    );
                    None
                }
            };
            let pad = match held {
                Some(pad) => Some(pad),
                None => row_pad(item).unwrap_or_else(|error| {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "a world pad row that does not read is left out of its export"
                    );
                    None
                }),
            };
            if let Some(pad) = pad {
                live.insert(*item, pad);
            }
        }
        if live.is_empty() && retired.is_empty() {
            return Ok(None);
        }
        let sealed = seal_world_pad_compartment(&position, world, &live, &retired, recipients)?;
        Ok(Some(ExportedWorldPads { sealed, retired }))
    }

    /// Publishes each live pad `opened` holds that current custody here
    /// lacks, in `wtxn`'s writer, each synced and its Mint journaled before
    /// the commit (`publish_world_pad_in_txn`). Every check comes before the
    /// first publication: a pad custody holds other bytes for refuses them
    /// all. A pad retired here, whose row was hard-erased here, or of a world
    /// whose keys were destroyed here is never published, nor is any in a
    /// custody that takes none (an archived vault). Retired pads the capsule
    /// names are evidence only: nothing here is retired for them. The caller
    /// commits, then reads back ([`Self::read_back_current_world_pads`]).
    ///
    /// # Errors
    ///
    /// A pad custody holds other bytes for; custody and storage faults.
    pub(crate) fn install_current_world_pads_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        opened: &OpenedWorldPads,
    ) -> Result<InstalledWorldPads> {
        let mut installed = InstalledWorldPads {
            held: Vec::new(),
            skipped: opened.retired.len(),
        };
        if self.core.gate_custody_archived()
            || crate::world_keys::world_keys_destroyed_in_txn(self, wtxn, opened.world)?
        {
            installed.skipped += opened.live.len();
            return Ok(installed);
        }
        let mut publish = Vec::new();
        for (item, pad) in &opened.live {
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
    /// with the bytes `opened` brought: an install's read back, after its
    /// commit.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn read_back_current_world_pads(
        &self,
        opened: &OpenedWorldPads,
        installed: &InstalledWorldPads,
    ) -> Result<bool> {
        for item in &installed.held {
            let Some(pad) = opened.live.get(item) else {
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
