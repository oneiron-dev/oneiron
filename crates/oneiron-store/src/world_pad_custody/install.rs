//! One world's pads installed into current custody and read back (KS-5, FIX
//! 6706; PAD-2, FIX 10470): the core a hydrated capsule's install and a
//! custody head's reopen share (`current`, and the restore's
//! `recovery::checkpoint` pad reopen). It takes the pads as their full ids and
//! bytes, so neither adapter forges the other's recipient.

use std::collections::BTreeMap;

use heed::RwTxn;
use zeroize::Zeroizing;

use crate::key_custody::identity::CustodyKind;
use crate::world_pad_custody::WorldPadCustody;
use crate::world_pad_custody::WorldPadItem;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// What an install did, for its read back.
pub struct InstalledWorldPads {
    /// Each pad it published into custody here, or found there already with
    /// the same bytes.
    pub held: Vec<WorldPadItem>,
    /// Each pad its source named that it left out: retired at the source or
    /// here, erased here, or a custody that takes none.
    pub skipped: usize,
}
