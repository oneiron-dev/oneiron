//! What an owner's deletion does to its checkpoint payload leaves (KS7-4,
//! FIX 5688).
//!
//! An erase marks every incarnation of the owner erased, an older retained
//! one included, and stages one Erase intent per incarnation through the
//! generation its leaf is at, in the erase's own transaction; custody's one
//! finisher destroys the leaves after the commit, so every old checkpoint
//! holding the owner's bytes keeps them only unreadable. An ordinary delete
//! marks the active incarnation retained and stages nothing: its leaf stays
//! for the checkpoints holding it, for the restore window (ARCH-0038
//! #key-store).
//!
//! Nothing here refuses or waits (Engine 10-20 08:4x, rulings 2 and 3): the
//! user act commits as it does today, and a legal hold, a missing kept
//! inventory or a custody fault delays only the key's retirement, never the
//! delete. While [`CHECKPOINT_PAYLOADS_ENABLED`] is off no instance row
//! exists, so every settle here touches nothing.

use heed::{RoTxn, RwTxn};

use crate::key_custody::identity::CustodyKind;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::checkpoint_payload::CHECKPOINT_PAYLOADS_ENABLED;
use crate::checkpoint_payload::PayloadItem;
use crate::checkpoint_payload::Subtype;
use crate::checkpoint_payload::corrupt;
use crate::checkpoint_payload::kept::KeptGenerations;

/// What an owner's deletion does to its compartments (Engine 10-20 08:4x,
/// ruling 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadDisposition {
    /// An ordinary delete: the leaves stay for the checkpoints holding them,
    /// and nothing new is sealed under the owner's active incarnation.
    Retain,
    /// The owner's erase: every incarnation's leaf retires, so no old
    /// checkpoint opens the owner's bytes again.
    Erase,
}

/// The record a legal hold on `item`'s owner names: an entity tree's own id,
/// an attachment occurrence's holding record. A code document or an
/// outbound call names no record a hold can target yet (Engine 10-20 08:4x,
/// ruling 4).
pub fn held_record(item: &PayloadItem) -> Option<[u8; 16]> {
    match item.subtype() {
        Subtype::EntityTree | Subtype::AttachmentOccurrence => item.owner()[..16].try_into().ok(),
        Subtype::CodeDocument | Subtype::OutboundCall => None,
    }
}

/// The kept-checkpoint inventory's answer for a retention retirement of
/// `item` through `through`: whether no kept checkpoint still needs a
/// generation at or below it. `kept` is the authenticated inventory of every
/// kept manifest (KS7-5), read when a host's prune hands its kept copies
/// over; with none, no retention retirement is ready, and a missing
/// inventory only ever delays a key (Engine 10-20 08:4x, ruling 3).
pub fn kept_inventory_releases(
    item: &PayloadItem,
    through: u64,
    kept: Option<&KeptGenerations>,
) -> bool {
    kept.is_some_and(|kept| kept.releases(item, through))
}
