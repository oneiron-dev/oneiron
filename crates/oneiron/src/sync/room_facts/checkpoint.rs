//! A room side row in a checkpoint (KS7-3a), read with the side row codec
//! and filed under its own key. The room, branch, turn or carrier it rides
//! with is named, but every variant carries actors or a platform handle (a
//! handle in a key is payload, never an opaque id) that no split here takes
//! out, so each row stays unclassified, named with it.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::{carrier_key, decode, named};
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::carrier_parts::is_part_key;
use crate::sync::checkpoint_payload::{Holder, Placement, SyncUnclassified};
use crate::workspace_roster::RoomSideRow;

/// A side row's actors and handles.
const SIDE_ROW_ACTORS: &str = "a room side row names actors or a platform handle";

/// Where the side row under `key` goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    // FIX 11790: a part goes with the manifest that lists it, and a manifest
    // as its joined row goes, under the entity its key names: every key
    // spells that entity second.
    if is_part_key(key) {
        return Placement::Part;
    }
    if let Some(parts) = crate::sync::room_parts::manifest(value) {
        return match key.split('/').nth(1).and_then(named) {
            Some(rides) => Placement::Manifest {
                holders: vec![Holder::new(OwnerRef::entity(&rides), Vec::new())],
                parts,
                joined: Some(SyncUnclassified::ActorSplit(SIDE_ROW_ACTORS)),
            },
            None => Placement::unclassified(None, SyncUnclassified::Undecodable),
        };
    }
    let row = match decode(value) {
        Ok(row) if carrier_key(&row, value) == key => row,
        _ => return Placement::unclassified(None, SyncUnclassified::Undecodable),
    };
    let rides = match &row {
        RoomSideRow::HostPin { room, .. } | RoomSideRow::Handle { room, .. } => Some(*room),
        RoomSideRow::Participation { room, branch, .. } => Some(branch.unwrap_or(*room)),
        RoomSideRow::Claim { claim } => named(&claim.turn_id),
        RoomSideRow::Response { parent, .. } => Some(*parent),
        RoomSideRow::Join { .. } | RoomSideRow::Offer { .. } => {
            row.merged_place().map(|(carrier, _)| carrier)
        }
    };
    Placement::unclassified(
        rides.map(|id| OwnerRef::entity(&id)),
        SyncUnclassified::ActorSplit(SIDE_ROW_ACTORS),
    )
}
