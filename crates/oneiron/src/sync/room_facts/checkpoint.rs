//! A room side row in a checkpoint (KS7-3a), read with the side row codec
//! and filed under its own key. The room, branch, turn or carrier it rides
//! with is named, but every variant carries actors or a platform handle (a
//! handle in a key is payload, never an opaque id) that no split here takes
//! out, so each row stays unclassified, named with it.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::erased::decode_held;
use super::{carrier_key, decode, named};
use crate::room_codec::offer_parts::{self, OfferManifest};
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::carrier_parts::{is_part_key, join_parts_from};
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

/// Whether the side row manifest `value` under `key` is the row its key
/// names, its parts joined through `part` (UC-10 PR 1), as the merge reads
/// a joined row: `Some(true)` when the joined row rides under its own key,
/// `Some(false)` when the parts join to another row or to none. `None` for
/// a value that is no manifest, and for one whose parts do not all join.
pub(in crate::sync) fn bound<B: AsRef<[u8]>>(
    key: &str,
    value: &[u8],
    part: impl FnMut(&str) -> Option<B>,
) -> Option<bool> {
    let joined = if offer_parts::is_manifest(value) {
        OfferManifest::parse(value)?.joined_from(part)?
    } else {
        join_parts_from(&crate::sync::room_parts::generic_manifest(value)?, part)?
    };
    Some(decode_held(&joined).is_ok_and(|row| carrier_key(&row, &joined) == key))
}
