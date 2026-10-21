//! A MESSAGE document in a checkpoint (KS7-3a), read with the head codec
//! and filed under its message: the head names ids and versions only, and
//! is the manifest of its snapshot's parts, which its message holds. The
//! joined snapshot is the message document's Loro history, whose stamps
//! only its own split takes out, so no part is sealed before KS7-3b joins
//! it.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::decode;
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::carrier_parts::is_part_key;
use crate::sync::checkpoint_payload::{Holder, Placement, SyncUnclassified};

/// A message document's snapshot: Loro history with its stamps.
const SNAPSHOT_STAMPS: &str =
    "a message document's snapshot, whose stamps only its split takes out";

/// Where the value under `key` in the message document map goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    if is_part_key(key) {
        return Placement::Part;
    }
    match decode(value) {
        Ok((carried, message)) if message.to_hex() == key => Placement::Manifest {
            holders: vec![Holder::new(OwnerRef::entity(&message), Vec::new())],
            parts: carried.snapshot,
            joined: Some(SyncUnclassified::ActorSplit(SNAPSHOT_STAMPS)),
        },
        _ => Placement::unclassified(None, SyncUnclassified::Undecodable),
    }
}
