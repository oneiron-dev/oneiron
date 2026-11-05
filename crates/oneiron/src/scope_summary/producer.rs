//! Core half of `scope_summary::producer`: its store-layer items live in `oneiron_store::scope_summary::producer` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::scope_summary::producer::*;

use crate::{EntityId, store::Store};
use std::cell::Cell;

/// The permit covers one exact body in one vault, only while its synchronous
/// internal batch applies. A generic embedded batch cannot forge a byline.
pub(super) fn admit(store: &Store, id: EntityId, body: &[u8]) -> MintPermit {
    let binding = (
        store as *const Store as usize,
        *id.as_bytes(),
        *blake3::hash(body).as_bytes(),
    );
    MintPermit(MINT.with(|slot| slot.replace(Some(binding))))
}

pub(super) fn admitted(store: &Store, id: EntityId, body: &[u8]) -> bool {
    let binding = (
        store as *const Store as usize,
        *id.as_bytes(),
        *blake3::hash(body).as_bytes(),
    );
    MINT.with(|slot| slot.get() == Some(binding))
}
