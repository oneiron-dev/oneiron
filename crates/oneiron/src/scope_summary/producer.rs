//! Private admission for locally minted scope-summary bodies.

use crate::{EntityId, store::Store};
use std::cell::Cell;

type Binding = (usize, [u8; 16], [u8; 32]);
thread_local! {
    static MINT: Cell<Option<Binding>> = const { Cell::new(None) };
}

pub(super) struct MintPermit(Option<Binding>);
impl Drop for MintPermit {
    fn drop(&mut self) {
        MINT.with(|slot| slot.set(self.0));
    }
}

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
