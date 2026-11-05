//! Private admission for locally minted scope-summary bodies.

use oneiron_contracts::entity_id::EntityId;
use std::cell::Cell;

type Binding = (usize, [u8; 16], [u8; 32]);
thread_local! {
    static MINT: Cell<Option<Binding>> = const { Cell::new(None) };
}

pub struct MintPermit(pub Option<Binding>);
impl Drop for MintPermit {
    fn drop(&mut self) {
        MINT.with(|slot| slot.set(self.0));
    }
}

