//! A base witness that commits its caller's own record with the turn (FIX
//! 8533): the record runs in the turn's write after the turn landed, given
//! the TURN and MESSAGE ids the turn actually stored, so the turn and the
//! record commit together or not at all.
//! `Memory::witness_linked_with_room_birth` is its call surface.

use super::super::*;
use super::program::{WitnessDoor, WitnessTarget};

impl Memory<'_> {
    /// [`Self::witness_with_room_birth`] whose `record` runs in the turn's
    /// own write once the turn landed, with the receipt read there. An error
    /// from `prepare` or from `record` rolls the whole turn back.
    pub(crate) fn witness_linked_with_room_birth(
        &self,
        turn: &WitnessTurn,
        prepare: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
        record: impl FnOnce(&mut heed::RwTxn<'_>, &WitnessReceipt) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        self.run_witness_as(
            crate::store::Callback::Audited,
            turn,
            WitnessTarget::Base { route: None },
            WitnessDoor::Guest,
            || {},
            |txn| prepare(txn).map(|()| None),
            |txn, landed| match landed {
                Some(receipt) => record(txn, receipt),
                None => Err(crate::error::Error::InvariantViolation(
                    "a base witness reads its receipt in its own write",
                )
                .into()),
            },
        )
    }
}
