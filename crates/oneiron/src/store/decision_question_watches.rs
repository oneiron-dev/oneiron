//! Which units a typed question watches for arrivals: the units its outcome
//! binding names, and the sources its newest standing answer rests on. The
//! question records (`llm::decision::questions`) write and erase these rows;
//! the store's batch and entity-document writes test a unit to wake the
//! question pump.
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Result};

pub(crate) const UNIT_WATCH: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::TYPED_QUESTION_UNIT_WATCH);
/// Key: source + question + root unit.
pub(crate) const RESTS_ON: SideTable<(EntityId, EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::TYPED_QUESTION_RESTS_ON);

/// Whether a question watches `unit` for arrivals. A batch that writes such a
/// unit wakes the question pump after it commits, as a claim write does.
pub(crate) fn unit_watched_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    unit: &EntityId,
) -> Result<bool> {
    Ok(UNIT_WATCH
        .iter_from(store, txn, unit.as_bytes())?
        .next()
        .transpose()?
        .is_some()
        || RESTS_ON
            .iter_from(store, txn, unit.as_bytes())?
            .next()
            .transpose()?
            .is_some())
}
