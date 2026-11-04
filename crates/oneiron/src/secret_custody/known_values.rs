//! The custody side of the known-value index (OF-560 C): which records it
//! never keys. The index itself is [`crate::store::known_value_index`].

pub use crate::store::known_value_index::KNOWN_VALUE_MIN_BYTES;
pub(crate) use crate::store::known_value_index::{
    KnownSource, KnownSweep, KnownValues, known_index_scope,
};
pub(super) use crate::store::known_value_index::{decodings, occurrences, remember_in_txn};

/// Whether the index never keys the value of the record named `name`: a
/// run-bound record's, its run's alone (FIX 8028), a cloud registration
/// slot's, whose tokens leave no known-value history for its erase to carry
/// (G7), and a short or bare dotenv value's, masked in its own file only
/// (FIX 7608 slice 6, CALL DOTENV-IMPORT).
pub(super) fn never_keyed(name: &str) -> bool {
    super::run_bound::is_run_bound_name(name)
        || super::is_cloud_registration_slot(name)
        || crate::store::repo_environment::is_unindexed_dotenv_name(name)
}
