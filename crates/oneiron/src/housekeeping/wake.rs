//! Retirement wake rows are owned by the store layer.

pub(crate) use crate::store::housekeeping_wake::note_wake_in_txn;
pub(super) use crate::store::housekeeping_wake::{WAKE_SWEEPS, clear, due_by, earliest_in_txn};
