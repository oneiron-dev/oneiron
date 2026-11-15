//! Retirement wake deadlines are noted through the store layer, as rows of each sweep's deadline
//! job.

pub(crate) use crate::store::housekeeping_wake::note_wake_in_txn;
pub(super) use crate::store::housekeeping_wake::{clear, due_by};
