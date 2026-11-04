//! Standing-query health facade.

pub use crate::store::query_health::{SavedQueryPass, SavedQueryWakeOutcome, SavedQueryWake, SavedQueryHealth, record_saved_query_wake, saved_query_health};
pub(super) use crate::store::query_health::{HEALTH, health_in_txn};
