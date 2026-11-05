//! Standing-query health facade.

pub(super) use crate::store::query_health::{HEALTH, health_in_txn};
pub use crate::store::query_health::{
    SavedQueryHealth, SavedQueryPass, SavedQueryWake, SavedQueryWakeOutcome,
    record_saved_query_wake, saved_query_health,
};
