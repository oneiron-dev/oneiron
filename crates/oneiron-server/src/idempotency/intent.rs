//! The intent a keyed mutation keeps before its route runs (FIX 9527, 6056).
//!
//! The entry's row is written before the route runs, holding the request it
//! answers and no outcome yet, and settled with the outcome once the route
//! answered a success. A run that never settles (a crash, a dropped
//! connection, a store that would not take the outcome) leaves that row, so
//! a retry under the same key learns the first one's outcome is unknown and
//! never runs the effect a second time. The caller acts again under a new
//! key. A route that answered a failure lets its row go, so a retry runs
//! again, as a failure was never kept. The row keeps the caller's stamps,
//! so an erase reaches it as it reaches an outcome.

use super::{
    CachedHttpResponse, IdempotencyStore, IdempotencyStoreError, StoredIdempotencyEntry, caller,
};
use crate::error::{ApiError, ApiErrorDetails};

/// The status an intent row holds: no HTTP status is 0.
pub(super) const INTENT_STATUS: u16 = 0;

impl IdempotencyStore {
    /// Keeps the intent of the request `request_target` sent with
    /// `request_body` as `store_key`, stamped as its outcome will be.
    pub(super) fn insert_intent(
        &self,
        store_key: &str,
        request_target: String,
        request_body: Vec<u8>,
        stamp: caller::EntryStamp,
    ) -> Result<(), IdempotencyStoreError> {
        let intent = StoredIdempotencyEntry {
            created_at_secs: self.now_secs(),
            request_body,
            status: INTENT_STATUS,
            request_target: Some(request_target),
            stamps: oneiron::store::ResponseStamps {
                actor: stamp.caller,
                ..Default::default()
            },
            erase_drops: stamp.erase_drops,
            ..Default::default()
        };
        self.vault
            .http_idempotency_put(store_key, &intent)
            .map_err(IdempotencyStoreError::storage)
    }

    /// Settles `store_key`'s intent with `response`, whatever its size,
    /// stamped with its caller (KS-2B2, FIX 7357). `false` when an erase took
    /// the row meanwhile: it stays as the erase left it.
    pub(super) fn settle(
        &self,
        store_key: &str,
        request_target: String,
        request_body: Vec<u8>,
        response: CachedHttpResponse,
        stamp: caller::EntryStamp,
    ) -> Result<bool, IdempotencyStoreError> {
        let stored = response.into_stored(self.now_secs(), request_target, request_body, stamp);
        self.vault
            .http_idempotency_settle(store_key, &stored)
            .map_err(IdempotencyStoreError::storage)
    }

    /// Lets `store_key`'s intent go after its route answered a failure.
    pub(super) fn release_intent(&self, store_key: &str) -> Result<(), IdempotencyStoreError> {
        self.vault
            .sync_state_delete(store_key)
            .map(|_| ())
            .map_err(IdempotencyStoreError::storage)
    }
}

/// The answer to a retry whose key holds an intent no outcome settled: the
/// first request's effect may or may not have landed, so it is not run again.
pub(super) fn outcome_unknown() -> ApiError {
    ApiError::new(
        "the first request with this key did not finish: its effect may have landed",
        ApiErrorDetails::InvalidState {
            state: Some("idempotent_outcome_unknown".to_owned()),
        },
        [
            "Read the resource's current state to see whether the effect landed.",
            "Send the request with a new Idempotency-Key to act again.",
        ],
    )
}
