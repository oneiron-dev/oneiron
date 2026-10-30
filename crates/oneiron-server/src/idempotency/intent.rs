//! The intent a keyed mutation keeps before its route runs (FIX 9527, 6056).
//!
//! The entry's row is written before the route runs, holding the request it
//! answers and no outcome yet, and settled with the outcome once the route
//! answered a success. A run that never settles (a crash, a dropped
//! connection, a store that would not take the outcome) leaves that row, so
//! a retry under the same key never runs the effect a second time. The
//! caller acts again under a new key. A route that answered a failure lets
//! its row go, so a retry runs again, as a failure was never kept. The row
//! keeps the caller's stamps, so an erase reaches it as it reaches an
//! outcome.
//!
//! The route runs with the row open as its intent ([`run_under_intent`]):
//! each write it commits through the vault's group commit counts itself on
//! the row in its own transaction (FIX 10379). A retry that finds counted
//! writes learns they landed and the reply was not kept
//! ([`reply_not_kept`]); one that finds none learns the outcome is unknown
//! ([`outcome_unknown`]), as a write that commits outside the group commit
//! counts nothing.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use oneiron::store::IdempotencyIntent;

use super::{
    CachedHttpResponse, IdempotencyStore, IdempotencyStoreError, StoredIdempotencyEntry, caller,
};
use crate::error::{ApiError, ApiErrorDetails};

/// The status an intent row holds: no HTTP status is 0.
pub(super) const INTENT_STATUS: u16 = StoredIdempotencyEntry::INTENT_STATUS;

/// The state a retry answers when its key's first request committed writes
/// and its reply was not kept (CALLS: FIX 10379 reply-not-kept answer).
const REPLY_NOT_KEPT_STATE: &str = "idempotent_reply_not_kept";

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

/// The answer to a retry whose key holds an intent on which
/// `committed_writes` writes counted themselves while the first request ran
/// (FIX 10379): they landed, and the reply was not kept, so the request is
/// not run again. The count is every write the vault's group commit kept on
/// the threads that served the request, its route's and any its auth made
/// there, so it says how many landed, not which: a route that writes more
/// than once may have stopped between its writes.
pub(super) fn reply_not_kept(committed_writes: u32) -> ApiError {
    ApiError::new(
        format!(
            "the first request with this key committed {committed_writes} write(s) while it ran; its reply was not kept"
        ),
        ApiErrorDetails::InvalidState {
            state: Some(REPLY_NOT_KEPT_STATE.to_owned()),
        },
        [
            "Read the resource's current state to see what landed.",
            "Send the request with a new Idempotency-Key to act again.",
        ],
    )
}

/// Runs `run`, a keyed route and the read of its reply, with the intent kept
/// as `store_key` open on the thread of each of its polls, so each write it
/// commits there, or on a hop that carries the intent, counts itself on the
/// intent's row (FIX 10379). A key the engine does not take as an intent
/// runs as it is, and its writes count nothing.
pub(super) async fn run_under_intent<F: Future>(store_key: &str, run: F) -> F::Output {
    IntentPolls {
        intent: IdempotencyIntent::new(store_key).ok(),
        run: Box::pin(run),
    }
    .await
}

/// A future each of whose polls runs with its intent open.
struct IntentPolls<F> {
    intent: Option<IdempotencyIntent>,
    run: Pin<Box<F>>,
}

impl<F: Future> Future for IntentPolls<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();
        oneiron::store::with_idempotency_intent(this.intent.as_ref(), || this.run.as_mut().poll(cx))
    }
}
