//! Durable HTTP idempotency storage and replay state.
//! Keyed requests share one lock, expiry clock, and response cache.
//! Request admission and capture live in the private request child.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::extract::{OriginalUri, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use oneiron::store::IdempotencyEntry as StoredIdempotencyEntry;

use crate::auth::{CoreAuth, require_owner_auth};
use crate::config::SyncServerConfig;
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

pub(crate) const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";
pub(crate) const IDEMPOTENCY_TTL: Duration = Duration::from_secs(86_400);

const IDEMPOTENCY_SYNC_STATE_PREFIX: &str = "http:idempotency:";
const SHARED_SECRET_PRINCIPAL: &str = "shared-secret";
const ANONYMOUS_PRINCIPAL: &str = "anonymous";

#[derive(Clone)]
pub(crate) struct IdempotencyLayerState {
    server: Arc<SyncServer>,
    store: IdempotencyStore,
}

impl IdempotencyLayerState {
    pub(crate) fn new(server: Arc<SyncServer>) -> Self {
        Self {
            store: IdempotencyStore::new(server.vault().clone()),
            server,
        }
    }

    /// The server a route's own keyed layer admits its caller against.
    pub(crate) fn server(&self) -> &SyncServer {
        &self.server
    }
}

#[derive(Clone)]
struct IdempotencyStore {
    vault: Arc<oneiron::Vault>,
    clock: Arc<dyn IdempotencyClock>,
    locks: Arc<IdempotencyLockTable>,
}

impl IdempotencyStore {
    fn new(vault: Arc<oneiron::Vault>) -> Self {
        Self {
            vault,
            clock: Arc::new(SystemClock),
            locks: Arc::new(IdempotencyLockTable::default()),
        }
    }

    #[cfg(test)]
    fn with_clock(vault: Arc<oneiron::Vault>, clock: Arc<dyn IdempotencyClock>) -> Self {
        Self {
            vault,
            clock,
            locks: Arc::new(IdempotencyLockTable::default()),
        }
    }

    fn now_secs(&self) -> u64 {
        self.clock.now_secs()
    }

    async fn lock_for(&self, store_key: &str) -> IdempotencyKeyGuard {
        self.locks.lock(store_key).await
    }

    fn lookup(
        &self,
        store_key: &str,
        request_target: &str,
        request_body: &[u8],
    ) -> Result<IdempotencyLookup, IdempotencyStoreError> {
        let Some(raw) = self
            .vault
            .sync_state_get(store_key)
            .map_err(IdempotencyStoreError::storage)?
        else {
            return Ok(IdempotencyLookup::Miss);
        };

        let stored = StoredIdempotencyEntry::decode(&raw).map_err(IdempotencyStoreError::decode)?;
        // Expiry is a delete, never an erase: the entry's instance keeps its
        // key, and the binding goes at the next checkpoint (KS-2B2).
        if self.now_secs().saturating_sub(stored.created_at_secs) >= IDEMPOTENCY_TTL.as_secs() {
            self.vault
                .sync_state_delete(store_key)
                .map_err(IdempotencyStoreError::storage)?;
            return Ok(IdempotencyLookup::Miss);
        }
        // An erase of an owner took the request and the response: the entry
        // answers that, never a miss, until it expires (KS-2B2).
        if stored.erased {
            return Ok(IdempotencyLookup::Erased);
        }
        if stored.request_body != request_body
            || stored
                .request_target
                .as_deref()
                .is_some_and(|target| target != request_target)
        {
            return Ok(IdempotencyLookup::Conflict);
        }

        // An intent no outcome settled: the first run never finished (FIX
        // 9527).
        if stored.status == intent::INTENT_STATUS {
            return Ok(IdempotencyLookup::Interrupted);
        }
        let response = CachedHttpResponse::of_stored(stored)?;
        Ok(IdempotencyLookup::Replay(response))
    }
}

#[derive(Default)]
struct IdempotencyLockTable {
    slots: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Where the expiry reclaim's next page starts (FIX 5951).
    sweep: reclaim::SweepCursor,
}

impl IdempotencyLockTable {
    async fn lock(self: &Arc<Self>, store_key: &str) -> IdempotencyKeyGuard {
        let slot = {
            let mut slots = self.slots.lock().await;
            slots
                .entry(store_key.to_owned())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let guard = slot.clone().lock_owned().await;
        IdempotencyKeyGuard {
            store_key: store_key.to_owned(),
            slot,
            table: self.clone(),
            guard: Some(guard),
        }
    }
}

struct IdempotencyKeyGuard {
    store_key: String,
    slot: Arc<tokio::sync::Mutex<()>>,
    table: Arc<IdempotencyLockTable>,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for IdempotencyKeyGuard {
    fn drop(&mut self) {
        self.guard.take();
        if Arc::strong_count(&self.slot) != 2 {
            return;
        }
        let Ok(mut slots) = self.table.slots.try_lock() else {
            return;
        };
        let Some(slot) = slots.get(&self.store_key) else {
            return;
        };
        if Arc::ptr_eq(slot, &self.slot) && Arc::strong_count(&self.slot) == 2 {
            slots.remove(&self.store_key);
        }
    }
}

enum IdempotencyLookup {
    Miss,
    Replay(CachedHttpResponse),
    Conflict,
    /// An erase of an owner took the cached response (KS-2B2).
    Erased,
    /// The first request's intent stands with no outcome (FIX 9527).
    Interrupted,
}

#[derive(Clone)]
struct CachedHttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    /// The rows the handler derived `body` from ([`ServedRows`]).
    rows: Vec<oneiron::EntityId>,
    /// The rows a replay re-admits ([`ServedRows::admit`]).
    admit: Option<Vec<oneiron::EntityId>>,
    /// [`ServedRows::sources`], kept as the entry's source stamps.
    sources: Vec<oneiron::EntityId>,
}

/// The rows a response was derived from, as its handler listed them while it
/// derived the response. A keyed response keeps them beside its cached
/// bytes, and a replay's release judges them (DEC-0005).
#[derive(Clone, Debug, Default)]
pub(crate) struct ServedRows {
    pub(crate) rows: Vec<oneiron::EntityId>,
    /// The rows the response named beyond its documents: an identity it
    /// addressed, a notification it delivered, a rider outcome or a pack
    /// source. A replay goes out only while the caller's read, as it stands
    /// then, still reads each of them. `None` when the handler could not list
    /// them all: a route that keeps them never replays such a response.
    pub(crate) admit: Option<Vec<oneiron::EntityId>>,
    /// The rows whose words the response carries without naming them, such
    /// as the CLAIMs a board's standing block was compiled from (FIX 8148).
    /// They are kept as the entry's source stamps, so an erase of one retires
    /// the response, and the route's release admits each again.
    pub(crate) sources: Vec<oneiron::EntityId>,
}

/// A cached success as its release judges it.
pub(crate) struct Replay<'a> {
    pub(crate) body: &'a [u8],
    pub(crate) rows: &'a [oneiron::EntityId],
    /// [`ServedRows::admit`]; `None` as well for an entry written before it
    /// was kept.
    pub(crate) admit: Option<&'a [oneiron::EntityId]>,
    /// [`ServedRows::sources`]; empty for an entry that kept none.
    pub(crate) sources: &'a [oneiron::EntityId],
}

/// Whether the caller's read, as it stands now, still reads every row a
/// replay re-admits: one snapshot, every claim status, so a settled outcome
/// the caller was shown still counts. Denied and missing rows alike refuse.
pub(crate) fn replay_admits(
    server: &SyncServer,
    auth: Option<&CoreAuth>,
    admit: &[oneiron::EntityId],
) -> Result<bool, ApiError> {
    if admit.is_empty() {
        return Ok(true);
    }
    let Some(auth) = auth else {
        return Ok(false);
    };
    let read = crate::api::scoped_read_for_core_auth(&server.vault, auth)?;
    read.recorded_lane()
        .and_then(|read| read.all_refs_readable(admit))
        .map_err(|error| {
            tracing::error!(kind = ?error.kind(), "idempotent replay admission failed");
            ApiError::internal_server_error("idempotent replay admission failed")
        })
}

impl CachedHttpResponse {
    fn replay(&self) -> Replay<'_> {
        Replay {
            body: &self.body,
            rows: &self.rows,
            admit: self.admit.as_deref(),
            sources: &self.sources,
        }
    }

    fn into_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response
    }
}

impl CachedHttpResponse {
    /// The entry this response is kept as: its time, the request it
    /// answers, and its owners' stamps, the caller's among them.
    fn into_stored(
        self,
        created_at_secs: u64,
        request_target: String,
        request_body: Vec<u8>,
        stamp: caller::EntryStamp,
    ) -> StoredIdempotencyEntry {
        let mut headers = Vec::with_capacity(self.headers.len());
        for (name, value) in &self.headers {
            headers.push((name.as_str().to_owned(), value.as_bytes().to_vec()));
        }
        StoredIdempotencyEntry {
            created_at_secs,
            request_body,
            status: self.status.as_u16(),
            headers,
            response_body: self.body,
            request_target: Some(request_target),
            served_rows: self.rows.iter().map(oneiron::EntityId::to_hex).collect(),
            replay_admits: self
                .admit
                .map(|admit| admit.iter().map(oneiron::EntityId::to_hex).collect()),
            stamps: oneiron::store::ResponseStamps {
                actor: stamp.caller,
                sources: self.sources,
                ..Default::default()
            },
            erased: false,
            erase_drops: stamp.erase_drops,
        }
    }

    /// The response a kept entry replays.
    fn of_stored(stored: StoredIdempotencyEntry) -> Result<Self, IdempotencyStoreError> {
        let mut headers = HeaderMap::new();
        for (name, value) in stored.headers {
            let name =
                HeaderName::from_bytes(name.as_bytes()).map_err(IdempotencyStoreError::header)?;
            let value = HeaderValue::from_bytes(&value).map_err(IdempotencyStoreError::header)?;
            headers.append(name, value);
        }

        Ok(Self {
            status: StatusCode::from_u16(stored.status).map_err(IdempotencyStoreError::status)?,
            headers,
            body: stored.response_body,
            rows: stored
                .served_rows
                .iter()
                .map(|id| oneiron::EntityId::from_hex(id))
                .collect::<Result<_, _>>()
                .map_err(IdempotencyStoreError::rows)?,
            admit: stored
                .replay_admits
                .map(|admit| {
                    admit
                        .iter()
                        .map(|id| oneiron::EntityId::from_hex(id))
                        .collect::<Result<_, _>>()
                })
                .transpose()
                .map_err(IdempotencyStoreError::rows)?,
            sources: stored.stamps.sources,
        })
    }
}

trait IdempotencyClock: Send + Sync {
    fn now_secs(&self) -> u64;
}

struct SystemClock;

impl IdempotencyClock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

#[derive(Debug)]
struct IdempotencyStoreError {
    message: String,
}

impl IdempotencyStoreError {
    fn storage(error: oneiron::Error) -> Self {
        Self {
            message: format!("idempotency store error: {error}"),
        }
    }

    fn decode(error: oneiron::Error) -> Self {
        Self {
            message: format!("idempotency decode error: {error}"),
        }
    }

    fn header(error: impl fmt::Display) -> Self {
        Self {
            message: format!("idempotency cached header error: {error}"),
        }
    }

    fn rows(error: impl fmt::Display) -> Self {
        Self {
            message: format!("idempotency cached rows error: {error}"),
        }
    }

    fn status(error: impl fmt::Display) -> Self {
        Self {
            message: format!("idempotency cached status error: {error}"),
        }
    }
}

impl fmt::Display for IdempotencyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

mod body_read;
mod caller;
mod intent;
mod reclaim;
mod request;

pub(crate) use self::request::{idempotency_for_mutating_form, idempotency_middleware};

#[cfg(test)]
mod tests;
