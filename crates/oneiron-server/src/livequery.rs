//! App-tier framing and coarse live-query state, separate from WindowSync.
//!
//! Facade construction uses only verified CoreAuth claims. No payload actor,
//! token re-parser, or default class can cross this boundary. Reads run in the
//! deferred owner loop, never in Observer B or through a second materializer.

use oneiron::memory::{Effort, Memory, RecallScope};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::{CoreAuth, CoreScope};
use crate::protocol::{ProtocolError, TAG_RPC, TAG_SUB};

mod error;
mod reads;
use error::AppError;
use reads::{Read, read_method};

/// RPC ids never index the subscription table.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RpcRequest {
    pub request_id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

pub(crate) fn decode_rpc(payload: &[u8]) -> Result<RpcRequest, ProtocolError> {
    serde_json::from_slice(payload)
        .map_err(|_| ProtocolError::InvalidPayload("invalid RPC request"))
}

pub(crate) fn bind_token(params: &Value) -> Result<String, ProtocolError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Bind {
        token: String,
    }
    serde_json::from_value::<Bind>(params.clone())
        .map(|bind| bind.token)
        .map_err(|_| ProtocolError::RpcNoPrincipal)
}

fn encode(tag: u8, value: &impl Serialize) -> Result<Vec<u8>, ProtocolError> {
    let mut frame = vec![tag];
    serde_json::to_writer(&mut frame, value)
        .map_err(|_| ProtocolError::InvalidPayload("app frame serialization failed"))?;
    let max = oneiron::sync::transport::MAX_DECODED_PAYLOAD_BYTES;
    if frame.len() > max {
        return Err(ProtocolError::FrameTooLarge {
            size: frame.len(),
            max,
        });
    }
    Ok(frame)
}

/// Unary v1 RPCs always terminate, including null and empty-list results.
pub(crate) fn rpc_result(request_id: u64, result: Value) -> Result<Vec<u8>, ProtocolError> {
    encode(
        TAG_RPC,
        &json!({ "requestId": request_id, "result": result, "last": true }),
    )
}

fn rpc_error(request_id: u64, error: AppError) -> Result<Vec<u8>, ProtocolError> {
    encode(
        TAG_RPC,
        &json!({ "requestId": request_id, "last": true, "error": error }),
    )
}

/// Both identity claims come from the credential, exactly as on the HTTP facade.
fn bound_memory<'a>(vault: &'a oneiron::Vault, auth: &CoreAuth) -> Result<Memory<'a>, AppError> {
    auth.require(CoreScope::Read)?;
    let principal = auth.principal_ref().ok_or_else(|| {
        AppError::forbidden(
            "facade routes bind writes to an authenticated principal",
            [
                "Present a slip minted with --principal-ref <32-hex person id>.",
                "An owner-grade credential names no principal and cannot write here.",
            ],
        )
    })?;
    let actor = oneiron::EntityId::from_hex(principal).map_err(|_| {
        AppError::forbidden(
            "principal_ref is not a 32-hex entity id",
            ["Re-mint the slip with a 32-character lowercase hex principal ref."],
        )
    })?;
    Ok(vault.memory(actor, bound_actor_class(auth)?))
}

fn bound_actor_class(auth: &CoreAuth) -> Result<oneiron::EdgeActorClass, AppError> {
    match auth.actor_class() {
        Some("human") => Ok(oneiron::EdgeActorClass::Human),
        Some("agent") => Ok(oneiron::EdgeActorClass::Agent),
        Some("system") => Ok(oneiron::EdgeActorClass::System),
        None | Some(_) => Err(AppError::forbidden(
            "facade routes bind writes to a declared actor class",
            [
                "Present a slip minted with --actor-class <human|agent|system>.",
                "Reconnect with a differently scoped slip to act as another actor.",
            ],
        )),
    }
}

pub(crate) fn bound_rpc(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    request: RpcRequest,
) -> Result<Vec<u8>, ProtocolError> {
    let result = (|| {
        if !read_method(&request.method) {
            return Err(AppError::bad_request("unknown read RPC", Some("method")));
        }
        // HTTP order: scope, request/limit validation, identity, engine call.
        auth.require(CoreScope::Read)?;
        let read = Read::parse(&request.method, request.params)?;
        let memory = bound_memory(vault, auth)?;
        read.run(&memory)
    })();
    match result {
        Ok(value) => rpc_result(request.request_id, value),
        Err(error) => rpc_error(request.request_id, error),
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScopedView {
    pub world_ref: Option<String>,
    pub facet: Option<String>,
    pub filter: Option<Value>,
    pub query: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Channel {
    #[default]
    View,
    Receipts,
    PendingConsent,
    // Reserved, explicitly rejected rather than aliasing a different stream.
    MemoryBoard,
    Gap,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", deny_unknown_fields)]
pub(crate) enum SubRequest {
    #[serde(rename = "sub.open")]
    Open {
        #[serde(rename = "subscriptionId")]
        subscription_id: u64,
        #[serde(rename = "scopedView")]
        scoped_view: ScopedView,
        #[serde(default)]
        channel: Channel,
        #[serde(default)]
        cursor: Option<Cursor>,
        #[serde(default)]
        origin: Option<String>,
    },
    #[serde(rename = "sub.ack")]
    Ack {
        #[serde(rename = "subscriptionId")]
        subscription_id: u64,
        cursor: Cursor,
    },
    #[serde(rename = "sub.close")]
    Close {
        #[serde(rename = "subscriptionId")]
        subscription_id: u64,
    },
}

pub(crate) fn sub_error(id: u64, error: AppError) -> Result<Vec<u8>, ProtocolError> {
    encode(
        TAG_SUB,
        &json!({ "subscriptionId": id, "last": true, "error": error }),
    )
}

impl SubRequest {
    pub(crate) fn id(&self) -> u64 {
        match self {
            Self::Open {
                subscription_id, ..
            }
            | Self::Ack {
                subscription_id, ..
            }
            | Self::Close { subscription_id } => *subscription_id,
        }
    }
}

pub(crate) mod connection;
mod source;

/// Opaque Loro cursor plus a container-batch ordinal. A single Loro commit
/// can materialize several containers; VV alone cannot acknowledge those
/// different snapshots without accidentally acknowledging an unseen batch.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cursor {
    pub document: String,
    pub version_vector: Vec<u8>,
    pub batch: u64,
}

pub(crate) mod subscriptions {
    use super::*;
    use loro::{ExportMode, LoroDoc, VersionVector};
    use oneiron::sync::bridge::{LiveQueryTee, MaterializedDiffSummary, OriginMark};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    pub(crate) const LIVEQUERY_RING_CAPACITY: usize = 1024;
    const MAX_SUBSCRIPTIONS: usize = 128;
    const MAX_RING_BYTES: usize = 8 * 1024 * 1024;

    pub(crate) struct DerivedView {
        pub value: Value,
        pub cursor: Cursor,
        /// Trusted server-derived paths, never a client-provided read set.
        /// Include membership containers, not only current result ids, so
        /// an insertion into an empty view also invalidates it.
        pub dependencies: BTreeSet<String>,
    }

    /// Implementations must use one authority-bound facade, honor every view
    /// constraint, and re-consult revocation before each derive/export. They
    /// must not return raw full-window updates as app-tier data.
    pub(crate) trait LiveQuerySource: Send + Sync {
        fn derive(&self, view: &ScopedView, channel: Channel) -> Result<DerivedView, AppError>;
        /// Validate/export the scoped document's updates since this VV. `false`
        /// means the cursor is past retention and requires full-state resync.
        fn can_resume(&self, cursor: &Cursor) -> Result<bool, AppError>;
    }

    /// Exercise Loro's real export door. Delta bytes remain server-side: a
    /// subscription re-derives its authorized view, never leaks a window.
    pub(crate) fn export_since(doc: &LoroDoc, cursor: &Cursor) -> Result<bool, AppError> {
        let vv = VersionVector::decode(&cursor.version_vector)
            .map_err(|_| AppError::bad_request("invalid cursor VV", Some("cursor")))?;
        let current = doc.oplog_vv();
        if !matches!(
            current.partial_cmp(&vv),
            Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
        ) {
            return Err(AppError::bad_request(
                "cursor is ahead of this document",
                Some("cursor"),
            ));
        }
        let shallow = doc.shallow_since_vv().to_vv();
        if !matches!(
            vv.partial_cmp(&shallow),
            Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
        ) {
            return Ok(false);
        }
        doc.export(ExportMode::updates(&vv))
            .map_err(|_| AppError::internal_server_error("cursor delta export failed"))?;
        Ok(true)
    }

    #[derive(Clone, Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct Push {
        pub subscription_id: u64,
        pub cursor: Cursor,
        pub kind: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub result: Option<Value>,
    }

    impl Push {
        pub(crate) fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
            encode(TAG_SUB, self)
        }
    }

    struct Subscription {
        view: ScopedView,
        channel: Channel,
        origin: Option<String>,
        dependencies: BTreeSet<String>,
        current: Value,
        ring: VecDeque<Push>,
        bytes: usize,
        acked: Option<Cursor>,
        needs_resync: bool,
    }

    /// Owned by one bound logical session; keep this owner across socket
    /// reconnects, but never reuse it for a different principal or claim set.
    /// RPC results are deliberately absent from this state.
    pub(crate) struct LiveQueries {
        source: Arc<dyn LiveQuerySource>,
        state: Mutex<State>,
        invalidations: Mutex<VecDeque<(String, MaterializedDiffSummary, OriginMark)>>,
        invalidation_gap: AtomicBool,
    }

    struct State {
        conn_id: u32,
        batch: u64,
        subs: BTreeMap<u64, Subscription>,
        index: BTreeMap<String, BTreeSet<u64>>,
    }

    impl State {
        fn reindex(&mut self) {
            self.index.clear();
            for (id, sub) in &self.subs {
                for path in &sub.dependencies {
                    self.index.entry(path.clone()).or_default().insert(*id);
                }
            }
        }

        fn cursor(&mut self, mut cursor: Cursor) -> Result<Cursor, AppError> {
            self.batch = self
                .batch
                .checked_add(1)
                .ok_or_else(|| AppError::internal_server_error("live-query ordinal exhausted"))?;
            cursor.batch = self.batch;
            Ok(cursor)
        }
    }

    impl LiveQueries {
        pub(crate) fn new(conn_id: u32, source: Arc<dyn LiveQuerySource>) -> Self {
            Self {
                source,
                state: Mutex::new(State {
                    conn_id,
                    batch: 0,
                    subs: BTreeMap::new(),
                    index: BTreeMap::new(),
                }),
                invalidations: Mutex::new(VecDeque::new()),
                invalidation_gap: AtomicBool::new(false),
            }
        }

        pub(crate) fn control(&self, request: SubRequest) -> Result<Vec<Push>, AppError> {
            match request {
                SubRequest::Open {
                    subscription_id,
                    scoped_view,
                    channel,
                    cursor,
                    origin,
                } => self.open(
                    subscription_id,
                    scoped_view,
                    channel,
                    cursor.as_ref(),
                    origin,
                ),
                SubRequest::Ack {
                    subscription_id,
                    cursor,
                } => {
                    self.ack(subscription_id, &cursor)?;
                    Ok(Vec::new())
                }
                SubRequest::Close { subscription_id } => {
                    self.close(subscription_id)?;
                    Ok(Vec::new())
                }
            }
        }

        /// Called only after a fresh bind to the SAME authority has succeeded.
        pub(crate) fn reconnect(&self, conn_id: u32) -> Result<(), AppError> {
            self.state.lock().map_err(|_| state_error())?.conn_id = conn_id;
            Ok(())
        }

        pub(crate) fn open(
            &self,
            id: u64,
            view: ScopedView,
            channel: Channel,
            cursor: Option<&Cursor>,
            origin: Option<String>,
        ) -> Result<Vec<Push>, AppError> {
            if matches!(channel, Channel::MemoryBoard | Channel::Gap) {
                return Err(AppError::not_implemented("reserved subscription channel"));
            }
            if let Some(world) = &view.world_ref {
                oneiron::EntityId::from_hex(world)
                    .map_err(|_| AppError::bad_request("invalid worldRef", Some("scopedView")))?;
            }
            let mut state = self.state.lock().map_err(|_| state_error())?;
            if let Some(sub) = state.subs.get_mut(&id) {
                if sub.view != view || sub.channel != channel {
                    return Err(AppError::bad_request(
                        "subscription id is already open",
                        Some("subscriptionId"),
                    ));
                }
                if let Some(cursor) = cursor {
                    // Consult the source on reconnect even when the ring has
                    // the cursor; retention and authority can both change.
                    if self.source.can_resume(cursor)? && !sub.needs_resync {
                        if sub.acked.as_ref() == Some(cursor) {
                            sub.origin = origin;
                            return Ok(sub.ring.iter().cloned().collect());
                        }
                        if let Some(position) = sub.ring.iter().rposition(|p| &p.cursor == cursor) {
                            sub.origin = origin;
                            sub.ring.drain(..=position);
                            sub.bytes = push_bytes(sub.ring.make_contiguous())?;
                            sub.acked = Some(cursor.clone());
                            return Ok(sub.ring.iter().cloned().collect());
                        }
                    }
                } else {
                    return Err(AppError::bad_request(
                        "subscription is already open",
                        Some("subscriptionId"),
                    ));
                }
            } else if state.subs.len() >= MAX_SUBSCRIPTIONS {
                return Err(AppError::bad_request(
                    "subscription limit exceeded",
                    Some("subscriptionId"),
                ));
            }
            // No retained history is never a silent catch-up. Even if Loro
            // still has the delta, re-derivation is a full-state resync, not
            // a promise that vanished intermediate app snapshots were replayed.
            if let Some(cursor) = cursor {
                self.source.can_resume(cursor)?;
            }
            let derived = self.source.derive(&view, channel)?;
            let next_cursor = state.cursor(derived.cursor)?;
            let mut pushes = Vec::new();
            if cursor.is_some() {
                pushes.push(Push {
                    subscription_id: id,
                    cursor: next_cursor.clone(),
                    kind: "gap",
                    result: None,
                });
            }
            pushes.push(Push {
                subscription_id: id,
                cursor: next_cursor,
                kind: "snapshot",
                result: Some(derived.value.clone()),
            });
            let bytes = push_bytes(&pushes)?;
            if bytes > MAX_RING_BYTES {
                return Err(AppError::bad_request(
                    "view snapshot too large",
                    Some("scopedView"),
                ));
            }
            state.subs.insert(
                id,
                Subscription {
                    view,
                    channel,
                    origin,
                    dependencies: derived.dependencies,
                    current: derived.value,
                    ring: pushes.iter().cloned().collect(),
                    bytes,
                    acked: None,
                    needs_resync: false,
                },
            );
            state.reindex();
            Ok(pushes)
        }

        /// Acks are cumulative and must name a cursor this sub actually sent.
        /// Unknown/future cursors cannot discard buffered history.
        pub(crate) fn ack(&self, id: u64, cursor: &Cursor) -> Result<(), AppError> {
            let mut state = self.state.lock().map_err(|_| state_error())?;
            let sub = state
                .subs
                .get_mut(&id)
                .ok_or_else(|| AppError::not_found("subscription", None))?;
            if sub.acked.as_ref() == Some(cursor) {
                return Ok(());
            }
            let position = sub
                .ring
                .iter()
                .rposition(|p| &p.cursor == cursor)
                .ok_or_else(|| AppError::bad_request("unknown ack cursor", Some("cursor")))?;
            sub.ring.drain(..=position);
            sub.bytes = push_bytes(sub.ring.make_contiguous())?;
            sub.acked = Some(cursor.clone());
            Ok(())
        }

        pub(crate) fn close(&self, id: u64) -> Result<(), AppError> {
            let mut state = self.state.lock().map_err(|_| state_error())?;
            state.subs.remove(&id);
            state.reindex();
            Ok(())
        }

        pub(crate) fn buffered(&self) -> Result<Vec<Push>, AppError> {
            let state = self.state.lock().map_err(|_| state_error())?;
            Ok(state
                .subs
                .values()
                .flat_map(|sub| sub.ring.iter().cloned())
                .collect())
        }

        #[cfg(test)]
        pub(crate) fn pending(&self, id: u64) -> Result<Vec<Push>, AppError> {
            let state = self.state.lock().map_err(|_| state_error())?;
            let sub = state
                .subs
                .get(&id)
                .ok_or_else(|| AppError::not_found("subscription", None))?;
            self.source.derive(&sub.view, sub.channel)?;
            Ok(sub.ring.iter().cloned().collect())
        }

        fn materialized(
            &self,
            changes: &[(String, MaterializedDiffSummary, OriginMark)],
        ) -> Result<(), AppError> {
            let mut state = self.state.lock().map_err(|_| state_error())?;
            // Coarse re-derive sees CURRENT state, not intermediate event
            // states. Suppress only when EVERY affecting invalidation is our
            // own; an earlier own write must not swallow a later foreign one.
            let mut affected = BTreeMap::<u64, bool>::new();
            for (path, diff, by) in changes {
                for (dependency, ids) in &state.index {
                    let relevant = dependency == path
                        || (dependency == "w:" && path.starts_with("w:"))
                        || path
                            .strip_prefix(dependency.as_str())
                            .is_some_and(|tail| tail.starts_with('/'))
                        || dependency
                            .strip_prefix(path.as_str())
                            .is_some_and(|tail| tail.starts_with('/'))
                        || diff.containers.iter().any(|changed| changed == dependency);
                    if !relevant {
                        continue;
                    }
                    for id in ids {
                        let own = by.conn_id == Some(state.conn_id)
                            || (by.origin.is_some() && by.origin == state.subs[id].origin);
                        affected
                            .entry(*id)
                            .and_modify(|echo| *echo &= own)
                            .or_insert(own);
                    }
                }
            }
            for (id, echo) in affected {
                let sub = &state.subs[&id];
                if sub.needs_resync {
                    continue;
                }
                let derived = self.source.derive(&sub.view, sub.channel)?;
                let changed = sub.current != derived.value;
                let cursor = state.cursor(derived.cursor)?;
                let sub = state.subs.get_mut(&id).ok_or_else(state_error)?;
                sub.dependencies = derived.dependencies;
                sub.current = derived.value.clone();
                if echo || !changed {
                    continue;
                }
                let push = Push {
                    subscription_id: id,
                    cursor: cursor.clone(),
                    kind: "snapshot",
                    result: Some(derived.value),
                };
                let bytes = push_bytes(std::slice::from_ref(&push))?;
                if sub.ring.len() >= LIVEQUERY_RING_CAPACITY
                    || sub.bytes.saturating_add(bytes) > MAX_RING_BYTES
                {
                    sub.ring.clear();
                    let gap = Push {
                        subscription_id: id,
                        cursor,
                        kind: "gap",
                        result: None,
                    };
                    sub.bytes = push_bytes(std::slice::from_ref(&gap))?;
                    sub.ring.push_back(gap);
                    sub.needs_resync = true;
                } else {
                    sub.bytes += bytes;
                    sub.ring.push_back(push);
                }
            }
            state.reindex();
            Ok(())
        }
    }

    impl LiveQueries {
        /// Drive from the server's subscription loop, OUTSIDE Observer B.
        /// Facade reads such as recall may persist retrieval telemetry; doing
        /// that inside the materializer callback would re-enter Loro.
        pub(crate) fn refresh(&self) -> Result<(), AppError> {
            let changes = {
                let mut pending = self.invalidations.lock().map_err(|_| state_error())?;
                std::mem::take(&mut *pending)
            };
            if self.invalidation_gap.swap(false, Ordering::AcqRel) {
                self.require_resync();
                return Ok(());
            }
            let changes: Vec<_> = changes.into_iter().collect();
            if let Err(error) = self.materialized(&changes) {
                self.require_resync();
                return Err(error);
            }
            Ok(())
        }

        fn require_resync(&self) {
            if let Ok(mut state) = self.state.lock() {
                for (id, sub) in &mut state.subs {
                    if let Some(cursor) = sub
                        .ring
                        .back()
                        .map(|p| p.cursor.clone())
                        .or_else(|| sub.acked.clone())
                    {
                        sub.ring.clear();
                        sub.ring.push_back(Push {
                            subscription_id: *id,
                            cursor,
                            kind: "gap",
                            result: None,
                        });
                        sub.bytes = 0;
                    }
                    sub.needs_resync = true;
                }
            }
        }
    }

    impl LiveQueryTee for LiveQueries {
        fn on_materialized(&self, path: &str, diff: &MaterializedDiffSummary, by: &OriginMark) {
            let Ok(mut pending) = self.invalidations.lock() else {
                self.invalidation_gap.store(true, Ordering::Release);
                return;
            };
            // Bound invalidation metadata independently of every subscription
            // ring. An overflow loses history explicitly, never silently.
            let bytes: usize = pending.iter().map(|(path, _, _)| path.len()).sum();
            if pending.len() >= LIVEQUERY_RING_CAPACITY
                || bytes.saturating_add(path.len()) > MAX_RING_BYTES
            {
                pending.clear();
                self.invalidation_gap.store(true, Ordering::Release);
                return;
            }
            // A coarse container dependency is enough to invalidate all its
            // descendants. Do not clone unbounded per-key delta metadata.
            pending.push_back((
                path.to_owned(),
                MaterializedDiffSummary {
                    containers: Vec::new(),
                    bytes: diff.bytes,
                },
                by.clone(),
            ));
        }
    }

    fn push_bytes(pushes: &[Push]) -> Result<usize, AppError> {
        serde_json::to_vec(pushes)
            .map(|bytes| bytes.len())
            .map_err(|_| AppError::internal_server_error("live-query serialization failed"))
    }

    fn state_error() -> AppError {
        AppError::internal_server_error("live-query state unavailable")
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod socket_tests;

#[cfg(test)]
mod production_tests;

#[cfg(test)]
mod production_socket_tests;
