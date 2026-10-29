//! The verb door of one action call (OF-181), split from its parent: each
//! verb-table row runs as its own generated facade route, in process, and
//! the door keeps what the row answered, its refusal words and its call
//! receipt's stamp (FIX 2887).
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{Extensions, HeaderMap, HeaderValue, header};
use axum::response::Response;
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, AgentVerbRefusalWords, RunCall,
    SelfAgentVerbCall, SelfEffect,
};
use oneiron::memory::{HostWriteOrigin, MEMORY_CODE_INTERNAL};
use tower::ServiceExt;

use crate::api::call_receipt::{
    CallStamp, RECEIPT_REF_HEADER, attempt_collector, with_attempt_collector,
};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The verb door of one action call. Each verb-table row runs as its own
/// generated facade route, in process, under the request's own headers and
/// connection, so it meets exactly what a direct call of the row meets.
///
/// The row writes as the credential, as its direct call does: an action is
/// its caller's own call, not a run's generated write, so the run origin the
/// dispatcher offers is not the row's source.
///
/// A memory run row reads with `read_key`, the credential's own read key
/// at the caller's locality, which this request was admitted on.
///
/// A row's refusal keeps the words its route answered with in `refused`,
/// which the action's record keeps beside its code; the guest sees only the
/// code. What its reply stated of its call receipt is kept in `stamp`, for
/// a caller that states it again on its own reply (FIX 2887).
pub(super) struct FacadeRowDoor {
    rows: Router,
    headers: HeaderMap,
    extensions: Extensions,
    runtime: tokio::runtime::Handle,
    read_key: ScopedReadActorKey,
    credential: Option<CoreAuth>,
    server: Arc<SyncServer>,
    refused: Mutex<Option<AgentVerbRefusalWords>>,
    stamp: Mutex<CallStamp>,
    /// The action call's attempt collector, taken where the door is built:
    /// each row runs on a spawned task, and a live-run hold in it reaches the
    /// action's receipt only through this (FIX 8107).
    collector: Option<std::sync::mpsc::Sender<oneiron::receipt::CallAttemptWitness>>,
}

/// A row that did not answer: no route words it.
fn unfinished() -> AgentVerbRefusalWords {
    AgentVerbRefusalWords {
        code: MEMORY_CODE_INTERNAL.to_owned(),
        message: "the action did not finish".to_owned(),
        suggestions: Vec::new(),
    }
}

impl FacadeRowDoor {
    pub(super) fn new(
        server: &Arc<SyncServer>,
        headers: HeaderMap,
        extensions: Extensions,
        read_key: ScopedReadActorKey,
        credential: Option<CoreAuth>,
    ) -> Self {
        Self {
            rows: super::super::recorded_facade_routes(Arc::clone(server))
                .with_state(Arc::clone(server)),
            headers,
            extensions,
            runtime: tokio::runtime::Handle::current(),
            read_key,
            credential,
            server: Arc::clone(server),
            refused: Mutex::new(None),
            stamp: Mutex::new(CallStamp::Unrecorded),
            collector: attempt_collector(),
        }
    }

    /// What the last row this door posted stated of its call receipt, on
    /// its success and its refusal alike: unrecorded when none ran through
    /// its route.
    pub(super) fn stamp(&self) -> CallStamp {
        self.stamp
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The row's reply: its JSON on success, else its refusal as answered,
    /// beside the call receipt its reply stated.
    async fn answer(
        rows: Router,
        request: Request,
    ) -> (CallStamp, Result<serde_json::Value, AgentVerbRefusalWords>) {
        let response = match rows.oneshot(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        };
        // Read before the body: success and refusal state it alike.
        let stamp = CallStamp::of_headers(response.headers());
        (stamp, Self::body(response).await)
    }

    /// A row reply's JSON on success, else its refusal as answered.
    async fn body(response: Response) -> Result<serde_json::Value, AgentVerbRefusalWords> {
        let refused = unfinished;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|_| refused())?;
        let body = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| refused())?
        };
        if status.is_success() {
            return Ok(body);
        }
        let text = |pointer: &str| {
            body.pointer(pointer)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let fallback = unfinished();
        Err(AgentVerbRefusalWords {
            code: text("/error/code").unwrap_or(fallback.code),
            message: text("/error/message").unwrap_or(fallback.message),
            suggestions: body
                .pointer("/error/suggestions")
                .and_then(serde_json::Value::as_array)
                .map(|all| {
                    all.iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

impl FacadeRowDoor {
    /// Posts the row to its facade route. The step's invocation rides as
    /// `x-oneiron-invocation`, so the route's verb hooks fire once for it.
    fn post_row(
        &self,
        call: &SelfAgentVerbCall,
        invocation: oneiron::runtime_hooks::InvocationId,
    ) -> Result<AgentVerbAnswer, AgentVerbRefusal> {
        let refused = || AgentVerbRefusal {
            code: MEMORY_CODE_INTERNAL.to_owned(),
        };
        if let Some(auth) = &self.credential {
            let auth = auth.clone();
            let server = Arc::clone(&self.server);
            let call = call.clone();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let row = async move {
                let invocation = invocation.to_hex();
                let context = super::super::FacadeCall::bound(&auth, None, Some(&invocation), None);
                let answer =
                    super::super::call_verb(&server, &context, call.verb.as_str(), Ok(call.input))
                        .await
                        .map(|answer| answer.value)
                        .map_err(|error| AgentVerbRefusalWords {
                            code: error.body.error.code,
                            message: error.body.error.message,
                            suggestions: error.body.error.suggestions,
                        });
                let _ = sender.send(answer);
            };
            self.runtime
                .spawn(with_attempt_collector(self.collector.clone(), row));
            let output = receiver.recv().map_err(|_| refused())?.map_err(|row| {
                let code = row.code.clone();
                *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = Some(row);
                AgentVerbRefusal { code }
            })?;
            return Ok(AgentVerbAnswer {
                output,
                rows: None,
                observations: Vec::new(),
            });
        }
        let body = serde_json::to_vec(&call.input).map_err(|_| refused())?;
        let mut request = axum::http::Request::post(format!("/{}", call.verb.as_str()))
            .body(Body::from(body))
            .map_err(|_| refused())?;
        *request.headers_mut() = self.headers.clone();
        request.headers_mut().remove(header::CONTENT_LENGTH);
        if let Ok(value) = HeaderValue::from_str(&invocation.to_hex()) {
            request.headers_mut().insert("x-oneiron-invocation", value);
        }
        // A step is a call of its own: it resumes no hook pause its route's
        // request named (L13 PR-D).
        request.headers_mut().remove("x-oneiron-hook-ask");
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        *request.extensions_mut() = self.extensions.clone();
        // The dispatcher holds its driver thread while the row runs on
        // the server runtime, as a request of its own would.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let rows = self.rows.clone();
        let row = async move {
            let _ = sender.send(Self::answer(rows, request).await);
        };
        self.runtime
            .spawn(with_attempt_collector(self.collector.clone(), row));
        let (stamp, answer) = receiver.recv().map_err(|_| refused())?;
        *self.stamp.lock().unwrap_or_else(PoisonError::into_inner) = stamp;
        let output = answer.map_err(|row| {
            let code = row.code.clone();
            *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = Some(row);
            AgentVerbRefusal { code }
        })?;
        Ok(AgentVerbAnswer {
            output,
            rows: None,
            observations: Vec::new(),
        })
    }
}

impl AgentVerbDoor for FacadeRowDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        _origin: &HostWriteOrigin,
        invocation: oneiron::runtime_hooks::InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(self.post_row(call, invocation))
    }

    /// The typed actions keep their own ceiling and owner proof; this door
    /// adds nothing to them. A search reads on the credential's lane, an
    /// edge's target is placed only when that lane reads it, a consult
    /// lands only refs that lane reads, and a TASK binding reads its TASK
    /// and workflow there (DEC-0005, FIX 5316).
    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(matches!(
            call,
            RunCall::Bridge(
                SelfEffect::MemorySearch
                    | SelfEffect::MemoryPutEdge
                    | SelfEffect::ConsultResult
                    | SelfEffect::WorkflowDispatch
            )
        )
        .then(|| self.read_key.clone()))
    }

    fn refusal_words(&self) -> Option<AgentVerbRefusalWords> {
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The receipt the last row's reply stated, as its header spelled it:
    /// none when no row ran through its route (FIX 8159).
    fn row_receipt(&self) -> Option<String> {
        self.stamp()
            .header_value()
            .and_then(|value| value.to_str().ok().map(str::to_owned))
    }

    /// A replayed action's first receipt, read as its reply's header reads,
    /// stated again by this door's caller in place of the unrecorded stamp
    /// a door that ran no row holds (FIX 8159).
    fn replay_row_receipt(&self, receipt: &str) {
        let Ok(value) = HeaderValue::from_str(receipt) else {
            return;
        };
        let mut headers = HeaderMap::new();
        headers.insert(RECEIPT_REF_HEADER, value);
        *self.stamp.lock().unwrap_or_else(PoisonError::into_inner) =
            CallStamp::of_headers(&headers);
    }
}
