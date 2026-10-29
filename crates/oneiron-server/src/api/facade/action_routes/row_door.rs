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
use oneiron::receipt::{
    ActionInputs, CallAttemptWitness, CallOutcome, CallReceiptInput, CallTransport,
};
use oneiron::skill_attribution::RunWriteToken;
use tower::ServiceExt;

use super::super::host_doors::support::with_calling_run_writes;
use super::super::{FacadeApiError, FacadeCallOutput};
use crate::api::call_receipt::{
    self, CallStamp, HeldOuterAttempt, RECEIPT_REF_HEADER, attempt_collector,
    attempt_witnessed_inside, with_attempt_collector, witness_attempt,
};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The transport the receipt of a row the credential's own facade call runs
/// in process states (FIX 10635, CALLS row): the facade's verb table it ran
/// through, as the request branch's in-process route records its rows.
const CREDENTIAL_ROW_TRANSPORT: CallTransport = CallTransport::HttpFacade;

/// The verb door of one action call. Each verb-table row runs as its own
/// generated facade route, in process, under the request's own headers and
/// connection, so it meets exactly what a direct call of the row meets.
///
/// The row writes as the credential, as its direct call does: an action is
/// its caller's own call, not a run's generated write, so the run origin the
/// dispatcher offers is not the row's source. The DerivedFrom edges it
/// leaves are still witnessed for the leased run that origin seals (FIX
/// 10748).
///
/// A memory run row reads with `read_key`, the credential's own read key
/// at the caller's locality, which this request was admitted on.
///
/// A row's refusal keeps the words its route answered with in `refused`,
/// which the action's record keeps beside its code; the guest sees only the
/// code. What its reply stated of its call receipt is kept in `stamp`, for
/// a caller that states it again on its own reply (FIX 2887); a row the
/// credential's own facade call ran records its receipt here (FIX 10635).
/// Each row's receipt names the action's own live-run hold, which it runs
/// inside (FIX 10938).
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
    collector: Option<std::sync::mpsc::Sender<CallAttemptWitness>>,
    /// The action's own live-run hold, as the hold witnessed it, once taken.
    outer: Mutex<Option<CallAttemptWitness>>,
}

/// A row that did not answer: no route words it.
fn unfinished() -> AgentVerbRefusalWords {
    AgentVerbRefusalWords {
        code: MEMORY_CODE_INTERNAL.to_owned(),
        message: "the action did not finish".to_owned(),
        suggestions: Vec::new(),
        reason_codes: Vec::new(),
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
            outer: Mutex::new(None),
        }
    }

    /// Names the action's own live-run hold, which every row it posts after
    /// runs inside (FIX 10938).
    pub(super) fn held_outer(&self, witness: CallAttemptWitness) {
        *self.outer.lock().unwrap_or_else(PoisonError::into_inner) = Some(witness);
    }

    /// What the last row this door posted stated of its call receipt, on
    /// its success and its refusal alike, or the receipt it recorded for a
    /// row the credential's own call ran: unrecorded when no row ran.
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
        let texts = |pointer: &str| -> Vec<String> {
            body.pointer(pointer)
                .and_then(serde_json::Value::as_array)
                .map(|all| {
                    all.iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        let fallback = unfinished();
        Err(AgentVerbRefusalWords {
            code: text("/error/code").unwrap_or(fallback.code),
            message: text("/error/message").unwrap_or(fallback.message),
            suggestions: texts("/error/suggestions"),
            reason_codes: texts("/error/reasonCodes"),
        })
    }
}

impl FacadeRowDoor {
    /// Posts the row to its facade route. The step's invocation rides as
    /// `x-oneiron-invocation`, so the route's verb hooks fire once for it.
    /// Its writes are witnessed for the leased run `origin` seals (FIX
    /// 10748), and its receipt names the action's hold (FIX 10938).
    fn post_row(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        invocation: oneiron::runtime_hooks::InvocationId,
    ) -> Result<AgentVerbAnswer, AgentVerbRefusal> {
        let refused = || AgentVerbRefusal {
            code: MEMORY_CODE_INTERNAL.to_owned(),
        };
        let run_writes = RunWriteToken::of_origin(origin);
        let outer = *self.outer.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(auth) = &self.credential {
            let auth = auth.clone();
            let server = Arc::clone(&self.server);
            let headers = self.headers.clone();
            let call = call.clone();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let row = async move {
                let invocation = invocation.to_hex();
                let context = super::super::FacadeCall::bound(&auth, None, Some(&invocation), None);
                let verb = call.verb.as_str();
                let request_digest = oneiron::receipt::call_json_digest(&call.input);
                let inputs = call_receipt::action_inputs(&server, verb, Some(&call.input));
                let (answer, attempt) = attempt_witnessed_inside(
                    outer,
                    super::super::call_verb(&server, &context, verb, Ok(call.input)),
                )
                .await;
                // A hold the row made, with none of the action's around it,
                // reaches the action's receipt too, as before (FIX 8107).
                if let Some(attempt) = attempt {
                    witness_attempt(attempt);
                }
                let stamp = record_credential_row(
                    &server,
                    &auth,
                    &headers,
                    verb,
                    (request_digest, inputs, attempt),
                    &answer,
                );
                let answer = answer
                    .map(|answer| answer.value)
                    .map_err(|error| AgentVerbRefusalWords {
                        code: error.body.error.code,
                        message: error.body.error.message,
                        suggestions: error.body.error.suggestions,
                        reason_codes: error.body.error.reason_codes,
                    });
                let _ = sender.send((stamp, answer));
            };
            self.runtime.spawn(with_attempt_collector(
                self.collector.clone(),
                with_calling_run_writes(run_writes, row),
            ));
            let (stamp, answer) = receiver.recv().map_err(|_| refused())?;
            *self.stamp.lock().unwrap_or_else(PoisonError::into_inner) = stamp;
            let output = answer.map_err(|row| {
                let code = row.code.clone();
                *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = Some(row);
                AgentVerbRefusal { code }
            })?;
            return Ok(AgentVerbAnswer::new(output, None));
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
        if let Some(outer) = outer {
            request.extensions_mut().insert(HeldOuterAttempt(outer));
        }
        // The dispatcher holds its driver thread while the row runs on
        // the server runtime, as a request of its own would.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let rows = self.rows.clone();
        let row = async move {
            let _ = sender.send(Self::answer(rows, request).await);
        };
        self.runtime.spawn(with_attempt_collector(
            self.collector.clone(),
            with_calling_run_writes(run_writes, row),
        ));
        let (stamp, answer) = receiver.recv().map_err(|_| refused())?;
        *self.stamp.lock().unwrap_or_else(PoisonError::into_inner) = stamp;
        let output = answer.map_err(|row| {
            let code = row.code.clone();
            *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = Some(row);
            AgentVerbRefusal { code }
        })?;
        Ok(AgentVerbAnswer::new(output, None))
    }
}

/// Records the receipt of a row the credential's own facade call ran in
/// process (FIX 10635), as a facade route's receipt door records its call:
/// attributed to the credential, its request and answer digested, the
/// inputs captured before it ran and the attempt it ran inside. A row run
/// inside an anonymous off-record session the credential is verified in
/// keeps none, judged as the route's receipt door judges it, and so does
/// an off-record row ([`call_receipt::record`]).
fn record_credential_row(
    server: &SyncServer,
    auth: &CoreAuth,
    headers: &HeaderMap,
    verb: &str,
    (request_digest, inputs, attempt): (String, Option<ActionInputs>, Option<CallAttemptWitness>),
    answer: &Result<FacadeCallOutput, FacadeApiError>,
) -> CallStamp {
    let (outcome, result_digest) = match answer {
        Ok(output) => (
            CallOutcome::Ok,
            serde_json::to_vec(&output.value)
                .ok()
                .map(|bytes| oneiron::task_verb::sdk::call_reply_digest(verb, &bytes)),
        ),
        Err(refusal) => (
            CallOutcome::Refused {
                code: refusal.body.error.code.clone(),
            },
            Some(oneiron::receipt::call_refusal_digest(
                &refusal.body.error.code,
                &refusal.body.error.message,
            )),
        ),
    };
    let anonymous =
        call_receipt::in_anonymous_session(server, headers, call_receipt::request_principal(auth));
    let (actor_ref, actor_class) = call_receipt::call_actor(auth);
    call_receipt::record(
        server,
        anonymous,
        CallReceiptInput {
            transport: CREDENTIAL_ROW_TRANSPORT,
            verb: verb.to_owned(),
            actor_ref,
            actor_class,
            credential_ref: call_receipt::credential_ref(auth),
            outcome,
            request_digest,
            result_digest,
            inputs,
            attempt,
            served: Vec::new(),
        },
    )
}

impl AgentVerbDoor for FacadeRowDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        invocation: oneiron::runtime_hooks::InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(self.post_row(call, origin, invocation))
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

    /// The host turn's hooks read on the credential's lane, the same
    /// verified caller key run admission uses (FIX 9841).
    fn host_turn_read_key(&self) -> Option<ScopedReadActorKey> {
        Some(self.read_key.clone())
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
