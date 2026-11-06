//! The verb-hook boundary of the direct native HTTP read routes (ARCH-0080
//! §3, FIX 1435). `POST /v1/core/query`, `/v1/core/context-pack`,
//! `/v1/core/hydrate`, `/v1/core/batch/shortId/hydrate` and
//! `GET /v1/core/memory/{id}/timeline` serve the five structured reads of the
//! vault-read table. Each read crosses the boundary a facade row crosses,
//! under its method's own tool name (`memory.query` and the others), so a
//! verb hook fires on it as on the same read through MCP.
//! [`native_read_hooked`] is the boundary each route calls.
//! `resume_native_read` runs again a read that a hook's ask stopped, and
//! `released_completed` releases the result it saved for the retry.

use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use axum::response::{IntoResponse, Response};
use oneiron::EntityId;
use oneiron::claim::ScopedReadReceipt;
use oneiron::code_run::vault_read::VaultReadMethod;
use oneiron::memory::{MemoryError, RewriteAdmit};
use oneiron::runtime_hooks::InvocationId;
use oneiron::runtime_hooks::verb::InvocationRelease;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use super::facade::{
    FacadeApiError, FacadeCall, details_on_device, facade_hooks_pre_admitting, replayed_value,
    row_hooks_abort, row_hooks_post,
};
use crate::auth::CoreAuth;
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

/// A direct native HTTP read's refusal (FIX 1435). The route's own refusal
/// keeps the envelope the route has always answered in, beside the receipt
/// of the read that refused it. A verb hook's stop, or its chain's own
/// failure, is the facade's refusal, as a facade row answers it.
pub(crate) enum NativeReadError {
    Route(ApiError, Option<Box<ScopedReadReceipt>>),
    Hooks(FacadeApiError),
}

impl NativeReadError {
    /// The route's refusal `error`, beside the receipt of the read that
    /// refused it.
    pub(crate) fn with_read_receipt(error: ApiError, receipt: ScopedReadReceipt) -> Self {
        Self::Route(error, Some(Box::new(receipt)))
    }

    /// The refusal as the engine's typed error, which settlement saves for
    /// the caller's retry: a hook's stop as the facade carries it, and the
    /// route's own refusal with its code, words and read receipt.
    #[cfg(feature = "code-sandbox-wasmtime")]
    fn into_memory_error(self) -> MemoryError {
        match self {
            Self::Route(error, receipt) => {
                let mut refusal = FacadeApiError::from(error).into_memory_error();
                refusal.read_receipt = receipt;
                refusal
            }
            Self::Hooks(refusal) => refusal.into_memory_error(),
        }
    }
}

impl From<ApiError> for NativeReadError {
    fn from(error: ApiError) -> Self {
        Self::Route(error, None)
    }
}

impl From<FacadeApiError> for NativeReadError {
    fn from(error: FacadeApiError) -> Self {
        Self::Hooks(error)
    }
}

impl From<MemoryError> for NativeReadError {
    fn from(error: MemoryError) -> Self {
        Self::Hooks(error.into())
    }
}

impl IntoResponse for NativeReadError {
    fn into_response(self) -> Response {
        match self {
            Self::Route(error, receipt) => {
                let refused = EnvelopedApiError::from(error);
                match receipt {
                    Some(receipt) => refused.with_read_receipt(*receipt),
                    None => refused,
                }
                .into_response()
            }
            Self::Hooks(refusal) => refusal.into_response(),
        }
    }
}

/// What one direct native HTTP read answered: the JSON its route returns,
/// and the rows that answer was derived from as the route lists them
/// (DEC-0005), `None` when the route lists none.
pub(crate) struct NativeReadAnswer {
    pub(crate) value: Value,
    rows: Option<Vec<EntityId>>,
}

impl NativeReadAnswer {
    /// An answer derived from `rows`.
    pub(crate) fn listed(value: Value, rows: Vec<EntityId>) -> Self {
        Self {
            value,
            rows: Some(rows),
        }
    }

    /// An answer whose route lists none of its rows.
    pub(crate) fn unlisted(value: Value) -> Self {
        Self { value, rows: None }
    }
}

/// A direct native HTTP read's request body, split at the native contract
/// (FIX 1435). `args` is the method's native request, as an MCP call of the
/// same tool carries it: the verb hooks read it and may rewrite it.
/// `controls` are the route's own members that the native contract does not
/// carry. They are kept from the caller's request whatever a hook does, so
/// hook data never names the session, room, audience or other control of
/// the read.
pub(crate) struct NativeReadBody {
    args: Value,
    controls: RouteControls,
}

impl NativeReadBody {
    /// `body` split at `names`, the names of the route's own members.
    pub(crate) fn split(body: Value, names: &'static [&'static str]) -> Self {
        let mut args = match body {
            Value::Object(args) => args,
            body => {
                return Self {
                    args: body,
                    controls: RouteControls {
                        names,
                        given: Map::new(),
                    },
                };
            }
        };
        let given = names
            .iter()
            .filter_map(|name| args.shift_remove_entry(*name))
            .collect();
        Self {
            args: Value::Object(args),
            controls: RouteControls { names, given },
        }
    }
}

/// A direct native HTTP read's route controls (FIX 1435): every name the
/// route keeps as its own, and the ones the caller's request gave. A
/// control the caller left out stays left out.
#[derive(Clone)]
struct RouteControls {
    names: &'static [&'static str],
    given: Map<String, Value>,
}

impl RouteControls {
    /// The route body a rewrite is admitted and read from: the rewritten
    /// native `args` beside the caller's own controls, so a control the
    /// caller left out stays out. A rewrite that names one of the route's
    /// controls, or is not a JSON object, is refused, as the route refuses
    /// a body it does not decode: hook data never sets a control, so no
    /// request a hook's ask saves carries one either.
    fn joined(&self, args: &Value) -> Result<Value, ApiError> {
        let Value::Object(args) = args else {
            return Err(body_refusal());
        };
        if self.names.iter().any(|name| args.contains_key(*name)) {
            return Err(body_refusal());
        }
        let mut body = args.clone();
        body.extend(self.given.clone());
        Ok(Value::Object(body))
    }
}

/// The verb-hook boundary of one direct native HTTP read of `method`, for
/// `call`'s caller (ARCH-0080 §3, FIX 1435). It is the facade's own
/// boundary, under the method's tool name, with the caller's read key,
/// invocation, hook pause and credential.
///
/// The route has already admitted the request (`admitted`) and its caller.
/// The pre chain then runs over the native request `body` holds, before any
/// media is embedded, image picked, pack assembled or row read. A rewrite
/// meets `VaultReadRequest::validate_body`, then `admit`: the route's own
/// decoder and request checks, on the rewrite beside the caller's own
/// controls, under the caller's own credential, on the chain's blocking
/// thread. The read runs on the request the chain left, as `admit` admitted
/// it there (FIX 1435): the last rewrite it accepted is kept for the read,
/// so a route whose checks read the vault runs them once per rewrite and
/// never on the async runtime. A final request other than the kept rewrite
/// meets `admit` again, on a blocking thread. The post chain runs over the
/// JSON the route answers, after its projection and observations, and its
/// view is what the caller reads.
///
/// A read that fails after the pre chain keeps a session-only call's pre
/// hook records and runs no post chain (FIX 5527). A hook's stop is the
/// facade's refusal. A retry of a read that settlement's drain already ran
/// gets the drained result in a `Completed` stop, and that result is
/// released for the caller now before the stop is answered
/// (`released_stop`, FIX 1435). A request with route controls saves no
/// credential: an ask saves only the native args, so only the caller's
/// retry runs it again.
pub(crate) async fn native_read_hooked<T, A, F, Fut>(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    method: VaultReadMethod,
    body: NativeReadBody,
    admitted: T,
    admit: A,
    read: F,
) -> Result<NativeReadAnswer, NativeReadError>
where
    T: Send + 'static,
    A: Fn(&Value) -> Result<T, ApiError> + Send + Sync + 'static,
    F: FnOnce(T) -> Fut,
    Fut: Future<Output = Result<NativeReadAnswer, NativeReadError>>,
{
    let NativeReadBody { args, controls } = body;
    let durable = controls.given.is_empty();
    let admit = Arc::new(admit);
    // The last rewrite `admit` accepted, beside the request it admitted.
    let accepted: Arc<Mutex<Option<(Value, T)>>> = Arc::new(Mutex::new(None));
    let check: RewriteAdmit = {
        let (admit, controls, accepted) =
            (Arc::clone(&admit), controls.clone(), Arc::clone(&accepted));
        Arc::new(move |_: &str, rewritten: &Value| -> Result<(), String> {
            let request = controls
                .joined(rewritten)
                .and_then(|body| admit(&body))
                .map_err(|refused| refused.message().to_owned())?;
            *accepted.lock().unwrap_or_else(PoisonError::into_inner) =
                Some((rewritten.clone(), request));
            Ok(())
        })
    };
    let sent = args.clone();
    let (hooks, _) =
        facade_hooks_pre_admitting(server, call, method.tool_name(), args, check, durable)
            .await
            .map_err(|stopped| released_stop(server, call.auth(), method, stopped))?;
    let accepted = accepted
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    let request = if hooks.args == sent {
        Ok(admitted)
    } else {
        match accepted {
            Some((rewritten, request)) if rewritten == hooks.args => Ok(request),
            _ => readmitted(admit, &hooks.args, controls).await,
        }
    };
    let ran = match request {
        Ok(request) => read(request).await,
        Err(refused) => Err(refused.into()),
    };
    match ran {
        Ok(answer) => Ok(NativeReadAnswer {
            value: row_hooks_post(server, hooks, answer.value).await?,
            rows: answer.rows,
        }),
        Err(error) => {
            row_hooks_abort(server, hooks).await;
            Err(error)
        }
    }
}

/// A hook's `stopped` refusal of a read of `method`, for `auth`, its caller
/// now. A `Completed` stop carries the result settlement's drain saved for
/// this retry: it is released by [`released_completed`] before the stop is
/// answered (FIX 1435). Any other refusal stays as it is.
fn released_stop(
    server: &SyncServer,
    auth: &CoreAuth,
    method: VaultReadMethod,
    mut stopped: FacadeApiError,
) -> FacadeApiError {
    if let Some((invocation, result)) = stopped.completed_hook_result() {
        let saved = std::mem::take(result);
        *result = released_completed(server, auth, method, invocation, saved);
    }
    stopped
}

/// The `result` that settlement's drain saved under `invocation` for a
/// read of `method`, as `auth`, its caller now, may read it (FIX 1435). The
/// rows the route listed it derived from are restored from the saved call
/// (`Vault::verb_hook_saved_producers`). The result and those rows meet the
/// facade's release of a kept answer ([`replayed_value`]): a row the
/// caller's credential no longer reads, a row erased since, or a row a
/// world withheld from where the answer goes keeps the result on this
/// device. A result saved with no rows is withheld on this device too: its
/// rows are unknown, so the caller's current read of them cannot be checked.
/// A withheld result is the content-free word that the call ran
/// ([`details_on_device`]).
fn released_completed(
    server: &SyncServer,
    auth: &CoreAuth,
    method: VaultReadMethod,
    invocation: &str,
    result: Value,
) -> Value {
    let producers = InvocationId::parse_hex(invocation).and_then(|invocation| {
        server
            .vault
            .verb_hook_saved_producers(invocation)
            .inspect_err(
                |error| tracing::warn!(%error, "a drained native read's rows did not read"),
            )
            .ok()
            .flatten()
    });
    if producers.is_none() {
        return details_on_device();
    }
    let release = InvocationRelease {
        peer: auth.peer(),
        value: result,
        rows: producers,
    };
    replayed_value(&server.vault, auth, method.tool_name(), release)
}

/// The rewrite `args` the pre chain left, admitted by the route's own
/// `admit` beside the caller's own `controls`, on a blocking thread, as the
/// chain's own checks run (FIX 1435).
async fn readmitted<T, A>(
    admit: Arc<A>,
    args: &Value,
    controls: RouteControls,
) -> Result<T, ApiError>
where
    T: Send + 'static,
    A: Fn(&Value) -> Result<T, ApiError> + Send + Sync + 'static,
{
    let args = args.clone();
    tokio::task::spawn_blocking(move || controls.joined(&args).and_then(|body| admit(&body)))
        .await
        .map_err(|_| ApiError::internal_server_error("native read admission did not finish"))?
}

/// `body` decoded as a route's own request type, refused as the route
/// refuses a body it does not decode.
pub(crate) fn decoded<R: DeserializeOwned>(body: &Value) -> Result<R, ApiError> {
    R::deserialize(body).map_err(|_| body_refusal())
}

/// The refusal of a request body a route does not decode, as its JSON
/// extractor's rejection maps it.
fn body_refusal() -> ApiError {
    ApiError::bad_request("invalid JSON request body", None)
}

/// `response` as the JSON its route writes, read back as one value for the
/// post chain. An answer that no hook changes goes out as the route has
/// always written it, each float in its own type's shortest form.
pub(crate) fn encoded<R: Serialize>(response: &R) -> Result<Value, ApiError> {
    serde_json::to_vec(response)
        .and_then(|bytes| serde_json::from_slice(&bytes))
        .map_err(|_| ApiError::internal_server_error("native read response encoding failed"))
}

/// The direct native HTTP read that `verb` names, if it names one: a
/// structured read of the vault-read table (FIX 1435). The facade's
/// dispatch has no row for it, so a call of it that its facade door saved
/// runs again through [`resume_native_read`].
#[cfg(feature = "code-sandbox-wasmtime")]
pub(crate) fn native_read_method(verb: &str) -> Option<VaultReadMethod> {
    use oneiron::code_run::vault_read::VaultReadAvailability;
    VaultReadMethod::ALL.into_iter().find(|method| {
        method.tool_name() == verb && method.availability() == VaultReadAvailability::StructuredRead
    })
}

/// Runs again a direct native HTTP read of `method` that a verb hook's ask
/// stopped, once the ask settled proceed (ARCH-0080 §3 Ask, FIX 1435).
/// `call` carries the caller's credential as it verified again now, the
/// room turn and invocation the call named, and the drain's permit. The
/// saved `request` meets the route's own admission, the core read scope
/// first. It then runs through the same boundary and read as the route, its
/// pre chain on the drain's permit. The answer goes beside the rows the
/// route lists for it, so the caller's retry is released by them.
#[cfg(feature = "code-sandbox-wasmtime")]
pub(crate) async fn resume_native_read(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    method: VaultReadMethod,
    request: Value,
) -> oneiron::runtime_hooks::verb::VerbAskResumed {
    use oneiron::runtime_hooks::verb::{VerbAskRefusal, VerbAskResumed};
    if call.auth().require(crate::auth::CoreScope::Read).is_err() {
        return VerbAskResumed::Refused(VerbAskRefusal::ScopeRefused);
    }
    let ran = match method {
        VaultReadMethod::Query => super::core_query_hooked(server, call, request).await,
        VaultReadMethod::ContextPack => {
            super::core_context_pack_hooked(server, call, request).await
        }
        VaultReadMethod::Hydrate => super::core_hydrate_hooked(server, call, request).await,
        VaultReadMethod::HydrateMany => {
            super::core_batch_short_id_hydrate_hooked(server, call, request).await
        }
        VaultReadMethod::MemoryTimeline => {
            super::core_memory_timeline_hooked(server, call, request).await
        }
        VaultReadMethod::Ask | VaultReadMethod::CodeSearch | VaultReadMethod::CodeExecute => {
            return VerbAskResumed::Refused(VerbAskRefusal::ContextUnavailable);
        }
    };
    match ran {
        Ok(NativeReadAnswer {
            value,
            rows: Some(producers),
        }) => VerbAskResumed::RanWithProducers {
            result: Ok(value),
            producers,
        },
        Ok(answer) => VerbAskResumed::Ran(Ok(answer.value)),
        Err(refused) => VerbAskResumed::Ran(Err(refused.into_memory_error())),
    }
}
