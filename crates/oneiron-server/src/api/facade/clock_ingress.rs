//! A facade, owner-table or MCP call over a damaged authority clock floor (FIX
//! 11190, FIX 11201, FIX 11202, FIX 11523).
//!
//! A damaged floor, on a handle that holds no anchor, refuses every reading
//! of the authority clock, so every proof judged against it refuses before a
//! door runs. Two calls are still the owner's to make over it, each under its
//! own policy:
//! - the owner's repair (`vault.authority.clock.repair`) is judged in the
//!   repair's own writer, against the floor it stages there: its ingress
//!   judges and spends nothing, and its caller reaches the writer as its
//!   transport took it ([`ClockRepairCaller`]);
//! - an owner's erase or revoke, as the engine classifies the verb and the
//!   caller's own payload (`revoke_lands::restriction_only_call`), reads the
//!   restriction-only clock in every synchronous stretch of its ingress,
//!   owner proof, hooks and door ([`scoped`], [`run_blocking`]), so it
//!   lands and revives nothing; it writes no floor.
//!
//! The binding door decides which a request is, from its path, its own body
//! and the floor, before any credential is judged ([`classify_request`]),
//! and marks it with a [`ClockIngress`] only it sets: no header, and no other
//! call on the same connection, opts into either. Every other call, and
//! every call over a whole or anchored floor, takes today's path unchanged.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::{FromRequestParts, Request};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{Extensions, HeaderMap};
use axum::response::{IntoResponse, Response};
use oneiron::authority::{CapabilitySlip, ClockRepairCaller};
use oneiron::code_run::actions::{ActionArgument, ActionRegistry};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::AuthorityClockRepair;
use serde_json::{Value, json};

use super::FacadeApiError;
use crate::auth::{BindingProof, CoreAuth, parse_signature};
use crate::server::SyncServer;

/// The verb whose caller its own writer judges.
pub(crate) const REPAIR_VERB: &str = "vault.authority.clock.repair";

/// Where every facade verb is served.
const FACADE_PREFIX: &str = "/v1/core/facade/";

/// Where the app's actions are served.
const ACTIONS_PREFIX: &str = "/v1/core/actions/";

/// The MCP endpoints whose `tools/call` names one verb.
const MCP_PATHS: [&str; 2] = ["/mcp", "/mcp/tool-first"];

/// The header an MCP call's slip rides in, ahead of `Authorization`.
const MCP_CREDENTIAL_HEADER: &str = "x-oneiron-mcp-credential";

/// The owner routes that share a facade verb, by full path (FIX 11523):
/// H1-H4, the four owner doors whose `hooked_row` runs the same row as the
/// facade. Each classifies as a direct call of its verb, so the owner's
/// revoke lands over a damaged floor; any other owner route keeps today's
/// path.
const OWNER_VERBS: [(&str, &str); 4] = [
    ("/v1/owner/guests/revoke", "vault.guests.revoke"),
    ("/v1/owner/support-grants/revoke", "vault.support_grants.revoke"),
    ("/v1/owner/legal-holds/lift-and-erase", "vault.legal_holds.lift_and_erase"),
    ("/v1/owner/embedding-spaces/probes/delete", "vault.embedding_spaces.probes.delete"),
];

/// The facade verb of an owner route in [`OWNER_VERBS`], if it names one.
fn owner_verb(path: &str) -> Option<&'static str> {
    OWNER_VERBS
        .iter()
        .find(|(route, _)| *route == path)
        .map(|(_, verb)| *verb)
}

/// What the binding door decided about a request over a floor that refuses
/// readings. It rides the request's extensions; only [`classify_request`]
/// makes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClockIngress {
    /// The owner's repair: nothing at ingress judges or spends its proof.
    Repair,
    /// An owner's erase or revoke: it reads the restriction-only clock.
    RestrictionOnly,
}

/// The binding door's decision on `request`: `None` for every request that
/// is not a facade, action, owner-table or MCP call, and for every call
/// while this handle's authority readings hold. Otherwise the call's verb
/// and its own payload are classified (an owner-table route by its row and
/// its body as sent; an MCP `tools/call` by the tool it names and the input
/// its arguments assemble; an action by the verb-table row its table
/// resolves and that row's input from its one argument), with the body read
/// here and handed back unchanged: a content-encoded body is classified on
/// a decoded copy, and a body that is not JSON, and a call classified as
/// neither, takes today's path as it arrived. A body this door cannot read
/// back (past the facade's request bound), and a call whose classification
/// faults, gets the clock's own typed refusal, `AUTHORITY_CLOCK_CORRUPT`.
pub(crate) async fn classify_request(
    server: &SyncServer,
    request: Request,
) -> Result<(Request, Option<ClockIngress>), Response> {
    let path = request.uri().path();
    // An owner route in the table classifies as a direct call of its verb
    // (FIX 11523); any other owner route is no call.
    let verb = path
        .strip_prefix(FACADE_PREFIX)
        .map(str::to_owned)
        .or_else(|| owner_verb(path).map(str::to_owned));
    let action = path.strip_prefix(ACTIONS_PREFIX).map(str::to_owned);
    let mcp = MCP_PATHS.contains(&path);
    if (verb.is_none() && action.is_none() && !mcp)
        || !server
            .vault()
            .authority_clock_refuses_readings()
            .unwrap_or(false)
    {
        return Ok((request, None));
    }
    if verb.as_deref() == Some(REPAIR_VERB) {
        return Ok((request, Some(ClockIngress::Repair)));
    }
    let (parts, body) = request.into_parts();
    let limit = oneiron::memory::caps::MAX_REMOTE_REQUEST_BYTES;
    let bytes = axum::body::to_bytes(body, limit)
        .await
        .map_err(|_| clock_corrupt_refusal())?;
    // This door runs outside the body codec, so a content-encoded body is
    // classified on a decoded copy (FIX 11520) and handed back raw.
    let decoded = crate::api::body_codec::decode_copy(&parts.headers, parts.uri.path(), &bytes);
    let probe: &[u8] = decoded.as_deref().unwrap_or(bytes.as_ref());
    let call = serde_json::from_slice::<Value>(probe)
        .ok()
        .and_then(|body| match verb {
            Some(verb) => Some((verb, body)),
            None => match action {
                Some(action) => {
                    let args: Vec<ActionArgument> =
                        serde_json::from_value(body.get("args")?.clone()).ok()?;
                    action_row_call(&action, &args)
                }
                None => mcp_tool_call(body),
            },
        });
    let ingress = match call {
        None => None,
        Some((verb, _)) if verb == REPAIR_VERB => Some(ClockIngress::Repair),
        // A classification whose own read fails keeps the clock's refusal.
        Some((verb, input)) => {
            oneiron::task_verb::revoke_lands::restriction_only_call(server.vault(), &verb, &input)
                .map_err(|_| clock_corrupt_refusal())?
                .then_some(ClockIngress::RestrictionOnly)
        }
    };
    Ok((Request::from_parts(parts, Body::from(bytes)), ingress))
}

/// The damaged floor's own typed refusal, as the engine words it.
fn clock_corrupt_refusal() -> Response {
    let corrupt = oneiron::Error::Record(oneiron::error::RecordError::AuthorityClockCorrupt);
    FacadeApiError::from(MemoryError::from(corrupt)).into_response()
}

/// The verb an MCP `tools/call` names and the input its arguments assemble,
/// as its generated tool assembles them; a call whose arguments do not
/// decode carries its `spec` as the input. An `invoke_action` call names
/// its verb-table row through the app's table (FIX 11524).
fn mcp_tool_call(body: Value) -> Option<(String, Value)> {
    if body.get("method")?.as_str()? != "tools/call" {
        return None;
    }
    let params = body.get("params")?;
    let tool = params.get("name")?.as_str()?.to_owned();
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if tool == crate::mcp::MCP_INVOKE_ACTION_TOOL {
        let verb = arguments.get("verb")?.as_str()?;
        let args: Vec<ActionArgument> =
            serde_json::from_value(arguments.get("args")?.clone()).ok()?;
        return action_row_call(verb, &args);
    }
    let input = serde_json::from_value::<crate::mcp::McpVerbArguments>(arguments.clone())
        .ok()
        .and_then(|args| crate::api::mcp_gateway::mcp_agent_verb_input(&tool, &args).ok())
        .or_else(|| arguments.get("spec").cloned())?;
    Some((tool, input))
}

/// An app action call's verb-table row and its input (FIX 11524): the row
/// the app's table resolves the action to under its own name, and the row's
/// whole input from the call's arguments, as the row's build reads them.
/// `None` for a factory action, an unregistered verb, or a call whose row
/// input does not decode: those keep today's path, and a mixed action
/// today's refusal.
fn action_row_call(action: &str, args: &[ActionArgument]) -> Option<(String, Value)> {
    let input = action_row_input(args)?;
    let app = ActionRegistry::app().ok()?;
    Some((app.row_verb(action)?.to_owned(), input))
}

/// A verb-table or run row action's whole input from the call's arguments
/// (FIX 11524), as the row's own build reads them: one text parsed as JSON,
/// or one structured argument. Any other shape is no row input.
fn action_row_input(args: &[ActionArgument]) -> Option<Value> {
    match args {
        [ActionArgument::Text(input)] => serde_json::from_str(input.as_str()).ok(),
        [ActionArgument::Json(input)] => Some(input.value().clone()),
        _ => None,
    }
}

/// Whether a call of `verb` on `input` runs as an owner's restriction-only
/// act at dispatch (a held socket's call, an MCP or code-mode row): only
/// while this handle's authority readings refuse, and only for a call the
/// engine classifies as wholly an erase or a revoke. A classification that
/// faults is no such act, and the call meets the clock's own refusal. Over a
/// whole or anchored floor nothing is classified.
pub(crate) fn restrictive_call(server: &SyncServer, verb: &str, input: Option<&Value>) -> bool {
    input.is_some_and(|input| {
        server
            .vault()
            .authority_clock_refuses_readings()
            .unwrap_or(false)
            && oneiron::task_verb::revoke_lands::restriction_only_call(server.vault(), verb, input)
                .unwrap_or(false)
    })
}

/// Whether an app action call of `verb` with `args` runs as an owner's
/// restriction-only act at dispatch (FIX 11524): only while this handle's
/// authority readings refuse, and only for a call whose row the app's table
/// resolves and the engine classifies as wholly an erase or a revoke. Any
/// other action keeps today's path, and a mixed action today's refusal.
pub(crate) fn restrictive_action(
    server: &SyncServer,
    verb: &str,
    args: &[ActionArgument],
) -> bool {
    // The app's table is read only while the readings refuse.
    let refuses = server
        .vault()
        .authority_clock_refuses_readings()
        .unwrap_or(true);
    refuses
        && action_row_call(verb, args)
            .is_some_and(|(row, input)| restrictive_call(server, &row, Some(&input)))
}

/// Whether the binding door left this request's owner repair unjudged.
pub(crate) fn repair_marked(extensions: &Extensions) -> bool {
    extensions.get::<ClockIngress>() == Some(&ClockIngress::Repair)
}

tokio::task_local! {
    /// Present while the task runs an owner's restriction-only act.
    static RESTRICTION_ONLY: ();
}

/// `call` run as an owner's restriction-only act when `restrictive`: each
/// poll enters a fresh restriction-only clock on its thread and leaves it
/// before it returns, so every synchronous stretch reads that clock and none
/// is held across an await, and a closure it hands [`run_blocking`]
/// enters it again on its own thread. Any other call runs as it is.
pub(crate) async fn scoped<F: Future>(restrictive: bool, call: F) -> F::Output {
    if !restrictive {
        return call.await;
    }
    RESTRICTION_ONLY
        .scope((), RestrictionPolls(Box::pin(call)))
        .await
}

/// A future each of whose polls reads the restriction-only clock.
struct RestrictionPolls<F>(Pin<Box<F>>);

impl<F: Future> Future for RestrictionPolls<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let _clock = oneiron::authority::restriction_only_clock();
        self.0.as_mut().poll(cx)
    }
}

/// [`tokio::task::spawn_blocking`] for a door's blocking work: inside an
/// owner's restriction-only act ([`scoped`]) the closure reads the
/// restriction-only clock on its own thread; anywhere else it runs as it is.
pub(crate) fn run_blocking<F, R>(work: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let restrictive = RESTRICTION_ONLY.try_with(|_| ()).is_ok();
    tokio::task::spawn_blocking(move || {
        let _clock = restrictive.then(oneiron::authority::restriction_only_clock);
        work()
    })
}

/// The repair's caller as a request's own headers and extensions carry it,
/// with nothing judged: its slip and holder proof as they arrived (an MCP
/// call's credential header first), beside the owner its managed ingress
/// attested if any; else that attested owner; else the self-hosted dev mode
/// on a host that admits it.
/// `None` for any other request, which takes the ordinary path.
pub(crate) fn request_repair_caller(
    server: &SyncServer,
    headers: &HeaderMap,
    extensions: &Extensions,
    mcp: bool,
) -> Option<ClockRepairCaller> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let bearer = || {
        header(AUTHORIZATION.as_str())
            .and_then(|value| value.split_once(char::is_whitespace))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token.trim())
    };
    let token = mcp
        .then(|| header(MCP_CREDENTIAL_HEADER))
        .flatten()
        .or_else(bearer);
    if let Some(token) = token {
        // Any other credential keeps its own path.
        if !token.starts_with("v2.slip.") {
            return None;
        }
        let slip = CapabilitySlip::from_token(token).ok()?;
        let proof = BindingProof::from_headers(headers).ok()?;
        let signature = parse_signature(&proof.signature).ok()?;
        let caller = ClockRepairCaller::holder_proof(
            slip,
            proof.timestamp,
            signature,
            proof.nonce.into_bytes(),
        );
        // A slip beside its supervisor's attestation binds only as the person
        // attested; the repair's writer holds it to that.
        return Some(match crate::auth::attested_owner(extensions, server) {
            Some(holder) => caller.beside_attested_owner(holder),
            None => caller,
        });
    }
    if let Some(holder) = crate::auth::attested_owner(extensions, server) {
        return Some(ClockRepairCaller::managed_owner(holder));
    }
    (server.managed_issuer.is_none()
        && server.config.auth_secret.is_none()
        && server.config.allow_unauthenticated)
        .then(ClockRepairCaller::dev_mode)
}

/// A facade route's caller: the credential its request carries, or, for
/// the owner's repair the binding door left unjudged, the repair's caller.
pub(crate) enum FacadeCaller {
    Credential(CoreAuth),
    ClockRepair(ClockRepairCaller),
}

impl FromRequestParts<Arc<SyncServer>> for FacadeCaller {
    type Rejection = crate::error::EnvelopedApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        server: &Arc<SyncServer>,
    ) -> Result<Self, Self::Rejection> {
        if repair_marked(&parts.extensions)
            && let Some(caller) =
                request_repair_caller(server, &parts.headers, &parts.extensions, false)
        {
            return Ok(Self::ClockRepair(caller));
        }
        CoreAuth::from_request_parts(parts, server)
            .await
            .map(Self::Credential)
    }
}

/// The owner refusal of the repair's door.
fn repair_refused() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{REPAIR_VERB} is the vault owner's"),
        &["Present the owner's own verified, unattenuated credential."],
    )
}

/// The repair's caller from a credential its transport already admitted (a
/// held socket's, or a request read while the clock held), with nothing read
/// from the clock: a managed vault's attested owner, a host root or the dev
/// mode (judged as the owner their host action names), or the owner's own
/// verified, unattenuated human slip. A slip cut from a host root gets the
/// typed refusal where no host acts as a person, and every other credential
/// the owner refusal.
pub(crate) fn repair_caller_of(
    server: &SyncServer,
    auth: &CoreAuth,
) -> MemoryResult<ClockRepairCaller> {
    if let Some(holder) = auth.managed_owner() {
        return Ok(ClockRepairCaller::managed_owner(holder));
    }
    if let Some(root) = auth.host_root() {
        return Ok(ClockRepairCaller::verified(root.clone()));
    }
    if auth.is_local_dev_hatch() {
        return Ok(ClockRepairCaller::dev_mode());
    }
    if auth.is_host_holder() {
        super::owner_binding::host_preflight(server, auth)?;
        return Err(repair_refused());
    }
    auth.verified_slip()
        .filter(|_| auth.is_owner_grade() && auth.actor_class() == Some("human"))
        .map(|slip| ClockRepairCaller::verified(slip.clone()))
        .ok_or_else(repair_refused)
}

/// The repair for `caller`, off the runtime: judged in its own writer.
pub(crate) async fn repair(
    server: &Arc<SyncServer>,
    caller: ClockRepairCaller,
) -> MemoryResult<AuthorityClockRepair> {
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::repair_authority_clock_as(server.vault(), caller)
    })
    .await
    .map_err(|_| super::host_doors::support::internal(REPAIR_VERB))?
}

/// The facade route's reply to the owner's repair the binding door left
/// unjudged: its input checked as the row checks it, and the repair's own
/// answer, or its typed refusal (`authority_clock_corrupt` for a vault that
/// proves no clock at all). The answer derives from no row.
pub(crate) async fn repair_reply(
    server: &Arc<SyncServer>,
    caller: ClockRepairCaller,
    input: Result<Value, FacadeApiError>,
) -> Response {
    let answered = async {
        let input = input?;
        oneiron::task_verb::sdk::validate_input(REPAIR_VERB, &input)?;
        let repaired = repair(server, caller).await?;
        serde_json::to_value(repaired)
            .map_err(|_| FacadeApiError::from(super::host_doors::support::internal(REPAIR_VERB)))
    };
    match answered.await {
        Ok(value) => super::unbound_reply(value).into_response(),
        Err(refused) => refused.into_response(),
    }
}
