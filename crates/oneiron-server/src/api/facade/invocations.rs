//! The facade's invocation claims: one call per client-named invocation id (OF-580).
//! `claim_door_invocation` and `finish_door_claim` are its call surface; a door gets a `DoorClaim`.
//! The live claim is the fast path; `InvocationClaimStore` is its restart twin (FIX 11889).

use super::*;
use crate::invocation_claims::{InvocationClaimStore, invocation_claim_key};

/// Claims the invocation a request names, once, around its whole route
/// (OF-580): a second request naming it for the same call waits for this
/// one's reply and gets it, and one naming it for another call is refused at
/// once. An action's verb-table row reaches its route here with its step's
/// id, and is claimed once, here. A request no credential authenticates, or
/// whose header is no id, is left to its route's own refusal. The caller is
/// the one the receipt layer resolved for this call ([`ResolvedCaller`],
/// FIX 2005), never resolved a second time.
pub(super) async fn facade_invocation_claim(
    State(server): State<Arc<SyncServer>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(Some(invocation)) = facade_invocation_id(request.headers()) else {
        return next.run(request).await;
    };
    let (mut parts, body) = request.into_parts();
    let resolved = parts
        .extensions
        .get::<ResolvedCaller>()
        .map(|resolved| resolved.auth.clone());
    let auth = match resolved {
        Some(auth) => auth,
        None => match CoreAuth::from_request_parts(&mut parts, &server).await {
            Ok(auth) => auth,
            Err(_) => return next.run(Request::from_parts(parts, body)).await,
        },
    };
    // A custody value's body arrives redacted from the outer layer; its claim
    // states the arrival's own digest (FIX 11442).
    let verb = parts.uri.path().trim_start_matches('/').to_owned();
    let (bytes, redacted) =
        super::secret_body::read_middleware_body(body, &verb, &mut parts.extensions).await;
    let digest = match parts
        .extensions
        .get::<super::secret_body::FacadeOriginalDigest>()
    {
        Some(stored) => stored.digest().to_owned(),
        None => match redacted {
            Some(value) => oneiron::receipt::call_json_digest(&value),
            None => oneiron::receipt::call_bytes_digest(&bytes),
        },
    };
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .map_or(&[][..], HeaderValue::as_bytes)
    };
    let call = invocation_body(
        Some(&auth),
        auth.locality(),
        &[
            b"facade".as_slice(),
            parts.uri.path().as_bytes(),
            header(ROOM_TURN_HEADER),
            header(SESSION_HEADER),
            digest.as_bytes(),
        ],
    );
    match claim_door_invocation(&server, invocation, call, auth.principal_entity()).await {
        DoorClaim::Run(claim) => {
            let response = claim
                .run(next.run(Request::from_parts(parts, Body::from(bytes))))
                .await;
            finish_door_claim(claim, response).await
        }
        DoorClaim::Answered(outcome) => {
            // The waiter's credential is judged again once the wait is over,
            // before a reply is its (FIX 8212): a revoked or expired one gets
            // the refusal it gets anywhere.
            if !auth.credential_is_live(server.vault()) {
                return crate::error::EnvelopedApiError::from(ApiError::unauthorized())
                    .into_response();
            }
            let verb = parts.uri.path().trim_start_matches('/');
            facade_replay(server.vault(), &auth, verb, outcome)
        }
        DoorClaim::InFlight => FacadeApiError::new(
            StatusCode::CONFLICT,
            INVOCATION_IN_FLIGHT,
            "another request is still running this invocation",
            ["Retry with the same invocation once the first call returns."],
        )
        .into_response(),
        DoorClaim::Conflict => FacadeApiError::new(
            StatusCode::CONFLICT,
            INVOCATION_CONFLICT,
            "this invocation id names a different call",
            ["Name a fresh invocation for a different call."],
        )
        .into_response(),
        DoorClaim::ReplyNotKept { committed_writes } => FacadeApiError::new(
            StatusCode::CONFLICT,
            crate::idempotency::REPLY_NOT_KEPT_STATE,
            format!(
                "the first request with this invocation committed {committed_writes} write(s) while it ran; its reply was not kept"
            ),
            [
                "Read the resource's current state to see what landed.",
                "Send the request with a new invocation to act again.",
            ],
        )
        .into_response(),
        DoorClaim::Erased => FacadeApiError::new(
            StatusCode::CONFLICT,
            INVOCATION_RESPONSE_ERASED,
            "the first response with this invocation was erased",
            ["Send the request with a new invocation to act again."],
        )
        .into_response(),
        DoorClaim::StoreFailed => FacadeApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            INVOCATION_STORE_FAILED,
            "the invocation claim could not be stored",
            ["Retry the request once the invocation store is available."],
        )
        .into_response(),
    }
}

/// The caller the facade's receipt layer resolved for one request, carried
/// in its extensions to the invocation claim and the route inside it, so
/// one call resolves its credential once (FIX 2005, FIX 12323). It keeps
/// the path and headers it was resolved from: a request built on another
/// one's extensions (an action's row, FIX 10938) is not the request it
/// names.
#[derive(Clone)]
pub(super) struct ResolvedCaller {
    pub(super) auth: CoreAuth,
    path: String,
    headers: HeaderMap,
}

impl ResolvedCaller {
    /// `auth`, as resolved for the request `parts` head.
    pub(super) fn of(auth: CoreAuth, parts: &axum::http::request::Parts) -> Self {
        Self {
            auth,
            path: parts.uri.path().to_owned(),
            headers: parts.headers.clone(),
        }
    }
}

/// The caller the receipt layer resolved for this same request, its path
/// and headers unchanged, for the route's own `CoreAuth` extractor (FIX
/// 12323). Only a caller whose standing the server reads again here, a
/// slip, a token id or an attested owner, is taken, and only while it is
/// still live ([`CoreAuth::credential_is_live`]). `None` for any other: the
/// extractor resolves it as before, so a revoked or expired credential is
/// refused there exactly as before, and an account key meets its own
/// verifier again.
pub(crate) fn resolved_facade_caller(
    parts: &axum::http::request::Parts,
    server: &SyncServer,
) -> Option<CoreAuth> {
    let resolved = parts.extensions.get::<ResolvedCaller>()?;
    let auth = &resolved.auth;
    let standing =
        auth.verified_slip().is_some() || auth.jti().is_some() || auth.managed_owner().is_some();
    (resolved.path == parts.uri.path()
        && resolved.headers == parts.headers
        && standing
        && auth.credential_is_live(server.vault()))
    .then(|| auth.clone())
}

/// How long a request naming an invocation another request is running
/// waits for that call's reply before it is told to retry.
pub(super) const INVOCATION_WAIT: Duration = Duration::from_secs(30);

/// The refusal a request naming a running invocation gets once its wait
/// runs out, or when the first call left no reply to send again.
pub(crate) const INVOCATION_IN_FLIGHT: &str = "invocation_in_flight";

/// The refusal a request naming a running invocation for a different call
/// gets at once.
pub(crate) const INVOCATION_CONFLICT: &str = "invocation_conflict";

/// The first response was erased and is never treated as a cache miss.
pub(crate) const INVOCATION_RESPONSE_ERASED: &str = "invocation_response_erased";

/// The durable intent could not be written or read, so the route did not run.
pub(crate) const INVOCATION_STORE_FAILED: &str = "invocation_store_failed";

/// What a door does with an invocation its client named (OF-580).
pub(crate) enum DoorClaim {
    /// This request runs the call: hand its reply to [`finish_door_claim`].
    Run(DoorInvocationClaim),
    /// The first call's reply, sent as this request's.
    Answered(InvocationOutcome),
    /// The first call is still running past the wait, or left no reply.
    InFlight,
    /// The id names a different call.
    Conflict,
    /// The first call committed writes but no reply was kept after the
    /// caller's bounded wait, or its open intent reached the TTL.
    ReplyNotKept { committed_writes: u32 },
    /// An owner's erase took the first call's claim or response.
    Erased,
    /// The claim store failed; no route effect ran.
    StoreFailed,
}

/// The live claim plus its durable intent. A normal drop without `finish`
/// releases the intent, matching the old live-only retry behavior. A process
/// crash runs no drop, so the intent stands and a duplicate cannot rerun.
pub(crate) struct DoorInvocationClaim {
    live: Option<InvocationClaim>,
    store: InvocationClaimStore,
    store_key: String,
}

impl DoorInvocationClaim {
    /// Runs a route future with its durable intent open on every poll, so
    /// grouped writes count on it (FIX 10379). Detached workers carry it too.
    pub(crate) async fn run<F: std::future::Future>(&self, run: F) -> F::Output {
        crate::idempotency::run_under_intent(&self.store_key, run).await
    }

    /// Saves a successful JSON outcome, releases a failed one, and wakes the
    /// live waiters in either case. A storage error is logged and leaves the
    /// durable intent standing rather than permitting a second run.
    pub(crate) fn finish(self, outcome: InvocationOutcome) {
        let keep = outcome.status < 400;
        self.finish_with(outcome, keep);
    }

    /// Releases a domain-level failure carried inside a 200 transport
    /// envelope, but still gives the original refusal to live waiters.
    pub(crate) fn finish_failed(self, outcome: InvocationOutcome) {
        self.finish_with(outcome, false);
    }

    fn finish_with(mut self, outcome: InvocationOutcome, keep: bool) {
        let kept = if keep {
            self.store.settle(&self.store_key, &outcome).map(|_| ())
        } else {
            self.store.release_intent(&self.store_key)
        };
        if let Err(error) = kept {
            tracing::error!(
                reason = "invocation_claim_finish_failed",
                error = %error,
                "failed to finish the durable invocation claim; its intent stands"
            );
        }
        if let Some(live) = self.live.take() {
            live.finish(outcome);
        }
    }
}

impl Drop for DoorInvocationClaim {
    fn drop(&mut self) {
        if self.live.is_some()
            && let Err(error) = self.store.release_intent(&self.store_key)
        {
            tracing::error!(
                reason = "invocation_claim_release_failed",
                error = %error,
                "failed to release an unfinished durable invocation claim"
            );
        }
    }
}

/// Claims `invocation` for the request whose call `body` names, waiting up
/// to [`INVOCATION_WAIT`] for another request's run of the same call. A live
/// miss then reads its durable twin: a settled answer replays, an open one
/// gets one bounded poll, and only a miss or released failure runs.
pub(crate) async fn claim_door_invocation(
    server: &SyncServer,
    invocation: InvocationId,
    body: [u8; 32],
    actor: Option<EntityId>,
) -> DoorClaim {
    let store = server.invocation_claims.clone();
    let store_key = invocation_claim_key(invocation);
    store.reclaim_expired_page().await;
    match server.vault.claim_invocation(invocation, body) {
        InvocationEntry::Claimed(live) => {
            let mut live = Some(live);
            let mut waited = false;
            loop {
                let _guard = store.lock_for(&store_key).await;
                let lookup = match store.lookup(&store_key, &body) {
                    Ok(lookup) => lookup,
                    Err(error) => {
                        tracing::error!(
                            reason = "invocation_claim_read_failed",
                            error = %error,
                            "failed to read a durable invocation claim"
                        );
                        return DoorClaim::StoreFailed;
                    }
                };
                match lookup {
                    crate::invocation_claims::InvocationClaimLookup::Miss => {
                        if let Err(error) = store.insert_intent(&store_key, body, actor) {
                            tracing::error!(
                                reason = "invocation_claim_intent_write_failed",
                                error = %error,
                                "failed to persist a durable invocation intent"
                            );
                            return DoorClaim::StoreFailed;
                        }
                        return DoorClaim::Run(DoorInvocationClaim {
                            live: live.take(),
                            store,
                            store_key,
                        });
                    }
                    crate::invocation_claims::InvocationClaimLookup::Replay(outcome) => {
                        if let Some(live) = live.take() {
                            live.finish(outcome.clone());
                        }
                        return DoorClaim::Answered(outcome);
                    }
                    crate::invocation_claims::InvocationClaimLookup::Conflict => {
                        return DoorClaim::Conflict;
                    }
                    crate::invocation_claims::InvocationClaimLookup::Erased => {
                        return DoorClaim::Erased;
                    }
                    crate::invocation_claims::InvocationClaimLookup::ReplyNotKept {
                        committed_writes,
                    } => return DoorClaim::ReplyNotKept { committed_writes },
                    crate::invocation_claims::InvocationClaimLookup::Interrupted {
                        committed_writes,
                    } if waited => {
                        return if committed_writes == 0 {
                            DoorClaim::InFlight
                        } else {
                            DoorClaim::ReplyNotKept { committed_writes }
                        };
                    }
                    crate::invocation_claims::InvocationClaimLookup::Interrupted { .. } => {
                        waited = true;
                    }
                }
                drop(_guard);
                tokio::time::sleep(INVOCATION_WAIT).await;
            }
        }
        InvocationEntry::Conflict => DoorClaim::Conflict,
        InvocationEntry::Busy(wait) => {
            match super::clock_ingress::run_blocking(move || wait.outcome(INVOCATION_WAIT)).await {
                Ok(Some(outcome)) => DoorClaim::Answered(outcome),
                _ => DoorClaim::InFlight,
            }
        }
    }
}

/// The call a claimed invocation names: the caller (its actor, class and
/// credential), where it sits, and the door's own parts, each
/// length-prefixed.
pub(crate) fn invocation_body(
    auth: Option<&CoreAuth>,
    locality: CallerLocality,
    parts: &[&[u8]],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron door invocation body v1");
    let mut part = |bytes: &[u8]| {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    if let Some(auth) = auth {
        let (actor_ref, actor_class) = call_receipt::call_actor(auth);
        part(actor_ref.as_bytes());
        part(actor_class.as_bytes());
        part(
            call_receipt::credential_ref(auth)
                .unwrap_or_default()
                .as_bytes(),
        );
    }
    part(match locality {
        CallerLocality::OnDevice => b"on-device".as_slice(),
        CallerLocality::OffDevice => b"off-device".as_slice(),
    });
    for &bytes in parts {
        part(bytes);
    }
    *hasher.finalize().as_bytes()
}

/// Sends `response` as the claimed call's reply, saving it for each request
/// waiting on the same call, beside what its route kept to release it again
/// ([`FacadeReleased`], FIX 8212): the answer before its release, its rows
/// and its caller's machine. A body that is not JSON is sent as it is and
/// releases the durable intent, as the old live claim allowed a later retry.
pub(crate) async fn finish_door_claim(claim: DoorInvocationClaim, response: Response) -> Response {
    let (mut head, body) = response.into_parts();
    let released = head.extensions.remove::<FacadeReleased>();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        let release = released.map(|released| released.kept(&body));
        claim.finish(InvocationOutcome {
            status: head.status.as_u16(),
            body,
            release,
        });
    }
    Response::from_parts(head, Body::from(bytes))
}

/// The first call's reply, sent again to a request that waited on it:
/// for a facade waiter `auth` on verb `verb` (FIX 8212), an answer its route
/// kept is released again for this waiter's credential and destination
/// ([`replayed_value`]), never run again; a reply kept with nothing beside
/// it, a refusal among them, has its words released again for this waiter
/// ([`rereleased_refusal`], FIX 10497). A chat waiter meets the same replay
/// through this (FIX 10499).
pub(crate) fn door_replay_for(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    verb: &str,
    outcome: InvocationOutcome,
) -> Response {
    let (status, body) = replayed_reply(vault, auth, verb, outcome);
    (status, Json(body)).into_response()
}

/// [`door_replay_for`] for a facade waiter: a refusal goes again as the
/// facade's own ([`FacadeApiError::replayed`], FIX 2005), every word and
/// field the first one carried under a request id of its own, so this
/// call's receipt records its code, while it still names the first call's
/// receipt, the original.
fn facade_replay(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    verb: &str,
    outcome: InvocationOutcome,
) -> Response {
    let (status, body) = replayed_reply(vault, auth, verb, outcome);
    match FacadeApiError::replayed(status, &body) {
        Some(refusal) => refusal.into_response(),
        None => (status, Json(body)).into_response(),
    }
}

/// The first call's status and body, released again for the waiter `auth`.
fn replayed_reply(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    verb: &str,
    outcome: InvocationOutcome,
) -> (StatusCode, serde_json::Value) {
    let status = StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = match outcome.release {
        Some(release) => replayed_value(vault, auth, verb, release),
        None => rereleased_refusal(vault, auth, outcome.body),
    };
    (status, body)
}

/// A refusal the first call kept with nothing beside it, released again for
/// the waiter `auth` (FIX 10497): words naming a row this waiter's
/// destination withholds leave as their code alone, never the first caller's
/// release of them. Anything else, and any reply that is no refusal, goes as
/// it was.
fn rereleased_refusal(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    body: serde_json::Value,
) -> serde_json::Value {
    let mut body = body;
    let denied = body
        .get("error")
        .and_then(|error| error.get("code"))
        .is_some_and(serde_json::Value::is_string)
        && crate::device_local::replay_withheld(
            vault,
            auth.destination(),
            &serde_json::to_vec(&body).unwrap_or_default(),
            &[],
        );
    if !denied {
        return body;
    }
    if let Some(error) = body
        .get_mut("error")
        .and_then(serde_json::Value::as_object_mut)
    {
        let words = "the call failed; its detail stays on this device";
        error.insert(
            "message".to_owned(),
            serde_json::Value::String(words.to_owned()),
        );
        error.insert(
            "suggestions".to_owned(),
            serde_json::Value::Array(Vec::new()),
        );
        error.remove("legal_hold");
    }
    body
}
