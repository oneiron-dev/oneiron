//! The facade's invocation claims: one call per client-named invocation id (OF-580).
//! `claim_door_invocation` and `finish_door_claim` are its call surface; a door gets a `DoorClaim`.
//! `oneiron::runtime_hooks::verb` defines the `InvocationClaim` and outcome records forwarded.

use super::*;

/// Claims the invocation a request names, once, around its whole route
/// (OF-580): a second request naming it for the same call waits for this
/// one's reply and gets it, and one naming it for another call is refused at
/// once. An action's verb-table row reaches its route here with its step's
/// id, and is claimed once, here. A request no credential authenticates, or
/// whose header is no id, is left to its route's own refusal.
pub(super) async fn facade_invocation_claim(
    State(server): State<Arc<SyncServer>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(Some(invocation)) = facade_invocation_id(request.headers()) else {
        return next.run(request).await;
    };
    let (mut parts, body) = request.into_parts();
    let Ok(auth) = CoreAuth::from_request_parts(&mut parts, &server).await else {
        return next.run(Request::from_parts(parts, body)).await;
    };
    let bytes = axum::body::to_bytes(body, FACADE_MAX_BODY_BYTES)
        .await
        .unwrap_or_default();
    let digest = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) => oneiron::receipt::call_json_digest(&value),
        Err(_) => oneiron::receipt::call_bytes_digest(&bytes),
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
    match claim_door_invocation(&server, invocation, call).await {
        DoorClaim::Run(claim) => {
            let response = next
                .run(Request::from_parts(parts, Body::from(bytes)))
                .await;
            finish_door_claim(claim, response).await
        }
        DoorClaim::Answered(outcome) => door_replay(outcome),
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
    }
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

/// What a door does with an invocation its client named (OF-580).
pub(crate) enum DoorClaim {
    /// This request runs the call: hand its reply to [`finish_door_claim`].
    Run(InvocationClaim),
    /// The first call's reply, sent as this request's.
    Answered(InvocationOutcome),
    /// The first call is still running past the wait, or left no reply.
    InFlight,
    /// The id names a different call.
    Conflict,
}

/// Claims `invocation` for the request whose call `body` names, waiting up
/// to [`INVOCATION_WAIT`] for another request's run of the same call. Each
/// door that takes a client's id claims it once, at its outermost point.
pub(crate) async fn claim_door_invocation(
    server: &SyncServer,
    invocation: InvocationId,
    body: [u8; 32],
) -> DoorClaim {
    match server.vault.claim_invocation(invocation, body) {
        InvocationEntry::Claimed(claim) => DoorClaim::Run(claim),
        InvocationEntry::Conflict => DoorClaim::Conflict,
        InvocationEntry::Busy(wait) => {
            match tokio::task::spawn_blocking(move || wait.outcome(INVOCATION_WAIT)).await {
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
/// waiting on the same call. A body that is not JSON is sent as it is and
/// saved for none of them.
pub(crate) async fn finish_door_claim(claim: InvocationClaim, response: Response) -> Response {
    let (head, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if let Ok(body) = serde_json::from_slice(&bytes) {
        claim.finish(InvocationOutcome {
            status: head.status.as_u16(),
            body,
        });
    }
    Response::from_parts(head, Body::from(bytes))
}

/// The first call's reply, sent again to a request that waited on it.
pub(crate) fn door_replay(outcome: InvocationOutcome) -> Response {
    let status = StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(outcome.body)).into_response()
}
