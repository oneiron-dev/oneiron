//! The call receipt a facade route writes for each verb call it serves.
//! `facade_call_receipt` is its call surface.
//! The engine's `CallReceiptInput` (`oneiron::receipt`) is the record forwarded here.

use super::*;

/// Records one facade call once its handler has answered, in its own write
/// transaction, and states the receipt on the reply: the
/// `x-oneiron-receipt-ref` header on every reply, and `receiptRef` inside a
/// refusal's error body. A success body keeps its shape (some are JSON
/// arrays). A call inside an anonymous off-record session records nothing
/// and says so (`none; no-record`).
///
/// The call is attributed to the authenticated credential. A request no
/// credential authenticates is answered as before, by the handler's own
/// refusal, and records nothing: there is nobody to scope it to.
pub(super) async fn facade_call_receipt(
    State(server): State<Arc<SyncServer>>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let Ok(auth) = CoreAuth::from_request_parts(&mut parts, &server).await else {
        return next.run(Request::from_parts(parts, body)).await;
    };
    // OF-063: the no-record exception serves only a caller verified in the
    // session, judged on arrival and again before the receipt is written.
    let principal = call_receipt::request_principal(&auth);
    let session_headers = parts.headers.clone();
    let anonymous = call_receipt::in_anonymous_session(&server, &session_headers, principal);
    let verb = parts.uri.path().trim_start_matches('/').to_owned();
    // The handler reads these same bytes. A body past the facade's limit
    // reaches it empty and is refused there as malformed, as it was before.
    let bytes = axum::body::to_bytes(body, FACADE_MAX_BODY_BYTES)
        .await
        .unwrap_or_default();
    let request = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
    // FIX 4280: a call serving a room NOTE to a caller verified in its room
    // keeps none either, judged on arrival, before a close drops its hold.
    let anonymous = anonymous
        || call_receipt::room_notes::header_room_note_call(
            &server,
            &session_headers,
            principal,
            &verb,
            request.as_ref(),
        );
    let request_digest = match &request {
        Some(value) => oneiron::receipt::call_json_digest(value),
        None => oneiron::receipt::call_bytes_digest(&bytes),
    };
    // OF-568: what the call reads, captured before it runs. OF-568 L4: the
    // attempt whose live run it holds, as the hold witnessed it.
    let inputs = call_receipt::action_inputs(&server, &verb, request.as_ref());
    let (mut response, attempt) =
        call_receipt::attempt_witnessed(next.run(Request::from_parts(parts, Body::from(bytes))))
            .await;
    let mut refusal = response.extensions_mut().remove::<FacadeApiError>();
    let status = response.status();
    let mut result_digest = None;
    if refusal.is_none() && status.is_success() {
        let (head, body) = response.into_parts();
        response = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(bytes) => {
                // A `reveal.wait` reply is digested with its value masked.
                result_digest = Some(oneiron::task_verb::sdk::call_reply_digest(&verb, &bytes));
                Response::from_parts(head, Body::from(bytes))
            }
            Err(_) => {
                let failed = FacadeApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    MEMORY_CODE_INTERNAL,
                    "result encoding failed",
                    ["Report this SDK response mismatch."],
                );
                let reply = failed.reply();
                refusal = Some(failed);
                reply
            }
        };
    }
    if let Some(refusal) = &refusal {
        result_digest = Some(oneiron::receipt::call_refusal_digest(
            &refusal.body.error.code,
            &refusal.body.error.message,
        ));
    }
    let outcome = match &refusal {
        Some(refusal) => CallOutcome::Refused {
            code: refusal.body.error.code.clone(),
        },
        None if status.is_success() => CallOutcome::Ok,
        // A reply no facade refusal built (an axum rejection): its status.
        None => CallOutcome::Refused {
            code: format!("HTTP_{}", status.as_u16()),
        },
    };
    let anonymous =
        anonymous || call_receipt::in_anonymous_session(&server, &session_headers, principal);
    let (actor_ref, actor_class) = call_receipt::call_actor(&auth);
    let stamp = call_receipt::record(
        &server,
        anonymous,
        CallReceiptInput {
            transport: CallTransport::HttpFacade,
            verb,
            actor_ref,
            actor_class,
            credential_ref: call_receipt::credential_ref(&auth),
            outcome,
            request_digest,
            result_digest,
            inputs,
            attempt,
            served: Vec::new(),
        },
    );
    if let Some(mut refusal) = refusal {
        refusal.body.error.receipt_ref = stamp.receipt_ref().map(str::to_owned);
        response = refusal.reply();
    }
    stamp.stamp_header(&mut response);
    response
}
