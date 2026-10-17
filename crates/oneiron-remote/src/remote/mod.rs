//! The remote backend: the ONE HTTP stack the SDK owns (ONE-1441 I13, D2).
//!
//! Neither language binding contains an HTTP client. JavaScript has no
//! `fetch`, Python has no `requests`, and both reach `oneiron-server` through
//! this file, so there is one place where a timeout, a body ceiling, or an
//! error envelope is decided.
//!
//! The client holds its credential and never believes it. A slip crosses
//! verbatim after `Authorization: Bearer `, and every request carries a fresh
//! holder proof signed with the connection key. The slip is parsed once, at
//! connect, only to hash it into that proof; its claims are never read:
//! authority is the server's to decide, and a client that inspected claims
//! would eventually start believing them. A host secret crosses as a bare
//! bearer.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use oneiron::authority::CapabilitySlip;
use oneiron::memory::MemoryError;
use reqwest::blocking::Client;
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, HeaderMap, HeaderValue,
};
use reqwest::{Method, StatusCode, Url};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::caps::{MAX_REMOTE_EXPORT_BYTES, MAX_REMOTE_REQUEST_BYTES, MAX_REMOTE_RESPONSE_BYTES};
use crate::error::{bad_request, forbidden, transport_error};

// OF-469: a pinned authority checkpoint, fetched for adoption.
mod checkpoint;
mod origin;
mod pairing;
mod response;
// OF-237: the network or an in-process server under one signing path.
mod wire;

use self::origin::{bearer_header, normalize_origin};
pub(crate) use self::pairing::{pair, parse_credential};
use self::response::{
    ReadFailure, describe_send_failure, encode_request, read_capped, read_error_envelope,
    read_export, serialize_request,
};
use self::wire::Wire;

/// Path prefix every facade verb hangs off.
const FACADE_PREFIX: &str = "v1/core/facade";
/// Path prefix a host-rendered lens card's routes hang off (OF-181).
const LENS_FRAMES_PREFIX: &str = "v1/core/lens-frames";

/// The header a slip holder's per-request proof crosses in.
const BINDING_HEADER: &str = "x-oneiron-binding";
/// Names the room turn a verb runs in; the server resolves its roster.
const ROOM_TURN_HEADER: &str = "x-oneiron-room-turn";
/// Names the off-record session a call runs inside (OF-063).
const SESSION_HEADER: &str = "x-oneiron-session";
/// The call receipt every facade reply states (OF-538): `call:<32hex>`, or
/// `none; no-record` for a call inside an anonymous off-record session.
const RECEIPT_REF_HEADER: &str = "x-oneiron-receipt-ref";
/// The prefix of a receipt ref the server recorded.
const RECEIPT_REF_PREFIX: &str = "call:";
/// Names the logical verb call a request is (ARCH-0080 §3), as 32 lowercase
/// hex digits: its verb hooks fire once for it, and a retry of a call a hook
/// stopped on an ask names the same one to find that ask.
const INVOCATION_HEADER: &str = "x-oneiron-invocation";

/// Connect timeout: finite, so a black-holed address fails instead of hanging.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The origin a served client's URLs are built on (OF-237). Only the path and
/// query cross the in-process transport; nothing dials this.
const IN_PROCESS_ORIGIN: &str = "http://localhost/";

/// Total request timeout, sized for a 32 MiB blob round trip.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// Full-vault exports can be much larger than one ordinary verb response.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// The remote half of [`crate::OneironClient`].
pub(crate) struct RemoteClient {
    base_url: Url,
    authorization: HeaderValue,
    holder: Option<Box<(CapabilitySlip, SigningKey)>>,
    /// The network, or a server this process runs.
    wire: Wire,
    export_limit: usize,
    /// The room turn every verb runs in, named to the server per request.
    room_turn: Option<oneiron::EntityId>,
    /// The off-record session every verb runs inside, named to the server
    /// per request (OF-063, FIX 1668).
    off_record_session: Option<HeaderValue>,
    /// The call receipt the last verb's reply stated, success or refusal
    /// (OF-538). Per handle: a clone starts with none.
    last_receipt_ref: std::sync::Mutex<Option<String>>,
}

/// Hand-written so the bearer cannot reach a log through a derive.
///
/// `HeaderValue` already redacts itself once marked sensitive, so this impl is
/// belt-and-braces: the field is omitted entirely rather than trusted to print
/// as `Sensitive`.
impl std::fmt::Debug for RemoteClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteClient")
            .field("base_url", &self.base_url())
            .finish_non_exhaustive()
    }
}

impl Clone for RemoteClient {
    fn clone(&self) -> Self {
        Self {
            base_url: self.base_url.clone(),
            authorization: self.authorization.clone(),
            holder: self.holder.clone(),
            wire: self.wire.clone(),
            export_limit: self.export_limit,
            room_turn: self.room_turn,
            off_record_session: self.off_record_session.clone(),
            last_receipt_ref: std::sync::Mutex::new(None),
        }
    }
}

impl RemoteClient {
    /// Validates the URL and credential shape, and builds the agent.
    ///
    /// This is ALL `connect` does. It claims no authority, mints no actor and
    /// makes no request: the first verb is the first round trip, and until
    /// then the server has not been asked to agree to anything.
    pub(crate) fn connect(
        url: &str,
        bearer: &str,
        holder: Option<SigningKey>,
    ) -> Result<Self, MemoryError> {
        let base_url = normalize_origin(url)?;
        let authorization = bearer_header(bearer)?;
        let agent = blocking_agent()?;
        let export_agent = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(EXPORT_TIMEOUT)
            .build()
            .map_err(|error| transport_error(format!("could not build export client: {error}")))?;
        let holder = slip_holder(bearer, holder)?;
        let stream_agent = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| {
                transport_error(format!("could not build streaming client: {error}"))
            })?;
        Ok(Self {
            base_url,
            authorization,
            holder,
            wire: Wire::Http {
                agent,
                export_agent,
                stream_agent,
            },
            export_limit: MAX_REMOTE_EXPORT_BYTES,
            room_turn: None,
            off_record_session: None,
            last_receipt_ref: std::sync::Mutex::new(None),
        })
    }

    /// [`Self::connect`] to a server this process runs, through `transport`
    /// (OF-237): the same credential headers, holder proof, room turn,
    /// invocation and readers, with no socket and no agent. Makes no request.
    pub(crate) fn in_process(
        transport: Arc<dyn crate::InProcessTransport>,
        bearer: &str,
        holder: Option<SigningKey>,
    ) -> Result<Self, MemoryError> {
        let base_url = Url::parse(IN_PROCESS_ORIGIN)
            .map_err(|_| transport_error("could not name the in-process origin"))?;
        Ok(Self {
            base_url,
            authorization: bearer_header(bearer)?,
            holder: slip_holder(bearer, holder)?,
            wire: Wire::InProcess(transport),
            export_limit: MAX_REMOTE_EXPORT_BYTES,
            room_turn: None,
            off_record_session: None,
            last_receipt_ref: std::sync::Mutex::new(None),
        })
    }

    /// The same connection with every verb run inside `room`'s turn.
    pub(crate) fn in_room_turn(&self, room: oneiron::EntityId) -> Result<Self, MemoryError> {
        crate::embedded::refuse_other_room(self.room_turn, room)?;
        Ok(Self {
            room_turn: Some(room),
            ..self.clone()
        })
    }

    /// The same connection with every verb run inside the off-record
    /// session `session_ref` names; the server binds it to this credential's
    /// principal (OF-063, FIX 1668).
    pub(crate) fn in_off_record_session(&self, session_ref: &str) -> Result<Self, MemoryError> {
        let session = HeaderValue::from_str(session_ref).map_err(|_| {
            bad_request(
                "invalid off-record session reference",
                &["Name the session by the ref it was entered under."],
            )
        })?;
        Ok(Self {
            off_record_session: Some(session),
            ..self.clone()
        })
    }

    /// The bearer, and for a slip holder a fresh holder proof: one per
    /// request, never reused.
    fn credential_headers(&self) -> Result<HeaderMap, MemoryError> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, self.authorization.clone());
        if let Some((slip, key)) = self.holder.as_deref() {
            let unsigned = || transport_error("could not sign this request's holder proof");
            let proof = oneiron::authority::holder_proof(slip, key, crate::unix_seconds_now())
                .map_err(|_| unsigned())?;
            let mut binding = HeaderValue::from_str(&proof.to_string()).map_err(|_| unsigned())?;
            binding.set_sensitive(true);
            headers.insert(BINDING_HEADER, binding);
        }
        Ok(headers)
    }

    /// [`Self::credential_headers`], and the room turn this handle runs in.
    fn turn_headers(&self) -> Result<HeaderMap, MemoryError> {
        let mut headers = self.credential_headers()?;
        if let Some(room) = self.room_turn {
            headers.insert(
                ROOM_TURN_HEADER,
                HeaderValue::from_str(&room.to_hex())
                    .map_err(|_| transport_error("could not name the room turn"))?,
            );
        }
        if let Some(session) = &self.off_record_session {
            headers.insert(SESSION_HEADER, session.clone());
        }
        Ok(headers)
    }

    /// The origin this client talks to, for diagnostics; `None` for a
    /// server this process runs, which has no origin of its own.
    pub(crate) fn base_url(&self) -> Option<&str> {
        match self.wire {
            Wire::Http { .. } => Some(self.base_url.as_str()),
            Wire::InProcess(_) => None,
        }
    }

    /// The call receipt the last verb's reply stated (OF-538): its
    /// `call:<32hex>` ref, success or refusal alike. `None` before any call,
    /// after a call that reached no server, and for a reply that by design
    /// has none (an anonymous off-record call).
    pub(crate) fn last_receipt_ref(&self) -> Option<String> {
        self.last_receipt_ref
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn note_receipt_ref(&self, receipt_ref: Option<String>) {
        *self
            .last_receipt_ref
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = receipt_ref;
    }

    /// POSTs one facade verb as a new logical call, under a fresh invocation
    /// id, and decodes its typed response.
    pub(crate) fn call<Q: Serialize, R: DeserializeOwned>(
        &self,
        verb: &str,
        request: &Q,
    ) -> Result<R, MemoryError> {
        self.call_as(verb, request, crate::invocation::mint())
    }

    /// [`Self::call`] under `invocation`: the id a retry of a pending call
    /// names, so the server finds the ask that call stopped on.
    pub(crate) fn call_as<Q: Serialize, R: DeserializeOwned>(
        &self,
        verb: &str,
        request: &Q,
        invocation: oneiron::runtime_hooks::InvocationId,
    ) -> Result<R, MemoryError> {
        self.note_receipt_ref(None);
        let url = self.verb_url(verb)?;
        let body = serialize_request(request)?;
        let mut headers = self.turn_headers()?;
        headers.insert(
            INVOCATION_HEADER,
            HeaderValue::from_str(&invocation.to_hex())
                .map_err(|_| transport_error("could not name the invocation"))?,
        );
        let body = encode_request(body, &mut headers);
        accept_json(&mut headers);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let reply = self.send(Method::POST, url, headers, Some(body), long_running(verb))?;
        // Read before the body: success and refusal state it alike, and the
        // typed return keeps its shape.
        self.note_receipt_ref(
            reply
                .headers
                .get(RECEIPT_REF_HEADER)
                .and_then(|value| value.to_str().ok())
                .filter(|value| value.starts_with(RECEIPT_REF_PREFIX))
                .map(str::to_owned),
        );

        let status = reply.status;
        // A 202 is a verb hook's pending ask: the verb did not run, and the
        // body is the refusal naming the ask and this call's invocation
        // (ARCH-0080 §3), which `OneironClient::retry` resends it under.
        if !status.is_success() || status == StatusCode::ACCEPTED {
            return Err(read_error_envelope(reply.body, status));
        }
        // The ordinary facade has a strict success-body ceiling. Export alone
        // streams JSON directly into its required result, under its own
        // larger ceiling: there is no second whole-body buffer. The
        // export-specific total timeout still refuses a stalled peer.
        if verb == "vault.export" {
            read_export(reply.body, reply.content_length, status, self.export_limit)
        } else {
            read_json(reply.body, status, verb)
        }
    }

    /// `POST /v1/core/lens-frames/{card_id}/events` (OF-181): one event on a
    /// card this server rendered, under this handle's credential and room
    /// turn. A deterministic tool the event validates to dispatches its verb
    /// under the same headers.
    pub(crate) fn lens_frame_event(
        &self,
        card_id: &str,
        request: &crate::LensFrameEventRequest,
    ) -> Result<crate::LensFrameEventReply, MemoryError> {
        let url = self.lens_frame_url(card_id, true)?;
        let body = serialize_request(request)?;
        let mut headers = self.turn_headers()?;
        accept_json(&mut headers);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let reply = self.send(Method::POST, url, headers, Some(body), false)?;
        let status = reply.status;
        // A model round trip answers 202 with its queued callback. Any other
        // 202 is a refusal as on a verb: a verb hook the dispatched tool met
        // asked first, and the body names the ask.
        if status == StatusCode::ACCEPTED {
            let body: serde_json::Value = read_json(reply.body, status, "a lens frame event")?;
            if body.get("callbackId").is_some() {
                return serde_json::from_value(body).map_err(|error| {
                    transport_error(format!(
                        "the server queued a lens callback this call could not decode: {error}"
                    ))
                });
            }
            let bytes = serde_json::to_vec(&body).unwrap_or_default();
            return Err(
                self::response::parse_error_envelope(&bytes).unwrap_or_else(|| {
                    transport_error(format!(
                        "the server answered {status} with a body that is not an Oneiron error envelope"
                    ))
                }),
            );
        }
        if !status.is_success() {
            return Err(read_error_envelope(reply.body, status));
        }
        read_json(reply.body, status, "a lens frame event")
    }

    /// `DELETE /v1/core/lens-frames/{card_id}` (OF-181): closes a card this
    /// server rendered and frees its frame. It sends no body.
    pub(crate) fn close_lens_frame(
        &self,
        card_id: &str,
    ) -> Result<crate::CloseLensFrameReply, MemoryError> {
        let url = self.lens_frame_url(card_id, false)?;
        let mut headers = self.turn_headers()?;
        accept_json(&mut headers);
        let reply = self.send(Method::DELETE, url, headers, None, false)?;
        let status = reply.status;
        if !status.is_success() {
            return Err(read_error_envelope(reply.body, status));
        }
        read_json(reply.body, status, "a lens frame close")
    }

    /// A card's route: the lens-frames prefix, the card id as ONE
    /// percent-encoded path segment, then `events` for an event. An id that
    /// cannot cross as one segment (empty, `.` or `..`, which a URL resolves
    /// away) is refused before any request.
    fn lens_frame_url(&self, card_id: &str, events: bool) -> Result<Url, MemoryError> {
        if matches!(card_id, "" | "." | "..") {
            return Err(bad_request(
                "the card id cannot cross as one path segment",
                &["Pass the cardId the rendered card carries."],
            ));
        }
        let unbuilt = || transport_error("could not build the lens frame URL");
        let mut url = self
            .base_url
            .join(LENS_FRAMES_PREFIX)
            .map_err(|_| unbuilt())?;
        {
            let mut segments = url.path_segments_mut().map_err(|()| unbuilt())?;
            segments.pop_if_empty().push(card_id);
            if events {
                segments.push("events");
            }
        }
        Ok(url)
    }

    pub(crate) async fn llm_post(
        &self,
        request: &oneiron::LlmRequest,
        lease: &oneiron::BudgetLease,
    ) -> Result<reqwest::Response, oneiron::LlmError> {
        let path = "v1/llm/generate";
        let url = self
            .base_url
            .join(path)
            .map_err(|_| oneiron::FatalLlmError::InvalidRequest)?;
        let bytes =
            serialize_request(request).map_err(|_| oneiron::FatalLlmError::InvalidRequest)?;
        let mut credential = self
            .credential_headers()
            .map_err(|_| oneiron::FatalLlmError::Auth)?;
        let bytes = encode_request(bytes, &mut credential);
        self.stream_agent()?
            .post(url)
            .timeout(REQUEST_TIMEOUT)
            .headers(credential)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header("x-oneiron-budget-lease", lease.id())
            .body(bytes)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    oneiron::RetryableLlmError::Timeout.into()
                } else {
                    oneiron::RetryableLlmError::StreamCut.into()
                }
            })
    }

    pub(crate) async fn llm_stream(
        &self,
        request: &oneiron::LlmRequest,
        lease: &oneiron::BudgetLease,
    ) -> Result<reqwest::Response, oneiron::LlmError> {
        let url = self
            .base_url
            .join("v1/llm/stream")
            .map_err(|_| oneiron::FatalLlmError::InvalidRequest)?;
        let bytes =
            serialize_request(request).map_err(|_| oneiron::FatalLlmError::InvalidRequest)?;
        let mut credential = self
            .credential_headers()
            .map_err(|_| oneiron::FatalLlmError::Auth)?;
        let bytes = encode_request(bytes, &mut credential);
        self.stream_agent()?
            .post(url)
            .headers(credential)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/x-ndjson")
            .header("x-oneiron-budget-lease", lease.id())
            .body(bytes)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    oneiron::RetryableLlmError::Timeout.into()
                } else {
                    oneiron::RetryableLlmError::StreamCut.into()
                }
            })
    }

    /// The streaming agent the own-server LLM transport posts on. A served
    /// client has none: that transport only ever connects over the network.
    fn stream_agent(&self) -> Result<&reqwest::Client, oneiron::LlmError> {
        match &self.wire {
            Wire::Http { stream_agent, .. } => Ok(stream_agent),
            Wire::InProcess(_) => Err(oneiron::FatalLlmError::InvalidRequest.into()),
        }
    }

    /// Joins the canonical verb path onto the normalized origin.
    ///
    /// Built through `Url::join` against a base whose path always ends in `/`,
    /// so there is no string concatenation to get an ambiguous number of
    /// slashes wrong.
    fn verb_url(&self, verb: &str) -> Result<Url, MemoryError> {
        self.base_url
            .join(&format!("{FACADE_PREFIX}/{verb}"))
            .map_err(|error| transport_error(format!("could not build the {verb} URL: {error}")))
    }
}

/// The slip and connection key a holder signs each request's proof with,
/// parsed once from `bearer`; `None` for a bare bearer such as the host
/// secret. Its claims are never read.
fn slip_holder(
    bearer: &str,
    holder: Option<SigningKey>,
) -> Result<Option<Box<(CapabilitySlip, SigningKey)>>, MemoryError> {
    let Some(key) = holder else {
        return Ok(None);
    };
    let slip = CapabilitySlip::from_token(bearer).map_err(|_| {
        bad_request(
            "the credential's slip is not a v2 slip token",
            &["Pair again and pass the credential exactly as pair returned it."],
        )
    })?;
    Ok(Some(Box::new((slip, key))))
}

/// Every route this client calls answers JSON.
fn accept_json(headers: &mut HeaderMap) {
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
}

/// Verbs whose one answer can take minutes, so they ride the export client's
/// total timeout: the whole-vault export, and an embedding-space move's check,
/// which runs the vault's probes through both spaces with no server deadline
/// (OF-370).
fn long_running(verb: &str) -> bool {
    matches!(verb, "vault.export" | "vault.embedding_spaces.move_check")
}

/// Decodes a success body read under the ordinary response ceiling; `what`
/// names the call in a refusal.
fn read_json<R: DeserializeOwned, B: Read>(
    body: B,
    status: StatusCode,
    what: &str,
) -> Result<R, MemoryError> {
    let bytes = read_capped(body, MAX_REMOTE_RESPONSE_BYTES).map_err(|failure| match failure {
        ReadFailure::TooLarge => transport_error(format!(
            "the server's response exceeded the {MAX_REMOTE_RESPONSE_BYTES}-byte read ceiling"
        )),
        ReadFailure::Io(message) => {
            transport_error(format!("the server's response was truncated: {message}"))
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        transport_error(format!(
            "the server answered {status} for {what} with a body this call could not decode: {error}"
        ))
    })
}

/// The blocking client every facade verb and `pair` share.
fn blocking_agent() -> Result<Client, MemoryError> {
    Client::builder()
        // A redirect must not move a bearer request outside the validated
        // origin or downgrade HTTPS to cleartext HTTP.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|error| transport_error(format!("could not build the HTTP client: {error}")))
}

#[cfg(test)]
mod tests;
