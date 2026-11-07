use super::*;

/// The server's error envelope, exactly as `api/facade.rs` serializes it:
/// the error, and beside it the read receipt a refused read carries
/// (FIX 8631).
#[derive(serde::Deserialize)]
struct ApiErrorEnvelope {
    error: ApiErrorBody,
    /// The refused read's narrowing receipt; absent on every other refusal.
    #[serde(default)]
    narrowing: Option<Box<oneiron::claim::ScopedReadReceipt>>,
}

/// `{code, message, requestId, suggestions}`.
///
/// `code` is a `String` and stays one: collapsing an unrecognized future
/// engine code into a local enum is precisely the lossy step the raw-string
/// envelope exists to avoid. `requestId` is accepted and dropped — it is
/// diagnostic metadata, not a public field of the error contract.
#[derive(serde::Deserialize)]
struct ApiErrorBody {
    code: String,
    message: String,
    #[serde(default)]
    suggestions: Vec<String>,
    /// A `WRONG_ROOT` refusal's `{attempted, replacement, schemaRef}`.
    #[serde(flatten)]
    wrong_root: Option<oneiron::memory::MemoryWrongRoot>,
    /// A verb hook's stop: skipped, pending on an ask, or hidden.
    #[serde(default)]
    hook: Option<oneiron::runtime_hooks::VerbHookStop>,
    /// When to call again, in seconds, on a provider outage (FIX 3194).
    #[serde(default, rename = "retryAfter")]
    retry_after: Option<u64>,
    /// Each time the refused call's limit resets, as Unix seconds (FIX 8190).
    #[serde(default, rename = "resetsAt")]
    resets_at: Vec<u64>,
    /// The refusal's stable reason codes, in order (FIX 7398).
    #[serde(default, rename = "reasonCodes")]
    reason_codes: Vec<String>,
    #[serde(default)]
    legal_hold: Option<Box<oneiron::error::LegalHoldNotice>>,
}

/// Serializes a request body and enforces the 64 MiB request ceiling.
///
/// Measured BEFORE the request is sent, so an oversized body costs one
/// serialization rather than an upload the server's `DefaultBodyLimit` would
/// reject at the far end after the bytes crossed the network.
pub(super) fn serialize_request<Q: Serialize>(request: &Q) -> Result<Vec<u8>, MemoryError> {
    within_ceiling(serialize_whole(request)?)
}

/// Serializes a request body whatever its length: a caller that sends a body
/// past the ceiling to a route that spools it (FIX 11454) measures it itself.
pub(super) fn serialize_whole<Q: Serialize>(request: &Q) -> Result<Vec<u8>, MemoryError> {
    serde_json::to_vec(request).map_err(|error| {
        bad_request(
            format!("this request could not be serialized: {error}"),
            &["Check the request for non-finite numbers or non-serializable values."],
        )
    })
}

/// `body`, when it is within the 64 MiB request ceiling.
pub(super) fn within_ceiling(body: Vec<u8>) -> Result<Vec<u8>, MemoryError> {
    check_request_length(body.len() as u64)?;
    Ok(body)
}

pub(super) fn check_request_length(length: u64) -> Result<(), MemoryError> {
    if length > MAX_REMOTE_REQUEST_BYTES as u64 {
        return Err(bad_request(
            format!("the request body exceeds the {MAX_REMOTE_REQUEST_BYTES}-byte ceiling"),
            &["Send less in one call; blob versions cap at 32 MiB of raw content."],
        ));
    }
    Ok(())
}

/// The bytes a serialized request crosses as (ARCH-0081 §8): zstd at 16 KiB or
/// more when that is smaller, naming its `Content-Encoding` in `headers`. It
/// runs after [`serialize_request`], whose ceiling is on the raw bytes.
pub(super) fn encode_request(body: Vec<u8>, headers: &mut HeaderMap) -> Vec<u8> {
    match oneiron::sync::transport::encode_http_body(&body) {
        Some(encoded) => {
            headers.insert(CONTENT_ENCODING, HeaderValue::from_static("zstd"));
            encoded
        }
        None => body,
    }
}

/// Decodes a success body straight from the wire into its typed result
/// (ABC transport row T19): a reply of any length, with no whole-body buffer
/// and no fixed ceiling (rule 5). A connection that fails mid-body is a
/// truncated reply; bytes that do not decode as `R`, a body that ends early
/// included, are named as such with `what`, the call.
pub(super) fn read_reply<R: DeserializeOwned, B: Read>(
    body: B,
    status: reqwest::StatusCode,
    what: &str,
) -> Result<R, MemoryError> {
    serde_json::from_reader(std::io::BufReader::new(body)).map_err(|error| {
        if error.is_io() {
            transport_error(format!("the server's response was truncated: {error}"))
        } else {
            transport_error(format!(
                "the server answered {status} for {what} with a body this call could not decode: {error}"
            ))
        }
    })
}

/// Decodes an export straight from the wire.
///
/// An export is one document that may pass the ordinary success ceiling, so
/// it streams into its typed result with no second whole-body buffer. No
/// code-only ceiling caps it (rule 5): the export-specific total timeout
/// still refuses a stalled peer.
pub(super) fn read_export<R: DeserializeOwned, B: Read>(
    body: B,
    status: reqwest::StatusCode,
) -> Result<R, MemoryError> {
    serde_json::from_reader(body).map_err(|error| {
        transport_error(format!(
            "the server answered {status} for export with an incomplete or invalid export: {error}"
        ))
    })
}

/// Rebuilds the engine's refusal from a failing response, losslessly.
///
/// The envelope decodes straight from the wire, whatever its length (ABC
/// transport row T20): a large refusal is read whole, and anything else stops
/// the decode at its first byte that is not the envelope, so a proxy's HTML
/// apology is never buffered. A body that does not parse as the envelope
/// becomes a transport error whose message names the status and nothing else.
/// The foreign bytes are dropped on purpose: an HTML error page rendered into
/// a `message` or a `suggestion` becomes text a caller displays, logs, or —
/// in the worst case — executes.
pub(super) fn read_error_envelope<B: Read>(body: B, status: reqwest::StatusCode) -> MemoryError {
    match serde_json::from_reader::<_, ApiErrorEnvelope>(std::io::BufReader::new(body)) {
        Err(error) if error.is_io() => transport_error(format!(
            "the server answered {status} with an unreadable error body"
        )),
        decoded => decoded.ok().and_then(error_of_envelope).unwrap_or_else(|| {
            transport_error(format!(
                "the server answered {status} with a body that is not an Oneiron error envelope"
            ))
        }),
    }
}

/// Rebuilds a [`MemoryError`] from envelope bytes, or `None` if they are not
/// one.
///
/// Split out from the response handling so the lossless-mapping property can
/// be tested against bytes rather than against a live server.
pub(super) fn parse_error_envelope(bytes: &[u8]) -> Option<MemoryError> {
    serde_json::from_slice::<ApiErrorEnvelope>(bytes)
        .ok()
        .and_then(error_of_envelope)
}

/// The [`MemoryError`] a decoded envelope carries, or `None` when it names no
/// code.
fn error_of_envelope(envelope: ApiErrorEnvelope) -> Option<MemoryError> {
    if envelope.error.code.is_empty() {
        // An envelope-shaped body with no code is not an Oneiron refusal; it
        // is something else that happened to have an `error` key.
        return None;
    }
    let suggestions = if envelope.error.suggestions.is_empty() {
        // The contract says `suggestions` is never empty. A server that sent
        // none is answered with the one suggestion that is always true rather
        // than with an empty array the caller has to special-case.
        vec!["Retry the call, and check the server logs for this request.".to_owned()]
    } else {
        envelope.error.suggestions
    };
    Some(MemoryError {
        code: envelope.error.code,
        message: envelope.error.message,
        suggestions,
        successor_short_id: None,
        gate_denial: None,
        read_receipt: envelope.narrowing,
        policy_denial: None,
        wrong_root: envelope.error.wrong_root.map(Box::new),
        hook: envelope.error.hook.map(Box::new),
        retry_after: envelope.error.retry_after,
        resets_at: envelope.error.resets_at,
        reason_codes: envelope.error.reason_codes,
        legal_hold: envelope.error.legal_hold,
    })
}

/// Describes a send failure without leaking the URL's credentials or body.
pub(super) fn describe_send_failure(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return "the request to the Oneiron server timed out".to_owned();
    }
    if error.is_connect() {
        return "could not connect to the Oneiron server".to_owned();
    }
    "the request to the Oneiron server failed".to_owned()
}
