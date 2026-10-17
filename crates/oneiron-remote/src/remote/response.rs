use super::*;

/// Maximum bytes read from a FAILING response before parsing is attempted.
///
/// Far smaller than the success ceiling and for a different reason: an error
/// body is a small JSON envelope, and anything large arriving on an error
/// status is a proxy's HTML apology. Reading 64 KiB is enough to parse the
/// envelope and little enough that a hostile endpoint cannot make the client
/// buffer a response it will refuse anyway.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// The server's error envelope, exactly as `api/facade.rs` serializes it.
#[derive(serde::Deserialize)]
struct ApiErrorEnvelope {
    error: ApiErrorBody,
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
}

/// Serializes a request body and enforces the 64 MiB request ceiling.
///
/// Measured BEFORE the request is sent, so an oversized body costs one
/// serialization rather than an upload the server's `DefaultBodyLimit` would
/// reject at the far end after the bytes crossed the network.
pub(super) fn serialize_request<Q: Serialize>(request: &Q) -> Result<Vec<u8>, MemoryError> {
    let body = serde_json::to_vec(request).map_err(|error| {
        bad_request(
            format!("this request could not be serialized: {error}"),
            &["Check the request for non-finite numbers or non-serializable values."],
        )
    })?;
    if body.len() > MAX_REMOTE_REQUEST_BYTES {
        return Err(bad_request(
            format!("the request body exceeds the {MAX_REMOTE_REQUEST_BYTES}-byte ceiling"),
            &["Send less in one call; blob versions cap at 32 MiB of raw content."],
        ));
    }
    Ok(body)
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

/// Why a read stopped short.
pub(super) enum ReadFailure {
    /// The body was still going at the ceiling.
    TooLarge,
    /// The connection failed mid-body.
    Io(String),
}

/// Reads at most `limit` bytes, and reports overrun rather than truncating.
///
/// `take(limit + 1)` is the whole trick: reading one byte past the ceiling
/// distinguishes "exactly at the limit" from "over it" without ever buffering
/// the excess, so the refusal happens BEFORE any JSON or base64 decode
/// allocates against an attacker-chosen length.
pub(super) fn read_capped<B: Read>(body: B, limit: usize) -> Result<Vec<u8>, ReadFailure> {
    let mut buffer = Vec::new();
    let mut reader = body.take(limit as u64 + 1);
    reader
        .read_to_end(&mut buffer)
        .map_err(|error| ReadFailure::Io(error.to_string()))?;
    if buffer.len() > limit {
        return Err(ReadFailure::TooLarge);
    }
    Ok(buffer)
}

/// Decodes an export straight from the wire, reading at most `limit` bytes.
///
/// An export is one document that may pass the ordinary success ceiling, so
/// it streams into its typed result with no second whole-body buffer. It is
/// still finite: a `Content-Length` over `limit` is refused before the body
/// is read, and the body goes through `take(limit + 1)`, so a peer that keeps
/// sending is cut off one byte past the limit whatever its header said.
pub(super) fn read_export<R: DeserializeOwned, B: Read>(
    body: B,
    content_length: Option<u64>,
    status: reqwest::StatusCode,
    limit: usize,
) -> Result<R, MemoryError> {
    let too_large = || {
        transport_error(format!(
            "the server's export exceeded the {limit}-byte read ceiling"
        ))
    };
    if content_length.is_some_and(|length| length > limit as u64) {
        return Err(too_large());
    }
    let mut reader = body.take(limit as u64 + 1);
    let decoded = serde_json::from_reader(&mut reader);
    if reader.limit() == 0 {
        return Err(too_large());
    }
    decoded.map_err(|error| {
        transport_error(format!(
            "the server answered {status} for export with an incomplete or invalid export: {error}"
        ))
    })
}

/// Rebuilds the engine's refusal from a failing response, losslessly.
///
/// A body that does not parse as the envelope becomes a transport error whose
/// message names the status and nothing else. The foreign bytes are dropped on
/// purpose: an HTML error page rendered into a `message` or a `suggestion`
/// becomes text a caller displays, logs, or — in the worst case — executes.
pub(super) fn read_error_envelope<B: Read>(body: B, status: reqwest::StatusCode) -> MemoryError {
    let Ok(bytes) = read_capped(body, MAX_ERROR_BODY_BYTES) else {
        return transport_error(format!(
            "the server answered {status} with an unreadable or oversized error body"
        ));
    };
    parse_error_envelope(&bytes).unwrap_or_else(|| {
        transport_error(format!(
            "the server answered {status} with a body that is not an Oneiron error envelope"
        ))
    })
}

/// Rebuilds a [`MemoryError`] from envelope bytes, or `None` if they are not
/// one.
///
/// Split out from the response handling so the lossless-mapping property can
/// be tested against bytes rather than against a live server.
pub(super) fn parse_error_envelope(bytes: &[u8]) -> Option<MemoryError> {
    let envelope = serde_json::from_slice::<ApiErrorEnvelope>(bytes).ok()?;
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
        read_receipt: None,
        policy_denial: None,
        wrong_root: envelope.error.wrong_root.map(Box::new),
        hook: envelope.error.hook.map(Box::new),
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
