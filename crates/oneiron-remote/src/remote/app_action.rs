//! Signed native action requests for an app-owned Fetch transport.

use super::*;
use crate::InProcessRequest;

/// Prepares one relative action request using the caller's own credential.
///
/// `action` is the native action body: `args`, `idempotencyKey`, and optional
/// `liveRun`. It is not a facade verb input. The caller owns the idempotency key.
/// Prepare a fresh request for each send; the binding proof must not be cached.
/// Hand its credential-bearing headers only to the existing native Fetch relay.
/// No request is sent and no credential is stored here.
pub fn prepare_app_action(
    credential: &str,
    verb: &str,
    action: &serde_json::Value,
) -> Result<InProcessRequest, MemoryError> {
    let (bearer, holder) = parse_credential(credential)?;
    let authorization = bearer_header(&bearer)?;
    let holder = slip_holder(&bearer, holder)?;
    let body = serialize_request(action)?;
    let mut headers = credential_headers_for(&authorization, holder.as_deref())?;
    let body = encode_request(body, &mut headers);
    accept_json(&mut headers);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(InProcessRequest {
        method: "POST".to_owned(),
        path: format!("/v1/core/actions/{verb}"),
        headers: headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
            .collect(),
        body,
    })
}
