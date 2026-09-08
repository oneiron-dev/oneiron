//! Transport-injected and cloud adapters over the same validated dispatch.

use std::sync::Arc;

use serde_json::Value;

use super::contract::{VaultReadAdapterKind, VaultReadMethod, VaultReadResponse, VaultReadWireOp};
use super::error::{VaultReadError, VaultReadResult, response_arm_mismatch};
use super::sealed;

/// Host-injected transport seam. HTTP and MCP daemons implement this later; no
/// URL, socket, authentication, retry, or timeout code lives in this crate.
///
/// Authentication and actor binding belong to the transport's construction
/// context, never to guest-authored request fields.
pub trait WireTransport: Send + Sync {
    /// Sends one canonical request body for `op` and returns the response
    /// bytes, which must be a `{"ok": ...}` or `{"err": ...}` envelope.
    fn round_trip(&self, op: VaultReadWireOp, request_json: &[u8]) -> VaultReadResult<Vec<u8>>;
}

/// Transport-injected adapter used by HTTP or MCP daemons.
pub struct WireTransportVaultReadAdapter {
    transport: Arc<dyn WireTransport>,
}

impl WireTransportVaultReadAdapter {
    /// Binds the adapter to one injected transport.
    #[must_use]
    pub fn new(transport: Arc<dyn WireTransport>) -> Self {
        Self { transport }
    }
}

fn protocol_mismatch(method: VaultReadMethod, message: String) -> VaultReadError {
    VaultReadError::ProtocolMismatch { method, message }
}

/// Decodes the wire envelope. The key set must be EXACTLY `{ "ok" }` or exactly
/// `{ "err" }`; both keys, neither key, or any extra key is a protocol
/// mismatch before arm deserialization. A bare operation DTO is therefore
/// rejected too.
pub(super) fn decode_wire_envelope(
    method: VaultReadMethod,
    op: VaultReadWireOp,
    bytes: &[u8],
) -> VaultReadResult<VaultReadResponse> {
    let envelope: serde_json::Map<String, Value> =
        serde_json::from_slice(bytes).map_err(|error| {
            protocol_mismatch(method, format!("response is not a JSON object: {error}"))
        })?;
    let has_ok = envelope.contains_key("ok");
    let has_err = envelope.contains_key("err");
    if envelope.len() != 1 || !(has_ok || has_err) {
        return Err(protocol_mismatch(
            method,
            format!(
                "response envelope must carry exactly one of \"ok\" or \"err\"; got {} key(s)",
                envelope.len()
            ),
        ));
    }
    if let Some(error) = envelope.get("err") {
        let error: VaultReadError = serde_json::from_value(error.clone()).map_err(|error| {
            protocol_mismatch(method, format!("err arm is not a VaultReadError: {error}"))
        })?;
        if error.method() != method {
            return Err(protocol_mismatch(
                method,
                format!(
                    "expected error for {method:?}, received {:?}",
                    error.method()
                ),
            ));
        }
        // Identity is validated; forward the semantic variant and payload intact.
        return Err(error);
    }
    let Some(ok) = envelope.get("ok") else {
        return Err(protocol_mismatch(method, "missing ok arm".to_owned()));
    };
    let response: VaultReadResponse = serde_json::from_value(ok.clone()).map_err(|error| {
        protocol_mismatch(method, format!("ok arm is not a tagged response: {error}"))
    })?;
    if response.wire_op() != op {
        return Err(response_arm_mismatch(method, response.wire_op()));
    }
    Ok(response)
}

impl sealed::Backend for WireTransportVaultReadAdapter {
    fn dispatch_validated(
        &self,
        request: sealed::ValidatedVaultReadRequest,
    ) -> VaultReadResult<VaultReadResponse> {
        let request = request.into_inner();
        let method = request.method();
        let op = request.wire_op();
        // The op is carried beside the body, so the body is the canonical
        // inner request DTO — never the tagged `{"op", "request"}` envelope.
        let body = request.canonical_body().map_err(|error| {
            protocol_mismatch(method, format!("request serialization failed: {error}"))
        })?;
        let bytes = self.transport.round_trip(op, &body)?;
        decode_wire_envelope(method, op, &bytes)
    }
}

/// Cloud placeholder exposing the identical Rust surface while cloud execution
/// remains unimplemented.
#[derive(Debug, Default, Clone, Copy)]
pub struct CloudVaultReadAdapter;

impl sealed::Backend for CloudVaultReadAdapter {
    fn dispatch_validated(
        &self,
        request: sealed::ValidatedVaultReadRequest,
    ) -> VaultReadResult<VaultReadResponse> {
        // Runtime peers never arrive here: their absence is runtime-wide, not
        // cloud-specific, so the shared wrapper answers them first.
        Err(VaultReadError::Unimplemented {
            adapter: VaultReadAdapterKind::Cloud,
            method: request.into_inner().method(),
        })
    }
}
