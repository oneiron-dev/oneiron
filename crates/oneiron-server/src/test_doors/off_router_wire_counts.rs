//! Doors for `tests/wire_counts_off_runtime.rs`: the wire counts an e-sign
//! QR capability refusal and an MCP envelope error make, each as its route
//! makes it. The HTTP observer counts every call before its route runs, so a
//! test through the router reaches these counts only once the observer's has
//! landed; through these doors it can hold the counter lock while they wait
//! and show they wait on the blocking pool, never on a runtime worker (FIX
//! [WIRE-TELEMETRY-SYNC-PERSIST-ON-ASYNC-PATH]).

use crate::server::SyncServer;

/// Counts one capability refusal on `/esign/verify/report`, under
/// `POST /esign/verify/report`.
pub async fn count_esign_capability_refusal(server: &SyncServer) {
    crate::api::count_capability_refusal_for_test(server).await;
}

/// Counts one MCP envelope error of the `parse_error` category.
pub async fn count_mcp_parse_error(server: &SyncServer) {
    crate::api::count_parse_error_for_test(server).await;
}
