//! A door to the check a host-door row's door runs before the row's pre
//! hooks (`row_door_admits`, FIX 1763), for the proof-rule guard test
//! (UC-01 PR 0a): the caller one request's headers name, judged for one verb,
//! as the facade and the MCP dispatch judge it before any hook fires.

use axum::http::HeaderMap;

use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Judges the caller `headers` name for `verb`, as the facade does before
/// the row's pre hooks: `Ok` when the row's door check admits the caller.
///
/// # Errors
///
/// `credential: ...` when the server authenticates no caller from
/// `headers`; else the row check's refusal, as `<code>: <message>`.
pub fn row_door_admits(server: &SyncServer, headers: &HeaderMap, verb: &str) -> Result<(), String> {
    let auth = CoreAuth::for_server(headers, server)
        .map_err(|refusal| format!("credential: {refusal:?}"))?;
    crate::api::row_door_admits(server, &auth, verb)
        .map_err(|refusal| format!("{}: {}", refusal.code, refusal.message))
}
