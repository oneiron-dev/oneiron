//! Doors for `tests/residence_media_vectors_server_test.rs`: the canonical
//! live window a residence read selects from, and one
//! `residence.media_vectors` call as the socket loop runs it, answered as the
//! wire answers it.

use oneiron::authority::PeerMachine;
use serde_json::Value;

use crate::server::SyncServer;

/// Serves the canonical live window `window`, registering it in the root's
/// window list as a first touch does. The caller keeps no handle: the test
/// holds no import while it reads.
///
/// # Errors
///
/// A key that names no window; the vault's.
pub async fn serve_window(server: &SyncServer, window: &str) -> anyhow::Result<()> {
    let key = oneiron::sync::WindowKey::try_new(window)
        .ok_or_else(|| anyhow::anyhow!("not a window key: {window}"))?;
    server
        .serve_window(&key)
        .await
        .map_err(|error| anyhow::anyhow!("serve window: {error:?}"))?;
    Ok(())
}

/// Runs `residence.media_vectors` with `params` for the machine `peer`, under
/// the holder-bound slip `token` proves with `timestamp`, `nonce` and the hex
/// `signature`, and answers the wire reply: `result` on success, `error` on a
/// refusal, as `requestId` 7.
///
/// # Errors
///
/// A slip the vault refuses; an RPC the socket loop refuses.
pub fn media_vectors_reply(
    server: &SyncServer,
    token: &str,
    timestamp: u64,
    nonce: &str,
    signature: &str,
    peer: PeerMachine,
    params: Value,
) -> anyhow::Result<Value> {
    let proof = crate::auth::BindingProof {
        timestamp,
        nonce: nonce.to_owned(),
        signature: signature.to_owned(),
    };
    let auth = crate::auth::CoreAuth::from_slip_token(token, &proof, server.vault().as_ref())
        .map_err(|error| anyhow::anyhow!("slip refused: {error:?}"))?;
    let request = crate::livequery::RpcRequest {
        request_id: 7,
        method: "residence.media_vectors".to_owned(),
        params,
    };
    let reply = crate::livequery::residence_rpc(
        server, &auth, peer, request, &mut None, &mut None, &mut None,
    )
    .map_err(|error| anyhow::anyhow!("rpc refused: {error:?}"))?;
    Ok(crate::livequery::test_wire::reply(&reply.queued(0)))
}
