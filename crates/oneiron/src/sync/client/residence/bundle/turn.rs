//! This machine's side of the home's publisher turn (FIX 3351): a publisher
//! asks for the turn before it assembles the slot's generation, and keeps
//! asking while it assembles, so a slow assembly keeps it.

use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use super::super::{ResidenceRpc, refused};
use crate::sync::residence::SEALED_BUNDLE_PUBLISH_LEASE_SECS;
use crate::sync::transport::TransportError;

/// How often a publisher that holds the turn asks again while it assembles:
/// well inside the lease, so one slow reply does not let it lapse.
const RENEW_SECS: u64 = SEALED_BUNDLE_PUBLISH_LEASE_SECS / 4;

#[derive(Deserialize)]
struct TurnReply {
    turn: bool,
}

/// Asks the home for the publisher turn, or, with `leave`, gives this
/// machine's place up; whether it holds the turn now.
pub(super) async fn ask_turn(rpc: &mut ResidenceRpc, leave: bool) -> Result<bool, TransportError> {
    let reply = rpc
        .request("residence.bundle.turn", json!({"leave": leave}))
        .await?;
    let reply: TurnReply = serde_json::from_value(reply).map_err(|_| refused())?;
    Ok(reply.turn)
}

/// Runs `work` off the runtime and asks for the turn again every
/// [`RENEW_SECS`] until it ends.
pub(super) async fn renewing_turn<T: Send + 'static>(
    rpc: &mut ResidenceRpc,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, TransportError> {
    let mut work = tokio::task::spawn_blocking(work);
    loop {
        tokio::select! {
            done = &mut work => {
                return done.map_err(|error| TransportError::Storage(error.to_string()));
            }
            () = tokio::time::sleep(Duration::from_secs(RENEW_SECS)) => {
                ask_turn(rpc, false).await?;
            }
        }
    }
}
