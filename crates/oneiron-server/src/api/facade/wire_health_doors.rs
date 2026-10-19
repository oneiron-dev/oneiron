//! The owner's wire detection policy, under the same proof as `/v1/owner/wire-health`.
use std::sync::Arc;

use oneiron::task_verb::sdk::{EmptyRequest, WireThresholds, WireThresholdsReceipt};

use super::host_doors::{Listed, off_runtime_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_wire_health_thresholds_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _: EmptyRequest,
) -> Listed<WireThresholds> {
    const VERB: &str = "vault.wire_health.thresholds.get";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    off_runtime_listing(VERB, move |_| {
        owner.revalidate(server.vault())?;
        server.wire_telemetry.thresholds().map_err(Into::into)
    })
    .await
}

pub(crate) async fn vault_wire_health_thresholds_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WireThresholds,
) -> Listed<WireThresholdsReceipt> {
    const VERB: &str = "vault.wire_health.thresholds.set";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    off_runtime_listing(VERB, move |_| {
        server
            .wire_telemetry
            .set_thresholds_as_owner(&owner, &input)
            .map_err(Into::into)
    })
    .await
}
