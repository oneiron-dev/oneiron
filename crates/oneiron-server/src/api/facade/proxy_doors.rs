//! Owner-only OpenAI proxy admission and selective remember-grant withdrawal.
use super::clock_ingress;
use super::host_doors::support::{Listed, internal, naming, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::EntityId;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    ProxyConnectorAdmitRequest, ProxyConnectorRegistration, ProxyConnectorRevokeWriteRequest,
};
use std::sync::Arc;

fn id(field: &str, reference: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(reference)
        .map_err(|_| MemoryError::bad_request(format!("{field} is a 32-hex id")))
}

pub(crate) async fn vault_connectors_proxy_admit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ProxyConnectorAdmitRequest,
) -> Listed<ProxyConnectorRegistration> {
    const VERB: &str = "vault.connectors.proxy.admit";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let answer = clock_ingress::run_blocking(move || {
        let actor = id("actor", &input.actor)?;
        let registration =
            server
                .vault()
                .admit_proxy_connector(&owner, actor, crate::api::unix_seconds_now())?;
        Ok(ProxyConnectorRegistration::from_registration(
            server.vault(),
            registration,
        )?)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    naming(answer, |registration| {
        EntityId::from_hex(&registration.key.id)
            .into_iter()
            .collect()
    })
}

pub(crate) async fn vault_connectors_proxy_revoke_write(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ProxyConnectorRevokeWriteRequest,
) -> Listed<ProxyConnectorRegistration> {
    const VERB: &str = "vault.connectors.proxy.revoke_write";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let answer = clock_ingress::run_blocking(move || {
        let actor = id("actor", &input.actor)?;
        let key = id("key", &input.key)?;
        let registration = server.vault().revoke_proxy_connector_write(
            &owner,
            actor,
            key,
            input.revision,
            crate::api::unix_seconds_now(),
        )?;
        Ok(ProxyConnectorRegistration::from_registration(
            server.vault(),
            registration,
        )?)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    naming(answer, |registration| {
        EntityId::from_hex(&registration.key.id)
            .into_iter()
            .collect()
    })
}
