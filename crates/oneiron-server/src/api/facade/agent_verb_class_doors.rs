//! The owner's verb-class rows for his agents' grants (FIX 8735): reads and
//! edits under the caller's own owner credential.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::policy_manifest_doors::{
    self, AgentVerbClassesConfigureRequest, AgentVerbClassesReceipt, AgentVerbClassesView,
};
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::{Listed, off_runtime_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_agents_verb_classes_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<AgentVerbClassesView> {
    const VERB: &str = "vault.agents.verb_classes.get";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let (answer, mut rows) = off_runtime_listing(VERB, move |_| {
        policy_manifest_doors::agent_verb_classes_as_owner(server.vault(), &owner)
            .map_err(Into::into)
    })
    .await;
    if let Ok(view) = &answer {
        rows.extend(EntityId::from_hex(&view.manifest_ref).ok());
    }
    (answer, rows)
}

pub(crate) async fn vault_agents_verb_classes_configure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AgentVerbClassesConfigureRequest,
) -> Listed<AgentVerbClassesReceipt> {
    const VERB: &str = "vault.agents.verb_classes.configure";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let (answer, mut rows) = off_runtime_listing(VERB, move |_| {
        policy_manifest_doors::configure_agent_verb_classes_as_owner(server.vault(), &owner, input)
            .map_err(Into::into)
    })
    .await;
    if let Ok(receipt) = &answer {
        rows.extend(EntityId::from_hex(&receipt.configuration.manifest_ref).ok());
    }
    (answer, rows)
}
