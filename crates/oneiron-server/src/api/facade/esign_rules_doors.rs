//! E-sign rule pack owner decisions (ARCH-0064 sections 2 and 8) use the request's owner proof and
//! its own Memory. The pack is side-table state, so these doors list no record.

use super::host_doors::support::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::blob_artifact::esign::{EsignRulesDecisionRequest, EsignRulesReceipt};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};
use std::sync::Arc;

pub(crate) async fn vault_esign_rules_approve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: EsignRulesDecisionRequest,
) -> Listed<EsignRulesReceipt> {
    const VERB: &str = "vault.esign.rules.approve";
    credential_listing(server, auth, caller, VERB, move |server, auth, memory| {
        memory.esign_rules_approve_as(&owner_proof(auth, server, VERB)?, &input)
    })
    .await
}

pub(crate) async fn vault_esign_rules_reject(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: EsignRulesDecisionRequest,
) -> Listed<EsignRulesReceipt> {
    const VERB: &str = "vault.esign.rules.reject";
    credential_listing(server, auth, caller, VERB, move |server, auth, memory| {
        memory.esign_rules_reject_as(&owner_proof(auth, server, VERB)?, &input)
    })
    .await
}
