//! Compliance owner decisions use the request's owner proof and its own Memory.
//! Pack data and receipts are side-table state, so these doors list no record.

use super::host_doors::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::campaign::compliance::{
    ComplianceAmendRequest, ComplianceApprovalRequest, ComplianceReceipt, ComplianceVerifyRequest,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};
use std::sync::Arc;

pub(crate) async fn vault_campaign_compliance_install(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ComplianceAmendRequest,
) -> Listed<ComplianceReceipt> {
    const VERB: &str = "vault.campaign.compliance.install";
    credential_listing(server, auth, caller, VERB, move |server, auth, memory| {
        memory.compliance_install_as(&owner_proof(auth, server, VERB)?, &input)
    })
    .await
}

pub(crate) async fn vault_campaign_compliance_approve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ComplianceApprovalRequest,
) -> Listed<ComplianceReceipt> {
    const VERB: &str = "vault.campaign.compliance.approve";
    credential_listing(server, auth, caller, VERB, move |server, auth, memory| {
        memory.compliance_approve_as(&owner_proof(auth, server, VERB)?, &input)
    })
    .await
}

pub(crate) async fn vault_campaign_compliance_reject(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ComplianceApprovalRequest,
) -> Listed<ComplianceReceipt> {
    const VERB: &str = "vault.campaign.compliance.reject";
    credential_listing(server, auth, caller, VERB, move |server, auth, memory| {
        memory.compliance_reject_as(&owner_proof(auth, server, VERB)?, &input)
    })
    .await
}

pub(crate) async fn vault_campaign_compliance_verify(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ComplianceVerifyRequest,
) -> Listed<ComplianceReceipt> {
    const VERB: &str = "vault.campaign.compliance.verify";
    credential_listing(server, auth, caller, VERB, move |server, auth, memory| {
        memory.compliance_verify_as(&owner_proof(auth, server, VERB)?, &input)
    })
    .await
}
