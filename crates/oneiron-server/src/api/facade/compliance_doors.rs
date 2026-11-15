//! Compliance owner decisions use the request's owner proof and its own Memory.
//! Pack data and receipts are side-table state, so these doors list no record.
//! Install and reject also admit the owner's delegate, on its own Memory and
//! the setting `campaign.compliance.agent_may_decide`; approve and verify
//! stay the owner's stamp.

use super::host_doors::support::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::campaign::compliance::{
    COMPLIANCE_INSTALL_VERB, COMPLIANCE_REJECT_VERB, ComplianceAmendRequest,
    ComplianceApprovalRequest, ComplianceReceipt, ComplianceVerifyRequest,
};
use oneiron::memory::{Memory, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};
use std::sync::Arc;

/// The delegate's admission for an install or reject: the host preflight, an
/// agent caller, and a live credential, or the door's owner refusal.
fn delegate_admitted(
    server: &SyncServer,
    auth: &CoreAuth,
    memory: &Memory<'_>,
    verb: &str,
) -> MemoryResult<()> {
    super::owner_binding::host_preflight(server, auth)?;
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(super::owner_binding::owner_refusal(verb));
    }
    if !auth.credential_is_live(server.vault()) {
        return Err(super::owner_binding::credential_dead());
    }
    Ok(())
}

pub(crate) async fn vault_campaign_compliance_install(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ComplianceAmendRequest,
) -> Listed<ComplianceReceipt> {
    credential_listing(
        server,
        auth,
        caller,
        COMPLIANCE_INSTALL_VERB,
        move |server, auth, memory| {
            if auth.is_owner_grade() {
                memory.compliance_install_as(
                    &owner_proof(auth, server, COMPLIANCE_INSTALL_VERB)?,
                    &input,
                )
            } else {
                delegate_admitted(server, auth, &memory, COMPLIANCE_INSTALL_VERB)?;
                memory.compliance_install_as_delegate(&input)
            }
        },
    )
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
    credential_listing(
        server,
        auth,
        caller,
        COMPLIANCE_REJECT_VERB,
        move |server, auth, memory| {
            if auth.is_owner_grade() {
                memory.compliance_reject_as(
                    &owner_proof(auth, server, COMPLIANCE_REJECT_VERB)?,
                    &input,
                )
            } else {
                delegate_admitted(server, auth, &memory, COMPLIANCE_REJECT_VERB)?;
                memory.compliance_reject_as_delegate(&input)
            }
        },
    )
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
