//! Typed critical-claim confirmations under the same owner proof as claim settlement.
use std::sync::Arc;

use oneiron::memory::{
    CriticalWriteConfirmAnswer, CriticalWriteConfirmPending, CriticalWriteConfirmPendingRequest,
    CriticalWriteConfirmReceipt, CriticalWriteConfirmReceiptRequest, CriticalWriteConfirmRequest,
    CriticalWriteConfirmSettlement, MemoryResult,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, credential_listing, internal, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_writes_critical_confirm_pending(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: CriticalWriteConfirmPendingRequest,
) -> Listed<Option<CriticalWriteConfirmPending>> {
    const VERB: &str = "vault.writes.critical_confirm.pending";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.critical_write_confirm_pending_as_owner(&owner, &input)
    })
    .await
}

pub(crate) async fn vault_writes_critical_confirm_clear(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: CriticalWriteConfirmRequest,
) -> Listed<CriticalWriteConfirmSettlement> {
    answer(
        server,
        auth,
        caller,
        input,
        CriticalWriteConfirmAnswer::Clear,
    )
    .await
}

pub(crate) async fn vault_writes_critical_confirm_decline(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: CriticalWriteConfirmRequest,
) -> Listed<CriticalWriteConfirmSettlement> {
    answer(
        server,
        auth,
        caller,
        input,
        CriticalWriteConfirmAnswer::Decline,
    )
    .await
}

async fn answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    input: CriticalWriteConfirmRequest,
    disposition: CriticalWriteConfirmAnswer,
) -> Listed<CriticalWriteConfirmSettlement> {
    let verb = match disposition {
        CriticalWriteConfirmAnswer::Clear => "vault.writes.critical_confirm.clear",
        CriticalWriteConfirmAnswer::Decline => "vault.writes.critical_confirm.decline",
    };
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, verb, move |server, _, memory| {
        crate::api::pairing::with_issuer(server, |issuer| {
            Ok(match disposition {
                CriticalWriteConfirmAnswer::Clear => {
                    memory.critical_write_confirm_clear_as_owner(&owner, issuer, &input)
                }
                CriticalWriteConfirmAnswer::Decline => {
                    memory.critical_write_confirm_decline_as_owner(&owner, issuer, &input)
                }
            })
        })
        .map_err(|_| internal(verb))?
    })
    .await
}

pub(crate) async fn vault_writes_critical_confirm_receipt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: CriticalWriteConfirmReceiptRequest,
) -> Listed<CriticalWriteConfirmReceipt> {
    const VERB: &str = "vault.writes.critical_confirm.receipt";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.critical_write_confirm_receipt_as_owner(&owner, &input)
    })
    .await
}
