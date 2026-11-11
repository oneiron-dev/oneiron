//! Credential-bound host projections of the typed code consent wait doors
//! (DOOR-079): answer one exact sealed wait, and read it with its answer,
//! settlement and replay-consumption receipts. HTTP, SDK, MCP and code mode
//! take the request's native Owner or person proof through `door_admits`
//! before any hook. The engine requires current Owner authority or the wait's
//! settlement policy and action power, and acts as that caller. No effect,
//! reply, grant or table read is made here.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::code_wait_doors::{
    CodeWaitRebindReceipt, CodeWaitRebindRequest, CodeWaitReceiptRequest, CodeWaitReceiptView,
    CodeWaitResolveRequest,
};
use oneiron::memory::{Memory, MemoryError, MemoryResult};

use super::FacadeApiError;
use super::host_doors::support::owner_listing::as_owner;
use super::host_doors::support::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The answer door's public spelling.
const RESOLVE_VERB: &str = "vault.code.waits.resolve";

/// The receipt door's public spelling.
const RECEIPT_VERB: &str = "vault.code.waits.receipt";

pub(crate) async fn vault_code_waits_resolve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeWaitResolveRequest,
) -> Listed<CodeWaitReceiptView> {
    as_person(server, auth, RESOLVE_VERB, move |memory, owner| {
        memory.code_wait_resolve_as(owner, input)
    })
    .await
}

pub(crate) async fn vault_code_waits_receipt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeWaitReceiptRequest,
) -> Listed<Option<CodeWaitReceiptView>> {
    as_person(server, auth, RECEIPT_VERB, move |memory, owner| {
        memory.code_wait_receipt_as(owner, input)
    })
    .await
}

/// The separate owner act, never a substitute for the holder's prepared witness.
pub(crate) async fn vault_code_waits_rebind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeWaitRebindRequest,
) -> Listed<CodeWaitRebindReceipt> {
    as_owner(
        server,
        auth,
        "vault.code.waits.rebind",
        move |memory, owner| memory.code_wait_rebind_as(owner, input),
    )
    .await
}

async fn as_person<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Memory<'_>, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let admitted = || {
        let person = if let Ok(owner) = owner_proof(auth, server, verb) {
            owner
        } else {
            let person = super::shared_act_doors::person(server, auth, verb)?;
            // A fallback slip stays person-tier even when its person owns the vault.
            if let Some(slip) = auth.verified_slip() {
                server
                    .vault()
                    .bind_person_credential(person, slip.clone())?
            } else {
                person
            }
        };
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok::<_, MemoryError>((person, caller))
    };
    let (person, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, verb, move |_, _, memory| {
        act(&memory, &person)
    })
    .await
}
