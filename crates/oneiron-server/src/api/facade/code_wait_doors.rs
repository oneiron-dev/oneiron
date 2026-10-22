//! Credential-bound host projections of the typed code consent wait doors
//! (DOOR-079): answer one exact sealed wait, and read it with its answer,
//! settlement and replay-consumption receipts. HTTP, SDK, MCP and code mode
//! all take the owner's proof here, from whichever surface the owner is
//! authenticated on, through the gate `door_admits` runs before any hook;
//! the engine door revalidates it and acts as that caller. No effect,
//! reply, grant or table read is made here.
use std::sync::Arc;

use oneiron::memory::code_wait_doors::{
    CodeWaitReceiptRequest, CodeWaitReceiptView, CodeWaitResolveRequest,
};

use super::host_doors::Listed;
use super::host_doors::support::owner_listing::as_owner;
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
    as_owner(server, auth, RESOLVE_VERB, move |memory, owner| {
        memory.code_wait_resolve_as(owner, input)
    })
    .await
}

pub(crate) async fn vault_code_waits_receipt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeWaitReceiptRequest,
) -> Listed<Option<CodeWaitReceiptView>> {
    as_owner(server, auth, RECEIPT_VERB, move |memory, owner| {
        memory.code_wait_receipt_as(owner, input)
    })
    .await
}
