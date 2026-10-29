//! The usage repair doors (FIX 6476): the stored usage events of this
//! server's metering scope that no longer decode, the removal of one
//! reviewed row by the hash of its bytes, and the receipts those removals
//! kept (FIX 7036). HTTP, MCP and the SDK reach the
//! engine writer the owner's routes reach, which admits the caller's own
//! owner proof or an agent's own Grant that names the verb, in the write
//! itself. The scope is the vault this server's meter is bound to, never a
//! caller's: every billing owner's rows in it, the vault owner's and each
//! room-paid payer account's (FIX 7035). The answers derive from host rows,
//! which are no entity's: the doors list none.

use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::usage_repair::{
    UndecodableUsageList, UsageRepairListRequest, UsageRepairReceipt, UsageRepairReceiptList,
    UsageRepairReceiptsRequest, UsageRepairRemoveRequest, UsageRepairVerb,
};
use oneiron::memory::{Memory, MemoryResult};

use super::FacadeApiError;
use super::host_doors::support::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use crate::usage::UsageScope;

/// `act` off the runtime on the caller's own handle, with the caller's own
/// owner proof when its credential is owner-grade and none otherwise, and
/// this server's metering scope.
async fn repair<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: UsageRepairVerb,
    act: impl FnOnce(
        &SyncServer,
        Memory<'_>,
        Option<&AuthenticatedOwner>,
        Option<&UsageScope>,
    ) -> MemoryResult<T>
    + Send
    + 'static,
) -> Listed<T> {
    let caller = match super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)
    {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    let owner = if auth.is_owner_grade() {
        match owner_proof(auth, server, verb.name()) {
            Ok(owner) => Some(owner),
            Err(error) => return (Err(error), Vec::new()),
        }
    } else {
        None
    };
    let scope = UsageScope::of(server);
    credential_listing(
        server,
        auth,
        caller,
        verb.name(),
        move |server, _, memory| act(server, memory, owner.as_ref(), scope.as_ref()),
    )
    .await
}

/// The usage repair rows' early authority check (FIX 7039): the caller
/// [`repair`] acts as, and its writer's own admission of it for `verb`
/// (the owner's own proof on an owner-grade credential, else an agent's own
/// Grant that names the verb), judged before the row's verb hooks fire. The
/// writer admits the caller again when it acts.
pub(super) fn repair_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: UsageRepairVerb,
) -> MemoryResult<()> {
    let (actor, class) =
        super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
    let owner = if auth.is_owner_grade() {
        Some(owner_proof(auth, server, verb.name())?)
    } else {
        None
    };
    crate::api::credential_memory(&server.vault, Some(auth), actor, class)
        .at(auth.locality())
        .usage_repair_admits(owner.as_ref(), verb)
}

/// `vault.usage.events.undecodable`: every stored usage event of the
/// metering scope that does not decode, by its row ref, length and hash.
pub(crate) async fn vault_usage_events_undecodable(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: UsageRepairListRequest,
) -> Listed<UndecodableUsageList> {
    repair(
        server,
        auth,
        UsageRepairVerb::List,
        |server, memory, owner, scope| {
            server
                .usage_ledger
                .list_undecodable_events(&memory, owner, scope)
        },
    )
    .await
}

/// `vault.usage.events.remove_undecodable`: removes one listed row while it
/// still holds the reviewed bytes and still does not decode, and answers
/// the receipt kept in the same write. `surface` is where the call reached
/// this install, for the receipt alone.
pub(crate) async fn vault_usage_events_remove_undecodable(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: UsageRepairRemoveRequest,
) -> Listed<UsageRepairReceipt> {
    repair(
        server,
        auth,
        UsageRepairVerb::Remove,
        move |server, memory, owner, scope| {
            server
                .usage_ledger
                .remove_undecodable_event(&memory, owner, scope, surface, &input)
        },
    )
    .await
}

/// `vault.usage.repair.receipts` (FIX 7036): every receipt a removal kept for
/// the metering scope, under the repair's own admission for this verb.
pub(crate) async fn vault_usage_repair_receipts(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: UsageRepairReceiptsRequest,
) -> Listed<UsageRepairReceiptList> {
    repair(
        server,
        auth,
        UsageRepairVerb::Receipts,
        |server, memory, owner, scope| {
            server
                .usage_ledger
                .list_repair_receipts(&memory, owner, scope)
        },
    )
    .await
}
