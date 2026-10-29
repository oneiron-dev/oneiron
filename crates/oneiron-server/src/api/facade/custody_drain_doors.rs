//! The host doors of the owner's custody member drain rows (FIX 11274; the
//! engine doors ruled 10-20, FIX 5843): `vault.custody.members.drain.begin`,
//! `vault.custody.members.drain.commit`, `vault.custody.members.drain.folder`
//! and `vault.custody.members.reenrol`. `host_doors` re-exports them, so the
//! generated HTTP facade handler and the MCP dispatcher call them by the
//! name every host door has. Each takes the vault owner's proof as
//! `/v1/owner` takes it, as `door_admits` already did before any hook ran,
//! and the engine door checks the owner again in its own read. The required
//! set lives in custody's own journal, which holds no row, so each door
//! lists none.

use std::sync::Arc;

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{
    CustodyDrainCommitRequest, CustodyDrainTicketView, CustodyMemberReenrolRequest,
    CustodyMemberRef, CustodySetRevision, custody_folder_member_drain_as,
    custody_member_drain_begin_as, custody_member_drain_commit_as, custody_member_reenrol_as,
};

use super::host_doors::support::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Runs `act` off the runtime as the vault owner `auth` proves for `verb`.
async fn as_custody_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Vault, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = tokio::task::spawn_blocking(move || act(server.vault(), &owner))
        .await
        .unwrap_or_else(|_| Err(internal(verb)));
    (answer, Vec::new())
}

/// `vault.custody.members.drain.begin`: the member is fenced and its
/// ticket returned, the drain's token in it for the member's own adapter.
pub(crate) async fn vault_custody_members_drain_begin(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CustodyMemberRef,
) -> Listed<CustodyDrainTicketView> {
    as_custody_owner(
        server,
        auth,
        "vault.custody.members.drain.begin",
        move |vault, owner| custody_member_drain_begin_as(vault, owner, input),
    )
    .await
}

/// `vault.custody.members.drain.commit`: the member leaves the set on its
/// ack.
pub(crate) async fn vault_custody_members_drain_commit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CustodyDrainCommitRequest,
) -> Listed<CustodySetRevision> {
    as_custody_owner(
        server,
        auth,
        "vault.custody.members.drain.commit",
        move |vault, owner| custody_member_drain_commit_as(vault, owner, input),
    )
    .await
}

/// `vault.custody.members.drain.folder`: this install drains a folder
/// member as its adapter.
pub(crate) async fn vault_custody_members_drain_folder(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CustodyMemberRef,
) -> Listed<CustodySetRevision> {
    as_custody_owner(
        server,
        auth,
        "vault.custody.members.drain.folder",
        move |vault, owner| custody_folder_member_drain_as(vault, owner, input),
    )
    .await
}

/// `vault.custody.members.reenrol`: a drained member comes back at the
/// next revision.
pub(crate) async fn vault_custody_members_reenrol(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CustodyMemberReenrolRequest,
) -> Listed<CustodySetRevision> {
    as_custody_owner(
        server,
        auth,
        "vault.custody.members.reenrol",
        move |vault, owner| custody_member_reenrol_as(vault, owner, input),
    )
    .await
}
