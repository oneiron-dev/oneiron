//! The host doors of the shared-vault rows (OF-158): the acts the shared
//! preset waits on (`vault.shared.*`), the membership changes that never wait
//! (`vault.members.*`) and the owner's fork alarms
//! (`vault.authority.handoff_alarms*`). `host_doors` re-exports them, so the
//! generated HTTP facade handler and the MCP dispatcher call them by the name
//! every host door has, and a tool call, a code-mode call and an SDK call
//! meet one admission.
//!
//! Each door hands the engine what its fn asks for, and no check of its own:
//! - a person's proof, where the engine admits a live person and its own
//!   roster check decides (`revalidate_person_in_txn`): an act's starter or
//!   executor, an Admin's named membership power, a member's own leave, a
//!   holder's receipts and notices;
//! - the owner's proof (`owner_routes::owner`), where the alarm is the
//!   vault owner's, as `/v1/owner/authority/handoff-alarms` takes it;
//! - the host's slip issuer (`api/pairing.rs`'s), wherever the engine revokes
//!   the slips of whoever lost a role or signs an owner handover;
//! - nothing, for the deletion marker the engine reads for anyone.
use std::sync::Arc;

use oneiron::authority::{AuthorityHandoffAlarm, HostSlipIssuer};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    PendingAuthorityAct, SharedActExecutionReceipt, SharedActOutcome, SharedVaultDeletion,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{
    self, EmptyRequest, HandoffAlarmRequest, SharedActExecuted, SharedActRequest,
    SharedMemberAddRequest, SharedMemberRequest, SharedMemberRoleRequest, SharedReceiptRequest,
    SharedRemoveOwnerRequest, SharedTransferRequest, SharedVaultRequest,
};

use super::host_doors::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The proof of the person this request authenticates as. An owner of the
/// vault gets the owner's proof bound to their slip, which the engine
/// rechecks in the acting writer; any other person gets their own proof from
/// their verified human slip, and the engine's roster, power and role checks
/// decide. A managed vault is owned through its supervisor and refuses, as
/// `/v1/owner` does there.
fn person(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<AuthenticatedOwner> {
    if let Ok(owner) = crate::api::owner_routes::owner(auth, server) {
        return Ok(owner);
    }
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is a live person's own act"),
            &["Present your own verified human credential."],
        )
    };
    if server.managed_issuer.is_some() {
        return Err(refused());
    }
    let slip = auth
        .verified_slip()
        .filter(|_| auth.actor_class() == Some("human"))
        .ok_or_else(refused)?;
    let principal = auth.principal_ref().ok_or_else(refused)?;
    let actor = oneiron::EntityId::from_hex(principal).map_err(|_| refused())?;
    // The slip is the person's own, as the owner's bound proof requires.
    if slip.claims().holder_ref != actor.to_hex() {
        return Err(refused());
    }
    server
        .vault()
        .authenticate_owner(actor, principal, true, GateDecisionId::now())
        .map_err(|_| refused())
}

/// The vault owner's proof, as `/v1/owner` takes it from the request.
fn owner_proof(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })
}

/// `act` under the host's slip issuer, the one `api/pairing.rs` builds for
/// its own slip doors.
fn with_slips<T>(
    server: &SyncServer,
    verb: &str,
    act: impl FnOnce(&HostSlipIssuer) -> MemoryResult<T>,
) -> MemoryResult<T> {
    crate::api::pairing::with_issuer(server, |issuer| Ok(act(issuer)))
        .map_err(|_| internal(verb))?
}

/// `act` off the runtime: every engine door here reads or writes LMDB.
async fn off_runtime<T: Send + 'static>(
    server: &Arc<SyncServer>,
    verb: &'static str,
    act: impl FnOnce(&Arc<SyncServer>) -> MemoryResult<T> + Send + 'static,
) -> MemoryResult<T> {
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || act(&server))
        .await
        .map_err(|_| internal(verb))?
}

/// `vault.shared.propose_delete`: start the vault's `delete_vault` act.
pub(crate) async fn vault_shared_propose_delete(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MemoryResult<PendingAuthorityAct> {
    const VERB: &str = "vault.shared.propose_delete";
    let starter = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::propose_shared_delete(server.vault(), &starter, input)
    })
    .await
}

/// `vault.shared.propose_transfer`: start a `transfer_ownership` act.
pub(crate) async fn vault_shared_propose_transfer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedTransferRequest,
) -> MemoryResult<PendingAuthorityAct> {
    const VERB: &str = "vault.shared.propose_transfer";
    let starter = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::propose_shared_transfer(server.vault(), &starter, input)
    })
    .await
}

/// `vault.shared.propose_remove_owner`: start a `remove_owner` act, with its
/// "export first?" answer.
pub(crate) async fn vault_shared_propose_remove_owner(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedRemoveOwnerRequest,
) -> MemoryResult<PendingAuthorityAct> {
    const VERB: &str = "vault.shared.propose_remove_owner";
    let starter = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::propose_shared_remove_owner(server.vault(), &starter, input)
    })
    .await
}

/// `vault.shared.execute`: a live Owner runs a matured act, with the host's
/// slip issuer.
pub(crate) async fn vault_shared_execute(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedActRequest,
) -> MemoryResult<SharedActExecuted> {
    const VERB: &str = "vault.shared.execute";
    let executor = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        with_slips(server, VERB, |slips| {
            sdk::execute_shared_act(server.vault(), &executor, Some(slips), input)
        })
    })
    .await
}

/// `vault.shared.receipt`: a receipt its reader was told about.
pub(crate) async fn vault_shared_receipt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedReceiptRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    const VERB: &str = "vault.shared.receipt";
    let reader = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::read_shared_receipt(server.vault(), &reader, input)
    })
    .await
}

/// `vault.shared.outcomes`: the reader's own outcome notices.
pub(crate) async fn vault_shared_outcomes(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MemoryResult<Vec<SharedActOutcome>> {
    const VERB: &str = "vault.shared.outcomes";
    let reader = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::read_shared_outcomes(server.vault(), &reader, input)
    })
    .await
}

/// `vault.shared.deletion`: the executed delete-the-vault act, if any. The
/// engine reads it for anyone.
pub(crate) async fn vault_shared_deletion(
    server: &Arc<SyncServer>,
    _auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<Option<SharedVaultDeletion>> {
    off_runtime(server, "vault.shared.deletion", |server| {
        sdk::read_shared_deletion(server.vault())
    })
    .await
}

/// `vault.members.add`: an Admin's `add_member` power, checked by the engine
/// against the live roster.
pub(crate) async fn vault_members_add(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedMemberAddRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.add";
    let admin = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::add_shared_member_as(server.vault(), &admin, input)
    })
    .await
}

/// `vault.members.change`: an Admin's `assign_role` power, with the host's
/// slip issuer for a lowered role.
pub(crate) async fn vault_members_change(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedMemberRoleRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.change";
    let admin = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        with_slips(server, VERB, |slips| {
            sdk::change_shared_member_as(server.vault(), &admin, Some(slips), input)
        })
    })
    .await
}

/// `vault.members.remove`: an Admin's `remove_member` power, with the host's
/// slip issuer.
pub(crate) async fn vault_members_remove(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedMemberRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.remove";
    let admin = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        with_slips(server, VERB, |slips| {
            sdk::remove_shared_member_as(server.vault(), &admin, Some(slips), input)
        })
    })
    .await
}

/// `vault.members.leave`: a member's own leave, under their own proof; the
/// engine refuses an Owner, who leaves through `remove_owner`.
pub(crate) async fn vault_members_leave(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.leave";
    let member = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        with_slips(server, VERB, |slips| {
            sdk::leave_shared_vault_as(server.vault(), &member, Some(slips), input)
        })
    })
    .await
}

/// `vault.authority.handoff_alarms`: every saved fork alarm, for the owner.
pub(crate) async fn vault_authority_handoff_alarms(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<Vec<AuthorityHandoffAlarm>> {
    const VERB: &str = "vault.authority.handoff_alarms";
    let owner = owner_proof(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::read_handoff_alarms(server.vault(), &owner)
    })
    .await
}

/// `vault.authority.handoff_alarms.acknowledge`: the owner has seen one alarm.
pub(crate) async fn vault_authority_handoff_alarms_acknowledge(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HandoffAlarmRequest,
) -> MemoryResult<AuthorityHandoffAlarm> {
    const VERB: &str = "vault.authority.handoff_alarms.acknowledge";
    let owner = owner_proof(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::acknowledge_handoff_alarm(server.vault(), &owner, input)
    })
    .await
}
