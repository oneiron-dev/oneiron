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
//! - nothing, for the deletion marker the engine reads for anyone;
//! - nothing but the host's slip issuer, for proof-of-control owner recovery,
//!   whose operator route (`api/operator_routes.rs`) checks the host's root,
//!   or a managed vault's attested account owner.
//!
//! Each row lists its rows (`host_door_lists`). An act, its objections and
//! receipt, a notice, an invitation, an erase ask and a fork alarm live in
//! the authority log and the shared-act tables, which hold no row, and an
//! act's effect reads the act, the roster and the grants its receipt names:
//! so beside its answer each lists the records it names, and none past
//! them. A receipt with a removal's export goes unlisted: no list covers the
//! records its export counted, after the first execution.
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
    SharedMemberAddRequest, SharedMemberInvited, SharedMemberRequest, SharedMemberRoleRequest,
    SharedReceiptRequest, SharedRemoveOwnerRequest, SharedTransferRequest, SharedVaultRequest,
};

use super::host_doors::{MaybeListed, internal};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The proof of the person this request authenticates as. An owner of the
/// vault gets the owner's proof bound to their slip, which the engine
/// rechecks in the acting writer; any other person gets their own proof from
/// their verified human slip, and the engine's roster, power and role checks
/// decide. On a managed vault only its owner, attested by its supervisor for
/// the request, gets a proof, through the owner door; anyone else refuses. An invitee's own slip (FIX 1925) is a person's
/// proof only at its invitation's doors (`auth::INVITEE_DOORS`).
pub(super) fn person(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    super::owner_binding::host_preflight(server, auth)?;
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
    if slip.claims().holder_ref != actor.to_hex()
        || (slip.claims().invitation_ref.is_some() && !crate::auth::INVITEE_DOORS.contains(&verb))
    {
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
    super::owner_binding::facade_owner(server, auth, verb)
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

/// [`off_runtime`] under `proof` for a door that lists its rows: beside its
/// answer, the rows `named` reads off it. A refused proof lists none.
pub(super) async fn as_person_naming<P: Send + 'static, T: Send + 'static>(
    server: &Arc<SyncServer>,
    verb: &'static str,
    proof: MemoryResult<P>,
    act: impl FnOnce(&Arc<SyncServer>, P) -> MemoryResult<T> + Send + 'static,
    named: impl FnOnce(&T) -> Option<Vec<oneiron::EntityId>>,
) -> MaybeListed<T> {
    let proof = match proof {
        Ok(proof) => proof,
        Err(refusal) => return (Err(refusal), Some(Vec::new())),
    };
    let answer = off_runtime(server, verb, move |server| act(server, proof)).await;
    let rows = answer.as_ref().map_or_else(|_| Some(Vec::new()), named);
    (answer, rows)
}

/// A receipt's rows: none past those it names, or `None` for one with a
/// removal's export, whose counted records no list names after the first
/// execution (`sdk::execute_shared_act_listing`).
pub(super) fn receipt_rows(receipt: &SharedActExecutionReceipt) -> Option<Vec<oneiron::EntityId>> {
    receipt.export.is_none().then(Vec::new)
}

/// `vault.shared.propose_delete`: start the vault's `delete_vault` act.
pub(crate) async fn vault_shared_propose_delete(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MaybeListed<PendingAuthorityAct> {
    const VERB: &str = "vault.shared.propose_delete";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, starter| sdk::propose_shared_delete(server.vault(), &starter, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.shared.propose_transfer`: start a `transfer_ownership` act.
pub(crate) async fn vault_shared_propose_transfer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedTransferRequest,
) -> MaybeListed<PendingAuthorityAct> {
    const VERB: &str = "vault.shared.propose_transfer";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, starter| sdk::propose_shared_transfer(server.vault(), &starter, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.shared.propose_remove_owner`: start a `remove_owner` act, with its
/// "export first?" answer.
pub(crate) async fn vault_shared_propose_remove_owner(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedRemoveOwnerRequest,
) -> MaybeListed<PendingAuthorityAct> {
    const VERB: &str = "vault.shared.propose_remove_owner";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, starter| sdk::propose_shared_remove_owner(server.vault(), &starter, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.shared.execute`: a live Owner runs a matured act, with the host's
/// slip issuer. Beside it, the rows it was derived from
/// ([`sdk::execute_shared_act_listing`]): `None` for an export-first
/// removal, whose receipt no list covers. A refusal before the act runs
/// lists no row.
pub(crate) async fn vault_shared_execute(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedActRequest,
) -> (
    MemoryResult<SharedActExecuted>,
    Option<Vec<oneiron::EntityId>>,
) {
    const VERB: &str = "vault.shared.execute";
    let executor = match person(server, auth, VERB) {
        Ok(executor) => executor,
        Err(refusal) => return (Err(refusal), Some(Vec::new())),
    };
    let ran = off_runtime(server, VERB, move |server| {
        with_slips(server, VERB, |slips| {
            Ok(sdk::execute_shared_act_listing(
                server.vault(),
                &executor,
                Some(slips),
                input,
            ))
        })
    })
    .await;
    ran.unwrap_or_else(|refusal| (Err(refusal), Some(Vec::new())))
}

/// `vault.shared.receipt`: a receipt its reader was told about.
pub(crate) async fn vault_shared_receipt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedReceiptRequest,
) -> MaybeListed<SharedActExecutionReceipt> {
    const VERB: &str = "vault.shared.receipt";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, reader| sdk::read_shared_receipt(server.vault(), &reader, input),
        receipt_rows,
    )
    .await
}

/// `vault.shared.outcomes`: the reader's own outcome notices.
pub(crate) async fn vault_shared_outcomes(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MaybeListed<Vec<SharedActOutcome>> {
    const VERB: &str = "vault.shared.outcomes";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, reader| sdk::read_shared_outcomes(server.vault(), &reader, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.shared.deletion`: the executed delete-the-vault act, if any. The
/// engine reads it for anyone.
pub(crate) async fn vault_shared_deletion(
    server: &Arc<SyncServer>,
    _auth: &CoreAuth,
    _input: EmptyRequest,
) -> MaybeListed<Option<SharedVaultDeletion>> {
    as_person_naming(
        server,
        "vault.shared.deletion",
        Ok(()),
        |server, ()| sdk::read_shared_deletion(server.vault()),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.members.add`: an Admin's `add_member` power, checked by the engine
/// against the live roster. Given the invitee's own device key, the host's
/// slip issuer signs the invitee's slip for the invitation (FIX 1925).
pub(crate) async fn vault_members_add(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedMemberAddRequest,
) -> MaybeListed<SharedMemberInvited> {
    const VERB: &str = "vault.members.add";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, admin| {
            if input.holder_key.is_none() {
                return sdk::add_shared_member_as(server.vault(), &admin, None, input);
            }
            with_slips(server, VERB, |slips| {
                sdk::add_shared_member_as(server.vault(), &admin, Some(slips), input)
            })
        },
        |invited| receipt_rows(&invited.receipt),
    )
    .await
}

/// `vault.members.change`: an Admin's `assign_role` power, with the host's
/// slip issuer for a lowered role.
pub(crate) async fn vault_members_change(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedMemberRoleRequest,
) -> MaybeListed<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.change";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, admin| {
            with_slips(server, VERB, |slips| {
                sdk::change_shared_member_as(server.vault(), &admin, Some(slips), input)
            })
        },
        receipt_rows,
    )
    .await
}

/// `vault.members.remove`: an Admin's `remove_member` power, with the host's
/// slip issuer.
pub(crate) async fn vault_members_remove(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedMemberRequest,
) -> MaybeListed<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.remove";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, admin| {
            with_slips(server, VERB, |slips| {
                sdk::remove_shared_member_as(server.vault(), &admin, Some(slips), input)
            })
        },
        receipt_rows,
    )
    .await
}

/// `vault.members.leave`: a member's own leave, under their own proof; the
/// engine refuses an Owner, who leaves through `remove_owner`.
pub(crate) async fn vault_members_leave(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MaybeListed<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.leave";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, member| {
            with_slips(server, VERB, |slips| {
                sdk::leave_shared_vault_as(server.vault(), &member, Some(slips), input)
            })
        },
        receipt_rows,
    )
    .await
}

/// `vault.authority.handoff_alarms`: every saved fork alarm, for the owner.
pub(crate) async fn vault_authority_handoff_alarms(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MaybeListed<Vec<AuthorityHandoffAlarm>> {
    const VERB: &str = "vault.authority.handoff_alarms";
    as_person_naming(
        server,
        VERB,
        owner_proof(server, auth, VERB),
        move |server, owner| sdk::read_handoff_alarms(server.vault(), &owner),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.authority.handoff_alarms.acknowledge`: the owner has seen one alarm.
pub(crate) async fn vault_authority_handoff_alarms_acknowledge(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HandoffAlarmRequest,
) -> MaybeListed<AuthorityHandoffAlarm> {
    const VERB: &str = "vault.authority.handoff_alarms.acknowledge";
    as_person_naming(
        server,
        VERB,
        owner_proof(server, auth, VERB),
        move |server, owner| sdk::acknowledge_handoff_alarm(server.vault(), &owner, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// Proof-of-control owner recovery (ARCH-0043, OF-163), for the host
/// operator's route alone (`/v1/operator/shared/recover-owner`): no verb row
/// reaches it, so no agent does. The operator has judged, outside the engine,
/// the claimant's proof that they control the organization owning the vault,
/// or a managed vault's attested account owner asked it as his own act.
/// The engine checks only what it holds (no live Owner left, `from` still an
/// Owner, `claimant` a live person) and signs the handover with the host's
/// slip issuer, keeping `proof` (the BLAKE3 of the judged proof note, never
/// the note) with it. It answers the receipt the membership doors answer.
pub(crate) async fn operator_recover_shared_owner(
    server: &Arc<SyncServer>,
    vault_id: u64,
    from: oneiron::EntityId,
    claimant: oneiron::EntityId,
    proof: Option<[u8; 32]>,
) -> MemoryResult<SharedActExecutionReceipt> {
    const VERB: &str = "operator.shared.recover_owner";
    off_runtime(server, VERB, move |server| {
        with_slips(server, VERB, |issuer| {
            Ok(server
                .vault()
                .recover_shared_owner_with_proof(issuer, vault_id, from, claimant, proof)?)
        })
    })
    .await
}
