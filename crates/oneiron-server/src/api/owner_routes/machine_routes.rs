//! `/v1/owner/machines`: the owner's answer for each of his linked machines
//! (mesh PR1b). He marks a machine yours, work or school, or rented, re-marks
//! it, or removes it, from any surface where he is authenticated: one of his
//! machines, a linked work, school or rented machine, or the hosted console
//! (the owner's ruling, 10-19: "it doesn't matter where you said yes, if you
//! said so"). This server's install carries his act under its own live
//! profile, so the answer holds on every replica before and after the owner
//! anchor. A hosted operator's root acts as nobody (FIX 2222): `owner()`
//! refuses it before any answer is written.
//!
//! Each change names the machine's revision the surface showed the owner
//! (`seen`, from `GET /machines/answer`); a stale one is a conflict, never a
//! silent overwrite.
//!
//! `/machines/held` is the owner's list of the carried answers that wait for
//! his confirm (row CARRIER-OWNER-PROOF): each needed an owner key's proof
//! and carried none. He confirms the ones he names on an install that holds
//! his key, and dismisses an ask on this install alone.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::authority::{
    ActSurface, AuthorityFold, FoldedMachine, HeldAnswerListing, MachineOwnership, MachineRole,
    OwnerDeviceRenewalProof, PeerMachine,
};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/machines/answer",
                summary: "One machine's answer (`?machine=<id>`): its role, the carrier of the owner's standing answer, and the revision a surface presents back as seen.",
                row: None,
                shape: None,
            },
            get(get_answer),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/machines/answer",
                summary: "The owner marks or re-marks one of his machines yours, work or school, or rented, from any linked surface; a stale seen is a conflict.",
                row: None,
                shape: Some(RestShape::json(
                    set_answer_body_schema,
                    machine_answer_schema,
                )),
            },
            post(set_answer),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/machines/remove",
                summary: "The owner removes one of his machines, terminally; a stale seen is a conflict.",
                row: None,
                shape: Some(RestShape::json(
                    remove_machine_body_schema,
                    machine_answer_schema,
                )),
            },
            post(remove),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/machines/held",
                summary: "The carried machine answers that wait for the owner's confirm, each with its carrier and whether he dismissed it here, the owner choices that wait, and whether this install can confirm.",
                row: None,
                shape: None,
            },
            get(get_held),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/machines/held/confirm",
                summary: "The owner confirms the held machine answers he names, on an install that holds his key: all of them stand or nothing is written; a named entry that no longer asks is a conflict.",
                row: None,
                shape: Some(RestShape::json(
                    held_entries_body_schema,
                    held_answers_schema,
                )),
            },
            post(confirm_held),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/machines/held/dismiss",
                summary: "The owner dismisses the ask of the held machine answers he names, on this install alone: each stays held, and his other devices still ask.",
                row: None,
                shape: Some(RestShape::json(
                    held_entries_body_schema,
                    held_answers_schema,
                )),
            },
            post(dismiss_held),
        ),
    ]
}

/// Where the owner's say-so reached this install, for the act's audit and
/// receipts only: no rule reads it. The hosted console behind his
/// supervisor's `ManagedOwnerAction`; a linked machine that proved itself on
/// this very request; else this install's own surface (its host action, its
/// CLI or its app). The machine proof is the one the binding door kept for
/// this caller's slip in `extensions` (FIX 6160), never read from the
/// headers again, where it kept one; the headers' on any other request
/// (FIX 6340: every door reads it here). A missing or malformed proof is
/// this install.
pub(crate) fn act_surface_admitted(
    server: &SyncServer,
    auth: &CoreAuth,
    headers: &HeaderMap,
    extensions: &Extensions,
) -> ActSurface {
    surface_of(server, auth, || {
        auth.machine_proof_admitted(headers, extensions)
    })
}

/// [`act_surface`]'s answer, with the machine proof `machine` reads, read
/// only once the caller is not the hosted console's.
fn surface_of(
    server: &SyncServer,
    auth: &CoreAuth,
    machine: impl FnOnce() -> Option<OwnerDeviceRenewalProof>,
) -> ActSurface {
    if auth.managed_owner().is_some() {
        return ActSurface::HostedConsole;
    }
    let Some(proof) = machine() else {
        return ActSurface::ThisInstall;
    };
    match server.vault().verify_machine_connection_proof(
        proof.machine,
        &proof.signature,
        &proof.token,
        proof.timestamp,
        &proof.nonce,
    ) {
        Ok(PeerMachine::Proven { machine, .. }) => ActSurface::LinkedDevice { machine },
        _ => ActSurface::ThisInstall,
    }
}

/// A revision as a surface shows it: 64 lower-case hex.
pub(crate) fn revision_hex(revision: &[u8; 32]) -> String {
    revision.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The revision a surface presented: 64 lower-case hex.
pub(crate) fn parse_revision(field: &str, value: &str) -> OwnerResult<[u8; 32]> {
    let refused = || OwnerError::Invalid(format!("{field} must be 64 lower-case hex"));
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refused());
    }
    let mut out = [0; 32];
    for (slot, pair) in out.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| refused())?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| refused())?;
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineQuery {
    /// The MACHINE row, as 32 hex.
    machine: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SetAnswer {
    /// The MACHINE row, as 32 hex.
    machine: String,
    /// The owner's answer: `yours`, `work_school` or `rented`. Only `yours`
    /// makes it one of his for his recipient choices.
    answer: MachineOwnership,
    /// The machine's revision the surface showed the owner, as 64 hex; none
    /// takes the current one.
    #[serde(default)]
    seen: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RemoveMachine {
    /// The MACHINE row, as 32 hex.
    machine: String,
    /// As for an answer.
    #[serde(default)]
    seen: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct MachineAnswer {
    machine: String,
    /// The roster chain's role: `yours`, `work_school`, `rented`,
    /// `hosted_node`, `execution_node`, `removed` or `unanswered` (an install
    /// that serves the vault and carries the owner's acts, until he answers
    /// whose it is with this route's POST).
    role: Option<&'static str>,
    /// The machine's revision, to present back as `seen`.
    revision: String,
    /// The machine whose install key carried the owner's latest standing
    /// answer, as hex; none for a bootstrap or anchor revision.
    carrier: Option<String>,
    /// The carried answers about this machine that wait for the owner's
    /// confirm on an owner device: each needed an owner key's proof and
    /// carried none, so it stands for nothing and `role` above is unchanged
    /// by it. An answer or a removal this install just carried with no owner
    /// key is listed here. Absent when none waits.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    held: Vec<HeldMachineAnswer>,
}

/// One answer about a machine that waits for the owner's confirm.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct HeldMachineAnswer {
    /// The held answer's log entry, as 64 hex.
    entry: String,
    /// The role it asks for, as `role` names them.
    role: &'static str,
    /// The machine key it names, 64 lower hex: the key the owner checks
    /// against the one the machine itself shows. The machine's proof binds
    /// its encryption key to this key.
    machine_key: String,
    /// Whether it names other keys than the machine stands under. The
    /// confirm route refuses such an answer.
    replaces_keys: bool,
    /// The machine whose install key carried it, as hex.
    carrier: Option<String>,
}

/// A role as the wire names it.
fn role_name(role: MachineRole) -> &'static str {
    match role {
        MachineRole::Owned(MachineOwnership::Yours) => "yours",
        MachineRole::Owned(MachineOwnership::WorkSchool) => "work_school",
        MachineRole::Owned(MachineOwnership::Rented) => "rented",
        MachineRole::HostedNode => "hosted_node",
        MachineRole::ExecutionNode => "execution_node",
        MachineRole::Removed => "removed",
        MachineRole::Unanswered => "unanswered",
    }
}

/// One machine's answer as `fold` holds it, with the answers about it that
/// still wait for the owner's confirm.
fn answer_of(machine: oneiron::EntityId, fold: &AuthorityFold) -> MachineAnswer {
    let folded = fold.machine(machine);
    let roster = folded.and_then(|folded| folded.roster.as_ref());
    let held = fold
        .held_machine_answers()
        .get(&machine)
        .into_iter()
        .flatten()
        .map(|(entry, answer)| HeldMachineAnswer {
            entry: revision_hex(entry),
            role: role_name(answer.profile.role),
            machine_key: revision_hex(&answer.profile.machine_key),
            replaces_keys: fold.replaces_standing_keys(&answer.profile),
            carrier: answer.carrier().map(|carrier| carrier.to_hex()),
        })
        .collect();
    MachineAnswer {
        machine: machine.to_hex(),
        role: roster.map(|roster| role_name(roster.profile.role)),
        revision: revision_hex(&folded.map_or([0; 32], FoldedMachine::answer_revision)),
        carrier: roster
            .and_then(oneiron::authority::MachineRevision::carrier)
            .map(|carrier| carrier.to_hex()),
        held,
    }
}

/// `GET /v1/owner/machines/answer?machine=<id>`: one machine's answer and its
/// revision, and the answers about it that wait for the owner's confirm. A
/// machine no revision names answers role null and the zero revision.
async fn get_answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<MachineQuery>, QueryRejection>,
) -> OwnerReply<MachineAnswer> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let answer = blocking(move || -> OwnerResult<MachineAnswer> {
        let machine = entity_id("machine", &query.machine)?;
        let fold = server.vault().authority_fold()?;
        Ok(answer_of(machine, &fold))
    })
    .await?;
    Ok(Json(answer))
}

/// The OpenAPI schema of `POST /v1/owner/machines/answer`'s body (FIX 11617): [`SetAnswer`].
pub(crate) fn set_answer_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SetAnswer>()
}

/// The OpenAPI schema of `POST /v1/owner/machines/remove`'s body (FIX 11617): [`RemoveMachine`].
pub(crate) fn remove_machine_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RemoveMachine>()
}

/// The OpenAPI schema of the machines answer/remove answers (FIX 11617): [`MachineAnswer`].
pub(crate) fn machine_answer_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<MachineAnswer>()
}

/// `POST /v1/owner/machines/answer`: the owner marks or re-marks one of his
/// machines. A role change between linked roles takes no carrier power away.
/// On an install that holds no owner key, an answer that needs the owner's
/// proof is stored and held: the reply lists it under `held` and the role is
/// unchanged, until he confirms it on an owner device.
async fn set_answer(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<SetAnswer>,
) -> OwnerReply<MachineAnswer> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let answer = blocking(move || -> OwnerResult<MachineAnswer> {
        let machine = entity_id("machine", &request.machine)?;
        let seen = request
            .seen
            .as_deref()
            .map(|seen| parse_revision("seen", seen))
            .transpose()?;
        server.vault().set_machine_role(
            &owner,
            surface,
            machine,
            MachineRole::Owned(request.answer),
            seen,
        )?;
        Ok(answer_of(machine, &server.vault().authority_fold()?))
    })
    .await?;
    Ok(Json(answer))
}

/// `POST /v1/owner/machines/remove`: the owner removes one of his machines.
/// Removal is terminal, and it is the one answer that takes the machine's
/// carrier power away: an act it carried that the removal saw keeps its
/// effect. A removal held for the owner's proof removes nothing yet, so the
/// machine's mesh pairing and grants stay until he confirms it.
async fn remove(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<RemoveMachine>,
) -> OwnerReply<MachineAnswer> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let answer = blocking(move || -> OwnerResult<MachineAnswer> {
        let machine = entity_id("machine", &request.machine)?;
        let seen = request
            .seen
            .as_deref()
            .map(|seen| parse_revision("seen", seen))
            .transpose()?;
        let landing = server.vault().set_machine_role(
            &owner,
            surface,
            machine,
            MachineRole::Removed,
            seen,
        )?;
        if landing.held().is_none() {
            revoke_removed_mesh(&server, machine);
        }
        Ok(answer_of(machine, &server.vault().authority_fold()?))
    })
    .await?;
    Ok(Json(answer))
}

/// The removed MACHINE's mesh pairing and grants are revoked in the log as
/// well (FIX 3374, L02 04:5x); its binding admits nothing already, so a
/// revocation that fails is logged.
fn revoke_removed_mesh(server: &SyncServer, machine: oneiron::EntityId) {
    crate::api::pairing::with_host_issuer(server, |issuer| {
        if let Some(issuer) = issuer
            && let Err(error) = server.vault().revoke_removed_machine_mesh(issuer, machine)
        {
            tracing::warn!(%error, "machine removal: its mesh grants were not revoked");
        }
    });
}

/// The held answers a confirm or a dismissal names.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct HeldEntries {
    /// The held answers' log entries as `GET /machines/held` listed them,
    /// each as 64 hex.
    entries: Vec<String>,
}

impl HeldEntries {
    /// The entries as the log names them.
    fn parsed(&self) -> OwnerResult<Vec<[u8; 32]>> {
        self.entries
            .iter()
            .map(|entry| parse_revision("entries", entry))
            .collect()
    }
}

/// The owner's acts that wait for his proof, as this install lists them.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct HeldAnswers {
    /// Each carried machine answer that still asks the owner. It stands for
    /// nothing until he confirms it.
    answers: Vec<ListedHeldAnswer>,
    /// Each owner choice that waits for his proof and still asks, by its
    /// log entry as 64 hex. He confirms one by making the choice again on an
    /// owner device.
    waiting_choices: Vec<String>,
    /// Whether this install holds an owner key, so a confirm here is proven.
    /// Where it is false, the confirm route refuses: confirm on an owner
    /// device.
    can_confirm: bool,
}

/// One held machine answer in the owner's list.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ListedHeldAnswer {
    /// The held answer's log entry, as 64 hex: what a confirm or a dismissal
    /// names.
    entry: String,
    /// The MACHINE row the answer is about, as hex.
    machine: String,
    /// The role it asks for, as `role` names them on `/machines/answer`.
    role: &'static str,
    /// The class the machine declares: `phone` or `computer`.
    device_class: &'static str,
    /// The machine key the answer names, 64 lower hex: the key the owner
    /// checks against the one the machine itself shows. The machine's proof
    /// binds its encryption key to this key.
    machine_key: String,
    /// Whether the answer names other keys than the machine stands under.
    /// The confirm route refuses such an answer: no route writes one, so
    /// its keys are its carrier's word alone. Dismiss it.
    replaces_keys: bool,
    /// The role the machine stands in now; none when no revision names it.
    standing: Option<&'static str>,
    /// The machine whose install key carried the answer, as hex.
    carrier: Option<String>,
    /// The role the carrier stands in; none when no revision names it.
    carrier_role: Option<&'static str>,
    /// Whether this install trusts the carrier as one of the owner's
    /// machines.
    carrier_is_yours: bool,
    /// Whether the owner dismissed this ask on this install.
    dismissed: bool,
}

/// The list as the wire spells it.
fn held_answers_of(listing: &HeldAnswerListing) -> HeldAnswers {
    HeldAnswers {
        answers: listing
            .answers
            .iter()
            .map(|listed| ListedHeldAnswer {
                entry: revision_hex(&listed.entry),
                machine: listed.answer.profile.machine.to_hex(),
                role: role_name(listed.answer.profile.role),
                device_class: listed.answer.profile.device_class.wire(),
                machine_key: revision_hex(&listed.answer.profile.machine_key),
                replaces_keys: listed.replaces_keys,
                standing: listed.standing.map(role_name),
                carrier: listed.answer.carrier().map(|carrier| carrier.to_hex()),
                carrier_role: listed.carrier_role.map(role_name),
                carrier_is_yours: listed.carrier_is_mine,
                dismissed: listed.dismissed,
            })
            .collect(),
        waiting_choices: listing.waiting_choices.iter().map(revision_hex).collect(),
        can_confirm: listing.can_confirm,
    }
}

/// The OpenAPI schema of the held confirm and dismiss bodies: [`HeldEntries`].
pub(crate) fn held_entries_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<HeldEntries>()
}

/// The OpenAPI schema of the held confirm and dismiss answers: [`HeldAnswers`].
pub(crate) fn held_answers_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<HeldAnswers>()
}

/// `GET /v1/owner/machines/held`: the carried machine answers that wait for
/// the owner's confirm, and the owner choices that wait.
async fn get_held(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<HeldAnswers> {
    let owner = owner(&auth, &server)?;
    let held = blocking(move || -> OwnerResult<HeldAnswers> {
        let listing = server.vault().held_machine_answers(&owner)?;
        Ok(held_answers_of(&listing))
    })
    .await?;
    Ok(Json(held))
}

/// `POST /v1/owner/machines/held/confirm`: the owner confirms the held
/// answers he names. Each becomes his own proven answer about its machine,
/// in one transaction. On an install that holds no owner key it refuses
/// before it writes (409, state `owner_key_required`): a confirm promises a
/// proven answer. A confirmed removal revokes the machine's mesh pairing and
/// grants, as `/machines/remove` does.
async fn confirm_held(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<HeldEntries>,
) -> OwnerReply<HeldAnswers> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let held = blocking(move || -> OwnerResult<HeldAnswers> {
        let confirmed =
            server
                .vault()
                .confirm_held_machine_answers(&owner, surface, &request.parsed()?)?;
        for machine in &confirmed.removed {
            revoke_removed_mesh(&server, *machine);
        }
        Ok(held_answers_of(&confirmed.listing))
    })
    .await?;
    Ok(Json(held))
}

/// `POST /v1/owner/machines/held/dismiss`: the owner dismisses the ask of
/// the held answers he names, on this install alone. Nothing is written to
/// the log: each answer stays held, and his other devices still ask.
async fn dismiss_held(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<HeldEntries>,
) -> OwnerReply<HeldAnswers> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let held = blocking(move || -> OwnerResult<HeldAnswers> {
        let listing = server
            .vault()
            .dismiss_held_machine_answers(&owner, &request.parsed()?)?;
        Ok(held_answers_of(&listing))
    })
    .await?;
    Ok(Json(held))
}
