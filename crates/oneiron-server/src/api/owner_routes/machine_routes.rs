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

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::authority::{ActSurface, FoldedMachine, MachineOwnership, MachineRole, PeerMachine};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/machines/answer", get(get_answer).post(set_answer))
        .route("/machines/remove", post(remove))
}

/// Where the owner's say-so reached this install, for the act's audit and
/// receipts only: no rule reads it. The hosted console behind his
/// supervisor's `ManagedOwnerAction`; a linked machine that proved itself on
/// this very request; else this install's own surface (its host action, its
/// CLI or its app).
pub(crate) fn act_surface(server: &SyncServer, auth: &CoreAuth, headers: &HeaderMap) -> ActSurface {
    if auth.managed_owner().is_some() {
        return ActSurface::HostedConsole;
    }
    let Ok(proof) = crate::auth::required_machine_proof(headers) else {
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveMachine {
    /// The MACHINE row, as 32 hex.
    machine: String,
    /// As for an answer.
    #[serde(default)]
    seen: Option<String>,
}

#[derive(Debug, Serialize)]
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

fn answer_of(machine: oneiron::EntityId, folded: Option<&FoldedMachine>) -> MachineAnswer {
    let roster = folded.and_then(|folded| folded.roster.as_ref());
    MachineAnswer {
        machine: machine.to_hex(),
        role: roster.map(|roster| role_name(roster.profile.role)),
        revision: revision_hex(&folded.map_or([0; 32], FoldedMachine::answer_revision)),
        carrier: roster
            .and_then(oneiron::authority::MachineRevision::carrier)
            .map(|carrier| carrier.to_hex()),
    }
}

/// `GET /v1/owner/machines/answer?machine=<id>`: one machine's answer and its
/// revision. A machine no revision names answers role null and the zero
/// revision.
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
        Ok(answer_of(machine, fold.machine(machine)))
    })
    .await?;
    Ok(Json(answer))
}

/// `POST /v1/owner/machines/answer`: the owner marks or re-marks one of his
/// machines. A role change between linked roles takes no carrier power away.
async fn set_answer(
    auth: CoreAuth,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetAnswer>, JsonRejection>,
) -> OwnerReply<MachineAnswer> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface(&server, &auth, &headers);
    let request = json_payload(payload)?;
    let answer = blocking(move || -> OwnerResult<MachineAnswer> {
        let machine = entity_id("machine", &request.machine)?;
        let seen = request
            .seen
            .as_deref()
            .map(|seen| parse_revision("seen", seen))
            .transpose()?;
        let folded = server.vault().set_machine_role(
            &owner,
            surface,
            machine,
            MachineRole::Owned(request.answer),
            seen,
        )?;
        Ok(answer_of(machine, Some(&folded)))
    })
    .await?;
    Ok(Json(answer))
}

/// `POST /v1/owner/machines/remove`: the owner removes one of his machines.
/// Removal is terminal, and it is the one answer that takes the machine's
/// carrier power away: an act it carried that the removal saw keeps its
/// effect.
async fn remove(
    auth: CoreAuth,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RemoveMachine>, JsonRejection>,
) -> OwnerReply<MachineAnswer> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface(&server, &auth, &headers);
    let request = json_payload(payload)?;
    let answer = blocking(move || -> OwnerResult<MachineAnswer> {
        let machine = entity_id("machine", &request.machine)?;
        let seen = request
            .seen
            .as_deref()
            .map(|seen| parse_revision("seen", seen))
            .transpose()?;
        let folded = server.vault().set_machine_role(
            &owner,
            surface,
            machine,
            MachineRole::Removed,
            seen,
        )?;
        Ok(answer_of(machine, Some(&folded)))
    })
    .await?;
    Ok(Json(answer))
}
