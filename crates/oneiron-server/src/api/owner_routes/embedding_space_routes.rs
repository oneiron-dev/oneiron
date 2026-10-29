//! `/v1/owner/embedding-spaces`: the owner declares embedding spaces, binds
//! kind slots and moves a slot to a new model version (OF-370; ARCH-0019
//! `#kind-slots`, ARCH-0004 `#swap-check-ruling`). A move fills its candidate
//! beside the serving space and swaps in only when the vault's own probes read
//! it not worse (NOT-WORSE = A); the owner may say yes over an undecided check,
//! undo a swap, or abandon a move. The media backfill fills and checks on its
//! own; `check` runs the probes now. The owner sees the documents each space's
//! model refused and may clear one, so the backfill tries it again. Each route
//! a `vault.embedding_spaces.*` row mirrors takes that row's input, answers its
//! output through the row's own fn (FIX 1951), and runs its verb hooks once
//! around the engine call (FIX 1953). Each change hands the request's owner
//! proof to its engine fn, which checks it again inside the write that commits
//! the change, after the hooks and the blocking hop (FIX 8200).

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::consent::AuthenticatedOwner;
use oneiron::embed::MediaRefused;
use oneiron::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    self, EmbeddingSpaceBindRequest, EmbeddingSpaceCandidateRequest, EmbeddingSpaceDeclareRequest,
    EmbeddingSpaceMoveChecked, EmbeddingSpaceMoveRequest, EmbeddingSpaceProbeDeleteRequest,
    EmbeddingSpaceProbePutRequest, EmbeddingSpaceRequest, EmbeddingSpacesView, EmptyRequest,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{OwnerReply, blocking, hooked_owner, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id, hooked_row, memory_refusal};
use crate::server::{MediaEmbedRefusal, SyncServer};

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/embedding-spaces", get(list).put(declare))
        .route("/embedding-spaces/bind", post(bind))
        .route("/embedding-spaces/one-space", post(one_space))
        .route("/embedding-spaces/retire", post(retire))
        .route("/embedding-spaces/move", post(begin_move))
        .route("/embedding-spaces/move/check", post(check_move))
        .route("/embedding-spaces/move/approve", post(approve_move))
        .route("/embedding-spaces/move/undo", post(undo_move))
        .route("/embedding-spaces/move/abandon", post(abandon_move))
        .route("/embedding-spaces/probes", get(probes).post(put_probe))
        .route("/embedding-spaces/probes/delete", post(delete_probe))
        .route("/embedding-spaces/refused", get(refused))
        .route("/embedding-spaces/refused/clear", post(clear_refused))
}

/// How long `move/check` holds the request for the probes before it answers
/// `running`; the check goes on and records its reading on the move.
const MOVE_CHECK_ANSWER_DEADLINE: Duration = Duration::from_secs(20);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusedQuery {
    space: String,
}

#[derive(Debug, Serialize)]
struct Refused {
    refused: Vec<MediaRefused>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClearRefused {
    space: String,
    /// The refused document, as 32 hex.
    id: String,
}

fn invalid(error: impl std::fmt::Display) -> OwnerError {
    OwnerError::Invalid(error.to_string())
}

/// An engine refusal of a space move's check, a bad request; an owner's proof
/// the check's write no longer admits answers as the owner door does (FIX
/// 8982).
fn space_refused(error: oneiron::Error) -> OwnerError {
    if error.kind() == oneiron::ErrorKind::ConsentOwnerNotAuthenticated {
        return error.into();
    }
    invalid(error)
}

/// A row fn's refusal as this route answers it: a proof the change's write no
/// longer admits answers as the owner door does (FIX 8200); any other keeps
/// its code, a bad request the engine's words.
fn row_refused(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    error: MemoryError,
) -> OwnerError {
    if let Err(refusal) = vault.recheck_owner(owner) {
        return OwnerError::from(refusal);
    }
    memory_refusal(error)
}

/// Row `verb`'s fn `run` on `request`, inside the row's verb hooks once, with
/// the request's owner proof for its write to check again.
async fn run_row<I, O, F>(
    server: Arc<SyncServer>,
    owner: AuthenticatedOwner,
    actor: oneiron::EntityId,
    verb: &'static str,
    request: I,
    run: F,
) -> OwnerReply<Value>
where
    I: Serialize + DeserializeOwned + Send + 'static,
    O: Serialize,
    F: FnOnce(&oneiron::Vault, &AuthenticatedOwner, I) -> MemoryResult<O> + Send + 'static,
{
    Ok(Json(
        blocking(move || {
            let vault: &oneiron::Vault = server.vault();
            hooked_row(vault, actor, verb, request, |request: I| {
                run(vault, &owner, request).map_err(|error| row_refused(vault, &owner, error))
            })
        })
        .await?,
    ))
}

/// `GET /v1/owner/embedding-spaces`.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    run_row(
        server,
        owner,
        actor,
        "vault.embedding_spaces.list",
        EmptyRequest {},
        |vault, owner, _| sdk::read_embedding_spaces(vault, owner),
    )
    .await
}

/// `PUT /v1/owner/embedding-spaces`: declares or widens one space; a new width
/// is a new space.
async fn declare(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EmbeddingSpaceDeclareRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let verb = "vault.embedding_spaces.declare";
    run_row(server, owner, actor, verb, request, sdk::declare_embedding_space_as).await
}

/// `POST /v1/owner/embedding-spaces/bind`: binds one kind slot, or returns it
/// to its default.
async fn bind(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EmbeddingSpaceBindRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let verb = "vault.embedding_spaces.bind";
    run_row(server, owner, actor, verb, request, sdk::bind_embedding_slot_as).await
}

/// `POST /v1/owner/embedding-spaces/one-space`: the one-space preset.
async fn one_space(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EmbeddingSpaceRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let verb = "vault.embedding_spaces.one_space";
    run_row(server, owner, actor, verb, request, sdk::bind_one_embedding_space_as).await
}

/// `POST /v1/owner/embedding-spaces/retire`: drops a space no slot binds and
/// no open move names, with its rows.
async fn retire(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EmbeddingSpaceRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let verb = "vault.embedding_spaces.retire";
    run_row(server, owner, actor, verb, request, sdk::retire_embedding_space_as).await
}

/// `POST /v1/owner/embedding-spaces/move`: starts moving every slot the
/// incumbent serves to the candidate.
async fn begin_move(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EmbeddingSpaceMoveRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let verb = "vault.embedding_spaces.move";
    run_row(server, owner, actor, verb, request, sdk::begin_embedding_space_move_as).await
}

/// `POST /v1/owner/embedding-spaces/move/check`: runs the move's probes now,
/// through both spaces' towers, and acts on the reading. Past
/// [`MOVE_CHECK_ANSWER_DEADLINE`] it answers `running` and the check finishes on
/// its own thread: the move's `last_check`, state and note show its reading,
/// and its row's post hooks run on what it read.
async fn check_move(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EmbeddingSpaceCandidateRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let runtime = tokio::runtime::Handle::current();
    // Dropping the timed-out future detaches the blocking task; it runs on.
    let checked = tokio::time::timeout(
        MOVE_CHECK_ANSWER_DEADLINE,
        blocking(move || {
            hooked_row(
                server.vault(),
                actor,
                "vault.embedding_spaces.move_check",
                request,
                |request: EmbeddingSpaceCandidateRequest| {
                    check_space_move(&server, &runtime, &owner, &request.candidate)
                },
            )
        }),
    )
    .await;
    Ok(Json(match checked {
        Ok(checked) => checked?,
        // The route's own answer: the row's outcomes and `running`.
        Err(_) => serde_json::json!({ "outcome": "running" }),
    }))
}

/// The move on `candidate`, checked now. The owner's proof is checked again
/// as the check concludes (FIX 8982); a proof that no longer holds answers as
/// the owner door does.
fn check_space_move(
    server: &SyncServer,
    runtime: &tokio::runtime::Handle,
    owner: &AuthenticatedOwner,
    candidate: &str,
) -> OwnerResult<EmbeddingSpaceMoveChecked> {
    let vault = server.vault();
    let moving = sdk::find_embedding_space_move(vault, owner, candidate).map_err(|error| {
        if error.code == MEMORY_CODE_NOT_FOUND {
            OwnerError::NotFound("embedding space move", candidate.to_owned())
        } else {
            row_refused(vault, owner, error)
        }
    })?;
    let (outcome, _) = server
        .check_space_move_listing(runtime, &moving, Some(owner))
        .map_err(|refusal| match refusal {
            MediaEmbedRefusal::Vault(error) => space_refused(error),
            refusal => invalid(refusal),
        })?;
    Ok(EmbeddingSpaceMoveChecked::from(outcome))
}

/// `POST /v1/owner/embedding-spaces/move/approve`: the owner's yes over a
/// check that did not read not worse.
async fn approve_move(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EmbeddingSpaceCandidateRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    // FIX 6907: a third-party candidate's withheld documents do not keep it
    // filling.
    let gates = Arc::clone(&server);
    run_row(
        server,
        owner,
        actor,
        "vault.embedding_spaces.move_approve",
        request,
        move |vault, owner, request: EmbeddingSpaceCandidateRequest| {
            let egress = gates.candidate_media_egress(&request.candidate);
            sdk::approve_embedding_space_move_admitted_as(
                vault,
                owner,
                request,
                egress
                    .as_ref()
                    .map(|gate| gate as &dyn oneiron::embed::EgressPredicate),
            )
        },
    )
    .await
}

/// `POST /v1/owner/embedding-spaces/move/undo`: binds a swapped-in move's
/// incumbent again.
async fn undo_move(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EmbeddingSpaceCandidateRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let verb = "vault.embedding_spaces.move_undo";
    run_row(server, owner, actor, verb, request, sdk::undo_embedding_space_move_as).await
}

/// `POST /v1/owner/embedding-spaces/move/abandon`: ends an open move with no
/// swap.
async fn abandon_move(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EmbeddingSpaceCandidateRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let verb = "vault.embedding_spaces.move_abandon";
    run_row(server, owner, actor, verb, request, sdk::abandon_embedding_space_move_as).await
}

/// `GET /v1/owner/embedding-spaces/probes`.
async fn probes(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    run_row(
        server,
        owner,
        actor,
        "vault.embedding_spaces.probes.list",
        EmptyRequest {},
        |vault, owner, _| sdk::read_embedding_space_probes(vault, owner),
    )
    .await
}

/// `POST /v1/owner/embedding-spaces/probes`: stores one probe the owner, or
/// another model, wrote.
async fn put_probe(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EmbeddingSpaceProbePutRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let verb = "vault.embedding_spaces.probes.put";
    run_row(server, owner, actor, verb, request, sdk::put_embedding_space_probe_as).await
}

/// `POST /v1/owner/embedding-spaces/probes/delete`.
async fn delete_probe(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EmbeddingSpaceProbeDeleteRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let verb = "vault.embedding_spaces.probes.delete";
    run_row(server, owner, actor, verb, request, sdk::delete_embedding_space_probe_as).await
}

/// `GET /v1/owner/embedding-spaces/refused?space=`: every document the space's
/// model refused by its content, with the reason and when.
async fn refused(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<RefusedQuery>, QueryRejection>,
) -> OwnerReply<Refused> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    Ok(Json(
        blocking(move || {
            Ok(Refused {
                refused: server.vault().media_refusals(&query.space)?,
            })
        })
        .await?,
    ))
}

/// `POST /v1/owner/embedding-spaces/refused/clear`: forgets one refusal, so
/// the backfill sends the same bytes to the space's model again. Its write
/// checks the request's owner proof again (FIX 8200). It answers every space,
/// as `vault.embedding_spaces.list` does.
async fn clear_refused(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ClearRefused>,
) -> OwnerReply<EmbeddingSpacesView> {
    let proof = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    Ok(Json(
        blocking(move || {
            let vault = server.vault();
            let id = entity_id("id", &request.id)?;
            if !vault.clear_media_refusal(&proof, &request.space, &id)? {
                return Err(OwnerError::NotFound(
                    "refused document",
                    format!("{} in {}", request.id, request.space),
                ));
            }
            sdk::embedding_spaces_view(vault).map_err(|error| row_refused(vault, &proof, error))
        })
        .await?,
    ))
}
