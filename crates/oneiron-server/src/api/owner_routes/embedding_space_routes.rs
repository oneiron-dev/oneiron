//! `/v1/owner/embedding-spaces`: the owner declares embedding spaces, binds
//! kind slots and moves a slot to a new model version (OF-370; ARCH-0019
//! `#kind-slots`, ARCH-0004 `#swap-check-ruling`). A move fills its candidate
//! beside the serving space and swaps in only when the vault's own probes read
//! it not worse (NOT-WORSE = A); the owner may say yes over an undecided check,
//! undo a swap, or abandon a move. The media backfill fills and checks on its
//! own; `check` runs the probes now. The owner sees the documents each space's
//! model refused and may clear one, so the backfill tries it again. Each route
//! a `vault.embedding_spaces.*` row mirrors takes that row's input and runs its
//! verb hooks once around the engine call (FIX 1953).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::embed::{
    EmbeddingSpace, InputKind, MediaRefused, SpaceMove, SpaceMoveOutcome, SpaceProbe, SpaceRef,
};
use oneiron::task_verb::sdk::{
    EmbeddingSpaceBindRequest, EmbeddingSpaceCandidateRequest, EmbeddingSpaceDeclareRequest,
    EmbeddingSpaceMoveRequest, EmbeddingSpaceProbeDeleteRequest, EmbeddingSpaceProbePutRequest,
    EmbeddingSpaceRequest, EmptyRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{OwnerReply, blocking, hooked_owner, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id, hooked_row};
use crate::server::SyncServer;

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

/// Every declared space, where each kind slot reads, and every move.
#[derive(Debug, Serialize)]
struct Spaces {
    spaces: Vec<EmbeddingSpace>,
    /// The vault's own text vector index, which an unbound text slot reads.
    text_index: EmbeddingSpace,
    /// Kind to declared space id; an absent text kind reads the text index.
    slots: BTreeMap<InputKind, String>,
    moves: Vec<SpaceMove>,
    /// Stored probes per kind.
    probes: BTreeMap<InputKind, usize>,
    /// Documents each space's model refused by their content, by space id; a
    /// space with none is absent.
    refused: BTreeMap<String, usize>,
}

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

#[derive(Debug, Serialize)]
struct MoveChecked {
    /// `filling`, `swapped_in`, `kept` or `undecided`; `running` once
    /// [`MOVE_CHECK_ANSWER_DEADLINE`] passes with the probes still running.
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    check: Option<oneiron::embed::SpaceMoveCheck>,
}

#[derive(Debug, Serialize)]
struct Probe {
    /// 32 hex.
    id: String,
    #[serde(flatten)]
    probe: SpaceProbe,
}

#[derive(Debug, Serialize)]
struct Probes {
    probes: Vec<Probe>,
}

#[derive(Debug, Serialize)]
struct Done {
    ok: bool,
}

fn probe_hex(id: [u8; 16]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn probe_id(hex: &str) -> OwnerResult<[u8; 16]> {
    let refused = || OwnerError::Invalid("id must be 32 hex".into());
    if hex.len() != 32 || !hex.is_ascii() {
        return Err(refused());
    }
    let mut id = [0_u8; 16];
    for (byte, pair) in id.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| refused())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| refused())?;
    }
    Ok(id)
}

fn invalid(error: impl std::fmt::Display) -> OwnerError {
    OwnerError::Invalid(error.to_string())
}

fn spaces(vault: &oneiron::Vault) -> OwnerResult<Spaces> {
    let bindings = vault.kind_slot_bindings()?;
    let slots = InputKind::ALL
        .into_iter()
        .filter_map(|kind| Some((kind, bindings.space_for(kind)?.to_owned())))
        .collect();
    let mut probes = BTreeMap::new();
    for (_, probe) in vault.space_probes()? {
        *probes.entry(probe.kind).or_insert(0) += 1;
    }
    Ok(Spaces {
        spaces: vault.embedding_spaces()?,
        text_index: vault.text_index_space(),
        slots,
        moves: vault.space_moves()?,
        probes,
        refused: vault.media_refusal_counts()?,
    })
}

/// `GET /v1/owner/embedding-spaces`.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    Ok(Json(
        blocking(move || {
            let vault = server.vault();
            hooked_row(vault, actor, "vault.embedding_spaces.list", EmptyRequest {}, |_| {
                spaces(vault)
            })
        })
        .await?,
    ))
}

/// `PUT /v1/owner/embedding-spaces`: declares or widens one space; a new width
/// is a new space.
async fn declare(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<EmbeddingSpaceDeclareRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    Ok(Json(
        blocking(move || {
            let vault = server.vault();
            hooked_row(
                vault,
                actor,
                "vault.embedding_spaces.declare",
                request,
                |request: EmbeddingSpaceDeclareRequest| {
                    vault.declare_embedding_space(request.0).map_err(invalid)?;
                    spaces(vault)
                },
            )
        })
        .await?,
    ))
}

/// `POST /v1/owner/embedding-spaces/bind`: binds one kind slot, or returns it
/// to its default.
async fn bind(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<EmbeddingSpaceBindRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    Ok(Json(
        blocking(move || {
            let vault = server.vault();
            hooked_row(
                vault,
                actor,
                "vault.embedding_spaces.bind",
                request,
                |request: EmbeddingSpaceBindRequest| {
                    match &request.space {
                        Some(space) => vault.bind_kind_slot(request.kind, space),
                        None => vault.unbind_kind_slot(request.kind),
                    }
                    .map_err(invalid)?;
                    spaces(vault)
                },
            )
        })
        .await?,
    ))
}

/// `POST /v1/owner/embedding-spaces/one-space`: the one-space preset.
async fn one_space(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<EmbeddingSpaceRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    Ok(Json(
        blocking(move || {
            let vault = server.vault();
            hooked_row(
                vault,
                actor,
                "vault.embedding_spaces.one_space",
                request,
                |request: EmbeddingSpaceRequest| {
                    vault
                        .bind_one_space_for_all(&request.space)
                        .map_err(invalid)?;
                    spaces(vault)
                },
            )
        })
        .await?,
    ))
}

/// `POST /v1/owner/embedding-spaces/retire`: drops a space no slot binds and
/// no open move names, with its rows.
async fn retire(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<EmbeddingSpaceRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    Ok(Json(
        blocking(move || {
            let vault = server.vault();
            hooked_row(
                vault,
                actor,
                "vault.embedding_spaces.retire",
                request,
                |request: EmbeddingSpaceRequest| {
                    vault
                        .retire_embedding_space(&request.space)
                        .map_err(invalid)?;
                    spaces(vault)
                },
            )
        })
        .await?,
    ))
}

/// `POST /v1/owner/embedding-spaces/move`: starts moving every slot the
/// incumbent serves to the candidate.
async fn begin_move(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<EmbeddingSpaceMoveRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    Ok(Json(
        blocking(move || {
            let vault = server.vault();
            hooked_row(
                vault,
                actor,
                "vault.embedding_spaces.move",
                request,
                |request: EmbeddingSpaceMoveRequest| -> OwnerResult<SpaceMove> {
                    let incumbent = request
                        .incumbent
                        .map_or(SpaceRef::TextIndex, SpaceRef::Declared);
                    vault
                        .begin_space_move(&request.candidate, incumbent, request.margin)
                        .map_err(invalid)
                },
            )
        })
        .await?,
    ))
}

/// `POST /v1/owner/embedding-spaces/move/check`: runs the move's probes now,
/// through both spaces' towers, and acts on the reading. Past
/// [`MOVE_CHECK_ANSWER_DEADLINE`] it answers `running` and the check finishes on
/// its own thread: the move's `last_check`, state and note show its reading,
/// and its row's post hooks run on what it read.
async fn check_move(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<EmbeddingSpaceCandidateRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
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
                    check_space_move(&server, &runtime, &request.candidate)
                },
            )
        }),
    )
    .await;
    Ok(Json(match checked {
        Ok(checked) => checked?,
        Err(_) => serde_json::to_value(MoveChecked {
            outcome: "running",
            check: None,
        })
        .unwrap_or_default(),
    }))
}

/// The move on `candidate`, checked now.
fn check_space_move(
    server: &SyncServer,
    runtime: &tokio::runtime::Handle,
    candidate: &str,
) -> OwnerResult<MoveChecked> {
    let moving = server
        .vault()
        .space_moves()?
        .into_iter()
        .find(|moving| moving.candidate == candidate)
        .ok_or_else(|| OwnerError::NotFound("embedding space move", candidate.to_owned()))?;
    let outcome = server.check_space_move(runtime, &moving).map_err(invalid)?;
    Ok(match outcome {
        SpaceMoveOutcome::Filling => MoveChecked {
            outcome: "filling",
            check: None,
        },
        SpaceMoveOutcome::SwappedIn(check) => MoveChecked {
            outcome: "swapped_in",
            check: Some(check),
        },
        SpaceMoveOutcome::Kept(check) => MoveChecked {
            outcome: "kept",
            check: Some(check),
        },
        SpaceMoveOutcome::Undecided(check) => MoveChecked {
            outcome: "undecided",
            check: Some(check),
        },
    })
}

/// `POST /v1/owner/embedding-spaces/move/approve`: the owner's yes over a
/// check that did not read not worse.
async fn approve_move(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<EmbeddingSpaceCandidateRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    move_step(
        auth,
        server,
        payload,
        "vault.embedding_spaces.move_approve",
        |vault, candidate| vault.approve_space_move(candidate),
    )
    .await
}

/// `POST /v1/owner/embedding-spaces/move/undo`: binds a swapped-in move's
/// incumbent again.
async fn undo_move(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<EmbeddingSpaceCandidateRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    move_step(
        auth,
        server,
        payload,
        "vault.embedding_spaces.move_undo",
        |vault, candidate| vault.undo_space_move(candidate),
    )
    .await
}

/// `POST /v1/owner/embedding-spaces/move/abandon`: ends an open move with no
/// swap.
async fn abandon_move(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<EmbeddingSpaceCandidateRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    move_step(
        auth,
        server,
        payload,
        "vault.embedding_spaces.move_abandon",
        |vault, candidate| vault.abandon_space_move(candidate),
    )
    .await
}

/// One owner step on the move `candidate` names, inside row `verb`'s hooks;
/// it answers every space.
async fn move_step<T, E: std::fmt::Display>(
    auth: CoreAuth,
    server: Arc<SyncServer>,
    payload: Result<Json<EmbeddingSpaceCandidateRequest>, JsonRejection>,
    verb: &'static str,
    step: impl FnOnce(&oneiron::Vault, &str) -> Result<T, E> + Send + 'static,
) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    Ok(Json(
        blocking(move || {
            let vault = server.vault();
            hooked_row(
                vault,
                actor,
                verb,
                request,
                |request: EmbeddingSpaceCandidateRequest| {
                    step(vault, &request.candidate).map_err(invalid)?;
                    spaces(vault)
                },
            )
        })
        .await?,
    ))
}

/// `GET /v1/owner/embedding-spaces/probes`.
async fn probes(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    Ok(Json(
        blocking(move || {
            let vault = server.vault();
            hooked_row(
                vault,
                actor,
                "vault.embedding_spaces.probes.list",
                EmptyRequest {},
                |_| {
                    Ok(Probes {
                        probes: vault
                            .space_probes()?
                            .into_iter()
                            .map(|(id, probe)| Probe {
                                id: probe_hex(id),
                                probe,
                            })
                            .collect(),
                    })
                },
            )
        })
        .await?,
    ))
}

/// `POST /v1/owner/embedding-spaces/probes`: stores one probe the owner, or
/// another model, wrote.
async fn put_probe(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<EmbeddingSpaceProbePutRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    Ok(Json(
        blocking(move || {
            let vault = server.vault();
            hooked_row(
                vault,
                actor,
                "vault.embedding_spaces.probes.put",
                request,
                |request: EmbeddingSpaceProbePutRequest| {
                    let mut targets = std::collections::BTreeSet::from([request.family]);
                    targets.extend(request.targets);
                    let probe = SpaceProbe {
                        kind: request.kind,
                        query: request.query,
                        family: request.family,
                        targets,
                        author: request.author,
                        written_at: vault.now_recorded_at(),
                    };
                    let id = vault.put_space_probe(probe.clone()).map_err(invalid)?;
                    Ok(Probe {
                        id: probe_hex(id),
                        probe,
                    })
                },
            )
        })
        .await?,
    ))
}

/// `POST /v1/owner/embedding-spaces/probes/delete`.
async fn delete_probe(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<EmbeddingSpaceProbeDeleteRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    Ok(Json(
        blocking(move || {
            let vault = server.vault();
            hooked_row(
                vault,
                actor,
                "vault.embedding_spaces.probes.delete",
                request,
                |request: EmbeddingSpaceProbeDeleteRequest| {
                    let id = probe_id(&request.id)?;
                    Ok(Done {
                        ok: vault.delete_space_probe(&id)?,
                    })
                },
            )
        })
        .await?,
    ))
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
/// the backfill sends the same bytes to the space's model again.
async fn clear_refused(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ClearRefused>, JsonRejection>,
) -> OwnerReply<Spaces> {
    owner(&auth, &server)?;
    let request = json_payload(payload)?;
    Ok(Json(
        blocking(move || {
            let id = entity_id("id", &request.id)?;
            if !server.vault().clear_media_refusal(&request.space, &id)? {
                return Err(OwnerError::NotFound(
                    "refused document",
                    format!("{} in {}", request.id, request.space),
                ));
            }
            spaces(server.vault())
        })
        .await?,
    ))
}
