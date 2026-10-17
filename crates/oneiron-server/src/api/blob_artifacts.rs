//! The artifact family's public HTTP surface (ARCH-0078, OF-511): one
//! contract over every blob kind. Create an artifact and append versions with
//! their made_by receipt; read the family view, born-from and a version's
//! export file; propose a native deck transaction or an organ's output; and
//! keep, discard or undo a proposal. Serving a pinned version stays on `/a/`.
//!
//! Comments whose spot was deleted are listed as unattached with their words;
//! the exact places those words read again are offered, and one is picked to
//! reattach (OF-368). A version restore reattaches by exact stored identity.
//!
//! Keep, Discard, Undo and Restore are the owner's consent and take the owner door;
//! the other writes take `core:write` and act as the caller.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State, rejection::JsonRejection},
    http::{
        HeaderValue, Response, StatusCode,
        header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE},
    },
    routing::{get, post},
};
use base64::Engine as _;
use oneiron::EntityId;
use oneiron::anchored_annotation::Locator;
use oneiron::blob_artifact::{
    ArtifactCreateRequest, ArtifactVersionView, BlobArtifactVersion, BlobVersionProvenance,
    BornFromSource,
};
use oneiron::edge::EdgeActorClass;
use oneiron::edit_roundtrip::{DeckEditContext, EditOutcome};
use oneiron::edit_settle::{NativeOutput, SettleConsent};
use oneiron::provenance::made_by::{MadeBy, MadeByTrigger};
use oneiron::write_envelope::WriteActor;
use serde::Deserialize;
use serde_json::{Value, json};

use super::conversation_members::actor;
use super::{core_engine_error, json_payload, parse_entity_id_param};
use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

/// The largest JSON body these routes take: a file travels base64 inside it.
const ARTIFACT_BODY_LIMIT: usize = 96 * 1024 * 1024;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/core/artifacts", post(create))
        .route("/v1/core/artifacts/born-from", get(born_from))
        .route("/v1/core/artifacts/{artifact}", get(view))
        .route("/v1/core/artifacts/{artifact}/versions", post(append))
        .route("/v1/core/artifacts/{artifact}/export", get(export_head))
        .route(
            "/v1/core/artifacts/{artifact}/versions/{version}/export",
            get(export_version),
        )
        .route("/v1/core/artifacts/{artifact}/proposals", get(proposals))
        .route(
            "/v1/core/artifacts/{artifact}/deck/proposals",
            post(propose_deck),
        )
        .route(
            "/v1/core/artifacts/{artifact}/outputs",
            post(propose_output),
        )
        .route(
            "/v1/core/artifacts/{artifact}/proposals/{proposal}/keep",
            post(keep),
        )
        .route(
            "/v1/core/artifacts/{artifact}/proposals/{proposal}/discard",
            post(discard),
        )
        .route(
            "/v1/core/artifacts/{artifact}/proposals/{proposal}/undo",
            post(undo),
        )
        .route(
            "/v1/core/artifacts/{artifact}/versions/{version}/restore",
            post(restore),
        )
        .route("/v1/core/artifacts/{artifact}/unattached", get(unattached))
        .route(
            "/v1/core/artifacts/{artifact}/reattach-offers",
            get(reattach_offers),
        )
        .route(
            "/v1/core/artifacts/{artifact}/threads/{thread}/reattach",
            post(reattach),
        )
        .layer(DefaultBodyLimit::max(ARTIFACT_BODY_LIMIT))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateArtifact {
    name: String,
    media_type: String,
    content_base64: String,
    #[serde(default)]
    run_ref: Option<String>,
    #[serde(default)]
    made_by: Option<MadeBy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AppendVersion {
    content_base64: String,
    /// Any earlier version to fork from; absent appends on the head.
    #[serde(default)]
    fork_parent: Option<u64>,
    #[serde(default)]
    run_ref: Option<String>,
    #[serde(default)]
    made_by: Option<MadeBy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProposeDeck {
    /// The deck transaction: a JSON object, or its exact canonical text.
    transaction: Value,
    run_ref: String,
    #[serde(default)]
    context: DeckEditContext,
    /// The envelope Keep gives the version, with the task or ask it answers.
    #[serde(default)]
    made_by: Option<MadeBy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProposeOutput {
    run_ref: String,
    name: String,
    media_type: String,
    content_base64: String,
    #[serde(default)]
    report: Value,
    #[serde(default)]
    made_by: Option<MadeBy>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct Settle {
    #[serde(default)]
    brief_ref: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// A format-typed place in a version, as the offers name it.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PlaceInput {
    Xlsx {
        sheet: String,
        range: String,
    },
    Docx {
        para_path: String,
        char_start: u64,
        char_end: u64,
    },
    Pptx {
        slide: u64,
        shape_id: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reattach {
    version: u64,
    place: PlaceInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BornFromQuery {
    #[serde(default)]
    task: Option<String>,
    #[serde(default)]
    ask: Option<String>,
    #[serde(default)]
    run: Option<String>,
    #[serde(default)]
    skill: Option<String>,
    #[serde(default)]
    agent_run: Option<String>,
}

async fn blocking<T: Send + 'static>(
    message: &'static str,
    work: impl FnOnce() -> oneiron::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| ApiError::internal_server_error("artifact task failed"))?
        .map_err(|error| core_engine_error(message, error))
}

fn decode_content(content: &str) -> Result<Vec<u8>, ApiError> {
    base64::engine::general_purpose::STANDARD
        .decode(content)
        .map_err(|_| ApiError::bad_request("content must be base64", Some("content_base64")))
}

/// A person's upload is theirs; an agent's version names the run that made it.
fn provenance(
    actor: WriteActor,
    run_ref: Option<String>,
) -> Result<BlobVersionProvenance, ApiError> {
    match run_ref {
        Some(run_ref) => Ok(BlobVersionProvenance::AgentRun { run_ref }),
        None if actor.actor_class() == EdgeActorClass::Human => {
            Ok(BlobVersionProvenance::UserUpload)
        }
        None => Err(ApiError::bad_request(
            "an agent's version names its run_ref",
            Some("run_ref"),
        )),
    }
}

fn version_json(version: &BlobArtifactVersion) -> Value {
    json!(ArtifactVersionView::from(version))
}

fn moment(server: &SyncServer) -> (oneiron::TimeRange, u64) {
    let now = server.vault().now_recorded_at();
    (
        oneiron::TimeRange {
            start: now,
            end: now,
        },
        now,
    )
}

fn owner_actor(auth: &CoreAuth, server: &SyncServer) -> Result<WriteActor, ApiError> {
    super::owner_routes::owner(auth, server)?;
    actor(auth, None)
}

/// `POST /v1/core/artifacts` through the `vault.artifacts.create` row's
/// door (OF-181), as the credential's actor. Its bytes ride the request
/// whole, past what one action argument carries, so the route runs the
/// row's door itself rather than the action table.
pub(super) async fn create(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CreateArtifact>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), super::facade::FacadeApiError> {
    auth.require(CoreScope::Write)?;
    let actor = actor(&auth, None)?;
    let request = json_payload(payload)?;
    let made_by = request
        .made_by
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| ApiError::bad_request("made_by is not encodable", Some("made_by")))?;
    let input = ArtifactCreateRequest {
        name: request.name,
        media_type: request.media_type,
        content_base64: request.content_base64,
        run_ref: request.run_ref,
        made_by,
    };
    let view = tokio::task::spawn_blocking(move || {
        crate::api::credential_memory(
            &server.vault,
            Some(&auth),
            actor.entity_ref(),
            actor.actor_class(),
        )
        .at(auth.locality())
        .artifacts_create(&input)
    })
    .await
    .map_err(|_| ApiError::internal_server_error("artifact task failed"))??;
    Ok((StatusCode::CREATED, Json(json!(view))))
}

pub(super) async fn view(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(artifact): Path<String>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    let view = blocking("artifact read failed", move || {
        server.vault().blob_artifact_view(&id)
    })
    .await?
    .ok_or_else(|| ApiError::not_found("artifact", Some(artifact.as_str())))?;
    Ok(Json(json!(view)))
}

pub(super) async fn append(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(artifact): Path<String>,
    payload: Result<Json<AppendVersion>, JsonRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let actor = actor(&auth, None)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    let request = json_payload(payload)?;
    let bytes = decode_content(&request.content_base64)?;
    let provenance = provenance(actor, request.run_ref)?;
    let version = blocking("artifact version append failed", move || {
        let vault = server.vault();
        let (occurred, now) = moment(&server);
        match (&request.made_by, request.fork_parent) {
            (Some(made_by), fork_parent) => vault.append_blob_artifact_version_made_by(
                &id,
                fork_parent,
                &bytes,
                &provenance,
                made_by,
                actor,
                occurred,
                now,
            ),
            (None, Some(parent)) => vault.fork_blob_artifact_version(
                &id,
                parent,
                &bytes,
                &provenance,
                actor,
                occurred,
                now,
            ),
            (None, None) => {
                vault.append_blob_artifact_version(&id, &bytes, &provenance, actor, occurred, now)
            }
        }
    })
    .await?;
    Ok(Json(version_json(&version)))
}

async fn export(
    auth: CoreAuth,
    server: Arc<SyncServer>,
    artifact: String,
    version: Option<u64>,
) -> Result<Response<Body>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    // Keys in a file reach the owner only; every other reader gets them
    // masked (OF-560).
    let sight = if auth.is_owner_grade() && auth.actor_class() != Some("agent") {
        oneiron::secret_custody::SecretSight::Owner
    } else {
        oneiron::secret_custody::SecretSight::Masked
    };
    // Who took the copy, for its travel receipt: the bound principal, else
    // the vault owner an owner-grade secret speaks for.
    let bound = auth
        .principal_ref()
        .map(|s| parse_entity_id_param(s, "principal_ref"))
        .transpose()?;
    let owner_grade = auth.is_owner_grade();
    let file = blocking("artifact export failed", move || {
        let vault = server.vault();
        let file = vault.export_blob_artifact_as(&id, version, sight)?;
        let by = bound.or_else(|| {
            owner_grade
                .then(|| vault.ensure_embedded_owner_actor().ok())
                .flatten()
        });
        if let (Some(file), Some(by)) = (&file, by) {
            vault.record_blob_artifact_download(file, &by)?;
        }
        Ok(file)
    })
    .await?
    .ok_or_else(|| ApiError::not_found("artifact version", Some(artifact.as_str())))?;
    // A download, never a page on the API origin: attachment, sandboxed.
    let disposition = format!(
        "attachment; filename=\"{}\"",
        file.name
            .chars()
            .filter(|c| c.is_ascii_graphic() && *c != '"' && *c != '\\' || *c == ' ')
            .collect::<String>()
    );
    let mut response = Response::new(Body::from(file.bytes));
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&file.media_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition)
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox; default-src 'none'"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(value) = HeaderValue::from_str(&file.version.to_string()) {
        headers.insert("x-oneiron-artifact-version", value);
    }
    if let Ok(value) = HeaderValue::from_str(file.kind.as_str()) {
        headers.insert("x-oneiron-artifact-kind", value);
    }
    Ok(response)
}

pub(super) async fn export_head(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(artifact): Path<String>,
) -> Result<Response<Body>, EnvelopedApiError> {
    export(auth, server, artifact, None).await
}

pub(super) async fn export_version(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((artifact, version)): Path<(String, u64)>,
) -> Result<Response<Body>, EnvelopedApiError> {
    export(auth, server, artifact, Some(version)).await
}

pub(super) async fn born_from(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Query(query): Query<BornFromQuery>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let trigger = |value: &str, field: &'static str, make: fn(EntityId) -> MadeByTrigger| {
        parse_entity_id_param(value, field).map(make)
    };
    let source = match (
        query.task.as_deref(),
        query.ask.as_deref(),
        query.run.as_deref(),
        query.skill.as_deref(),
        query.agent_run,
    ) {
        (Some(task), None, None, None, None) => {
            BornFromSource::Trigger(trigger(task, "task", MadeByTrigger::Task)?)
        }
        (None, Some(ask), None, None, None) => {
            BornFromSource::Trigger(trigger(ask, "ask", MadeByTrigger::Ask)?)
        }
        (None, None, Some(run), None, None) => {
            BornFromSource::Trigger(trigger(run, "run", MadeByTrigger::Run)?)
        }
        (None, None, None, Some(skill), None) => {
            BornFromSource::Trigger(trigger(skill, "skill", MadeByTrigger::Skill)?)
        }
        (None, None, None, None, Some(run_ref)) => BornFromSource::AgentRun(run_ref),
        _ => {
            return Err(ApiError::bad_request(
                "name exactly one of task, ask, run, skill or agent_run",
                None,
            )
            .into());
        }
    };
    let (born, versions) = blocking("born-from read failed", move || {
        let vault = server.vault();
        let born = match &source {
            BornFromSource::Trigger(trigger) => vault.rows_born_from(&trigger.row())?,
            BornFromSource::AgentRun(_) => Vec::new(),
        };
        Ok((born, vault.artifacts_born_from(&source)?))
    })
    .await?;
    Ok(Json(json!({ "born": born, "versions": versions })))
}

pub(super) async fn proposals(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(artifact): Path<String>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    let pending = blocking("proposal list failed", move || {
        server.vault().pending_proposals(&id)
    })
    .await?;
    Ok(Json(json!({ "proposals": pending })))
}

pub(super) async fn propose_deck(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(artifact): Path<String>,
    payload: Result<Json<ProposeDeck>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let actor = actor(&auth, None)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    let request = json_payload(payload)?;
    let transaction = match request.transaction {
        Value::String(text) => text,
        other => other.to_string(),
    };
    let outcome = blocking("deck proposal failed", move || {
        let vault = server.vault();
        match vault.propose_blob_artifact_deck_edit(
            &id,
            &transaction,
            &request.run_ref,
            request.context,
        )? {
            EditOutcome::Proposed(proposal) => {
                let now = vault.now_recorded_at();
                vault
                    .retain_edit_proposal(&id, &proposal, request.made_by.as_ref(), actor, now)
                    .map(|pending| Ok(json!(pending)))
            }
            EditOutcome::Rejected { inspection, report } => {
                Ok(Err(json!({ "inspection": inspection, "report": report })))
            }
        }
    })
    .await?;
    Ok(match outcome {
        Ok(pending) => (StatusCode::CREATED, Json(json!({ "proposed": pending }))),
        Err(rejected) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "rejected": rejected })),
        ),
    })
}

pub(super) async fn propose_output(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(artifact): Path<String>,
    payload: Result<Json<ProposeOutput>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let actor = actor(&auth, None)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    let request = json_payload(payload)?;
    let output = NativeOutput {
        bytes: decode_content(&request.content_base64)?,
        run_ref: request.run_ref,
        name: request.name,
        media_type: request.media_type,
        report: request.report,
        made_by: request.made_by,
    };
    let pending = blocking("native output proposal failed", move || {
        let vault = server.vault();
        vault.propose_native_output(&id, &output, actor, vault.now_recorded_at())
    })
    .await?;
    Ok((StatusCode::CREATED, Json(json!({ "proposed": pending }))))
}

fn settle_request(payload: Option<Json<Settle>>) -> Settle {
    payload.map(|Json(settle)| settle).unwrap_or_default()
}

pub(super) async fn keep(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((artifact, proposal)): Path<(String, String)>,
    payload: Option<Json<Settle>>,
) -> Result<Json<Value>, EnvelopedApiError> {
    let actor = owner_actor(&auth, &server)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    let request = settle_request(payload);
    let outcome = blocking("keep failed", move || {
        let (occurred, now) = moment(&server);
        server.vault().keep_pending_proposal(
            &id,
            &proposal,
            &SettleConsent::OwnerConsent {
                brief_ref: request.brief_ref,
            },
            actor,
            occurred,
            now,
        )
    })
    .await?;
    Ok(Json(json!({
        "version": version_json(&outcome.version),
        "stranded": outcome.stranded_proposal.is_some(),
        "remapped": outcome.reanchor.remapped.len(),
        "drifted": outcome.reanchor.drifted.len(),
        "receipt": outcome.receipt,
    })))
}

pub(super) async fn discard(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((artifact, proposal)): Path<(String, String)>,
    payload: Option<Json<Settle>>,
) -> Result<Json<Value>, EnvelopedApiError> {
    let actor = owner_actor(&auth, &server)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    let request = settle_request(payload);
    let outcome = blocking("discard failed", move || {
        let vault = server.vault();
        vault.discard_pending_proposal(
            &id,
            &proposal,
            &SettleConsent::OwnerConsent {
                brief_ref: request.brief_ref,
            },
            actor,
            request.reason.as_deref().unwrap_or_default(),
            vault.now_recorded_at(),
        )
    })
    .await?;
    Ok(Json(json!({ "receipt": outcome.receipt })))
}

pub(super) async fn undo(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((artifact, proposal)): Path<(String, String)>,
    payload: Option<Json<Settle>>,
) -> Result<Json<Value>, EnvelopedApiError> {
    let actor = owner_actor(&auth, &server)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    let request = settle_request(payload);
    let outcome = blocking("undo failed", move || {
        let (occurred, now) = moment(&server);
        server.vault().undo_kept_proposal(
            &id,
            &proposal,
            &SettleConsent::OwnerConsent {
                brief_ref: request.brief_ref,
            },
            actor,
            occurred,
            now,
        )
    })
    .await?;
    Ok(Json(json!({
        "undo": outcome.undo,
        "version": version_json(&outcome.version),
        "remapped": outcome.reanchor.remapped.len(),
        "drifted": outcome.reanchor.drifted.len(),
    })))
}

fn place_json(locator: &Locator) -> Value {
    match locator {
        Locator::Xlsx { sheet, range } => {
            json!({ "xlsx": { "sheet": sheet, "range": range.to_a1() } })
        }
        Locator::Docx {
            para_path,
            char_start,
            char_end,
        } => json!({ "docx": {
            "para_path": para_path,
            "char_start": char_start,
            "char_end": char_end,
        } }),
        Locator::Pptx { slide, shape_id } => {
            json!({ "pptx": { "slide": slide, "shape_id": shape_id } })
        }
        _ => Value::Null,
    }
}

fn place_locator(place: PlaceInput) -> Result<Locator, ApiError> {
    match place {
        PlaceInput::Xlsx { sheet, range } => Locator::xlsx(sheet, &range),
        PlaceInput::Docx {
            para_path,
            char_start,
            char_end,
        } => Locator::docx(para_path, char_start, char_end),
        PlaceInput::Pptx { slide, shape_id } => Locator::pptx(slide, shape_id),
    }
    .map_err(|_| ApiError::bad_request("place is not a valid locator", Some("place")))
}

pub(super) async fn restore(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((artifact, version)): Path<(String, u64)>,
) -> Result<Json<Value>, EnvelopedApiError> {
    let actor = owner_actor(&auth, &server)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    let outcome = blocking("restore failed", move || {
        let (occurred, now) = moment(&server);
        server
            .vault()
            .restore_blob_artifact_version(&id, version, actor, occurred, now)
    })
    .await?;
    Ok(Json(json!({
        "version": version_json(&outcome.version),
        "restored_version": outcome.undo.restored_version,
        "reattached": outcome.reanchor.remapped.len(),
    })))
}

pub(super) async fn unattached(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(artifact): Path<String>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    let threads = blocking("unattached list failed", move || {
        server.vault().unattached_annotation_threads(&id)
    })
    .await?;
    let threads: Vec<Value> = threads
        .iter()
        .map(|unattached| {
            json!({
                "thread": unattached.thread.thread_id,
                "pinned_version": unattached.thread.anchor.version,
                "place": place_json(&unattached.thread.anchor.locator),
                "snapshot": unattached.snapshot,
                "detached_at_version": unattached.detached_at_version,
                "held_task": unattached.held_task,
            })
        })
        .collect();
    Ok(Json(json!({ "unattached": threads })))
}

pub(super) async fn reattach_offers(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(artifact): Path<String>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    let offers = blocking("reattach offers failed", move || {
        server.vault().annotation_reattach_offers(&id)
    })
    .await?;
    let offers: Vec<Value> = offers
        .iter()
        .map(|offer| {
            json!({
                "thread": offer.thread_id,
                "version": offer.version,
                "place": place_json(&offer.locator),
            })
        })
        .collect();
    Ok(Json(json!({ "offers": offers })))
}

pub(super) async fn reattach(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((artifact, thread)): Path<(String, String)>,
    payload: Result<Json<Reattach>, JsonRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let actor = actor(&auth, None)?;
    let id = parse_entity_id_param(&artifact, "artifact")?;
    let thread = parse_entity_id_param(&thread, "thread")?;
    let request = json_payload(payload)?;
    let locator = place_locator(request.place)?;
    let reattached = blocking("reattach failed", move || {
        let (occurred, now) = moment(&server);
        server.vault().reattach_annotation_thread(
            &id,
            &thread,
            request.version,
            &locator,
            actor,
            occurred,
            now,
        )
    })
    .await?;
    Ok(Json(json!({
        "thread": reattached.thread_id,
        "version": reattached.anchor.version,
        "place": place_json(&reattached.anchor.locator),
    })))
}
