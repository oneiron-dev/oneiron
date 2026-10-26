//! Proposal-only cloud leg. No raw entities, caller ids, approvals, or authority rows.
//!
//! A proposal is written as the caller it was asked by, through the actor-
//! bound claim door every facade proposal takes (FIX 7959): the one host-
//! action resolver names that caller first, so a hosted operator's root gets
//! its typed support-grant refusal before any lookup (FIX 8154). It lands
//! Proposed whatever the caller's grade, so one that waits on authority
//! stays a proposal.
use super::super::{DagWriteError, core_engine_error, json_payload, scoped_read_for_core_auth};
use crate::{
    auth::{CoreAuth, CoreScope},
    error::{ApiError, ApiErrorEnvelope},
    server::SyncServer,
};
use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
};
use oneiron::{EdgeActorClass, EntityId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoreProposeRequest {
    subject: String,
    predicate: String,
    value: serde_json::Value,
}
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreProposeResponse {
    id: String,
    approval: &'static str,
}
#[utoipa::path(post,path="/v1/core/propose",request_body=CoreProposeRequest,
    responses((status=200,description="A new Proposed claim; no prior head closed.",body=CoreProposeResponse),
        (status=400,description="Invalid proposal.",body=ApiErrorEnvelope),
        (status=401,description="Authentication required.",body=ApiErrorEnvelope),
        (status=403,description="core:propose or core:write required.",body=ApiErrorEnvelope)))]
pub(crate) async fn core_propose(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreProposeRequest>, JsonRejection>,
) -> Result<Json<CoreProposeResponse>, DagWriteError> {
    // Membership picks a verb; `require` also checks the effective record and
    // channel ceiling. No unrelated read verb may change this write decision.
    let permission = if auth.has_scope(CoreScope::Write) {
        CoreScope::Write
    } else {
        CoreScope::Propose
    };
    auth.require(permission)?;
    let request = json_payload(payload)?;
    let subject = EntityId::from_hex(&request.subject)
        .map_err(|_| ApiError::bad_request("invalid subject reference", Some("subject")))?;
    let proposer = request_writer(&server, &auth)?;
    if !subject_admitted(&server, &auth, &proposer, subject)? {
        // One answer for absent and unreadable, so the refusal discloses
        // nothing; its words say what a caller can do about either.
        return Err(ApiError::new(
            "subject not found or not readable",
            crate::error::ApiErrorDetails::Forbidden {
                required_scope: Some("proposal:subject".to_owned()),
            },
            ["Create the subject entity first, or propose against one this credential can read."],
        )
        .into());
    }
    let id = EntityId::now();
    let input = oneiron::memory::ClaimInput {
        id: Some(id.to_hex()),
        predicate: request.predicate,
        subject_ref: subject.to_hex(),
        value: request.value,
        confidence: 1.0,
        source: "tool_output".to_owned(),
        world_ref: None,
        relationship_ref: None,
        scope: Some(serde_json::json!({ "proposal_principal": auth.principal() })),
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
        confidence_details: None,
    };
    let vault = Arc::clone(&server.vault);
    tokio::task::spawn_blocking(move || {
        crate::api::credential_memory(&vault, Some(&auth), proposer.actor, proposer.class)
            .at(auth.locality())
            .claim_propose(&input)
    })
    .await
    .map_err(|_| ApiError::internal_server_error("proposal did not finish"))??;
    Ok(Json(CoreProposeResponse {
        id: id.to_hex(),
        approval: "proposed",
    }))
}

/// Who a core write is written as (FIX 7959, FIX 8154, FIX 8222), from the
/// one host-action resolver every door asks.
pub(crate) struct RequestWriter {
    pub(crate) actor: EntityId,
    pub(crate) class: EdgeActorClass,
    /// The vault's owner in person: a host action, a managed vault's
    /// attested owner, or the owner's own credential.
    pub(crate) owner: bool,
}

/// The caller a core write (a proposal, a VAD annotation) is written as: a
/// self-hosted root or the dev mode as the owner its host action names; a
/// hosted operator's root gets the typed refusal, with no other actor
/// tried; any other caller as the principal its credential binds, else the
/// holder its verified slip proved. A caller that names neither writes as
/// no one, never as this host.
pub(crate) fn request_writer(
    server: &SyncServer,
    auth: &CoreAuth,
) -> Result<RequestWriter, ApiError> {
    if let Some(action) = crate::api::host_action::host_action_of(server.vault(), auth) {
        let actor = action
            .map_err(crate::api::host_action::host_action_refusal)?
            .actor();
        return Ok(RequestWriter {
            actor: actor.entity_ref(),
            class: actor.actor_class(),
            owner: true,
        });
    }
    let actor = auth
        .principal_entity()
        .or_else(|| {
            auth.verified_slip()
                .and_then(|proof| EntityId::from_hex(&proof.claims().holder_ref).ok())
        })
        .ok_or_else(|| ApiError::forbidden_scope(WRITER_PRINCIPAL))?;
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    let owner = auth.managed_owner().is_some()
        || match auth.verified_slip() {
            Some(proof) => server
                .vault()
                .credential_facets_owner_exempt(proof)
                .map_err(|error| core_engine_error("proposal owner check failed", error))?,
            None => false,
        };
    Ok(RequestWriter {
        actor,
        class,
        owner,
    })
}

/// What a core write from a caller that names no principal lacks.
const WRITER_PRINCIPAL: &str = "core:write+principal_ref";

/// Whether this proposal may name `subject` (FIX 8155). The owner's own
/// proposal asks only that the subject exists, as it always did. Any other
/// verified credential's lookup runs under its own bounds (its records,
/// relationship grants and destination) without asking a read verb it was
/// not given; a caller with no slip reads under its scoped read lane.
/// Hidden and absent subjects answer alike.
fn subject_admitted(
    server: &SyncServer,
    auth: &CoreAuth,
    proposer: &RequestWriter,
    subject: EntityId,
) -> Result<bool, ApiError> {
    let failed = |error| core_engine_error("proposal target lookup failed", error);
    if proposer.owner {
        return Ok(server.vault().get(&subject).map_err(failed)?.is_some());
    }
    let read = match auth.verified_slip() {
        Some(proof) => {
            let key = server
                .vault()
                .credential_target_key(proof)
                .map_err(failed)?
                .ok_or_else(ApiError::unauthorized)?;
            server
                .vault()
                .scoped_read(key.for_destination(&auth.destination()))
        }
        None => scoped_read_for_core_auth(server.vault().as_ref(), auth)?,
    };
    Ok(read
        .read(&[oneiron::claim::PointRead::id(subject)], None)
        .map_err(failed)?
        .single()
        .value
        .is_some())
}
