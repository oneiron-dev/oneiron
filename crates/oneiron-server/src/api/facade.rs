//! ONE-1441 WIRE-P1: the bounded HTTP projection of the engine memory surface.
//!
//! One route per §HEAD-CONTRACT verb at `/v1/core/facade/<verb>`, the verb's
//! full dotted name, and nothing else. Every handler does the same four things: require the
//! scope, resolve the actor from the CREDENTIAL, bind
//! [`oneiron::Vault::memory`] to it, and serialize what the engine returned.
//! There is no transport-only domain model here — the request and response
//! types ARE the engine DTOs — so this projection and the in-process N-API
//! binding cannot drift into two dialects of the same verb.
//!
//! The route projection is generated from `scripts/sdk/agent-verbs.json`.
//! Claim lifecycle, scoped reads, export, notes, artifacts, tasks and rooms
//! all use the same inventory and engine DTOs as the native clients. Every
//! route runs its row through the generated dispatch (`facade/generated/dispatch.rs`), the one
//! the held socket's `rpc.req` runs too (OF-489), so a verb meets the same
//! admission on both. Live subscriptions remain owned by the held socket
//! rather than this router.
//!
//! ERRORS are the facade's own, not the server's closed
//! [`crate::error::ErrorCode`] enum.
//! The engine's `code` string travels verbatim inside the same
//! `{error:{code,message,requestId,suggestions}}` envelope shape the rest of
//! `/v1/core` uses, so a future engine code reaches a client losslessly
//! instead of collapsing into `INTERNAL_SERVER_ERROR`. `crate::error` is not
//! edited to admit these codes; that is the whole point of the local type.

pub(super) mod action_routes;
mod admission_doors;
mod affect_doors;
mod agent_definition_doors;
mod agent_grant_doors;
#[path = "facade/generated/agent_verbs.rs"]
mod agent_verbs;
mod aging_doors;
mod artifact_hosting_doors;
mod asr_doors;
mod authority_history_doors;
mod board_stream_doors;
mod booking_doors;
mod browser_doors;
mod budget_doors;
mod calendar_doors;
mod call_context;
mod campaign_doors;
mod campaign_split_doors;
mod channel_doors;
mod checkout_doors;
mod claim_settle_doors;
mod cleanup_doors;
pub(crate) mod clock_ingress;
mod clustering_doors;
mod coach_offer_doors;
mod code_doors;
mod code_import_doors;
mod code_run_doors;
mod code_view_doors;
mod code_wait_doors;
mod codebase_doors;
mod comm_widen_doors;
mod commitment_doors;
mod compliance_doors;
mod connector_call_doors;
mod connector_pack_doors;
mod connector_revision_doors;
mod connector_slate_doors;
mod connector_witness_read_doors;
mod consent_doors;
mod consolidation_doors;
mod content_policy_doors;
mod coordination_doors;
mod core_write_doors;
mod coreference_doors;
mod courtesy_delete_doors;
mod craft_candidate_doors;
mod credential_doors;
mod critic_review_doors;
mod critical_confirm_doors;
mod decision_ask_doors;
mod decision_band_doors;
pub(super) mod decision_role_asks;
mod deck_creation_doors;
mod disclosure_doors;
#[path = "facade/generated/dispatch.rs"]
mod dispatch;
mod embedding_space_doors;
mod errors;
mod eval_doors;
pub(super) mod export_transfer;
mod extraction_doors;
mod fanout_doors;
mod federation_burst_doors;
mod federation_connect_doors;
mod feedback_doors;
mod files_doors;
mod fold_doors;
mod foreign_code_doors;
pub(super) mod free_time_doors;
mod gate_policy_doors;
mod git_push_doors;
mod goal_optimize_doors;
mod graduation_doors;
mod grants_doors;
mod graph_ask_doors;
mod guest_document_doors;
mod guest_doors;
mod hook_regen_doors;
mod hook_session;
mod hooks;
pub(super) mod host_doors;
mod host_trigger_doors;
mod hub_doors;
mod hyde_doors;
mod identity;
mod identity_doors;
mod identity_topology_doors;
mod inbox_group_doors;
mod invocations;
mod invoke;
mod learning_doors;
mod legal_hold_doors;
mod lens_selection_doors;
mod linear_doors;
mod live_run_doors;
mod live_voice_doors;
mod merge_queue_checker_doors;
mod merge_queue_doors;
mod mesh_doors;
mod model_catalog_doors;
mod model_manifest_doors;
mod model_step_doors;
mod model_stream_doors;
mod note_doors;
mod off_record_doors;
mod off_record_room_doors;
mod origin_doors;
mod origin_publish_doors;
mod output;
pub(super) mod owner_binding;
mod pack_preview_doors;
mod persona_doors;
mod plugin_section_doors;
mod policy_doors;
mod program_read_doors;
mod project_card_doors;
mod proxy_doors;
mod reaction_doors;
mod receipts;
mod release;
mod reply_doors;
mod repo_doors;
mod research_doors;
mod residence_doors;
mod result_doors;
mod retrieval_doors;
pub(super) mod role_picks;
mod root_request_doors;
mod run_read_doors;
mod run_review_doors;
mod runner_seat_doors;
mod saved_query_doors;
mod seal_doors;
mod search_home_doors;
mod secret_body;
mod secret_custody_doors;
mod secret_grant_doors;
mod secret_lift_doors;
mod secret_use_doors;
mod setting_doors;
mod share_doors;
mod shared_act_doors;
mod shared_admin_doors;
mod shared_member_doors;
mod shared_policy_doors;
mod sieve_doors;
mod sieve_observation_doors;
mod skill_attribution_doors;
mod skill_default_doors;
mod skill_doors;
mod skill_execution_doors;
mod slim_doors;
mod standing_doors;
mod summary_doors;
mod support_grant_doors;
#[cfg(test)]
pub(super) mod tests;
mod trusted_contact_doors;
pub(super) mod ui_action_routes;
mod usage_repair_doors;
mod vault_shape_doors;
mod vector_doors;
mod voice_bank_doors;
mod wave_doors;
mod weave_doors;
mod web_connector_doors;
mod web_fetch_doors;
mod widen_proposal_doors;
mod wire_health_doors;

pub(crate) use admission_doors::{admission_observer, call_verb};
pub(crate) use asr_doors::AsrSessions;
pub(crate) use call_context::{FacadeCall, FacadeCallOutput};
use call_context::{VerbContext, context_required, facade_invocation_id};
pub(crate) use connector_call_doors::{
    connector_answer_as, connector_call_listing_as, connector_call_listing_on,
};
pub(crate) use export_transfer::ExportTransfers;
pub(crate) use hooks::*;
pub(crate) use host_doors::ai_speech_for_run;
pub(crate) use host_doors::{
    ai_media_as_owner, ai_media_for_run, ai_options_for_program, ai_video_as_owner,
    ai_video_cancel_as_owner, ai_video_cancel_for_run, ai_video_for_run, ai_video_poll_as_owner,
    ai_video_poll_for_run, vault_hooks_replay_as_owner,
};
pub(crate) use identity::*;
pub(crate) use invocations::*;
use invoke::*;
pub(crate) use model_stream_doors::ModelStreams;
use output::*;
use receipts::*;
pub(crate) use release::*;
pub(crate) use secret_use_doors::self_use_as;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Request, State};
use axum::http::{Extensions, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use oneiron::receipt::{CallOutcome, CallReceiptInput, CallTransport};
use serde::Serialize;

use super::call_receipt;
use crate::auth::{CoreAuth, CoreScope};
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::claim::{CallerLocality, ScopedReadActorKey};
use oneiron::federation::record_scope::BirthPosition;
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::memory::RewriteAdmit;
use oneiron::memory::caps::MAX_REMOTE_REQUEST_BYTES;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_LEASE_REQUIRED, MEMORY_CODE_MODEL_UNAVAILABLE,
    MEMORY_CODE_NOT_FOUND, MEMORY_CODE_OFF_RECORD_SESSION_DOOR, MEMORY_CODE_OWNER_BINDING_REQUIRED,
    MEMORY_CODE_PENDING_ASK, MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER, MemoryError,
};
use oneiron::runtime_hooks::verb::{
    HOOK_RESULT_NOT_RETAINED, InvocationClaim, InvocationEntry, InvocationOutcome,
    VerbAskCredential, VerbAskDoor, VerbAskDrainPermit, VerbAskRefusal,
};
use oneiron::runtime_hooks::{InvocationId, VerbCall, VerbHookPre, VerbHookStop, hook_class};
use oneiron::task_verb::verb_hook_boundary;
use oneiron::{EdgeActorClass, EntityId};

use super::credential_memory;
use super::write_facet::{SESSION_HEADER, landing_facet};
use super::{host_action, owner_routes, pairing, scoped_read_for_core_auth};

/// Request-body ceiling for the facade nest: 64 MiB.
///
/// Sized for the largest legal blob append (32 MiB raw) once base64 and JSON
/// framing are paid for. Applied as a layer on THIS router, so the limit is a
/// property of the facade projection and no other route's body handling moves.
const FACADE_MAX_BODY_BYTES: usize = MAX_REMOTE_REQUEST_BYTES;

/// The facade route table.
///
/// Exactly one row per verb, all `POST`: the read verbs carry structured
/// request bodies (`vault.recall` has five inputs), and `/v1/core`'s own read
/// routes — `/query`, `/context-pack`, `/hydrate` — already post their
/// requests for the same reason. One method per verb also keeps the route
/// census a flat list a contract test can compare against the catalog.
pub(crate) fn facade_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .merge(agent_verbs::routes())
        .fallback(facade_unknown_verb)
        .layer(DefaultBodyLimit::max(FACADE_MAX_BODY_BYTES))
}

/// The anonymous-chat SDK route, mounted with the existing standalone
/// handler outside invocation claims, wire telemetry and call receipts.
pub(crate) fn anonymous_chat_routes() -> Router<Arc<SyncServer>> {
    agent_verbs::anonymous_chat_routes().layer(DefaultBodyLimit::max(FACADE_MAX_BODY_BYTES))
}

/// [`facade_routes`] with every reply's call receipt (OF-538): one layer
/// around the generated routes and the unknown-verb fallback alike. Inside
/// it, a request that names its invocation claims it for the whole route.
pub(crate) fn recorded_facade_routes(server: Arc<SyncServer>) -> Router<Arc<SyncServer>> {
    facade_routes()
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&server),
            facade_invocation_claim,
        ))
        .layer(axum::middleware::from_fn_with_state(
            server,
            facade_call_receipt,
        ))
}

/// A facade path that names no verb. One naming a canonical verb under the
/// wrong root is refused with that verb as its correction, before the actor,
/// the body or any effect is touched; there is no redirect and no alias.
async fn facade_unknown_verb(uri: axum::http::Uri) -> FacadeApiError {
    unknown_verb(uri.path().trim_start_matches('/'))
}

/// Every generated facade route ([`agent_verbs`]): the request's credential
/// and headers are the call's context, its JSON body the verb's input, and
/// the row runs in the facade's dispatch ([`call_verb`]), which the held
/// socket runs too. A body that is not JSON is refused where the row reads
/// it, as its handler refused it before. Its answer meets one destination
/// release before it is sent ([`released_reply`], FIX 8170). What its answer
/// holds (a deck preview's renderer) is kept until the reply's body is
/// encoded (FIX 8238). The owner's clock repair the binding door left
/// unjudged runs with its caller judged in its own writer (FIX 11190).
async fn facade_route(
    caller: clock_ingress::FacadeCaller,
    State(server): State<Arc<SyncServer>>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let auth = match caller {
        clock_ingress::FacadeCaller::Credential(auth) => auth,
        clock_ingress::FacadeCaller::ClockRepair(caller) => {
            return clock_ingress::repair_reply(&server, caller, facade_json(payload)).await;
        }
    };
    super::answer_hold::until_encoded(async move {
        let call = FacadeCall::http(&server, &auth, &headers, &extensions);
        let verb = uri.path().trim_start_matches('/');
        // A wiped custody body's value, scoped for its door (FIX 11442).
        let secret = extensions
            .get::<secret_body::FacadeSecret>()
            .map(secret_body::FacadeSecret::secret);
        let input = facade_json(payload);
        let output = match secret {
            Some(secret) => {
                secret_body::scope_secret(secret, call_verb(&server, &call, verb, input)).await
            }
            None => call_verb(&server, &call, verb, input).await,
        };
        match output {
            Ok(output) => released_reply(&server, &auth, verb, output).into_response(),
            Err(refused) => refused.into_response(),
        }
    })
    .await
}

/// `verb`, which names no facade verb, refused before the actor, the input
/// or any effect is touched: with its correction when it is a canonical verb
/// under the wrong root, else as not found.
fn unknown_verb(verb: &str) -> FacadeApiError {
    let served = oneiron::task_verb::sdk::AgentVerb::ALL
        .iter()
        .filter(|verb| verb.is_facade())
        .map(|verb| verb.as_str());
    match oneiron::task_verb::sdk::wrong_root_in(verb, served) {
        Some(refusal) => refusal.into(),
        None => FacadeApiError::new(
            StatusCode::NOT_FOUND,
            MEMORY_CODE_NOT_FOUND,
            format!("`{verb}` is not an SDK verb"),
            ["Use a verb from the SDK catalog."],
        ),
    }
}

/// A facade failure on its way to the wire.
///
/// Carries the RAW engine code string, never [`crate::error::ErrorCode`]. An
/// engine code this server has never heard of still reaches the client spelled
/// the way the engine spelled it; only the HTTP status is this file's opinion.
#[derive(Clone, Debug)]
pub(crate) struct FacadeApiError {
    status: StatusCode,
    body: FacadeErrorEnvelope,
}

/// `{error: {...}}`, the same transport envelope shape `/v1/core` uses,
/// with the read receipt beside the error when a read verb refused.
#[derive(Clone, Debug, Serialize)]
struct FacadeErrorEnvelope {
    error: FacadeErrorBody,
    /// Boxed so the refusal stays small on every `Result` that carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    narrowing: Option<Box<oneiron::claim::ScopedReadReceipt>>,
}

/// The facade error payload: `{code, message, requestId, suggestions}`.
///
/// `code` is a `String` and that is the load-bearing difference from
/// [`crate::error::ApiErrorEnvelopeBody`]. `details` is absent because the
/// engine vocabulary has no per-code detail variants to project.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FacadeErrorBody {
    code: String,
    message: String,
    request_id: String,
    suggestions: Vec<String>,
    /// The lasting receipt of the call this refusal answered (OF-538),
    /// `call:<32hex>`, resolvable through `vault.receipts.get`. Set by the
    /// facade's receipt layer once the call is recorded; absent for a call
    /// that has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_ref: Option<String>,
    /// A `WRONG_ROOT` refusal's `{attempted, replacement, schemaRef}`.
    #[serde(flatten)]
    wrong_root: Option<Box<oneiron::memory::MemoryWrongRoot>>,
    /// A verb hook's stop (ARCH-0080 §3): skipped with its reason, pending
    /// on an ask with the invocation and the ask, or hidden.
    #[serde(skip_serializing_if = "Option::is_none")]
    hook: Option<Box<VerbHookStop>>,
    /// When to call again, in seconds, on a refusal no provider answered
    /// (FIX 3194); the reply carries it as `Retry-After` too.
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<u64>,
    /// Each time the refused call's limit resets, as Unix seconds, when its
    /// source said (FIX 8190).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    resets_at: Vec<u64>,
    /// The refusal's stable reason codes, in its producer's order, when it
    /// named any (FIX 7398).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reason_codes: Vec<String>,
    /// A failed run's program type feedback (FIX 10389), beside the refusal
    /// and never among its words: each item released whole, or withheld
    /// with none of its text when its own release check holds it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    program_steps: Vec<oneiron::code_run::ProgramStepFeedbackRelease>,
}

/// The OpenAPI mirror of a facade refusal's body ([`FacadeErrorEnvelope`]):
/// the engine's `MemoryError` as the wire carries it, `code` spelled as the
/// engine spells it. A route that answers with [`FacadeApiError`] names it as
/// that refusal's body.
#[derive(utoipa::ToSchema)]
#[expect(
    dead_code,
    reason = "OpenAPI schema mirror; a refusal serializes FacadeErrorEnvelope"
)]
pub(crate) struct MemoryErrorEnvelopeSchema {
    error: MemoryErrorBodySchema,
    narrowing: Option<crate::api::read_receipt::ReadReceiptSchema>,
}

/// The OpenAPI mirror of [`FacadeErrorBody`].
#[derive(utoipa::ToSchema)]
#[expect(
    dead_code,
    reason = "OpenAPI schema mirror; a refusal serializes FacadeErrorBody"
)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemoryErrorBodySchema {
    code: String,
    message: String,
    request_id: String,
    suggestions: Vec<String>,
    receipt_ref: Option<String>,
    retry_after: Option<u64>,
    resets_at: Option<Vec<u64>>,
    reason_codes: Option<Vec<String>>,
    #[schema(value_type = Option<Vec<Object>>)]
    program_steps: Option<Vec<serde_json::Value>>,
}
