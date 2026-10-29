//! `/v1/owner/conversation-learning/setup`: a shared vault's one training
//! question, asked once at setup (OF-420 T3). The owner's canon: the admin is
//! asked once at vault setup, and the setting stays off until turned on;
//! private worlds never count.
//!
//! - `GET` answers where the question stands: `unshared`; `pending`, with its
//!   `question_ref` and when it was asked; or `answered`, with the answer,
//!   who gave it, the setting act and revision it left and when. Every reply
//!   carries the setting's current revision as `seen`. A pending question
//!   reads the same until it is answered, and reading consumes nothing.
//! - `PUT` takes `{ question_ref, on, seen }`, all required (a body missing
//!   one is a bad request): yes turns the setting on with people not allowed
//!   to opt out, no signs it off. The same answer again returns the recorded
//!   one; a different one is refused as already answered, and the setting's
//!   own door (`PUT /v1/owner/conversation-learning`) changes it from then
//!   on.
//!
//! The caller is the person their proof names, as on the setting's own door
//! ([`super::world_privacy_routes::holder`]): no agent reaches these routes,
//! a read slip never answers, and the engine judges the admin in its own
//! transaction on both. A stale `seen` is a conflict, never a silent
//! overwrite, and leaves the question pending.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::get;
use oneiron::error::RecordError;
use oneiron::federation::{
    SharedTrainingSetup, SharedTrainingSetupAnswer, SharedTrainingSetupQuestion,
};
use oneiron::world_keys::PolicyRevision;
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface_admitted, parse_revision, revision_hex};
use super::world_privacy_routes::holder;
use super::{OwnerReply, blocking};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::{CoreAuth, CoreScope};
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

/// The grant a person who does not own the vault needs on their own slip to
/// read the question, as for the setting's own reads.
const SETUP_READS: CoreScope = CoreScope::Read;
/// The grant they need on it to answer, as for the setting's own acts; the
/// engine then judges who may.
const SETUP_ACTS: CoreScope = CoreScope::Write;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/conversation-learning/setup", get(view).put(answer))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct AnswerSetup {
    /// The pending question's `question_ref`, as 64 hex. Required.
    question_ref: String,
    /// Yes or no: whether the vault's conversations count for training.
    /// Required.
    on: bool,
    /// The revision the surface showed the admin, as 64 hex. Required.
    seen: String,
}

/// Where the setup question stands, with the setting's current revision.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
enum SetupReply {
    /// The vault was never shared: there is no setup question.
    Unshared {
        /// The setting's current revision, 64 hex.
        seen: String,
    },
    /// Asked and not yet answered.
    Pending {
        /// The question to answer, 64 hex.
        question_ref: String,
        /// When it was asked, in seconds on the vault's clock.
        created_at: u64,
        /// Present back as `seen`, 64 hex.
        seen: String,
    },
    /// Answered: the setting's own door changes it from now on.
    Answered {
        /// Whether the answer turned the setting on.
        on: bool,
        /// The admin who answered, 32 hex; null when the answering choice's
        /// row is not stored here.
        answered_by: Option<String>,
        /// The setting act that answered it, 64 hex.
        setting_act: String,
        /// The setting revision that act left, 64 hex.
        setting_revision: String,
        /// When it was answered, in seconds on the vault's clock.
        answered_at: u64,
        /// The setting's current revision, 64 hex.
        seen: String,
    },
}

fn setup_reply(question: &SharedTrainingSetupQuestion) -> SetupReply {
    let seen = revision_hex(&question.seen.0);
    match &question.setup {
        None => SetupReply::Unshared { seen },
        Some(SharedTrainingSetup::Pending {
            question_ref,
            created_at,
        }) => SetupReply::Pending {
            question_ref: revision_hex(question_ref),
            created_at: *created_at,
            seen,
        },
        Some(SharedTrainingSetup::Answered {
            on,
            answered_by,
            setting_act,
            setting_revision,
            answered_at,
        }) => SetupReply::Answered {
            on: *on,
            answered_by: answered_by.as_ref().map(oneiron::EntityId::to_hex),
            setting_act: revision_hex(setting_act),
            setting_revision: revision_hex(&setting_revision.0),
            answered_at: *answered_at,
            seen,
        },
    }
}

/// The OpenAPI schema of `PUT /v1/owner/conversation-learning/setup`'s body (FIX 11611):
/// [`AnswerSetup`].
pub(crate) fn answer_setup_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<AnswerSetup>()
}

/// The OpenAPI schema of `PUT /v1/owner/conversation-learning/setup`'s answer (FIX 11611):
/// [`SetupReply`].
pub(crate) fn setup_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SetupReply>()
}

/// The engine's typed refusals as the caller's: a stale `seen` is a change
/// since their review; a question the vault does not hold is a bad request;
/// a caller who is no admin, a vault never shared, a question already
/// answered, conflicting setting choices, or an answer this install cannot
/// carry or does not count is a refusal naming its rule. Proof failures stay
/// the owner door's 403.
fn refusal(error: oneiron::Error) -> OwnerError {
    match error {
        oneiron::Error::ConcurrentWrite(_) => OwnerError::Changed(error.to_string()),
        oneiron::Error::InvalidConfig(message) => OwnerError::Invalid(message),
        oneiron::Error::Record(RecordError::AuthorityRefused(_)) => {
            OwnerError::Refused(error.to_string())
        }
        error => OwnerError::Engine(Box::new(error)),
    }
}

/// `GET /v1/owner/conversation-learning/setup`: where the vault's setup
/// training question stands, for its admin.
async fn view(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<SetupReply> {
    let person = holder(&auth, &server, SETUP_READS)?;
    let reply = blocking(move || -> OwnerResult<SetupReply> {
        let question = server
            .vault()
            .shared_training_setup_status(&person)
            .map_err(refusal)?;
        Ok(setup_reply(&question))
    })
    .await?;
    Ok(Json(reply))
}

/// `PUT /v1/owner/conversation-learning/setup`: the vault's admin answers
/// it, as their own act from this surface.
async fn answer(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AnswerSetup>,
) -> OwnerReply<SetupReply> {
    let person = holder(&auth, &server, SETUP_ACTS)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<SetupReply> {
        let given = SharedTrainingSetupAnswer {
            question_ref: parse_revision("question_ref", &body.question_ref)?,
            on: body.on,
            seen: PolicyRevision(parse_revision("seen", &body.seen)?),
        };
        let question = server
            .vault()
            .answer_shared_training_setup(&person, surface, &given)
            .map_err(refusal)?;
        Ok(setup_reply(&question))
    })
    .await?;
    Ok(Json(reply))
}
