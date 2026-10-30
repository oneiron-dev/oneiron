//! `/v1/owner/secrets/reveal*`: the owner's side of reveal by handle
//! (OF-560; ARCH-0069 #reveal-check). An agent asks for a secret's value for
//! its model (`reveal`); here the owner reads each ask with its card and the
//! digest it shows, and answers it once: `once`, `standing` (approve and stop
//! asking, on this connection × this class × this project) or `deny`. The
//! owner also reads a value on their own surface, with a reason the receipt
//! keeps. The value travels only in that reply's body, as standard base64;
//! nothing here logs it, and the engine writes every receipt.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use base64::Engine as _;
use oneiron::secret_custody::{
    RevealGrantScope, RevealTarget, SecretRevealAnswer, SecretRevealAnswered, SecretRevealAsk,
    SecretRevealReceipt,
};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// The most reveals one read lists.
const MAX_REVEALS_PAGE: usize = 200;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/secrets/reveals", get(reveals))
        .route("/secrets/reveals/answer", post(answer))
        .route("/secrets/reveal", post(reveal))
}

/// The OpenAPI schema of `POST /v1/owner/secrets/reveals/answer`'s body (FIX 11611):
/// [`AnswerReveal`].
pub(crate) fn answer_reveal_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<AnswerReveal>()
}

/// The OpenAPI schema of `POST /v1/owner/secrets/reveals/answer`'s answer (FIX 11611):
/// [`AnsweredView`].
pub(crate) fn reveal_answered_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<AnsweredView>()
}

/// The OpenAPI schema of `POST /v1/owner/secrets/reveal`'s body (FIX 11611): [`OwnerReveal`].
pub(crate) fn owner_reveal_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<OwnerReveal>()
}

/// The OpenAPI schema of `POST /v1/owner/secrets/reveal`'s answer (FIX 11611): [`RevealedView`].
pub(crate) fn revealed_view_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RevealedView>()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevealsQuery {
    /// Only the asks still waiting on an answer.
    #[serde(default)]
    pending: bool,
    /// At most this many, newest first; 50 when unset.
    #[serde(default)]
    limit: Option<usize>,
}

/// One reveal's receipt, as the owner reads it. It names the handle, never
/// the value.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ReceiptView {
    reveal: String,
    handle: String,
    class: String,
    why: String,
    reader: String,
    connection: Option<String>,
    provider: Option<String>,
    project: Option<String>,
    run: Option<String>,
    answered_by: Option<String>,
    /// The last consent act's Gate receipt, `gate:<hex>`.
    receipt_ref: Option<String>,
    lease: Option<String>,
    asked_at: u64,
    delivered_at: Option<u64>,
    /// The file an agent's read of a marked file named, as 32 hex.
    file: Option<String>,
    /// Why the reveal closed with no value, `None` otherwise (FIX 8350).
    cause: Option<String>,
    /// The reach of the standing grant that answered it (FIX 2354).
    scope: Option<&'static str>,
}

impl From<SecretRevealReceipt> for ReceiptView {
    fn from(receipt: SecretRevealReceipt) -> Self {
        Self {
            reveal: receipt.reveal.to_hex(),
            handle: receipt.handle,
            class: receipt.class,
            why: receipt.why,
            reader: receipt.reader,
            connection: receipt.connection,
            provider: receipt.provider,
            project: receipt.project.map(|project| project.to_hex()),
            run: receipt.run,
            answered_by: receipt.answered_by,
            receipt_ref: receipt
                .decision
                .map(|decision| format!("gate:{}", decision.to_hex())),
            lease: receipt.lease.map(|lease| lease.to_hex()),
            asked_at: receipt.asked_at,
            delivered_at: receipt.delivered_at,
            file: receipt.file.map(|file| file.to_hex()),
            cause: receipt.cause.map(|cause| cause.as_str().to_owned()),
            scope: receipt.scope.map(RevealGrantScope::as_str),
        }
    }
}

/// One reveal: its receipt, where it stands and, while it waits on the
/// owner, the card and the digest an answer sends back.
#[derive(Debug, Serialize)]
struct RevealView {
    #[serde(flatten)]
    receipt: ReceiptView,
    state: &'static str,
    expires_at: u64,
    /// The engine's line on where the value goes.
    disclosure: Option<String>,
    /// Lowercase hex; an answer sends exactly this back as `expected_digest`.
    expected_digest: Option<String>,
    /// The registry row a `standing` answer writes at its default reach.
    grant_ref: Option<String>,
    /// The reaches a `standing` answer may send as `scope`, the narrowest
    /// first (FIX 2354); empty for a repo file reveal, which sends
    /// `repo_scope`.
    scopes: Vec<&'static str>,
    card: Option<oneiron::genui::ConsentAskCard>,
}

impl From<SecretRevealAsk> for RevealView {
    fn from(ask: SecretRevealAsk) -> Self {
        Self {
            receipt: ask.receipt.into(),
            state: ask.state.as_str(),
            expires_at: ask.expires_at,
            disclosure: ask.disclosure,
            expected_digest: ask.once_digest.map(|digest| digest.to_hex()),
            grant_ref: ask.grant_ref,
            scopes: ask.scopes.into_iter().map(RevealGrantScope::as_str).collect(),
            card: ask.card,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Answer {
    Once,
    Standing,
    Deny,
}

impl From<Answer> for SecretRevealAnswer {
    fn from(answer: Answer) -> Self {
        match answer {
            Answer::Once => Self::Once,
            Answer::Standing => Self::Standing,
            Answer::Deny => Self::Deny,
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct AnswerReveal {
    /// The reveal, as 32 hex.
    reveal: String,
    /// The `expected_digest` the reveal was listed with.
    expected_digest: String,
    /// `once`, `standing` or `deny`.
    outcome: Answer,
    /// For a standing answer to a repo file reveal, its reach (FIX 9236):
    /// `file`, `file_task`, `repo` or `repo_task`. Absent: this file, until
    /// revoked.
    #[serde(default)]
    repo_scope: Option<oneiron::secret_custody::RepoFileRevealScope>,
    /// For a standing answer to any other reveal, its reach (FIX 2354):
    /// `project`, `every_project`, `task` or `run`, one of the reveal's
    /// `scopes`. Absent: this project.
    #[serde(default)]
    scope: RevealGrantScope,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct AnsweredView {
    reveal: String,
    outcome: &'static str,
    receipt_ref: String,
    /// The standing grant a `standing` answer wrote; revoke it in the
    /// consent registry.
    grant_ref: Option<String>,
    /// That grant's reach (FIX 2354); `None` for a repo file reveal's.
    scope: Option<&'static str>,
}

impl From<SecretRevealAnswered> for AnsweredView {
    fn from(answered: SecretRevealAnswered) -> Self {
        Self {
            reveal: answered.reveal.to_hex(),
            outcome: answered.answer.as_str(),
            receipt_ref: format!("gate:{}", answered.decision.to_hex()),
            grant_ref: answered.grant_ref,
            scope: answered.scope.map(RevealGrantScope::as_str),
        }
    }
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct OwnerReveal {
    /// The secret's handle, such as `sc12`; or `name`.
    #[serde(default)]
    handle: Option<String>,
    /// The secret's custody name; or `handle`.
    #[serde(default)]
    name: Option<String>,
    /// Why the owner reads it, one line of 1..=512 bytes; the receipt keeps it.
    reason: String,
}

/// The owner's read: the value, in this body only, and its receipt.
#[derive(Serialize, schemars::JsonSchema)]
struct RevealedView {
    value_base64: String,
    receipt: ReceiptView,
}

/// `GET /v1/owner/secrets/reveals?pending=true&limit=50`: the vault's
/// reveals, newest first, each with its receipt and, while it waits on the
/// owner, its ask card and digest. No value is read.
async fn reveals(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<RevealsQuery>, QueryRejection>,
) -> OwnerReply<Vec<RevealView>> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let limit = query.limit.unwrap_or(50).min(MAX_REVEALS_PAGE);
    let views = blocking(move || -> OwnerResult<Vec<RevealView>> {
        Ok(server
            .vault()
            .secret_reveals(&owner, query.pending, limit)?
            .into_iter()
            .map(RevealView::from)
            .collect())
    })
    .await?;
    Ok(Json(views))
}

/// `POST /v1/owner/secrets/reveals/answer`: the owner's answer to one asked
/// reveal, against the exact digest it was listed with. Each reveal is
/// answered once, while its window is open.
async fn answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AnswerReveal>,
) -> OwnerReply<AnsweredView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let answered = blocking(move || -> OwnerResult<AnsweredView> {
        let reveal = entity_id("reveal", &request.reveal)?;
        let digest = digest_bytes(&request.expected_digest)?;
        Ok(server
            .vault()
            .answer_secret_reveal_scoped(
                &owner,
                &reveal,
                &digest,
                request.outcome.into(),
                request.repo_scope,
                request.scope,
            )?
            .into())
    })
    .await?;
    Ok(Json(answered))
}

/// `POST /v1/owner/secrets/reveal` with `{"handle"}` or `{"name"}`, and
/// `"reason"`: the owner reads one secret's value. The reply carries it as
/// `value_base64`, beside the receipt that names the reason.
async fn reveal(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<OwnerReveal>,
) -> OwnerReply<RevealedView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let revealed = blocking(move || -> OwnerResult<RevealedView> {
        let target = match (request.handle, request.name) {
            (Some(handle), None) => RevealTarget::Handle(handle),
            (None, Some(name)) => RevealTarget::Name(name),
            _ => {
                return Err(OwnerError::Invalid(
                    "name the secret by exactly one of handle or name".to_owned(),
                ));
            }
        };
        let revealed = server
            .vault()
            .reveal_secret_as_owner(&owner, &target, &request.reason)?;
        Ok(RevealedView {
            value_base64: base64::engine::general_purpose::STANDARD.encode(&*revealed.value),
            receipt: revealed.receipt.into(),
        })
    })
    .await?;
    Ok(Json(revealed))
}

/// 64 lowercase hex to the 32-byte digest; anything else is refused whole.
fn digest_bytes(value: &str) -> OwnerResult<[u8; 32]> {
    let invalid = || OwnerError::Invalid("expected_digest must be 64 lowercase hex".to_owned());
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    let mut digest = [0_u8; 32];
    for (at, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[at * 2..at * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(digest)
}
