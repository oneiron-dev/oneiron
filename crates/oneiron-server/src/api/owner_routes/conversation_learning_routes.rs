//! `/v1/owner/conversation-learning`: the vault's "Learn from my
//! conversations" setting, and each person's own opt-out (FIX 4489, FIX 5502
//! owner rulings, OF-420). The owner's rulings (10-19): one setting per
//! vault, set by its admin and off until the admin turns it on; while it is
//! on, everything in the vault counts, people, agents and guests alike, and
//! private worlds never do. The admin may let people opt out; then a person
//! may leave their own messages out. Turning it off, or opting out, stops new
//! sharing and withdraws nothing already shared.
//!
//! The caller is the person their proof names, from whichever linked
//! surface they are on: the vault's owner through the owner door, or any
//! other live person on their own verified human slip
//! ([`super::world_privacy_routes::holder`]). The person is always the
//! proof's own, never a body's id, and no agent reaches these routes. The
//! engine's doors revalidate the person in their own transaction and sign
//! under this install's live profile.
//!
//! - `GET /conversation-learning` answers the setting (on, whether people
//!   may opt out, the revision a surface presents back as `seen`, who set
//!   it and the one line a member's surface shows) to a live member,
//!   delegate or guest. `PUT` takes `{ on, allow_opt_out, seen }`, both
//!   flags required (a body missing one is a bad request, never a silent
//!   change); only the vault's admin sets it, the engine's writer judging
//!   that in its transaction.
//! - `GET /conversation-learning/me` answers the caller's own opt-out;
//!   `PUT` takes `{ leave_out, seen }`, `leave_out` required. While the
//!   vault does not let people opt out it is refused ("this vault does not
//!   allow opt-outs"), and a choice already made is kept and ignored.
//!
//! A stale `seen` is a conflict, never a silent overwrite.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::get;
use oneiron::authority::{ConversationLearningView, ConversationTrainingView};
use oneiron::error::RecordError;
use oneiron::feedback::{
    AnonymousReceiptView, PersonTrainingReceipts, PersonTrainingSubmission, PieceFilesProblem,
    TrainingPieceState, TrainingReceiptsCursor,
};
use oneiron::world_keys::PolicyRevision;
use oneiron_vault_contract::conversation_training::TrainingReceiptStatusV2;
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface, parse_revision, revision_hex};
use super::world_privacy_routes::holder;
use super::{OwnerReply, blocking};
use crate::api::{json_payload, query_params};
use crate::auth::{CoreAuth, CoreScope};
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

/// The grant a person who does not own the vault needs on their own slip to
/// read the setting or their opt-out (CALLS "FIX 4489 conversation-learning
/// scope").
const LEARNING_READS: CoreScope = CoreScope::Read;
/// The grant they need on it to set either (CALLS "FIX 4489
/// conversation-learning scope"); the engine's writer then judges who may.
const LEARNING_ACTS: CoreScope = CoreScope::Write;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/conversation-learning", get(view).put(set))
        .route("/conversation-learning/me", get(own_view).put(set_own))
        .route("/conversation-learning/receipts", get(receipts))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetLearning {
    /// Whether the vault's conversations count for training. Required.
    on: bool,
    /// Whether people may leave their own messages out. Required.
    allow_opt_out: bool,
    /// The revision the surface showed the admin, as 64 hex; none takes the
    /// current one.
    #[serde(default)]
    seen: Option<String>,
}

#[derive(Debug, Serialize)]
struct LearningReply {
    /// Whether the setting is on now. No choice, an off and a conflict read
    /// as off.
    on: bool,
    /// Whether people may leave their own messages out now.
    allow_opt_out: bool,
    /// Present back as `seen`, 64 hex; zero while no choice is live.
    revision: String,
    /// The live setting choices conflict: it reads as off until a choice
    /// that saw them all supersedes them.
    conflicted: bool,
    /// The authority entry of the choice in force, 64 hex; null while none
    /// counts or the choices conflict.
    act: Option<String>,
    /// The admin who set it, as 32 hex; null while no choice counts.
    set_by: Option<String>,
    /// The one read-only line a member's surface shows while it is on; null
    /// while off.
    line: Option<String>,
}

fn reply(view: &ConversationLearningView) -> LearningReply {
    LearningReply {
        on: view.on,
        allow_opt_out: view.allow_opt_out,
        revision: revision_hex(&view.revision.0),
        conflicted: view.conflicted,
        act: view.act.as_ref().map(revision_hex),
        set_by: view.set_by.as_ref().map(oneiron::EntityId::to_hex),
        line: view.line.clone(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetOwn {
    /// Whether the caller's own messages are left out. Required.
    leave_out: bool,
    /// The revision the surface showed the person, as 64 hex; none takes the
    /// current one.
    #[serde(default)]
    seen: Option<String>,
}

#[derive(Debug, Serialize)]
struct OwnReply {
    /// The person whose opt-out this is, as 32 hex: the proof's own.
    person: String,
    /// Whether they asked to leave their own messages out.
    leave_out: bool,
    /// Whether the vault lets people opt out now; while it does not,
    /// `leave_out` is kept and ignored.
    allowed: bool,
    /// Present back as `seen`, 64 hex; zero while no choice is live.
    revision: String,
    /// The person's live choices conflict: it reads as left out until a
    /// choice that saw them all supersedes them.
    conflicted: bool,
    /// The authority entry of the choice in force, 64 hex; null while none
    /// counts or the choices conflict.
    act: Option<String>,
}

fn own_reply(view: &ConversationTrainingView) -> OwnReply {
    OwnReply {
        person: view.person.to_hex(),
        leave_out: view.leave_out,
        allowed: view.allowed,
        revision: revision_hex(&view.revision.0),
        conflicted: view.conflicted,
        act: view.act.as_ref().map(revision_hex),
    }
}

/// The engine's typed refusals as the caller's: a stale revision is a change
/// since their review; a caller who is no admin, a vault that does not allow
/// opt-outs, or a choice this install cannot carry or does not count is a
/// refusal naming its rule. Proof failures stay the owner door's 403.
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

/// The `seen` a body carries, as a revision.
fn seen_revision(seen: Option<&str>) -> OwnerResult<Option<PolicyRevision>> {
    seen.map(|seen| parse_revision("seen", seen).map(PolicyRevision))
        .transpose()
}

/// `GET /v1/owner/conversation-learning`: the vault's setting, for a live
/// member, delegate or guest.
async fn view(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<LearningReply> {
    let person = holder(&auth, &server, LEARNING_READS)?;
    let answer = blocking(move || -> OwnerResult<LearningReply> {
        let view = server
            .vault()
            .conversation_learning_view(&person)
            .map_err(refusal)?;
        Ok(reply(&view))
    })
    .await?;
    Ok(Json(answer))
}

/// `PUT /v1/owner/conversation-learning`: the vault's admin sets it, as
/// their own act from this surface.
async fn set(
    auth: CoreAuth,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetLearning>, JsonRejection>,
) -> OwnerReply<LearningReply> {
    let person = holder(&auth, &server, LEARNING_ACTS)?;
    let surface = act_surface(&server, &auth, &headers);
    let body = json_payload(payload)?;
    let answer = blocking(move || -> OwnerResult<LearningReply> {
        let seen = seen_revision(body.seen.as_deref())?;
        let view = server
            .vault()
            .set_conversation_learning(&person, surface, body.on, body.allow_opt_out, seen)
            .map_err(refusal)?;
        Ok(reply(&view))
    })
    .await?;
    Ok(Json(answer))
}

/// `GET /v1/owner/conversation-learning/me`: the caller's own opt-out.
async fn own_view(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<OwnReply> {
    let person = holder(&auth, &server, LEARNING_READS)?;
    let answer = blocking(move || -> OwnerResult<OwnReply> {
        let view = server
            .vault()
            .conversation_training_view(&person)
            .map_err(refusal)?;
        Ok(own_reply(&view))
    })
    .await?;
    Ok(Json(answer))
}

/// `PUT /v1/owner/conversation-learning/me`: the caller leaves their own
/// messages out, or lets them back in, as their own act from this surface.
async fn set_own(
    auth: CoreAuth,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetOwn>, JsonRejection>,
) -> OwnerReply<OwnReply> {
    let person = holder(&auth, &server, LEARNING_ACTS)?;
    let surface = act_surface(&server, &auth, &headers);
    let body = json_payload(payload)?;
    let answer = blocking(move || -> OwnerResult<OwnReply> {
        let seen = seen_revision(body.seen.as_deref())?;
        let view = server
            .vault()
            .set_conversation_training(&person, surface, body.leave_out, seen)
            .map_err(refusal)?;
        Ok(own_reply(&view))
    })
    .await?;
    Ok(Json(answer))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptsQuery {
    /// The `next` of the page before, as 34 hex; none starts at the first.
    #[serde(default)]
    after: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReceiptsReply {
    /// The person whose receipts these are, as 32 hex: the proof's own.
    person: String,
    /// The submissions carrying the person's words.
    submissions: Vec<SubmissionReceipt>,
    /// Present back as `after` for the rest; null on the last page.
    next: Option<String>,
}

#[derive(Debug, Serialize)]
struct SubmissionReceipt {
    /// The submission, as 32 hex.
    id: String,
    /// The conversation it was selected from, as 32 hex.
    source: String,
    /// The worlds its rows sit in, 32 hex each.
    worlds: Vec<String>,
    /// Where it stands here: `held`, `published`, `withheld` or `withdrawn`.
    custody: &'static str,
    /// The intake's last receipt for it (`stored`, `excluded`,
    /// `removal_pending`, `removed` or `rejected`); null while none came.
    receipt: Option<TrainingReceiptStatusV2>,
    /// Where its own signed receipts say it stands, for a piece that left
    /// through the anonymous training window (TL-6); null for a hosted one.
    /// It never names the piece's code or anyone else in it.
    anonymous: Option<AnonymousReceipt>,
    /// The runs the intake says used it.
    used_runs: Vec<UsedRun>,
    /// What a withdrawal reaches, once it is withdrawn or its removal is
    /// pending or done; null before.
    withdrawal_note: Option<&'static str>,
    /// When it was prepared, unix seconds.
    prepared_at: u64,
    /// When it was published, unix seconds; null while it never left.
    published_at: Option<u64>,
}

#[derive(Debug, Serialize)]
struct AnonymousReceipt {
    /// What the last signed receipt says (`uploading`, `accepted`,
    /// `rejected`, `conflict`, `invalid_submission`, `eligible`, `refused`,
    /// `removal_pending`, `removed` or `unknown`); null while none came.
    state: Option<&'static str>,
    /// That receipt's revision; 0 before any.
    revision: u64,
    /// The reason it gave, for a rejection or the re-filter's refusal.
    reason: Option<String>,
    /// When the intake signed it, unix seconds.
    at: Option<u64>,
    /// The sealed bytes the intake holds so far, while it uploads.
    progress: Option<u64>,
    /// A local problem with the piece's outbox files that keeps it from
    /// shipping (FIX 6916), while it is still to upload: `missing` or
    /// `mismatched`; null when none stands. It clears once a window ships.
    /// It names no file, path or code.
    files_problem: Option<&'static str>,
    /// When the shipper first found that problem, unix seconds; null when
    /// none stands.
    files_problem_since: Option<u64>,
}

#[derive(Debug, Serialize)]
struct UsedRun {
    /// The intake's run id.
    run_id: String,
    /// The model or checkpoint the run made.
    model: String,
    /// When it used the submission, unix seconds.
    used_at: u64,
}

fn receipts_reply(page: PersonTrainingReceipts) -> ReceiptsReply {
    ReceiptsReply {
        person: page.person.to_hex(),
        submissions: page
            .submissions
            .into_iter()
            .map(submission_receipt)
            .collect(),
        next: page.next.as_ref().map(TrainingReceiptsCursor::to_hex),
    }
}

fn submission_receipt(submission: PersonTrainingSubmission) -> SubmissionReceipt {
    SubmissionReceipt {
        id: submission.id.to_hex(),
        source: submission.source.to_hex(),
        worlds: submission
            .worlds
            .iter()
            .map(oneiron::EntityId::to_hex)
            .collect(),
        custody: submission.custody.as_str(),
        receipt: submission.receipt,
        anonymous: submission.anonymous.map(anonymous_receipt),
        used_runs: submission
            .used_runs
            .into_iter()
            .map(|run| UsedRun {
                run_id: run.run_id,
                model: run.model,
                used_at: run.used_at,
            })
            .collect(),
        withdrawal_note: submission.withdrawal_note,
        prepared_at: submission.prepared_at,
        published_at: submission.published_at,
    }
}

fn anonymous_receipt(view: AnonymousReceiptView) -> AnonymousReceipt {
    AnonymousReceipt {
        state: view.state.map(TrainingPieceState::as_str),
        revision: view.revision,
        reason: view.reason,
        at: view.at,
        progress: view.progress,
        files_problem: view.files_problem.map(PieceFilesProblem::as_str),
        files_problem_since: view.files_problem_since,
    }
}

/// `GET /v1/owner/conversation-learning/receipts?after=<next>`: one page of
/// the caller's own publisher training receipts, read for the person their
/// proof names as the `GET`s above are: the submissions carrying their
/// words, never anyone else's. The page's `next`, passed back as `after`,
/// reads the rest.
async fn receipts(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ReceiptsQuery>, QueryRejection>,
) -> OwnerReply<ReceiptsReply> {
    let person = holder(&auth, &server, LEARNING_READS)?;
    let query = query_params(query)?;
    let answer = blocking(move || -> OwnerResult<ReceiptsReply> {
        let after = query
            .after
            .as_deref()
            .map(|after| {
                TrainingReceiptsCursor::from_hex(after).ok_or_else(|| {
                    OwnerError::Invalid(
                        "after must be a receipts page's next, as 34 hex".to_owned(),
                    )
                })
            })
            .transpose()?;
        let page = server
            .vault()
            .conversation_training_receipts(&person, after)
            .map_err(refusal)?;
        Ok(receipts_reply(page))
    })
    .await?;
    Ok(Json(answer))
}
