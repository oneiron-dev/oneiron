//! `/v1/owner/conversation-learning`: a person reads and sets their own
//! "Learn from my conversations" choice (FIX 4489, OF-420). The owner's
//! ruling: real conversation text for training stays off until the PERSON
//! says yes, the yes can be scoped per world, and private worlds are never
//! included.
//!
//! Each person acts for themselves from whichever linked surface they are on:
//! the vault's owner through the owner door, or any other live person on
//! their own verified human slip ([`super::world_privacy_routes::holder`]).
//! The person is always the proof's own, never a body's id, and no agent
//! reaches these routes. The engine's door revalidates the person in the
//! writing transaction and signs the choice under this install's live
//! profile.
//!
//! `GET` answers the caller's choice, the worlds that count now, and the
//! revision a surface presents back as `seen`. `PUT` says yes for a list of
//! worlds, or turns it off: a missing, `null` or empty `worlds` is off (CALLS
//! "FIX 4489 conversation-learning PUT body"). A stale `seen` is a conflict,
//! never a silent overwrite; a world that is not live or not read everywhere
//! refuses the whole put, naming it.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::get;
use oneiron::authority::ConversationTrainingView;
use oneiron::error::RecordError;
use oneiron::feedback::{
    PersonTrainingControl, PersonTrainingReceipts, PersonTrainingSubmission, TrainingReceiptsCursor,
};
use oneiron::world_keys::PolicyRevision;
use oneiron_vault_contract::conversation_training::TrainingReceiptStatusV1;
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface, parse_revision, revision_hex};
use super::world_privacy_routes::holder;
use super::{OwnerReply, blocking};
use crate::api::{json_payload, query_params};
use crate::auth::{CoreAuth, CoreScope};
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// The grant a person who does not own the vault needs on their own slip to
/// read their choice (CALLS "FIX 4489 conversation-learning scope").
const LEARNING_READS: CoreScope = CoreScope::Read;
/// The grant they need on it to set it (CALLS "FIX 4489
/// conversation-learning scope").
const LEARNING_ACTS: CoreScope = CoreScope::Write;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/conversation-learning", get(view).put(set))
        .route("/conversation-learning/receipts", get(receipts))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetLearning {
    /// The worlds to learn from, each 32 hex (base reality included); none,
    /// `null` or an empty list turns it off.
    #[serde(default)]
    worlds: Option<Vec<String>>,
    /// The revision the surface showed the person, as 64 hex; none takes the
    /// current one.
    #[serde(default)]
    seen: Option<String>,
}

#[derive(Debug, Serialize)]
struct LearningReply {
    /// The person whose choice this is, as 32 hex: the proof's own.
    person: String,
    /// Whether any of the person's conversations count for training now.
    on: bool,
    /// The worlds that count now, 32 hex each: the choice in force less every
    /// world no longer live or no longer read everywhere; empty when off.
    worlds: Vec<String>,
    /// The worlds the choice in force names, as signed; null when it is off,
    /// no choice counts, or the person's live choices conflict.
    chosen: Option<Vec<String>>,
    /// Present back as `seen`, 64 hex; zero while no choice is live.
    revision: String,
    /// The person's live choices conflict: it reads as off until a choice
    /// that saw them all supersedes them.
    conflicted: bool,
    /// The authority entry of the choice in force, 64 hex; null while none
    /// counts or the choices conflict.
    act: Option<String>,
}

fn hex_ids(ids: &BTreeSet<oneiron::EntityId>) -> Vec<String> {
    ids.iter().map(oneiron::EntityId::to_hex).collect()
}

fn reply(view: &ConversationTrainingView) -> LearningReply {
    LearningReply {
        person: view.person.to_hex(),
        on: view.worlds.is_some(),
        worlds: view.worlds.as_ref().map(hex_ids).unwrap_or_default(),
        chosen: view.chosen.as_ref().map(hex_ids),
        revision: revision_hex(&view.revision.0),
        conflicted: view.conflicted,
        act: view.act.as_ref().map(revision_hex),
    }
}

/// The engine's typed refusals as the person's: a stale revision is a change
/// since their review; a world that may not be listed is a bad request naming
/// it; a choice this install cannot carry or does not count is a refusal
/// naming its rule. Proof failures stay the owner door's 403.
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

/// `GET /v1/owner/conversation-learning`: the caller's own choice.
async fn view(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<LearningReply> {
    let person = holder(&auth, &server, LEARNING_READS)?;
    let answer = blocking(move || -> OwnerResult<LearningReply> {
        let view = server
            .vault()
            .conversation_training_view(&person)
            .map_err(refusal)?;
        Ok(reply(&view))
    })
    .await?;
    Ok(Json(answer))
}

/// `PUT /v1/owner/conversation-learning`: the caller says yes for `worlds`,
/// or turns it off, as their own act from this surface.
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
        let worlds = body
            .worlds
            .iter()
            .flatten()
            .map(|world| entity_id("world", world))
            .collect::<OwnerResult<BTreeSet<_>>>()?;
        let seen = body
            .seen
            .as_deref()
            .map(|seen| parse_revision("seen", seen).map(PolicyRevision))
            .transpose()?;
        let view = server
            .vault()
            .set_conversation_training(&person, surface, Some(worlds), seen)
            .map_err(refusal)?;
        Ok(reply(&view))
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
    /// The withdrawals the person's own choice recorded: off, or fewer
    /// worlds.
    controls: Vec<ControlReceipt>,
    /// The submissions of the person's words.
    submissions: Vec<SubmissionReceipt>,
    /// Present back as `after` for the rest; null on the last page.
    next: Option<String>,
}

#[derive(Debug, Serialize)]
struct ControlReceipt {
    /// The control, as 32 hex.
    id: String,
    /// The worlds the choice still counts, 32 hex each; null is off.
    worlds: Option<Vec<String>>,
    /// Whether its file was written to the outbox.
    written: bool,
    /// The intake's last receipt for it (`stored`, `excluded`,
    /// `removal_pending`, `removed` or `rejected`); null while none came.
    receipt: Option<TrainingReceiptStatusV1>,
    /// What a withdrawal reaches: runs that start after the intake has it.
    withdrawal_note: &'static str,
    /// When it was recorded, unix seconds.
    recorded_at: u64,
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
    /// The intake's last receipt for it; null while none came.
    receipt: Option<TrainingReceiptStatusV1>,
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
        controls: page.controls.into_iter().map(control_receipt).collect(),
        submissions: page
            .submissions
            .into_iter()
            .map(submission_receipt)
            .collect(),
        next: page.next.as_ref().map(TrainingReceiptsCursor::to_hex),
    }
}

fn control_receipt(control: PersonTrainingControl) -> ControlReceipt {
    ControlReceipt {
        id: control.id.to_hex(),
        worlds: control.worlds.as_ref().map(hex_ids),
        written: control.written,
        receipt: control.receipt,
        withdrawal_note: control.withdrawal_note,
        recorded_at: control.recorded_at,
    }
}

fn submission_receipt(submission: PersonTrainingSubmission) -> SubmissionReceipt {
    SubmissionReceipt {
        id: submission.id.to_hex(),
        source: submission.source.to_hex(),
        worlds: hex_ids(&submission.worlds),
        custody: submission.custody.as_str(),
        receipt: submission.receipt,
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

/// `GET /v1/owner/conversation-learning/receipts?after=<next>`: one page of
/// the caller's own publisher training receipts, read for the person their
/// proof names as the `GET` above is. Only rows that name them are listed;
/// the page's `next`, passed back as `after`, reads the rest.
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
