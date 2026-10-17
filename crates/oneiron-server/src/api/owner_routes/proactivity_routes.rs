//! `/v1/owner/proactivity`, `/v1/owner/stewardship` and
//! `/v1/owner/representation` (OF-194): the owner's read of a delivered
//! digest, their keep-in-touch rules, and the review of a drafted follow-up.
//! `/v1/owner/coach/training-offers` (OF-577) answers the Coach's offers the
//! inbox and digest deliver; an answer records an intent and applies nothing.
//! `/v1/owner/identity/asks` (OF-123) is the needs-you strip's identity asks,
//! each with its one-tap choice card, and their answers.
//! `/v1/owner/proactivity/action-mode` (OF-335) is the owner's action-mode
//! policy: the state-index window with its targets and the mode bands the
//! nightly refresh proposes from.
//! Approving a draft approves its exact content, then schedules it through
//! the ordinary outbound gate as the Dreamer on the owner's behalf; the
//! gate's grants, consent and windows still decide the send.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::dreamer_runner::maintenance::action_mode::ActionModePolicy;
use oneiron::dreamer_runner::maintenance::digest::ProactivityDigest;
use oneiron::dreamer_runner::maintenance::identity::{
    IdentityAskView, IdentityCardCopy, IdentitySettled,
};
use oneiron::dreamer_runner::maintenance::representation::{
    RepresentationCitation, RepresentationRequest, schedule_approved_representation,
};
use oneiron::dreamer_runner::maintenance::stewardship::{StewardshipRule, StewardshipRules};
use oneiron::memory::OutboundScheduleContext;
use oneiron::skill_optimize::{OfferAnswer, OfferAnswerRecord, TrainingOffer};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::stamp::now_unix_ms;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/proactivity/digest", get(read_digest))
        .route(
            "/proactivity/action-mode",
            get(action_mode).post(set_action_mode),
        )
        .route("/stewardship", get(stewardship).post(set_stewardship))
        .route("/representation", get(review_representation))
        .route("/representation/approve", post(approve_representation))
        .route("/representation/decline", post(decline_representation))
        .route("/coach/training-offers", get(training_offers))
        .route("/coach/training-offers/answer", post(answer_training_offer))
        .route("/identity/asks", get(identity_asks))
        .route("/identity/asks/answer", post(answer_identity_ask))
}

fn now_secs() -> u64 {
    now_unix_ms() / 1_000
}

/// A digest id, as 64 hex.
fn digest_id(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut id = [0_u8; 32];
    for (byte, pair) in id.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(id)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestQuery {
    /// A digest id from an inbox NOTIFICATION's `source.result`, as 64 hex;
    /// none reads the latest.
    #[serde(default)]
    id: Option<String>,
}

#[derive(Debug, Serialize)]
struct DigestView {
    id: String,
    digest: ProactivityDigest,
}

/// `GET /v1/owner/proactivity/digest`: one delivered digest, verified
/// against its id.
async fn read_digest(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<DigestQuery>, QueryRejection>,
) -> OwnerReply<Option<DigestView>> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let view = blocking(move || -> OwnerResult<Option<DigestView>> {
        let vault = server.vault();
        let digest = match query.id.as_deref() {
            None => vault.latest_proactivity_digest()?,
            Some(hex) => {
                let id = digest_id(hex)
                    .ok_or_else(|| OwnerError::Invalid("id must be a 64-hex digest id".into()))?;
                vault.read_proactivity_digest(id)?
            }
        };
        Ok(digest.map(|digest| DigestView {
            id: digest.id.iter().map(|byte| format!("{byte:02x}")).collect(),
            digest,
        }))
    })
    .await?;
    Ok(Json(view))
}

/// `GET /v1/owner/proactivity/action-mode`: the owner's action-mode policy.
async fn action_mode(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Option<ActionModePolicy>> {
    owner(&auth, &server)?;
    let policy = blocking(move || Ok(server.vault().action_mode_policy()?)).await?;
    Ok(Json(policy))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetActionMode {
    /// None clears the policy, and no night refreshes an index for it.
    policy: Option<ActionModePolicy>,
}

/// `POST /v1/owner/proactivity/action-mode`: replaces the whole policy.
async fn set_action_mode(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetActionMode>, JsonRejection>,
) -> OwnerReply<Option<ActionModePolicy>> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let policy = blocking(move || {
        Ok(server
            .vault()
            .set_action_mode_policy(&owner, request.policy)?)
    })
    .await?;
    Ok(Json(policy))
}

/// `GET /v1/owner/stewardship`: the owner's keep-in-touch rules.
async fn stewardship(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Option<StewardshipRules>> {
    owner(&auth, &server)?;
    let rules = blocking(move || Ok(server.vault().stewardship_rules()?)).await?;
    Ok(Json(rules))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetStewardship {
    rules: Vec<StewardshipRule>,
}

/// `POST /v1/owner/stewardship`: replaces the whole rule set.
async fn set_stewardship(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetStewardship>, JsonRejection>,
) -> OwnerReply<StewardshipRules> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let rules = blocking(move || {
        Ok(server
            .vault()
            .set_stewardship_rules(&owner, request.rules, now_secs())?)
    })
    .await?;
    Ok(Json(rules))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalQuery {
    /// A `dreamer.representation.proposal` claim id, as 32 hex.
    proposal: String,
}

#[derive(Debug, Serialize)]
struct RepresentationView {
    proposal: String,
    request: RepresentationRequest,
    /// The exact text an approval sends.
    content: String,
    evidence: Vec<RepresentationCitation>,
    voice: Vec<RepresentationCitation>,
}

/// `GET /v1/owner/representation`: one drafted follow-up, as approval would
/// send it.
async fn review_representation(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ProposalQuery>, QueryRejection>,
) -> OwnerReply<RepresentationView> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let view = blocking(move || -> OwnerResult<RepresentationView> {
        let vault = server.vault();
        let id = entity_id("proposal", &query.proposal)?;
        let review = vault.review_representation(&owner, &id)?;
        let bytes = oneiron::compaction::output::restore_output(vault, review.content())?;
        Ok(RepresentationView {
            proposal: id.to_hex(),
            request: review.request().clone(),
            content: String::from_utf8(bytes)
                .map_err(|_| OwnerError::Changed("the draft is not text".into()))?,
            evidence: review.evidence().to_vec(),
            voice: review.voice().to_vec(),
        })
    })
    .await?;
    Ok(Json(view))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveRepresentation {
    /// A proposal id from `GET /v1/owner/representation`. The id is the
    /// draft's content hash, so it names exactly the text reviewed.
    proposal: String,
    /// The owner's local offset, for the send's delivery window.
    #[serde(default)]
    utc_offset_minutes: Option<i16>,
    #[serde(default)]
    iana_timezone: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApprovedView {
    proposal: String,
    intent_ref: String,
    outcome: String,
    gate_outcome: Option<String>,
}

/// `POST /v1/owner/representation/approve`: approves the draft and schedules
/// it. The outbound gate still decides whether, and when, it goes.
async fn approve_representation(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ApproveRepresentation>, JsonRejection>,
) -> OwnerReply<ApprovedView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let view = blocking(move || -> OwnerResult<ApprovedView> {
        let vault = server.vault();
        let id = entity_id("proposal", &request.proposal)?;
        let now = now_secs();
        let review = vault.review_representation(&owner, &id)?;
        let approved = vault.approve_representation(&owner, &review, now)?;
        let facade = vault.memory(
            vault.dreamer_authority()?.entity_ref(),
            oneiron::EdgeActorClass::System,
        );
        let context = OutboundScheduleContext {
            utc_offset_minutes: request.utc_offset_minutes,
            iana_timezone: request.iana_timezone,
            ..OutboundScheduleContext::default()
        };
        let receipt = schedule_approved_representation(&facade, approved, &context, now)
            .map_err(|error| OwnerError::Refused(error.to_string()))?;
        Ok(ApprovedView {
            proposal: id.to_hex(),
            intent_ref: receipt.intent_ref,
            outcome: receipt.outcome,
            gate_outcome: receipt.gate_outcome,
        })
    })
    .await?;
    Ok(Json(view))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclineRepresentation {
    proposal: String,
}

/// `POST /v1/owner/representation/decline`: declines the draft for good.
async fn decline_representation(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<DeclineRepresentation>, JsonRejection>,
) -> OwnerReply<()> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    blocking(move || -> OwnerResult<()> {
        let vault = server.vault();
        let id = entity_id("proposal", &request.proposal)?;
        let review = vault.review_representation(&owner, &id)?;
        vault.decline_representation(&owner, &review, now_secs())?;
        Ok(())
    })
    .await?;
    Ok(Json(()))
}

/// `GET /v1/owner/coach/training-offers`: the offers awaiting the owner.
async fn training_offers(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<TrainingOffer>> {
    owner(&auth, &server)?;
    let offers = blocking(move || {
        Ok(oneiron::skill_optimize::pending_training_offers(
            server.vault(),
        )?)
    })
    .await?;
    Ok(Json(offers))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerTrainingOffer {
    /// An offer id, as 32 hex.
    offer: String,
    /// The offer's `digest`: the answer binds the snapshot shown.
    digest: String,
    answer: OfferAnswer,
}

/// `POST /v1/owner/coach/training-offers/answer`: the owner's answer to the
/// exact offer they saw.
async fn answer_training_offer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<AnswerTrainingOffer>, JsonRejection>,
) -> OwnerReply<OfferAnswerRecord> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let record = blocking(move || -> OwnerResult<OfferAnswerRecord> {
        let offer = entity_id("offer", &request.offer)?;
        Ok(oneiron::skill_optimize::settle_training_offer(
            server.vault(),
            &owner,
            &offer,
            &request.digest,
            request.answer,
            now_secs(),
        )?)
    })
    .await?;
    Ok(Json(record))
}

/// A choice card's words when the client names none; a client in another
/// language passes its own.
const IDENTITY_PROMPT: &str = "Who is this?";
const IDENTITY_SOMEONE_NEW: &str = "Someone new";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityCardQuery {
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    someone_new: Option<String>,
    /// A provisional candidate's button, with `{name}` and `{day}`.
    #[serde(default)]
    provisional: Option<String>,
}

#[derive(Debug, Serialize)]
struct IdentityAskCard {
    #[serde(flatten)]
    ask: IdentityAskView,
    card: oneiron::lens::GeneratedUiCard,
}

/// `GET /v1/owner/identity/asks`: every open identity ask, each with its
/// one-tap choice card. Asks still being decided carry `escalated_at: null`.
async fn identity_asks(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<IdentityCardQuery>, QueryRejection>,
) -> OwnerReply<Vec<IdentityAskCard>> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let copy = IdentityCardCopy {
        prompt: query.prompt.unwrap_or_else(|| IDENTITY_PROMPT.to_owned()),
        someone_new: query
            .someone_new
            .unwrap_or_else(|| IDENTITY_SOMEONE_NEW.to_owned()),
        provisional: query.provisional,
    };
    let asks = blocking(move || -> OwnerResult<Vec<IdentityAskCard>> {
        let vault = server.vault();
        let mut cards = Vec::new();
        for ask in vault.identity_asks()? {
            let card = vault.identity_card(&ask.ask, &copy)?;
            cards.push(IdentityAskCard { ask, card });
        }
        Ok(cards)
    })
    .await?;
    Ok(Json(asks))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerIdentityAsk {
    /// An ask, as 64 hex.
    ask: String,
    /// One of its options: `is:<id>` or `someone_new`.
    choice: String,
}

/// `POST /v1/owner/identity/asks/answer`: the owner's choice on one ask. The
/// mention takes it, and the words around it are saved as a hint.
async fn answer_identity_ask(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<AnswerIdentityAsk>, JsonRejection>,
) -> OwnerReply<IdentitySettled> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let settled = blocking(move || -> OwnerResult<IdentitySettled> {
        Ok(server
            .vault()
            .answer_identity_ask(&owner, &request.ask, &request.choice, now_secs())?)
    })
    .await?;
    Ok(Json(settled))
}
