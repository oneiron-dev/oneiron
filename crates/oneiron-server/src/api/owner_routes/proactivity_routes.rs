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
//! `/v1/owner/self-heal/findings` (OF-418) lists one detector's raised T3
//! findings with the owner's labels and takes the owner's one label on each,
//! which a `t2` detector of the same family learns from.
//! `/v1/owner/self-heal/minted` is each family's T2 the detector pass
//! registered from those labels, and the closed-form T1 that graduated it.
//! `/v1/owner/coach/code-fixes` (OF-380) is the Coach's code-fix work on each
//! failure case: the class, the invented example's verdict and each
//! candidate's fixed or not-fixed result, with no text of the failure.
//! `/v1/owner/coach/judge-asks` (OF-420) is the judge's calibration asks:
//! the minutes a person funds for them, and their pick on a delivered one,
//! which becomes a label in the judged skill's anchor. The asks reach only
//! the person's own digest, which `/v1/owner/proactivity/digest/assemble`
//! assembles for them.
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
use oneiron::dreamer_runner::maintenance::code_fix::{CodeFixSettled, MAX_CODE_FIX_WORK};
use oneiron::dreamer_runner::maintenance::digest::ProactivityDigest;
use oneiron::dreamer_runner::maintenance::identity::{
    IdentityAskView, IdentityCardCopy, IdentitySettled,
};
use oneiron::dreamer_runner::maintenance::representation::{
    RepresentationCitation, RepresentationRequest, schedule_approved_representation,
};
use oneiron::dreamer_runner::maintenance::stewardship::{StewardshipRule, StewardshipRules};
use oneiron::failure_signals::CodeFixSource;
use oneiron::memory::OutboundScheduleContext;
use oneiron::self_heal::detector_pass::MAX_T3_FINDINGS;
use oneiron::self_heal::distillation::{MintedRegistration, ReviewedFinding};
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
        .route("/proactivity/digest/assemble", post(assemble_digest))
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
        .route("/coach/code-fixes", get(code_fixes))
        .route(
            "/coach/judge-asks/minutes",
            get(judge_ask_minutes).post(fund_judge_asks),
        )
        .route("/coach/judge-asks/pick", post(pick_judge_ask))
        .route("/identity/asks", get(identity_asks))
        .route("/identity/asks/answer", post(answer_identity_ask))
        .route("/self-heal/findings", get(self_heal_findings))
        .route("/self-heal/findings/label", post(label_self_heal_finding))
        .route("/self-heal/minted", get(self_heal_minted))
}

fn now_secs() -> u64 {
    now_unix_ms() / 1_000
}

/// A digest or ask id as 64 hex.
fn hex_id(id: &[u8; 32]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
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
    /// Each of the digest's `judge_asks`, by id as 64 hex and in order: a
    /// pick names one.
    judge_ask_ids: Vec<String>,
    digest: ProactivityDigest,
}

impl DigestView {
    fn new(digest: ProactivityDigest) -> Self {
        Self {
            id: hex_id(&digest.id),
            judge_ask_ids: digest
                .judge_asks
                .iter()
                .map(|ask| hex_id(&ask.id))
                .collect(),
            digest,
        }
    }
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
        Ok(digest.map(DigestView::new))
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/proactivity/digest/assemble`: the caller's own digest,
/// assembled now: what a due regular digest carries, and once a cadence
/// period the judge calibration asks their funded minutes buy, which no
/// other digest delivers. `null` when nothing is due.
async fn assemble_digest(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Option<DigestView>> {
    let owner = owner(&auth, &server)?;
    let view = blocking(move || -> OwnerResult<Option<DigestView>> {
        Ok(server
            .vault()
            .proactivity_digest(&owner, now_secs(), None)?
            .map(DigestView::new))
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeAskMinutes {
    minutes: u32,
}

/// `GET /v1/owner/coach/judge-asks/minutes`: the caller's remaining
/// judge-ask minutes; zero until they fund some.
async fn judge_ask_minutes(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<JudgeAskMinutes> {
    let owner = owner(&auth, &server)?;
    let minutes = blocking(move || {
        Ok(oneiron::skill_optimize::judge_digest_minutes(
            server.vault(),
            &owner,
        )?)
    })
    .await?;
    Ok(Json(JudgeAskMinutes { minutes }))
}

/// `POST /v1/owner/coach/judge-asks/minutes`: sets the caller's balance.
/// Each delivered ask spends the calibration policy's minutes; zero stops
/// the asks, and nothing refills it.
async fn fund_judge_asks(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<JudgeAskMinutes>, JsonRejection>,
) -> OwnerReply<JudgeAskMinutes> {
    let owner = owner(&auth, &server)?;
    let JudgeAskMinutes { minutes } = json_payload(payload)?;
    blocking(move || {
        Ok(oneiron::skill_optimize::set_judge_digest_minutes(
            server.vault(),
            &owner,
            minutes,
        )?)
    })
    .await?;
    Ok(Json(JudgeAskMinutes { minutes }))
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JudgeAskChoice {
    A,
    B,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PickJudgeAsk {
    /// A delivered ask's id, as 64 hex (a digest's `judge_ask_ids`).
    ask: String,
    /// `a` or `b`: the ask's `option_a` or its `option_b`.
    choice: JudgeAskChoice,
}

#[derive(Debug, Serialize)]
struct JudgeLabelView {
    ask: String,
    chosen: String,
    picked_at: u64,
}

/// `POST /v1/owner/coach/judge-asks/pick`: the caller's pick on an ask their
/// digest delivered, a final label in the judged skill's anchor. The same
/// pick again returns it; the other one fails.
async fn pick_judge_ask(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<PickJudgeAsk>, JsonRejection>,
) -> OwnerReply<JudgeLabelView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let label = blocking(move || -> OwnerResult<JudgeLabelView> {
        let ask = digest_id(&request.ask)
            .ok_or_else(|| OwnerError::Invalid("ask must be a 64-hex ask id".into()))?;
        let label = oneiron::skill_optimize::record_judge_pick(
            server.vault(),
            &owner,
            ask,
            matches!(request.choice, JudgeAskChoice::B),
            now_secs(),
        )?;
        Ok(JudgeLabelView {
            ask: hex_id(&label.ask.id),
            chosen: label.chosen,
            picked_at: label.picked_at,
        })
    })
    .await?;
    Ok(Json(label))
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingsQuery {
    /// The detector's family, as configured.
    family: String,
    #[serde(default)]
    limit: Option<usize>,
}

/// One raised T3 finding as the owner sees it.
#[derive(Debug, Serialize)]
struct FindingView {
    /// The finding's event id, as 32 hex: what a label names.
    event: String,
    detector: String,
    class: &'static str,
    /// When the window it judged began.
    from: u64,
    learned_at: u64,
    /// The retrieval runs it judged.
    runs: Vec<String>,
    /// `true` confirmed, `false` rejected, absent not yet labeled.
    label: Option<bool>,
}

/// `GET /v1/owner/self-heal/findings?family=<family>`: one detector's raised
/// T3 findings, newest first, each with the owner's label.
async fn self_heal_findings(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<FindingsQuery>, QueryRejection>,
) -> OwnerReply<Vec<FindingView>> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let findings = blocking(move || {
        Ok(server
            .vault()
            .t3_findings(&query.family, query.limit.unwrap_or(MAX_T3_FINDINGS))?)
    })
    .await?;
    Ok(Json(
        findings
            .into_iter()
            .map(|finding| FindingView {
                event: finding.event_id.to_hex(),
                detector: finding.event.detector_id,
                class: finding.event.event_class.as_str(),
                from: finding.event.valid_from,
                learned_at: finding.learned_at,
                runs: finding
                    .event
                    .evidence_refs
                    .iter()
                    .map(|run| run.to_hex())
                    .collect(),
                label: finding.label,
            })
            .collect(),
    ))
}

/// One family's registered T2 as the owner sees it.
#[derive(Debug, Serialize)]
struct MintedView {
    family: String,
    /// The wording-and-corpus revision, as 64 hex.
    revision: String,
    /// The labeled findings it asks with, as 32 hex each.
    positive: Vec<String>,
    negative: Vec<String>,
    registered_at: u64,
    /// The T1 detector that reproduces every label; while present the T2
    /// no longer runs.
    graduated_to: Option<String>,
}

impl From<MintedRegistration> for MintedView {
    fn from(registration: MintedRegistration) -> Self {
        let hex = |ids: &[oneiron::EntityId]| -> Vec<String> {
            ids.iter().map(|id| id.to_hex()).collect()
        };
        Self {
            revision: blake3::Hash::from_bytes(registration.revision)
                .to_hex()
                .to_string(),
            positive: hex(&registration.positive_events),
            negative: hex(&registration.negative_events),
            family: registration.family,
            registered_at: registration.registered_at,
            graduated_to: registration.graduated_to,
        }
    }
}

/// `GET /v1/owner/self-heal/minted`: each family's registered T2, by family.
async fn self_heal_minted(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<MintedView>> {
    owner(&auth, &server)?;
    let registrations = blocking(move || Ok(server.vault().minted_registrations()?)).await?;
    Ok(Json(
        registrations.into_iter().map(MintedView::from).collect(),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LabelFinding {
    family: String,
    /// The finding's event id, as 32 hex.
    event: String,
    /// Whether the finding names a real problem.
    positive: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeFixQuery {
    #[serde(default)]
    limit: Option<usize>,
}

/// One failure's code-fix work as the owner sees it: a case's, or a blocked
/// report's whose run has no failed case.
#[derive(Debug, Serialize)]
struct CodeFixView {
    /// The failure case, as 32 hex; absent for a blocked report's work.
    case: Option<String>,
    /// The blocked report's receipt, as 32 hex; absent for a case's work.
    blocked_report: Option<String>,
    /// The proposed heal the work follows, as 32 hex.
    proposal: String,
    route: String,
    queued_at: u64,
    /// Absent until the run settles.
    settled: Option<CodeFixSettled>,
}

/// `GET /v1/owner/coach/code-fixes?limit=<n>`: the Coach's code-fix work,
/// newest first (at most 256).
async fn code_fixes(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<CodeFixQuery>, QueryRejection>,
) -> OwnerReply<Vec<CodeFixView>> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let work = blocking(move || {
        Ok(server
            .vault()
            .code_fix_work(query.limit.unwrap_or(MAX_CODE_FIX_WORK))?)
    })
    .await?;
    Ok(Json(
        work.into_iter()
            .map(|work| {
                let (case, blocked_report) = match work.source {
                    CodeFixSource::Case { case_ref } => (Some(case_ref), None),
                    CodeFixSource::Blocked { receipt, .. } => (None, Some(receipt.to_hex())),
                };
                CodeFixView {
                    case,
                    blocked_report,
                    proposal: work.proposal.to_hex(),
                    route: work.route,
                    queued_at: work.queued_at,
                    settled: work.settled,
                }
            })
            .collect(),
    ))
}

/// `POST /v1/owner/self-heal/findings/label`: the owner's one label on a
/// raised T3 finding. A label never changes; a second, different one is
/// refused.
async fn label_self_heal_finding(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<LabelFinding>, JsonRejection>,
) -> OwnerReply<ReviewedFinding> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let label = blocking(move || -> OwnerResult<ReviewedFinding> {
        let event = entity_id("event", &request.event)?;
        Ok(server
            .vault()
            .review_t3_finding(&owner, &request.family, event, request.positive)?)
    })
    .await?;
    Ok(Json(label))
}
