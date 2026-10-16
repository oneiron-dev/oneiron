//! The membership question through the host's ladder: does the candidate belong to the
//! saved query its owner's rubric describes? The judge's backend is the pack's first read on
//! the binding's lease, with the owner's rubric and the evidence as its own messages; the
//! `why` the verdict keeps is a generation beside it, after the verdict is decided.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::decision::catalogue::SAVED_QUERY_MATCH;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionRung,
    GeneratedDecisions, GeneratedMiss, GeneratedRung, GeneratedStep, HeldLadder, ProviderPin,
    Reversibility,
};
use crate::llm::{ContentPart, LlmMessage, LlmMessageRole, LlmRequest, ResponseFormat};
use crate::retrieval_depth::RetrievalDeadline;

use super::evaluator::{SavedQueryJudgeBinding, judge_failure};
use super::evidence::{MatchDecision, MatchVerdict};
use super::support::{MAX_TEXT_BYTES, canonical_json_bytes, invalid};

/// The time one shipped judgment may take.
const JUDGMENT_BUDGET: Duration = Duration::from_secs(120);

/// The host's ladder for the membership question, the dial and learned bands it routes
/// under, its wording of the question and of the note's ask, and the time one judgment may
/// take. The judge's read sits at the dial's first rung, in place of that slot's provider.
#[derive(Clone)]
pub struct MembershipDecisions {
    pub ladder: HeldLadder,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    /// Does the candidate belong to the saved query?
    pub wording: String,
    /// Why the decided verdict holds.
    pub why_wording: String,
    pub budget: Duration,
}

impl MembershipDecisions {
    /// The shipped wording on an unstaffed ladder: the judge's read, at the big rung, is the
    /// one rung, and every band starts in shadow.
    pub fn shipped() -> Result<Self> {
        let wording: Wording = serde_json::from_str(include_str!("decision_wording.json"))
            .map_err(|_| invalid("shipped membership wording is not readable"))?;
        Ok(Self {
            ladder: HeldLadder::unstaffed(),
            dial: DecisionDial {
                first: DecisionRung::Big,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            bands: DecisionBandPolicy::default(),
            wording: wording.membership,
            why_wording: wording.why,
            budget: JUDGMENT_BUDGET,
        })
    }
}

/// The shipped wording, as data.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Wording {
    membership: String,
    why: String,
}

/// `candidate`'s verdict under `rubric` through the binding's ladder for the query's
/// `owner`, the judge's `shell` (the rubric and evidence as its messages) the first read,
/// and the `why` the verdict keeps.
pub(super) async fn judge(
    binding: &SavedQueryJudgeBinding<'_>,
    owner: EntityId,
    shell: LlmRequest,
    rubric: &Value,
    rubric_version: &str,
    candidate: EntityId,
) -> Result<MatchDecision> {
    let decisions = binding.decisions;
    let rubric_hash = blake3::hash(&canonical_json_bytes(rubric)?);
    let question = SAVED_QUERY_MATCH.question(
        &[rubric_hash.as_bytes(), rubric_version.as_bytes()],
        decisions.wording.clone(),
        AnswerContract::Noul,
    )?;
    let seal = |request: LlmRequest| -> Result<LlmRequest> { Ok(request) };
    let rung = GeneratedRung {
        pin: ProviderPin {
            rung: decisions.dial.first,
            model: shell.model.to_string(),
            version: shell.model.to_string(),
        },
        backend: binding.backend,
        step: GeneratedStep::Raw {
            lease: binding.lease,
        },
        request: shell.clone(),
        seal: &seal,
    };
    let state = json!({"entity": candidate.to_hex(), "rubric_version": rubric_version});
    let decided = decisions
        .ladder
        .ladder()
        .run_pack_generated(
            &rung,
            &[&question],
            owner,
            &[candidate],
            &state,
            decisions.dial,
            &decisions.bands,
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), decisions.budget),
        )
        .await
        .map_err(|error| judge_failure(error.to_string()))?;
    let verdict = match decided {
        GeneratedDecisions::Decided { decisions, .. } => {
            match decisions.first().map(|decision| &decision.answer) {
                Some(DecisionAnswer::Noul(true)) => MatchVerdict::Match,
                Some(DecisionAnswer::Noul(false)) => MatchVerdict::NoMatch,
                _ => return Err(judge_failure("membership read did not decide".to_owned())),
            }
        }
        GeneratedDecisions::Unread(GeneratedMiss::Backend(error)) => {
            return Err(judge_failure(error.to_string()));
        }
        GeneratedDecisions::Unread(GeneratedMiss::Budget(_)) | GeneratedDecisions::Trapped => {
            return Err(judge_failure("membership read did not run".to_owned()));
        }
    };
    let why = membership_why(binding, shell, verdict, &decisions.why_wording).await?;
    Ok(MatchDecision { verdict, why })
}

/// The note a decided verdict keeps: the judge's backend, on the binding's lease, says why
/// `verdict` holds over the rubric and evidence in `request`. Generation; it cannot change
/// the verdict.
async fn membership_why(
    binding: &SavedQueryJudgeBinding<'_>,
    mut request: LlmRequest,
    verdict: MatchVerdict,
    wording: &str,
) -> Result<String> {
    request.envelope.response_format = ResponseFormat::Json {
        schema: json!({
            "type": "object",
            "properties": {"why": {"type": "string"}},
            "required": ["why"],
            "additionalProperties": false,
        }),
    };
    request.messages.push(LlmMessage {
        role: LlmMessageRole::User,
        content: vec![ContentPart::Text {
            text: json!({"verdict": verdict.as_str(), "ask": wording}).to_string(),
        }],
    });
    let response = binding
        .backend
        .generate(request, binding.lease)
        .await
        .map_err(|error| judge_failure(error.to_string()))?;
    let why = response
        .message
        .content
        .iter()
        .find_map(|part| match part {
            ContentPart::Text { text } => serde_json::from_str::<Value>(text.trim()).ok(),
            _ => None,
        })
        .and_then(|reply| reply.get("why").and_then(Value::as_str).map(str::to_owned))
        .filter(|why| !why.trim().is_empty())
        .ok_or_else(|| judge_failure("response carried no why".to_owned()))?;
    Ok(why.chars().take(MAX_TEXT_BYTES).collect())
}
