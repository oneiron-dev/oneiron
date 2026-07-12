#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimCheckerVote {
    Confirm,
    Hold,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimCheckerVerdict {
    Confirm,
    Hold,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimCheckerResult {
    verdict: ClaimCheckerVerdict,
    reason_code: Option<&'static str>,
}

impl ClaimCheckerResult {
    #[must_use]
    pub fn verdict(self) -> ClaimCheckerVerdict {
        self.verdict
    }

    #[must_use]
    pub fn reason_code(self) -> Option<&'static str> {
        self.reason_code
    }
}

#[must_use]
pub fn aggregate_votes(votes: [ClaimCheckerVote; 3]) -> ClaimCheckerResult {
    let positives = votes
        .iter()
        .filter(|vote| **vote == ClaimCheckerVote::Confirm)
        .count();
    if positives >= 2 {
        return ClaimCheckerResult {
            verdict: ClaimCheckerVerdict::Confirm,
            reason_code: None,
        };
    }

    let unavailable = votes
        .iter()
        .filter(|vote| **vote == ClaimCheckerVote::Unavailable)
        .count();
    if unavailable >= 2 {
        return ClaimCheckerResult {
            verdict: ClaimCheckerVerdict::Indeterminate,
            reason_code: Some(CHECKER_UNAVAILABLE_REASON),
        };
    }

    ClaimCheckerResult {
        verdict: ClaimCheckerVerdict::Hold,
        reason_code: Some(CHECKER_VETO_REASON),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};

    use serde_json::json;

    use crate::llm::{
        BudgetLease, CallClass, CallPurpose, ContentPart, FatalLlmError, FinishReason, LlmBackend,
        LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmResult,
        LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, RetryableLlmError,
    };

    use super::{
        CHECKER_UNAVAILABLE_REASON, CHECKER_VETO_REASON, ClaimCheckInput, ClaimChecker,
        ClaimCheckerVerdict, ClaimCheckerVote, aggregate_votes,
    };

    fn block_on_ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    struct ScriptedBackend {
        responses: Mutex<VecDeque<LlmResult<LlmResponse>>>,
        requests: Mutex<Vec<LlmRequest>>,
    }

    impl LlmBackend for ScriptedBackend {
        fn generate<'a>(
            &'a self,
            request: LlmRequest,
            _lease: &'a BudgetLease,
        ) -> LlmGenerateFuture<'a> {
            self.requests.lock().unwrap().push(request);
            let response = self.responses.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { response })
        }

        fn stream<'a>(
            &'a self,
            _request: LlmRequest,
            _lease: &'a BudgetLease,
        ) -> LlmStreamResult<'a> {
            unreachable!("claim checker uses generate")
        }
    }

    fn response(verdict: &str) -> LlmResponse {
        LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: json!({ "verdict": verdict }).to_string(),
                }],
            },
            usage: LlmUsage::zero(),
            finish_reason: FinishReason::Stop,
        }
    }

    #[test]
    fn two_positive_votes_and_one_error_confirm() {
        let result = aggregate_votes([
            ClaimCheckerVote::Confirm,
            ClaimCheckerVote::Unavailable,
            ClaimCheckerVote::Confirm,
        ]);

        assert_eq!(result.verdict(), ClaimCheckerVerdict::Confirm);
        assert_eq!(result.reason_code(), None);
    }

    #[test]
    fn every_partial_vote_combination_has_fail_closed_semantics() {
        let votes = [
            ClaimCheckerVote::Confirm,
            ClaimCheckerVote::Hold,
            ClaimCheckerVote::Unavailable,
        ];

        for first in votes {
            for second in votes {
                for third in votes {
                    let triple = [first, second, third];
                    let positives = triple
                        .iter()
                        .filter(|vote| **vote == ClaimCheckerVote::Confirm)
                        .count();
                    let unavailable = triple
                        .iter()
                        .filter(|vote| **vote == ClaimCheckerVote::Unavailable)
                        .count();
                    let expected = if positives >= 2 {
                        (ClaimCheckerVerdict::Confirm, None)
                    } else if unavailable >= 2 {
                        (
                            ClaimCheckerVerdict::Indeterminate,
                            Some(CHECKER_UNAVAILABLE_REASON),
                        )
                    } else {
                        (ClaimCheckerVerdict::Hold, Some(CHECKER_VETO_REASON))
                    };
                    let result = aggregate_votes(triple);

                    assert_eq!((result.verdict(), result.reason_code()), expected);
                }
            }
        }
    }

    #[test]
    fn online_checker_uses_three_durable_autocheck_votes() {
        let backend = ScriptedBackend {
            responses: Mutex::new(VecDeque::from([
                Ok(response("confirm")),
                Ok(response("hold")),
                Ok(response("confirm")),
            ])),
            requests: Mutex::new(Vec::new()),
        };
        let checker = ClaimChecker::new(
            ModelId::new("openai/checker@2026-07-13").unwrap(),
            ModelTierRef("checker".to_owned()),
            ModelLocality::ThirdParty,
        );
        let input = ClaimCheckInput {
            claim: "the claim".to_owned(),
            claim_hash: [0x11; 32],
            gate_policy_version: "gate-v4".to_owned(),
            manifest_hash: [0x22; 32],
        };

        let result = block_on_ready(checker.check(
            &backend,
            &BudgetLease::for_test("checker-lease"),
            &input,
        ));

        assert_eq!(result.verdict(), ClaimCheckerVerdict::Confirm);
        assert_eq!(result.checker_binding(), checker.binding());
        let requests = backend.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        for request in requests.iter() {
            assert_eq!(request.envelope.purpose, CallPurpose::AutoCheck);
            assert!(matches!(request.envelope.class, CallClass::Durable { .. }));
            let CallClass::Durable { fallback } = &request.envelope.class else {
                unreachable!();
            };
            assert_eq!(fallback.name, "fail_closed_to_proposed");
        }
    }

    #[test]
    fn bounded_retry_is_independent_per_vote() {
        let backend = ScriptedBackend {
            responses: Mutex::new(VecDeque::from([
                Err(RetryableLlmError::Timeout.into()),
                Ok(response("confirm")),
                Err(FatalLlmError::ContentFiltered.into()),
                Ok(response("hold")),
            ])),
            requests: Mutex::new(Vec::new()),
        };
        let checker = ClaimChecker::new(
            ModelId::new("openai/checker@2026-07-13").unwrap(),
            ModelTierRef("checker".to_owned()),
            ModelLocality::ThirdParty,
        );
        let input = ClaimCheckInput {
            claim: "the claim".to_owned(),
            claim_hash: [0x11; 32],
            gate_policy_version: "gate-v4".to_owned(),
            manifest_hash: [0x22; 32],
        };

        let result = block_on_ready(checker.check(
            &backend,
            &BudgetLease::for_test("checker-lease"),
            &input,
        ));

        assert_eq!(result.verdict(), ClaimCheckerVerdict::Hold);
        assert_eq!(result.reason_code(), Some(CHECKER_VETO_REASON));
        assert_eq!(backend.requests.lock().unwrap().len(), 4);
    }

    #[test]
    fn checker_binding_changes_with_behavior_configuration() {
        let checker_a = ClaimChecker::new(
            ModelId::new("openai/checker-a@2026-07-13").unwrap(),
            ModelTierRef("checker".to_owned()),
            ModelLocality::ThirdParty,
        );
        let checker_b = ClaimChecker::new(
            ModelId::new("openai/checker-b@2026-07-13").unwrap(),
            ModelTierRef("checker".to_owned()),
            ModelLocality::ThirdParty,
        );
        let checker_retry_change = checker_a.clone().with_retries_per_vote_for_test(2);

        assert_ne!(checker_a.binding(), checker_b.binding());
        assert_ne!(checker_a.binding(), checker_retry_change.binding());
        assert_eq!(checker_a.binding(), checker_a.binding());
    }
}
use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::entity_id::bytes_to_hex_lower;
use crate::llm::{
    BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback,
    LlmBackend, LlmError, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, ModelId,
    ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence,
};

pub const CHECKER_VETO_REASON: &str = "gate.pending.checker.veto";
pub const CHECKER_UNAVAILABLE_REASON: &str = "gate.pending.checker.unavailable";

const DEFAULT_RETRIES_PER_VOTE: usize = 1;
const CHECKER_BINDING_VERSION: &str = "oneiron.claim_checker.binding.v1";
const CHECKER_PROMPT_VERSION: &str = "oneiron.claim_checker.prompt.v1";
const CHECKER_USER_PROMPT_VERSION: &str = "oneiron.claim_checker.user-prompt.v1";
const CHECKER_SYSTEM_PROMPT: &str = "You are the Oneiron production claim checker. Return strict JSON only. Confirm only when the claim is safe to retain in the Auto lane; otherwise hold.";
const CHECKER_RESPONSE_SCHEMA_VERSION: &str = "oneiron.claim_checker.response.v1";
const CHECKER_AGGREGATION_VERSION: &str = "oneiron.claim_checker.positive-2-of-3.partial-errors.v1";
const CHECKER_VOTE_COUNT: u8 = 3;
const CHECKER_POSITIVE_THRESHOLD: u8 = 2;
const CHECKER_FALLBACK_NAME: &str = "fail_closed_to_proposed";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClaimCheckerBinding([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimCheckInput {
    pub claim: String,
    pub claim_hash: [u8; 32],
    pub gate_policy_version: String,
    pub manifest_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimCheckEvidence {
    claim_hash: [u8; 32],
    gate_policy_version: String,
    manifest_hash: [u8; 32],
    checker_binding: ClaimCheckerBinding,
    result: ClaimCheckerResult,
}

impl ClaimCheckEvidence {
    #[cfg(test)]
    pub(crate) fn new_bound(
        claim_hash: [u8; 32],
        gate_policy_version: String,
        manifest_hash: [u8; 32],
        checker_binding: ClaimCheckerBinding,
        result: ClaimCheckerResult,
    ) -> Self {
        Self {
            claim_hash,
            gate_policy_version,
            manifest_hash,
            checker_binding,
            result,
        }
    }

    #[must_use]
    pub fn verdict(&self) -> ClaimCheckerVerdict {
        self.result.verdict()
    }

    #[must_use]
    pub fn reason_code(&self) -> Option<&'static str> {
        self.result.reason_code()
    }

    #[must_use]
    pub fn claim_hash(&self) -> [u8; 32] {
        self.claim_hash
    }

    #[must_use]
    pub fn gate_policy_version(&self) -> &str {
        &self.gate_policy_version
    }

    #[must_use]
    pub fn manifest_hash(&self) -> [u8; 32] {
        self.manifest_hash
    }

    #[must_use]
    pub fn checker_binding(&self) -> ClaimCheckerBinding {
        self.checker_binding
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimChecker {
    model: ModelId,
    tier: ModelTierRef,
    locality: ModelLocality,
    retries_per_vote: usize,
}

impl ClaimChecker {
    #[must_use]
    pub fn new(model: ModelId, tier: ModelTierRef, locality: ModelLocality) -> Self {
        Self {
            model,
            tier,
            locality,
            retries_per_vote: DEFAULT_RETRIES_PER_VOTE,
        }
    }

    #[cfg(test)]
    fn with_retries_per_vote_for_test(mut self, retries_per_vote: usize) -> Self {
        self.retries_per_vote = retries_per_vote;
        self
    }

    #[must_use]
    pub fn binding(&self) -> ClaimCheckerBinding {
        let mut hasher = Sha256::new();
        hash_binding_field(&mut hasher, CHECKER_BINDING_VERSION.as_bytes());
        hash_binding_field(&mut hasher, self.model.as_str().as_bytes());
        hash_binding_field(&mut hasher, self.tier.as_str().as_bytes());
        hash_binding_field(
            &mut hasher,
            match self.locality {
                ModelLocality::OnDevice => b"on_device",
                ModelLocality::OwnServer => b"own_server",
                ModelLocality::ThirdParty => b"third_party",
            },
        );
        hash_binding_field(&mut hasher, CHECKER_PROMPT_VERSION.as_bytes());
        hash_binding_field(&mut hasher, CHECKER_SYSTEM_PROMPT.as_bytes());
        hash_binding_field(&mut hasher, CHECKER_USER_PROMPT_VERSION.as_bytes());
        hash_binding_field(&mut hasher, CHECKER_RESPONSE_SCHEMA_VERSION.as_bytes());
        hash_binding_field(
            &mut hasher,
            &serde_json::to_vec(&checker_response_schema())
                .expect("checker response schema is serializable"),
        );
        hash_binding_field(&mut hasher, CHECKER_AGGREGATION_VERSION.as_bytes());
        hash_binding_field(&mut hasher, &[CHECKER_VOTE_COUNT]);
        hash_binding_field(&mut hasher, &[CHECKER_POSITIVE_THRESHOLD]);
        hash_binding_field(&mut hasher, &(self.retries_per_vote as u64).to_be_bytes());
        hash_binding_field(&mut hasher, b"auto_check");
        hash_binding_field(&mut hasher, b"durable");
        hash_binding_field(&mut hasher, CHECKER_FALLBACK_NAME.as_bytes());
        ClaimCheckerBinding(hasher.finalize().into())
    }

    pub async fn check(
        &self,
        backend: &dyn LlmBackend,
        lease: &BudgetLease,
        input: &ClaimCheckInput,
    ) -> ClaimCheckEvidence {
        let mut votes = [ClaimCheckerVote::Unavailable; 3];
        for vote in &mut votes {
            *vote = self.vote(backend, lease, input).await;
        }
        ClaimCheckEvidence {
            claim_hash: input.claim_hash,
            gate_policy_version: input.gate_policy_version.clone(),
            manifest_hash: input.manifest_hash,
            checker_binding: self.binding(),
            result: aggregate_votes(votes),
        }
    }

    async fn vote(
        &self,
        backend: &dyn LlmBackend,
        lease: &BudgetLease,
        input: &ClaimCheckInput,
    ) -> ClaimCheckerVote {
        for attempt in 0..=self.retries_per_vote {
            match backend.generate(self.request(input), lease).await {
                Ok(response) => {
                    if let Some(vote) = parse_vote(&response) {
                        return vote;
                    }
                }
                Err(LlmError::Retryable(_)) => {}
                Err(LlmError::Fatal(_) | LlmError::BudgetDenied(_)) => {
                    return ClaimCheckerVote::Unavailable;
                }
            }
            if attempt == self.retries_per_vote {
                break;
            }
        }
        ClaimCheckerVote::Unavailable
    }

    fn request(&self, input: &ClaimCheckInput) -> LlmRequest {
        let schema = checker_response_schema();
        let user = format!(
            "claim_hash={}\ngate_policy_version={}\nmanifest_hash={}\nclaim:\n{}",
            bytes_to_hex_lower(&input.claim_hash),
            input.gate_policy_version,
            bytes_to_hex_lower(&input.manifest_hash),
            input.claim
        );
        LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                purpose: CallPurpose::AutoCheck,
                class: CallClass::Durable {
                    fallback: DeterministicFallback {
                        name: CHECKER_FALLBACK_NAME.to_owned(),
                        config: None,
                    },
                },
                tier: TierPrecedence {
                    per_call: Some(self.tier.clone()),
                    vault_policy: None,
                    purpose_default: None,
                    global_default: self.tier.clone(),
                },
                response_format: ResponseFormat::Json { schema },
                locality: self.locality,
            },
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: CHECKER_SYSTEM_PROMPT.to_owned(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text { text: user }],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        }
    }
}

fn hash_binding_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn checker_response_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "verdict": { "type": "string", "enum": ["confirm", "hold"] }
        },
        "required": ["verdict"]
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VoteResponse {
    verdict: VoteResponseVerdict,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum VoteResponseVerdict {
    Confirm,
    Hold,
}

fn parse_vote(response: &LlmResponse) -> Option<ClaimCheckerVote> {
    if response.message.role != LlmMessageRole::Assistant || response.message.content.len() != 1 {
        return None;
    }
    let ContentPart::Text { text } = &response.message.content[0] else {
        return None;
    };
    let response: VoteResponse = serde_json::from_str(text).ok()?;
    Some(match response.verdict {
        VoteResponseVerdict::Confirm => ClaimCheckerVote::Confirm,
        VoteResponseVerdict::Hold => ClaimCheckerVote::Hold,
    })
}
