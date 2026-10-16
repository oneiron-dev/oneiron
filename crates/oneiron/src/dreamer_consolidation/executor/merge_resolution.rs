//! A conflict set's resolution: the typed pack (how it resolves, and which candidate's
//! identity a merge keeps), then the resolved value as generation beside the decision.

use super::decisions::{conflict_state, id_options, named_id};
use super::*;
use crate::dreamer_wake::WakePassDeadline;
use crate::llm::decision::catalogue::CONFLICT_RESOLUTION;
use crate::llm::decision::{AnswerContract, DecisionAnswer};

/// A conflict's resolutions. With no prior head in scope, supersede degrades to merge (D7:
/// at most one prior head; the promotion writer owns the supersession).
const RESOLUTIONS: [&str; 4] = ["merge", "supersede", "accumulate", "escalate"];

pub(super) enum MergeResolution {
    Merge {
        value: Value,
        candidate_ref: Option<EntityId>,
    },
    Accumulate,
    Escalate,
}

/// What a conflict's pack decided: its resolution, when one was read, and the listed
/// candidate whose identity a merge keeps.
pub(super) struct ConflictAnswers {
    pub(super) resolution: Option<String>,
    pub(super) identity: Option<EntityId>,
}

impl ConsolidationExecutor<'_> {
    /// The conflict's typed pack: how it resolves, and which listed candidate's identity a
    /// merge keeps (a merge across predicates must name one). None when the step trapped.
    #[expect(
        clippy::too_many_arguments,
        reason = "the step, its pass clock and scope join the conflict and the charge tally"
    )]
    pub(super) async fn decide_conflict(
        &self,
        step_ctx: &DurableStepContext<'_>,
        pass: &WakePassDeadline,
        conflict: &ConflictSet,
        members: &[&PromotionCandidate],
        prior_heads: &[super::super::PriorHead],
        scope: &crate::llm::Scope,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<Option<ConflictAnswers>> {
        let mut questions = vec![
            CONFLICT_RESOLUTION.question(
                &[b"resolution".as_slice()],
                self.decisions.resolution_wording.clone(),
                AnswerContract::Choice {
                    options: RESOLUTIONS
                        .iter()
                        .map(|label| (*label).to_owned())
                        .collect(),
                },
            )?,
        ];
        let across = members.iter().any(|member| {
            candidate_facts(&member.candidate)
                .is_ok_and(|facts| facts.predicate != conflict.identity.predicate)
        });
        let ids: Vec<EntityId> = members.iter().map(|member| member.claim_id).collect();
        for (group, options) in id_options(&ids, !across).into_iter().enumerate() {
            let group = group.to_string();
            questions.push(CONFLICT_RESOLUTION.question(
                &[b"identity".as_slice(), group.as_bytes()],
                self.decisions.identity_wording.clone(),
                AnswerContract::Choice { options },
            )?);
        }
        let evidence: Vec<EntityId> = prior_heads.iter().map(|prior| prior.claim_id).collect();
        let state = conflict_state(&conflict.identity, members, prior_heads)?;
        let Some(decided) = self
            .decide(
                step_ctx, pass, scope, &questions, &evidence, &state, charges,
            )
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(ConflictAnswers {
            resolution: match &decided[0].answer {
                DecisionAnswer::Choice(label) => Some(label.clone()),
                _ => None,
            },
            identity: named_id(decided[1..].iter().collect()),
        }))
    }

    /// The value a decided merge or supersede writes, generated beside the decision under
    /// the rules in force at that moment (H398); a reply that names none escalates. None
    /// when the step trapped.
    #[expect(
        clippy::too_many_arguments,
        reason = "the decided resolution and identity join the conflict and the charge tally"
    )]
    pub(super) async fn merged_value(
        &self,
        step_ctx: &DurableStepContext<'_>,
        resolution: &str,
        identity: Option<EntityId>,
        conflict: &ConflictSet,
        members: &[&PromotionCandidate],
        prior_heads: &[super::super::PriorHead],
        scope: &crate::llm::Scope,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<Option<MergeResolution>> {
        let call = self.role(DREAMER_VERDICT_ROLE);
        let mut request = Self::value_request(
            &call,
            resolution,
            identity,
            &conflict.identity,
            members,
            prior_heads,
            scope,
        )?;
        if let Some(rules) = failure_rules::load(step_ctx.vault)? {
            rules.bind(Stage::Conflict, &mut request);
        }
        let mut request = step_ctx
            .vault
            .authorize_model_role(DREAMER_VERDICT_ROLE, request, &call.inference)?
            .into_request();
        super::super::roles::bind_reasoning(step_ctx.vault, call.backend, &mut request)?;
        let step_hash = request.canonical_hash()?;
        let outcome = call_as_step(step_ctx, call.backend, self.guard, request).await;
        let response = match outcome? {
            StepOutcome::Finished { response, .. } => response,
            StepOutcome::Trapped { .. } => return Ok(None),
        };
        charges.record_terminal(
            step_ctx.vault,
            step_ctx.attempt_id,
            step_hash,
            &response.usage,
        )?;
        let rules = failure_rules::load(step_ctx.vault)?;
        if rules.is_some_and(|rules| !rules.accepts(Stage::Conflict, &response)) {
            return Ok(Some(MergeResolution::Escalate));
        }
        // A decision that names no value writes no claim: it parks as an open conflict.
        Ok(Some(match decode_merged_value(&response) {
            Some(value) => MergeResolution::Merge {
                value,
                candidate_ref: identity,
            },
            None => MergeResolution::Escalate,
        }))
    }

    fn value_request(
        call: &RoleCall<'_>,
        resolution: &str,
        kept: Option<EntityId>,
        identity: &ConflictIdentity,
        members: &[&PromotionCandidate],
        prior_heads: &[super::super::PriorHead],
        scope: &crate::llm::Scope,
    ) -> Result<LlmRequest> {
        let mut lines = format!("resolution {resolution}\n");
        if let Some(kept) = kept {
            lines.push_str(&format!("keeps candidate_ref {}\n", kept.to_hex()));
        }
        lines.push_str(&format!("predicate {}\n", identity.predicate));
        for prior in prior_heads {
            lines.push_str(
                &serde_json::json!({"prior_head": prior.claim_id.to_hex(),
                "predicate": prior.body.predicate,
                "source": prior.body.source.map(crate::claim::ClaimSource::as_str),
                "value": rmpv_to_json(&prior.body.value)})
                .to_string(),
            );
            lines.push('\n');
        }
        for member in members {
            let facts = candidate_facts(&member.candidate)?;
            lines.push_str(&format!(
                "- candidate_ref: {} predicate: {} value: {}\n",
                member.claim_id.to_hex(),
                facts.predicate,
                serde_json::to_string(&rmpv_to_json(&facts.value)).unwrap_or_default()
            ));
        }
        let system = "Conflicting values were extracted for one claim identity, and they \
             resolve into one claim. Respond with JSON: {\"value\": <the resolved claim's \
             value as JSON>}. On supersede the value is the newest one stated; on merge it is \
             one value that holds what the candidates state.";
        Ok(LlmRequest {
            model: call.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: scope.clone(),
                purpose: CallPurpose::Consolidation,
                class: CallClass::Durable {
                    fallback: crate::llm::DeterministicFallback {
                        name: "json_rules_v1".into(),
                        config: Some(
                            serde_json::json!({"version":1,"rows":[{"failure":"fatal","value":{"value":null}}]}),
                        ),
                    },
                },
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Consolidation,
                    ModelTierRef("consolidation".into()),
                ),
                response_format: ResponseFormat::Json {
                    schema: serde_json::json!({"type": "object", "properties": {"value": {}}}),
                },
                locality: call.inference.selected_locality().ok_or_else(||
                    crate::Error::InvalidConfig("consolidation host binding needs locality".into()))?,
            }.with_purpose_defaults(),
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: system.to_owned(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text { text: lines }],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        })
    }
}

/// The non-null `value` a resolved-value reply names, if any.
fn decode_merged_value(response: &LlmResponse) -> Option<Value> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let parsed: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    parsed
        .get("value")
        .filter(|value| !value.is_null())
        .map(json_to_rmpv)
}
