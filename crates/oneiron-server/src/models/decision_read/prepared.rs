//! A native label read's rendered inputs, held on the reader that sends them.

use super::{
    DecisionReader, FatalLlmError, LabelReadGenerationOutcome, LabelReadRequest, LabelReadout,
    LlmResult, ReadRelease, RetryableLlmError, WorkPhysical, prompt_of, refused,
};

pub(super) struct PreparedDecisionRead<'reader, 'request> {
    reader: &'reader DecisionReader,
    prompts: Vec<String>,
    questions: &'request [LabelReadout<'request>],
    work_until: Option<std::time::Instant>,
}

impl<'reader, 'request> PreparedDecisionRead<'reader, 'request> {
    pub(super) fn new(
        reader: &'reader DecisionReader,
        request: &LabelReadRequest<'request>,
    ) -> LlmResult<Self> {
        // Before the state renders or the tokenizer and completion are asked.
        if !reader.permitted {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        if request.questions.is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let prompts = request
            .questions
            .iter()
            .map(|question| reader.recipe.render(&prompt_of(request.state, question)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(refused)?;
        Ok(Self {
            reader,
            prompts,
            questions: request.questions,
            work_until: request.work_until,
        })
    }

    pub(super) fn read(
        self,
        physical: Option<WorkPhysical>,
        release: Option<ReadRelease<'_>>,
        admit_next: Option<&(dyn Fn() -> bool + Sync)>,
    ) -> LlmResult<LabelReadGenerationOutcome> {
        self.reader.read_prepared(
            &self.prompts,
            self.questions,
            self.work_until,
            physical,
            release,
            admit_next,
        )
    }
}

impl DecisionReader {
    fn read_prepared(
        &self,
        prompts: &[String],
        questions: &[LabelReadout<'_>],
        work_until: Option<std::time::Instant>,
        physical: Option<WorkPhysical>,
        release: Option<ReadRelease<'_>>,
        admit_next: Option<&(dyn Fn() -> bool + Sync)>,
    ) -> LlmResult<LabelReadGenerationOutcome> {
        let reader = self;
        let read = async {
            let _worker = reader.hold_worker().await?;
            reader
                .read_pack(prompts, questions, physical, release, admit_next)
                .await
        };
        // One bound for the tokenizer and completion waits: the decision's work cutoff.
        match work_until {
            Some(until) => reader.runtime.block_on(async {
                tokio::time::timeout_at(until.into(), read)
                    .await
                    .unwrap_or_else(|_| Err(RetryableLlmError::Timeout.into()))
            }),
            None => reader.runtime.block_on(read),
        }
    }
}

/// The reader owns the rendered prompts; only the core's question slice is borrowed.
struct PreparedHouseRead<'request> {
    reader: std::sync::Arc<DecisionReader>,
    prompts: Vec<String>,
    questions: &'request [LabelReadout<'request>],
}

impl DecisionReader {
    pub(crate) fn prepare_extraction<'request>(
        self: &std::sync::Arc<Self>,
        request: &LabelReadRequest<'request>,
        vault: &oneiron::Vault,
        context: &oneiron::llm::decision::DecisionCallContext<'_>,
        locality: oneiron::ModelLocality,
    ) -> oneiron::Result<Box<dyn oneiron::llm::decision::PreparedDecisionRead + 'request>> {
        let prepared = PreparedDecisionRead::new(self, request).map_err(|_| {
            oneiron::Error::InvalidConfig("decision read: native input preparation failed".into())
        })?;
        // Token ids do not exist until the paid tokenizer answers. This admits the
        // complete native input plan, not a fictional finalized completion body.
        let plan = serde_json::json!({
            "wire_model": self.wire_model,
            "revision": self.revision,
            "tokenize_endpoint": self.http.url(super::TOKENIZE_PATH),
            "completion_endpoint": self.http.url(super::COMPLETION_PATH),
            "tokenize": self.recipe.tokens().iter()
                .map(|token| super::tokenize_body(token, false))
                .chain(std::iter::once(super::tokenize_body(self.recipe.eos(), true)))
                .collect::<Vec<_>>(),
            "initial_completion": super::completion_fields(
                serde_json::json!(prepared.prompts), self.recipe.n_probs()),
            "retry_completions": self.recipe.n_probs_full().map(|full| {
                prepared.prompts.iter()
                    .map(|prompt| super::completion_fields(serde_json::json!(prompt), full))
                    .collect::<Vec<_>>()
            }),
            "forced_end": {"token": self.recipe.eos(), "bias": super::EOS_BIAS},
        });
        let text = serde_json::to_string(&plan).map_err(|_| {
            oneiron::Error::InvalidConfig("decision read: native input plan encoding failed".into())
        })?;
        let admission = oneiron::LlmRequest {
            model: self.engine.clone(),
            envelope: oneiron::CallEnvelope {
                seat_effort: None,
                scope: context.scope.clone(),
                tier: oneiron::TierPrecedence::for_purpose(
                    context.purpose,
                    oneiron::ModelTierRef(
                        crate::config::models::role_key(
                            oneiron::llm::manifest::ModelRole::LocalReasoner,
                        )
                        .to_owned(),
                    ),
                ),
                purpose: context.purpose.clone(),
                class: oneiron::CallClass::BestEffort,
                response_format: oneiron::ResponseFormat::Text,
                locality,
                host_keyless: false,
            },
            messages: vec![oneiron::LlmMessage {
                role: oneiron::LlmMessageRole::User,
                content: vec![oneiron::ContentPart::Text {
                    text,
                    signature: None,
                }],
            }],
            tools: Vec::new(),
            params: std::collections::BTreeMap::new(),
            provider_options: std::collections::BTreeMap::from([(
                "house".to_owned(),
                serde_json::json!({"admission_view": "native-input-plan"}),
            )]),
            host_segments: None,
        };
        vault.authorize_raw_inference(
            admission,
            &oneiron::llm::HostInferenceContext {
                binding: oneiron::llm::HostInferenceBinding::Advertised {
                    model: self.engine.clone(),
                    locality,
                    keyless: false,
                },
                extraction_egress: context.extraction_egress,
            },
        )?;
        Ok(Box::new(PreparedHouseRead {
            reader: std::sync::Arc::clone(self),
            prompts: prepared.prompts,
            questions: prepared.questions,
        }))
    }
}

impl oneiron::llm::decision::PreparedDecisionRead for PreparedHouseRead<'_> {
    fn read(
        &self,
        work_until: Option<std::time::Instant>,
        lease: &oneiron::BudgetLease,
        may_send: Option<&(dyn Fn() -> bool + Sync)>,
        admit_next: Option<&(dyn Fn() -> bool + Sync)>,
    ) -> LlmResult<LabelReadGenerationOutcome> {
        let release = || {
            if may_send.is_none_or(|may_send| may_send()) {
                Ok(())
            } else {
                Err(FatalLlmError::Auth.into())
            }
        };
        self.reader.read_prepared(
            &self.prompts,
            self.questions,
            work_until,
            lease.work_context().map(|context| context.physical),
            may_send.map(|_| (&release as oneiron::llm::DispatchRelease<'_>, lease)),
            admit_next,
        )
    }
}
