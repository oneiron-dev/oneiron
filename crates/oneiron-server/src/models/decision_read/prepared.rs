//! A native label read's rendered inputs, held on the reader that sends them.

use super::{
    DecisionReader, FatalLlmError, LabelReadGenerationOutcome, LabelReadRequest, LabelReadout,
    LlmResult, ReadRelease, RetryableLlmError, prompt_of, refused,
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
        release: Option<ReadRelease<'_>>,
        admit_next: Option<&(dyn Fn() -> bool + Sync)>,
    ) -> LlmResult<LabelReadGenerationOutcome> {
        let Self {
            reader,
            prompts,
            questions,
            work_until,
        } = self;
        let read = async {
            let _worker = reader.hold_worker().await?;
            reader
                .read_pack(&prompts, questions, release, admit_next)
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
