//! Responses stream accumulation and polling.
//! Entry: OpenAiResponsesStreamAccumulator::push_event.
//! Stream types and their private fields stay in the parent; this module owns their impls.

use super::{
    Context, FatalLlmError, FinishReason, JsonValue, LlmResponse, LlmResult, LlmStreamEvent,
    LlmUsage, OpenAiCompatProviderStream, OpenAiCompatStreamFrame, OpenAiResponsesLlmStream,
    OpenAiResponsesStreamAccumulator, Pin, Poll, Stream, VecDeque, classify_openai_status,
    parse_responses_usage, reasoning_signature, responses_error, responses_event_type,
    responses_finish_reason,
};

impl OpenAiResponsesStreamAccumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_event(&mut self, event: &JsonValue) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.assembly.is_done() {
            return Ok(Vec::new());
        }
        let index = || {
            event
                .get("output_index")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0)
        };
        let delta = || event.get("delta").and_then(JsonValue::as_str).unwrap_or("");
        match responses_event_type(event) {
            "response.output_item.added" | "response.output_item.done" => {
                let item = event.get("item").ok_or(FatalLlmError::InvalidRequest)?;
                match item.get("type").and_then(JsonValue::as_str) {
                    Some("function_call") => {
                        let header = self.tools.entry(index()).or_default();
                        if header.call_id.is_empty() {
                            header.call_id = item
                                .get("call_id")
                                .and_then(JsonValue::as_str)
                                .unwrap_or_default()
                                .to_owned();
                            header.name = item
                                .get("name")
                                .and_then(JsonValue::as_str)
                                .unwrap_or_default()
                                .to_owned();
                        }
                        let header = header.clone();
                        self.tool_called = true;
                        let mut events = self.assembly.tool(
                            &format!("tool-{}", index()),
                            &header.call_id,
                            &header.name,
                            "",
                        )?;
                        // An item whose arguments came whole, with no deltas,
                        // carries them on its done event.
                        if responses_event_type(event) == "response.output_item.done"
                            && !header.streamed
                            && let Some(arguments) =
                                item.get("arguments").and_then(JsonValue::as_str)
                        {
                            self.tools.entry(index()).or_default().streamed = true;
                            events.extend(self.assembly.tool(
                                &format!("tool-{}", index()),
                                &header.call_id,
                                &header.name,
                                arguments,
                            )?);
                        }
                        Ok(events)
                    }
                    // A finished reasoning item carries its encrypted content,
                    // which a whole replay sends back.
                    Some("reasoning")
                        if responses_event_type(event) == "response.output_item.done" =>
                    {
                        match reasoning_signature(item, &self.model) {
                            Some(signature) => self.assembly.reasoning(
                                &format!("reasoning-{}", index()),
                                "",
                                Some(signature),
                            ),
                            None => Ok(Vec::new()),
                        }
                    }
                    Some(other) if other.ends_with("_call") => {
                        Err(FatalLlmError::InvalidRequest.into())
                    }
                    _ => Ok(Vec::new()),
                }
            }
            "response.created" | "response.in_progress" => {
                if let Some(model) = event
                    .get("response")
                    .and_then(|response| response.get("model"))
                    .and_then(JsonValue::as_str)
                {
                    model.clone_into(&mut self.model);
                }
                Ok(Vec::new())
            }
            "response.output_text.delta" | "response.refusal.delta" => {
                let content = event
                    .get("content_index")
                    .and_then(JsonValue::as_u64)
                    .unwrap_or(0);
                self.assembly
                    .text(&format!("text-{}-{content}", index()), delta())
            }
            "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => self
                .assembly
                .reasoning(&format!("reasoning-{}", index()), delta(), None),
            "response.function_call_arguments.delta" => {
                let header = self
                    .tools
                    .get_mut(&index())
                    .ok_or(FatalLlmError::InvalidRequest)?;
                header.streamed = true;
                let header = header.clone();
                self.assembly.tool(
                    &format!("tool-{}", index()),
                    &header.call_id,
                    &header.name,
                    delta(),
                )
            }
            "response.completed" | "response.incomplete" => {
                let response = event.get("response").unwrap_or(&JsonValue::Null);
                let usage = response
                    .get("usage")
                    .map_or_else(LlmUsage::zero, parse_responses_usage);
                let reason = if self.tool_called {
                    FinishReason::ToolCalls
                } else {
                    responses_finish_reason(response, &[])
                };
                self.assembly.finish(usage, reason)
            }
            "response.failed" | "error" => Err(responses_error(event)),
            _ => Ok(Vec::new()),
        }
    }

    pub fn finish_eof(&mut self) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.assembly.is_done() {
            Ok(Vec::new())
        } else {
            // A socket that ends before its terminal event cut the turn.
            Err(oneiron::RetryableLlmError::StreamCut.into())
        }
    }

    #[must_use]
    pub fn abort_with_usage(&mut self, usage: LlmUsage) -> Vec<LlmStreamEvent> {
        self.assembly.abort(usage)
    }
}

impl<'a> OpenAiResponsesLlmStream<'a> {
    #[must_use]
    pub fn new(provider_stream: OpenAiCompatProviderStream<'a>) -> Self {
        Self {
            provider_stream,
            accumulator: OpenAiResponsesStreamAccumulator::new(),
            pending: VecDeque::new(),
            ended: false,
        }
    }

    /// Drains the turn into one reply, for a caller that asked for no stream.
    pub async fn into_response(mut self) -> LlmResult<LlmResponse> {
        loop {
            let next = std::future::poll_fn(|cx| Pin::new(&mut self).poll_next(cx)).await;
            match next {
                Some(Ok(LlmStreamEvent::Done {
                    message,
                    usage,
                    finish_reason,
                    reply_assertions,
                })) => {
                    return Ok(LlmResponse {
                        message,
                        usage,
                        finish_reason,
                        reply_assertions,
                        token_scores: None,
                    });
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(error),
                None => return Err(oneiron::RetryableLlmError::StreamCut.into()),
            }
        }
    }
}

impl Stream for OpenAiResponsesLlmStream<'_> {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(event) = this.pending.pop_front() {
                return Poll::Ready(Some(event));
            }
            if this.ended {
                return Poll::Ready(None);
            }
            match this.provider_stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(OpenAiCompatStreamFrame::Chunk(event)))) => {
                    match this.accumulator.push_event(&event) {
                        Ok(events) => this.pending.extend(events.into_iter().map(Ok)),
                        Err(error) => {
                            this.ended = true;
                            return Poll::Ready(Some(Err(error)));
                        }
                    }
                }
                Poll::Ready(Some(Ok(OpenAiCompatStreamFrame::Abort { usage }))) => {
                    this.pending
                        .extend(this.accumulator.abort_with_usage(usage).into_iter().map(Ok));
                }
                Poll::Ready(Some(Ok(OpenAiCompatStreamFrame::Status(response)))) => {
                    this.ended = true;
                    return Poll::Ready(Some(Err(classify_openai_status(
                        response.status,
                        &response.headers,
                        &response.body,
                    ))));
                }
                Poll::Ready(Some(Err(error))) => {
                    this.ended = true;
                    return Poll::Ready(Some(Err(error.into())));
                }
                Poll::Ready(None) => {
                    this.ended = true;
                    match this.accumulator.finish_eof() {
                        Ok(events) => this.pending.extend(events.into_iter().map(Ok)),
                        Err(error) => return Poll::Ready(Some(Err(error))),
                    }
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
