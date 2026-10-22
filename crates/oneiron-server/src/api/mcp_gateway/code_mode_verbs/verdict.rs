//! The decision ladder a code-mode run's routine steps ask before they act.
//! `LadderDecider` (its `RoutineDecider` impl) is its call surface.
//! The code_mode_verbs root defines `LadderDecider`; `oneiron::llm::decision` owns the rungs.

use super::*;

/// A strict run's step no rung answered, with no model asked (CUA E2
/// strict denial, CALLS row): it goes up at zero tokens, its decision a
/// [`StrictDenied`] record, and the subgoal's clock as it was.
pub(super) fn strict_denied(
    denial: StrictDenial,
    question: &str,
    until_ms: Option<u64>,
) -> RoutineReply {
    RoutineReply {
        answer: RoutineAnswer::Denied { denial },
        screenshot: false,
        until_ms,
        decision: StrictDenied::decision(denial, question),
    }
}

impl LadderDecider {
    /// One `ai.verdict` of the run's caller, `input`, with the step's
    /// screenshot `held` for it: through the asker's door (its connector,
    /// its credential, or its agent on the run's line), on the server's
    /// runtime while this thread waits. The verdict's output, or the door's
    /// refusal; the call's own failure is the decider's.
    pub(super) fn verdict(
        &self,
        input: Value,
        held: Option<HeldImage>,
    ) -> Result<Result<Value, McpGatewayError>, BrowserError> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        let origin = self.origin.clone();
        match self.asker.clone() {
            VerdictAsker::Connector(actor) => {
                let run = McpCodeRun {
                    origin,
                    run_id: self.run_id,
                };
                self.runtime.spawn(HELD_IMAGE.scope(held, async move {
                    let _ = sender.send(execute_step_verdict(&server, &actor, input, run).await);
                }));
            }
            VerdictAsker::Credential(auth, _) => {
                self.runtime.spawn(HELD_IMAGE.scope(held, async move {
                    let id = InvocationId::mint().to_hex();
                    let call = crate::api::facade::FacadeCall::bound(&auth, None, Some(&id), None);
                    let answer =
                        crate::api::facade::call_verb(&server, &call, "ai.verdict", Ok(input))
                            .await
                            .map(|answer| (answer.value, answer.rows.unwrap_or_default()))
                            .map_err(|error| super::mcp_facade_error(error.into_memory_error()));
                    let _ = sender.send(answer);
                }));
            }
            VerdictAsker::Agent(actor, line) => {
                self.runtime.spawn_blocking(move || {
                    let answered = crate::server::answer_as_agent(
                        &server,
                        actor,
                        &origin,
                        InvocationId::mint(),
                        AgentVerb::AiVerdict,
                        input,
                        held,
                        line.as_ref(),
                    );
                    // Only the verdict is read here; its rows are not.
                    let answered =
                        answered.map(|(output, rows)| (output, rows.unwrap_or_default()));
                    let _ = sender.send(answered.map_err(super::mcp_facade_error));
                });
            }
        }
        let answered = receiver
            .recv()
            .map_err(|_| BrowserError::Decider("the ladder did not answer".to_owned()))?;
        Ok(answered.map(|(output, _)| output))
    }
}

impl RoutineDecider for LadderDecider {
    fn decide(&mut self, ask: RoutineAsk<'_>) -> Result<RoutineReply, BrowserError> {
        let (strict, until_ms) = (ask.no_model, ask.until_ms);
        // Strict: a screenshot is read only from the Local-vision rung up,
        // so the step goes up before any rung is asked or admitted.
        if strict && ask.image.is_some() {
            return Ok(strict_denied(StrictDenial::Image, ask.question, until_ms));
        }
        let question = ask.question.to_owned();
        // A step with no candidates finds its target in the screenshot.
        let contract = if ask.options.is_empty() {
            AnswerContract::Box
        } else {
            AnswerContract::Choice {
                options: ask.options,
            }
        };
        let request = AiVerdictRequest {
            question: question.clone(),
            contract,
            evidence: Vec::new(),
            state: Some(ask.state),
            // No model: the ladder stops at its rule rung.
            ceiling: ask.no_model.then_some(DecisionRung::Rule),
            // A step acts on a live page: at a cut it abstains and goes up.
            reversibility: AiVerdictReversibility::OutboundEffect,
            deadline_ms: None,
            routine: true,
            image: ask.image.map(|(image, _)| image.to_owned()),
            misses: ask.misses,
            until_ms: ask.until_ms,
        };
        let input =
            serde_json::to_value(&request).map_err(|e| BrowserError::Decider(e.to_string()))?;
        let held = ask
            .image
            .map(|(image, png)| HeldImage::new(self.run_id, image, png.to_vec()));
        let output = match self.verdict(input, held)? {
            // Strict: no rung up to the rule ceiling takes the question, as
            // the ladder finds before it runs any, by its reason (FIX 8047);
            // a hook's or a provider's `model_unavailable` is no NoRule.
            Err(error)
                if strict
                    && error.kind == "model_unavailable"
                    && error
                        .message
                        .starts_with(crate::decision_verdict::NO_RUNG_REASON) =>
            {
                return Ok(strict_denied(StrictDenial::NoRule, &question, until_ms));
            }
            Err(error) => {
                let detail = format!("{}: {}", error.kind, error.message);
                return Err(BrowserError::Decider(detail));
            }
            Ok(output) => output,
        };
        let verdict: AiVerdict = serde_json::from_value(output.clone())
            .map_err(|e| BrowserError::Decider(e.to_string()))?;
        let answer = match verdict.outcome {
            Some(RoutineOutcome::Act { candidate }) => RoutineAnswer::Act { candidate },
            Some(RoutineOutcome::Point { x, y, .. }) => RoutineAnswer::Point { x, y },
            Some(RoutineOutcome::None) => RoutineAnswer::None,
            Some(RoutineOutcome::Reobserve) => RoutineAnswer::Reobserve,
            // The subgoal's clock cut the call: the step stops on it.
            Some(RoutineOutcome::AskUp {
                reason: Some(HumanAskReason::Deadline),
            }) => RoutineAnswer::Deadline,
            // Strict: the rule rung ran and gave no answer; its receipt
            // stands as the decision.
            Some(RoutineOutcome::AskUp { reason: Some(_) }) if strict => RoutineAnswer::Denied {
                denial: StrictDenial::RuleAbstained,
            },
            Some(RoutineOutcome::AskUp { reason }) => RoutineAnswer::AskUp {
                reason: reason
                    .and_then(|reason| serde_json::to_value(reason).ok())
                    .and_then(|reason| reason.as_str().map(str::to_owned)),
            },
            None => {
                return Err(BrowserError::Decider(
                    "the ladder answered no routine outcome".to_owned(),
                ));
            }
        };
        Ok(RoutineReply {
            answer,
            screenshot: verdict.screenshot,
            until_ms: verdict.until_ms,
            decision: output,
        })
    }

    fn check_text(&mut self, check: TextCheck<'_>) -> Result<TextCheckReply, BrowserError> {
        field_writer::check_text(self, check)
    }
}
