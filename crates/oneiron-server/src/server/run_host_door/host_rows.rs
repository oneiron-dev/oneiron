//! Host-served verb rows for an agent run and its model options.
//! `host_row` uses the run's actor, payer, and existing decision surfaces.
//! The door, trait implementation, and shared helpers stay in the parent module.

use super::{
    AdmittedRenderer, AgentVerb, AiOperation, AiOptions, AiOptionsRequest, AiVerdictRequest, Arc,
    BTreeSet, DecisionRung, EntityId, GraphAskOutcome, GraphAskRequest, HeldImage, HostUnitDecider,
    LadderGraphAnswerer, Memory, MemoryError, MemoryResult, Modality, QuestionAnswersRequest,
    QuestionBackfillRequest, QuestionCreateRequest, QuestionEditRequest,
    QuestionOutcomeWindowsRequest, QuestionPauseRequest, QuestionPaused, QuestionReadRequest,
    RenderRefusal, RunAdmission, SyncServer, TaskWaveRequest, Value, WriteActor, agent_lane,
    closed_outcome_windows, create_question, decode, edit_question, encode, inside_host_dial,
    internal, on_caller_payer, owners, pause_question, question_answers, read_question,
    resume_held_wave, run_graph_ask_receipted, run_verdict, schedule_backfill,
    select_graph_units_by_type, wave_plan, wave_receipt,
};

/// One row the host serves, asked for the agent: never for a principal or
/// a time the input names. An `ai.verdict` keeps the rows its evidence
/// resolved to in `evidence`, and a connector call the rows its passes
/// picked, or `None` there when those are not known.
pub(super) fn host_row(
    server: &SyncServer,
    actor: WriteActor,
    memory: &Memory<'_>,
    verb: AgentVerb,
    input: Value,
    line: Option<&RunAdmission>,
    evidence: &mut Option<Vec<EntityId>>,
) -> MemoryResult<Value> {
    let (principal, class) = (actor.entity_ref(), actor.actor_class());
    let vault = server.vault();
    let now = oneiron_vault_contract::now_ts();
    match verb {
        AgentVerb::Report => {
            let request: oneiron::feedback::ReportRequest = decode(input)?;
            request.validate().map_err(MemoryError::from)?;
            let vector = request
                .embedding_text()
                .and_then(|text| server.embed_query(&text).ok());
            encode(memory.report_with_embedding(request, vector.as_deref())?)
        }
        // Its query embeds bill the payer the run's line binds (FIX 805).
        AgentVerb::VaultRecall => encode(server.recall(
            memory,
            principal,
            class,
            decode(input)?,
            line.and_then(RunAdmission::payer),
        )?),
        AgentVerb::AiVerdict => {
            let request: AiVerdictRequest = decode(input)?;
            let held = HeldImage::in_task(request.image.as_deref());
            // An image is pulled through the agent's own lane before any
            // model reads it, unless it is the run's own held screenshot.
            let lane = match (&request.image, &held) {
                (Some(_), None) => Some(agent_lane(server, actor)?),
                _ => None,
            };
            encode(run_verdict(
                server,
                principal,
                class,
                memory,
                lane.as_ref(),
                held,
                &request,
                // It bills the payer the run's line binds (FIX 3574).
                line.and_then(RunAdmission::payer),
                evidence.get_or_insert_with(Vec::new),
            )?)
        }
        AgentVerb::VaultGraphAsk => {
            let request: GraphAskRequest = decode(input)?;
            request.validate()?;
            let lane = agent_lane(server, actor)?;
            let units = match request.select {
                Some(select) => {
                    select_graph_units_by_type(&lane, select.entity_type, select.limit)?
                }
                None => request.units,
            };
            let dial = server
                .decision_host()
                .dial(request.ceiling.unwrap_or(DecisionRung::Big));
            let budget = oneiron::llm::decision::questions::question_call_budget(
                server.vault(),
                request.unit_deadline_ms,
            )?;
            let mut answerer = LadderGraphAnswerer::new(server, actor, dial, budget)?
                .with_posture(request.posture)
                .with_criteria(request.criteria.unwrap_or_default());
            // Its model rungs bill the payer the run's line binds (FIX 3574).
            let asked = on_caller_payer(line.and_then(RunAdmission::payer), || {
                run_graph_ask_receipted(&lane, actor, request.question, &units, &mut answerer, now)
            });
            encode(match asked {
                Ok(receipts) => GraphAskOutcome::from(receipts),
                Err(failure) => GraphAskOutcome::from_failure(failure)?,
            })
        }
        AgentVerb::VaultQuestionsCreate => {
            let request: QuestionCreateRequest = decode(input)?;
            let mut definition = request.definition;
            definition.dial = inside_host_dial(server, definition.dial, verb)?;
            encode(create_question(vault, actor, definition, now)?)
        }
        AgentVerb::VaultQuestionsEdit => {
            let request: QuestionEditRequest = decode(input)?;
            let mut definition = request.definition;
            definition.dial = inside_host_dial(server, definition.dial, verb)?;
            encode(edit_question(
                vault,
                actor,
                request.id,
                request.expected_version,
                definition,
                now,
            )?)
        }
        AgentVerb::VaultQuestionsPause => {
            let request: QuestionPauseRequest = decode(input)?;
            pause_question(vault, principal, request.id, request.paused)?;
            encode(QuestionPaused {
                id: request.id,
                paused: request.paused,
            })
        }
        AgentVerb::VaultQuestionsBackfill => {
            let request: QuestionBackfillRequest = decode(input)?;
            encode(schedule_backfill(
                vault,
                principal,
                request.id,
                request.expected_version,
                request.at.unwrap_or(now),
                request.joins,
            )?)
        }
        AgentVerb::VaultQuestionsRead => {
            let request: QuestionReadRequest = decode(input)?;
            encode(read_question(
                vault,
                principal,
                request.id,
                request.version,
            )?)
        }
        AgentVerb::VaultQuestionsOutcomeWindows => {
            let request: QuestionOutcomeWindowsRequest = decode(input)?;
            encode(closed_outcome_windows(vault, principal, request.id)?)
        }
        AgentVerb::VaultQuestionsAnswers => {
            let request: QuestionAnswersRequest = decode(input)?;
            encode(question_answers(vault, principal, &request)?)
        }
        AgentVerb::VaultArtifactsReviewSlides => {
            let request: oneiron::blob_artifact::SlideReviewSubmit = decode(input)?;
            let host = server.decision_host();
            // Its render takes a turn in the renderer line as it starts, at
            // the agent's fair place (FIX 7653).
            let renderer = AdmittedRenderer::at_render(server, Some(principal), Arc::default());
            encode(memory.artifacts_review_slides_through(
                &request,
                &HostUnitDecider::new(server, class, "vault.artifacts.review_slides"),
                host.dial(DecisionRung::Big),
                &host.bands(),
                renderer.as_ref().map(AdmittedRenderer::slides),
            )?)
        }
        AgentVerb::VaultArtifactsBodyDeckPreview => {
            let request = decode(input)?;
            // The agent's fair turn in the renderer line comes before any of
            // the preview's work, as a served caller's does, and is kept with
            // the memory it leased until the answer is encoded (FIX 7653).
            let turn = server
                .renderer_turns
                .admit_blocking(principal)
                .map_err(|_| RenderRefusal::Deadline.memory_error())?;
            let renderer = AdmittedRenderer::held(server, turn, Arc::default())?;
            let preview = memory.artifacts_body_deck_preview(
                &request,
                renderer.as_ref().map(AdmittedRenderer::slides),
            );
            encode(crate::slide_render::rendered(preview, renderer)?)
        }
        AgentVerb::AiOptions => encode(ai_options(server, principal, line, decode(input)?)?),
        // The run's own speech, on the line its entry spends on (FIX 3194).
        AgentVerb::AiSpeech => {
            let line = line.ok_or_else(|| internal(verb))?;
            encode(
                tokio::runtime::Handle::current().block_on(crate::api::ai_speech_for_run(
                    server,
                    line,
                    decode(input)?,
                ))?,
            )
        }
        // The run's own wave: planned for its agent and queued on its own
        // surface, whose bound lease is the wave's creator (OF-532). Asked
        // again while its plan is held at its spend cap, it resumes that
        // plan (FIX 1723).
        AgentVerb::TasksWave => {
            let request: TaskWaveRequest = decode(input)?;
            let lane = agent_lane(server, actor)?;
            let (epic, constraints) =
                wave_plan(server, actor, |id| lane.is_entity_readable(id), &request)?;
            let queued = memory.enqueue_wave_plan(epic, &request.objective, constraints, now)?;
            encode(wave_receipt(resume_held_wave(server, actor, queued, now)?)?)
        }
        // The agent's own grant and gate, under the step's invocation; the
        // rows its passes picked join the row's (FIX 5455). A web call on the
        // deploy's key spends on the entry's line (FIX 11604).
        AgentVerb::ConnectorCall => {
            let (reply, picked) =
                crate::api::connector_call_listing_on(server, memory, decode(input)?, line)?;
            match picked {
                Some(mut picked) => {
                    if let Some(rows) = evidence.as_mut() {
                        rows.append(&mut picked);
                    }
                }
                None => *evidence = None,
            }
            encode(reply)
        }
        // The agent's own handle; a connector call under its grant and gate.
        AgentVerb::SelfUse => encode(crate::api::self_use_as(server, memory, decode(input)?)?),
        AgentVerb::VaultHooksReplay => Err(owners(verb, "hook replays are the owner's")),
        _ => match granted_media(server, principal, verb) {
            Some(operation) => granted_media_row(server, principal, line, verb, operation, input),
            None => Err(owners(verb, "ai.* media calls are the owner's")),
        },
    }
}

/// The `ai.*` media operation `verb` calls when a live Grant the owner
/// minted the run's agent `agent` names it (FIX 3208), else `None`: the
/// verb stays the owner's. A Grant that cannot be read names none.
fn granted_media(server: &SyncServer, agent: EntityId, verb: AgentVerb) -> Option<AiOperation> {
    let operation = match verb {
        AgentVerb::AiImage => AiOperation::Image,
        AgentVerb::AiTranscribe => AiOperation::Transcribe,
        AgentVerb::AiEmbed => AiOperation::Embed,
        AgentVerb::AiVideo | AgentVerb::AiVideoPoll | AgentVerb::AiVideoCancel => {
            AiOperation::Video
        }
        _ => return None,
    };
    server
        .vault()
        .agent_ai_operations(agent)
        .ok()?
        .contains(operation.as_str())
        .then_some(operation)
}

/// One `ai.*` media row the owner's Grant admits the run's agent `agent`
/// for (FIX 3208), on `line`, the line its entry spends on, as its own
/// `ai.speech` is: its call, its video job from submit to end, and the poll
/// and cancel of the jobs its own run submitted there.
fn granted_media_row(
    server: &SyncServer,
    agent: EntityId,
    line: Option<&RunAdmission>,
    verb: AgentVerb,
    operation: AiOperation,
    input: Value,
) -> MemoryResult<Value> {
    let line = line.ok_or_else(|| internal(verb))?;
    let runtime = tokio::runtime::Handle::current();
    match verb {
        AgentVerb::AiVideo => encode(runtime.block_on(crate::api::ai_video_for_run(
            server,
            line,
            decode(input)?,
            Some(agent),
        ))?),
        AgentVerb::AiVideoPoll => encode(runtime.block_on(crate::api::ai_video_poll_for_run(
            server,
            line,
            decode(input)?,
        ))?),
        AgentVerb::AiVideoCancel => encode(runtime.block_on(
            crate::api::ai_video_cancel_for_run(server, line, decode(input)?),
        )?),
        _ => encode(runtime.block_on(crate::api::ai_media_for_run(
            server,
            line,
            operation,
            decode(input)?,
        ))?),
    }
}

/// `ai.options` from the host's model runtime: the rows the agent could call
/// now (FIX 2942). Its `ai.speech` is admitted, on `line`, so it lists the
/// speech rows, with what that line has left (FIX 3194), and so are the
/// media operations a live Grant the owner minted `agent` names (FIX 3208);
/// every other `ai.*` call door is the owner's and refuses the agent.
fn ai_options(
    server: &SyncServer,
    agent: EntityId,
    line: Option<&RunAdmission>,
    request: AiOptionsRequest,
) -> MemoryResult<AiOptions> {
    let operation = request
        .operation
        .as_deref()
        .map(|name| {
            AiOperation::parse(name).ok_or_else(|| {
                MemoryError::bad_request(
                    "operation is one of text, image, video, speech, transcribe, embed",
                )
            })
        })
        .transpose()?;
    let inputs = request
        .inputs
        .iter()
        .map(|name| {
            serde_json::from_value::<Modality>(Value::String(name.trim().to_owned())).map_err(
                |_| MemoryError::bad_request("inputs are text, image, audio, video or embedding"),
            )
        })
        .collect::<MemoryResult<BTreeSet<_>>>()?;
    let left = line.map(|line| line.read().remaining_units);
    // Text is the raw routes', which a run never reaches; a run with no
    // line calls no granted row.
    let granted: BTreeSet<AiOperation> = server
        .vault()
        .agent_ai_operations(agent)
        .unwrap_or_default()
        .iter()
        .filter_map(|name| AiOperation::parse(name))
        .filter(|operation| *operation != AiOperation::Text)
        .collect();
    let listed = if granted.is_empty() || line.is_none() {
        crate::api::ai::run_options(server, left, operation, &inputs)
    } else {
        crate::api::ai::line_options(server, left, operation, &inputs, |row_operation| {
            row_operation == AiOperation::Speech || granted.contains(&row_operation)
        })
    };
    let options = listed
        .options
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()
        .map_err(|_| internal(AgentVerb::AiOptions))?;
    Ok(AiOptions {
        options,
        media_units_left: listed.media_units_left,
    })
}
