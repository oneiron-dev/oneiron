//! The model request of the REPL and its stored-output context projection.
//! Entry: `EngineNativeExecutor::build_llm_request`.
//! Executor state belongs to `engine_executor::driver`; replay rows belong to `code_run`.

use super::*;

impl EngineNativeExecutor<'_> {
    /// Resolve a typed model-facing re-expand action through the same routed
    /// replay store as the original observation, including off-record overlays.
    pub fn reexpand_observation(
        &self,
        record: &CodeRunReplayRecord,
        action: OutputAffordance,
    ) -> EngineExecutorResult<Vec<u8>> {
        self.verify_storage_dispatcher_binding()?;
        if self.output_run != Some(record.run_id) {
            return Err(Error::InvalidConfig("executor output run mismatch".into()).into());
        }
        let OutputAffordance::Reexpand(source) = action else {
            return Err(Error::InvalidConfig("expected reexpand action".into()).into());
        };
        // The manifest names the body: no other observation is read.
        for seq in 0..completed_step_count(record)? {
            let path = observation_output_path(seq);
            let Some(output) = record.outputs.iter().find(|output| output.path == path) else {
                continue;
            };
            if output.output_ref() == source {
                // A body that is not clean reaches the model as the mark.
                if !clean_for_context(&self.storage, Some(record.run_id), output)? {
                    return Ok(CODE_RUN_OUTPUT_PREVIEW_WITHHELD.as_bytes().to_vec());
                }
                return Ok(self
                    .storage
                    .get_code_run_raw_output(output)?
                    .ok_or(Error::CorruptedIndex("executor replay output bytes"))?);
            }
        }
        Err(Error::CorruptedIndex("missing recoverable executor observation").into())
    }

    /// Sync every durably completed observation before either a model request
    /// or a compaction mint. No uncommitted runtime output enters context.
    /// Returns the step that holds each source, for the views that expand it.
    pub(in crate::engine_executor) fn sync_output_context(
        &mut self,
        record: &CodeRunReplayRecord,
    ) -> EngineExecutorResult<HashMap<OutputRef, u64>> {
        // Reconstruct references from the routed durable replay record. No
        // observation is copied into the base vault for off-record sessions.
        // Working flags are projections of committed typed coverage. Rebuild
        // rather than trusting a cached flag or any raw-output existence.
        self.output_context = OutputWorkingContext::default();
        self.output_run = Some(record.run_id);
        let coverage = self.storage.code_run_compaction_coverage(record.run_id)?;
        let mut steps = HashMap::new();
        for (seq, _, observation) in self.observation_refs(record)? {
            self.output_context
                .record_referenced(seq, observation.source, observation.overview)?;
            if coverage.iter().any(|row| row.covers(record.run_id, seq)) {
                self.output_context.compact_span(seq, seq);
            }
            steps.insert(observation.source, seq);
        }
        Ok(steps)
    }

    /// Every completed step's observation reference, from its manifest: no
    /// past body is read to build a turn's context.
    pub(in crate::engine_executor) fn observation_refs(
        &self,
        record: &CodeRunReplayRecord,
    ) -> EngineExecutorResult<Vec<(u64, CodeRunRawOutput, ObservationRef)>> {
        let mut refs = Vec::new();
        for seq in 0..completed_step_count(record)? {
            let path = observation_output_path(seq);
            let output = record
                .outputs
                .iter()
                .find(|output| output.path == path)
                .ok_or(Error::CorruptedIndex("executor replay output path"))?;
            refs.push((seq, output.clone(), observation_ref(output)));
        }
        Ok(refs)
    }

    pub(super) fn build_llm_request(
        &mut self,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        wire_prompt: &str,
        continuation: Option<&ContinuationNote>,
    ) -> EngineExecutorResult<LlmRequest> {
        let completed_steps = completed_step_count(record)?;
        let mut messages = Vec::new();
        messages.push(LlmMessage {
            role: LlmMessageRole::System,
            content: vec![ContentPart::Text {
                text: executor_system_prompt(wire_prompt),
            }],
        });
        messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: format!("Run id: {}\nTask:\n{}", config.run_id.to_hex(), config.task),
            }],
        });

        let steps = self.sync_output_context(record)?;
        // Only a Full view expands its body; older steps cost their reference.
        // A Full body is held against the run's share of the result-memory
        // pool first: one that does not fit stays in its file, and its view
        // falls back to the reference the run reads it by.
        self.context_holds.clear();
        let mut holds = Vec::new();
        let mut left = Vec::new();
        let views = {
            let share = &self.result_share;
            let watch = self.storage.limit_watch();
            self.output_context
                .assemble_with(completed_steps, self.output_decay, |source| {
                    let seq = steps
                        .get(&source)
                        .ok_or(Error::CorruptedIndex("missing executor observation"))?;
                    let Some(hold) = share.hold(source.byte_len, watch) else {
                        left.push((*seq, source));
                        return Ok(None);
                    };
                    holds.push((source, hold));
                    load_context_output(&self.storage, record, &observation_output_path(*seq))
                        .map(|text| Some(text.into_bytes()))
                })?
        };
        let memory_note = result_memory_note(&self.result_share, &holds, &left);
        self.context_holds = holds.into_iter().map(|(_, hold)| hold).collect();
        let epochs = self.compaction_epochs(record.run_id)?;
        if !epochs.is_empty() {
            self.admit_compaction_read()?;
        }
        // The replies parked calls resumed with, by the step that parked.
        let resumed: BTreeMap<u64, &CodeRunRawOutput> = record
            .outputs
            .iter()
            .filter_map(|output| resumed_output_wait(&output.path).map(|(seq, _)| (seq, output)))
            .collect();
        let mut swapped = false;
        for (seq, view) in views.iter().enumerate() {
            messages.extend(self.fold_tail(&epochs, record, seq)?);
            match super::compaction::epoch_frame(&epochs, record.run_id, seq, &views)? {
                Some(Some(frame)) => {
                    messages.push(frame);
                    swapped = true;
                    continue;
                }
                Some(None) => continue,
                None => {}
            }
            let view = view.clone();
            // ONE-1929 framing remains engine-authored. The stored program and
            // observation never change; only this model-facing projection does.
            let console = match view.tier {
                OutputTier::Full | OutputTier::Overview => String::from_utf8(view.bytes)
                    .map_err(|_| Error::CorruptedIndex("executor observation encoding"))?,
                OutputTier::Stub => serde_json::to_string(&json!({
                    "sandbox.fs.read_file": recoverable_chunk_path(seq as u64, view.source, 0),
                    "byte_len": view.source.byte_len,
                    "max_chunk_bytes": RECOVERABLE_OUTPUT_CHUNK_BYTES,
                }))?,
            };
            let turn = CodeRunHistoryTurn {
                code: load_context_output(&self.storage, record, &script_output_path(seq as u64))?,
                console,
            };
            messages.push(LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: turn.assistant_exec(),
                }],
            });
            messages.push(LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: turn.user_console(seq as u64),
                }],
            });
            if let Some(output) = resumed.get(&(seq as u64)) {
                messages.push(self.resumed_reply_message(record, seq as u64, output)?);
            }
        }
        messages.extend(self.fold_tail(&epochs, record, views.len())?);

        // Past a swap, the run's results are named once more beside the
        // frame that replaced the turns that bound them.
        if swapped && let Some(brief) = self.bindings_brief(record)? {
            messages.push(LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text { text: brief }],
            });
        }
        if let Some(note) = memory_note {
            messages.push(LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text { text: note }],
            });
        }
        // An approved continuation's note, its own message (FIX 3694).
        messages.extend(turn_note(continuation, completed_steps));
        messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: executor_turn_instruction(completed_steps, wire_prompt),
            }],
        });

        let mut request = LlmRequest {
            model: config.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                // A scoped child's calls carry the resource scope its loan
                // lent it (FIX 7507); every other run's keep the default.
                scope: self
                    .gated_write
                    .scoped_child_scope()
                    .cloned()
                    .unwrap_or_default(),
                purpose: CallPurpose::Other {
                    name: ENGINE_EXECUTOR_PURPOSE_NAME.to_owned(),
                },
                class: CallClass::Durable {
                    fallback: DeterministicFallback {
                        name: ENGINE_EXECUTOR_FALLBACK_NAME.to_owned(),
                        config: Some(json!({
                            "run_id": config.run_id.to_hex(),
                            "step_seq": completed_steps,
                        })),
                    },
                },
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Other {
                        name: ENGINE_EXECUTOR_PURPOSE_NAME.into(),
                    },
                    config.global_tier.clone(),
                ),
                response_format: ResponseFormat::Text,
                locality: config.model_locality,
            },
            messages,
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        };
        if let Some(seat) = self.seat {
            seat.bind(&mut request);
        }
        // FIX 4930: the step's own call marks where its prefix ends, so the
        // fork a compaction sends after it names the same block.
        crate::code_run::main_prefix_boundary(&mut request)?;
        Ok(request)
    }
}

impl EngineNativeExecutor<'_> {
    /// What follows a parked step's turn once its wait was answered: the
    /// reply inline within one reply's bound, else its card under `wait<s>`.
    /// A body that is not clean reaches the model as its card, which withholds
    /// it.
    pub(super) fn resumed_reply_message(
        &self,
        record: &CodeRunReplayRecord,
        seq: u64,
        output: &CodeRunRawOutput,
    ) -> EngineExecutorResult<LlmMessage> {
        let wait = parked_wait_at(&self.storage, record, seq)?.ok_or(Error::CorruptedIndex(
            "executor resumed reply without a wait",
        ))?;
        let head = format!(
            "The call parked at step {seq} ({}, wait {}) answered",
            wait.effect.as_str(),
            wait.wait_id.to_hex()
        );
        let text = if output.raw_len <= RESULT_REPLY_INLINE_BYTES as u64
            && clean_for_context(&self.storage, Some(record.run_id), output)?
        {
            let body: serde_json::Value =
                serde_json::from_str(&load_utf8_output(&self.storage, record, &output.path)?)
                    .map_err(|_| Error::CorruptedIndex("executor resumed reply"))?;
            format!("{head}:\n{}", serde_json::to_string(&body["reply"])?)
        } else {
            let name = format!("wait{seq}");
            let card = crate::code_run::result_card(
                &self.storage,
                record.run_id,
                output,
                Some(name.as_str()),
            )?;
            format!(
                "{head}; the reply is the result {name}:\n{}",
                serde_json::to_string(&card)?
            )
        };
        Ok(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text { text }],
        })
    }
}

/// Bound results a post-swap brief lists, newest first.
pub(super) const BRIEF_BINDINGS: usize = 64;

/// Characters of a result's preview a brief line carries.
pub(super) const BRIEF_PREVIEW_CHARS: usize = 120;

impl EngineNativeExecutor<'_> {
    /// The run's live result names, newest first, a line each from its
    /// manifest and taint sidecars alone: no body is read.
    pub(super) fn bindings_brief(
        &self,
        record: &CodeRunReplayRecord,
    ) -> EngineExecutorResult<Option<String>> {
        if record.bindings.is_empty() {
            return Ok(None);
        }
        let mut lines = vec![
            "Results bound in this run (describe(name) gives a card; a card's `read` path reads \
             it a chunk at a time):"
                .to_owned(),
        ];
        for binding in record.bindings.iter().rev().take(BRIEF_BINDINGS) {
            let Some(output) = record
                .outputs
                .iter()
                .find(|output| output.handle == binding.handle)
            else {
                return Err(Error::CorruptedIndex("executor result binding").into());
            };
            let preview: String = if clean_for_context(&self.storage, Some(record.run_id), output)?
            {
                output
                    .preview
                    .text
                    .chars()
                    .take(BRIEF_PREVIEW_CHARS)
                    .map(|c| if c == '\n' { '\u{23ce}' } else { c })
                    .collect()
            } else {
                "withheld".to_owned()
            };
            lines.push(format!(
                "{} \u{2014} {}, {} bytes, {} lines, {} \u{2014} preview: {preview}",
                binding.name,
                match output.kind {
                    crate::code_run::CodeRunOutputKind::Text => "text",
                    crate::code_run::CodeRunOutputKind::Binary => "binary",
                },
                grouped(output.raw_len),
                grouped(output.lines),
                if output.complete {
                    "complete"
                } else {
                    "incomplete"
                },
            ));
        }
        if record.bindings.len() > BRIEF_BINDINGS {
            lines.push(format!(
                "\u{2026}and {} more",
                record.bindings.len() - BRIEF_BINDINGS
            ));
        }
        Ok(Some(lines.join("\n")))
    }
}

/// `n` with its thousands grouped: `2,104,331`.
pub(super) fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (at, digit) in digits.chars().enumerate() {
        if at > 0 && (digits.len() - at) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Past 60% of the run's result-memory share, a line naming the biggest
/// bodies held; and one line for every body that stayed in its file because
/// it did not fit, naming why and how to read it.
pub(super) fn result_memory_note(
    share: &crate::result_memory::ResultShare,
    held: &[(OutputRef, crate::result_memory::ResultHold)],
    left: &[(u64, OutputRef)],
) -> Option<String> {
    let mut lines = Vec::new();
    let share_bytes = share.bytes();
    let held_bytes = share.held();
    if held_bytes.saturating_mul(10) > share_bytes.saturating_mul(6) {
        let mut biggest: Vec<_> = held.iter().map(|(source, _)| *source).collect();
        biggest.sort_by_key(|source| std::cmp::Reverse(source.byte_len));
        let names: Vec<_> = biggest
            .iter()
            .take(3)
            .map(|source| {
                format!(
                    "output:blake3:{}:{}",
                    crate::entity_id::bytes_to_hex_lower(&source.hash),
                    source.byte_len
                )
            })
            .collect();
        lines.push(format!(
            "Result memory: {held_bytes} of this run's {share_bytes} bytes held \
             (limits.code_result_session_memory_bytes); biggest: {}.",
            names.join(", ")
        ));
    }
    for (seq, source) in left {
        lines.push(format!(
            "Result of step {seq} ({} bytes) left context memory: it would pass \
             limits.code_result_session_memory_bytes or limits.code_result_memory_bytes. \
             It is stored whole; read it with sandbox.fs.read_file(\"{}\").",
            source.byte_len,
            recoverable_chunk_path(*seq, *source, 0)
        ));
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}
