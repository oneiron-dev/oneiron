//! The serve judge's replay evidence: each reserved receipt's task and
//! response, read whole from its attempt, and the states the judge's
//! questions read them in, cut only where the ladder's state bound needs;
//! and the whole responses and rubric the shared decision path scores and
//! pairs blind preferences from.
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use oneiron::compaction::output::{OutputRef, restore_output};
use oneiron::dispatch_byoa::{decode_byoa_exhaust, parse_byoa_result_ref};
use oneiron::dreamer_runner::decode_dreamer_attempt_payload;
use oneiron::dreamer_runner::maintenance::agent_health::{
    AgentHealthTone, HEALTH_REVIEW_RECEIPT_PREFIX,
};
use oneiron::limit_ask::EngineLimit;
use oneiron::llm::decision::MAX_DECISION_STATE_BYTES;
use oneiron::skill_optimize::{
    HeldOutReplayCase, HonestyReplay, JudgeRubric, SkillEditGoal, SkillReplayResponse,
    SkillReplayResponses, judge_rubric, skill_edit_goal,
};
use oneiron::{EntityId, Result, Vault};
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use serde::Serialize;
use serde_json::{Value, json};

use super::{ATTEMPT_RECEIPT, ServeReplayJudge};

/// Room a judgment's call puts around a state the judge builds, past the
/// case fields [`fit`] is told of: the question's axis and kind, a
/// decorator's coverage floor, the JSON around them.
const CALL_ROOM: usize = 1_024;

/// `text` whole, or cut to `at` bytes on a character boundary.
fn cut(text: &str, at: Option<usize>) -> &str {
    let Some(at) = at else {
        return text;
    };
    let mut end = text.len().min(at);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The bytes `value` takes as JSON.
fn json_len<T: Serialize + ?Sized>(value: &T) -> usize {
    serde_json::to_vec(value).map_or(0, |bytes| bytes.len())
}

/// The cut a judgment's state is built at: `None` while `state` with every
/// text whole, and the `beside` bytes its call puts around it, fits the
/// ladder's state bound ([`MAX_DECISION_STATE_BYTES`]), which refuses a
/// larger state. Past it, half the `longest` text, halving until it fits.
/// The texts' own `[limits]` rows never cut; only the ladder's bound does.
fn fit(beside: usize, longest: usize, state: impl Fn(Option<usize>) -> Value) -> Option<usize> {
    let room = MAX_DECISION_STATE_BYTES.saturating_sub(beside.saturating_add(CALL_ROOM));
    let mut at = None;
    loop {
        let fits = json_len(&state(at)) <= room;
        at = match at {
            _ if fits => return at,
            None if longest > 0 => Some(longest / 2),
            Some(bytes) if bytes > 0 => Some(bytes / 2),
            _ => return at,
        };
    }
}

/// `state`, saying where its texts were cut (`cut_at_bytes`) when they were,
/// so a provider knows it reads a cut text.
fn cut_at(mut state: Value, at: Option<usize>) -> Value {
    if let Some(bytes) = at {
        state["cut_at_bytes"] = json!(bytes);
    }
    state
}

/// The attempt behind a terminal pack receipt (`attempt:<32 hex>`), when its
/// row is still kept.
fn attempt_of(vault: &Vault, receipt: &str) -> Result<Option<AttemptRecord>> {
    let Some(hex) = receipt.strip_prefix(ATTEMPT_RECEIPT) else {
        return Ok(None);
    };
    let id = EntityId::from_hex(hex)?;
    AttemptQueue::new(vault).get(AttemptId::from_bytes(id.as_bytes())?)
}

/// The task an attempt was given: a Dreamer or agent payload's input, else
/// the payload as text.
fn task_text(attempt: &AttemptRecord) -> String {
    decode_dreamer_attempt_payload(&attempt.payload).map_or_else(
        |_| String::from_utf8_lossy(&attempt.payload).into_owned(),
        |payload| payload.input.to_string(),
    )
}

/// What an attempt answered, through its result ref: a code-run output, a
/// BYOA run's transcript (else its stdout), an entity's text, or the ref
/// itself when nothing here resolves it.
fn response_text(vault: &Vault, attempt: &AttemptRecord) -> String {
    let Some(result) = attempt.result_ref() else {
        return String::new();
    };
    let text = result.as_str();
    if let Ok(output) = OutputRef::from_handle(text) {
        return restore_output(vault, output)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
    }
    if let Ok((artifact, version)) = parse_byoa_result_ref(result) {
        return decode_byoa_exhaust(vault, &artifact, version)
            .ok()
            .and_then(|(_, _, exhaust)| {
                // The judge reads the answer whole, however long it ran.
                let stream = exhaust.transcript.as_ref().unwrap_or(&exhaust.stdout);
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut stream.reader(), &mut bytes).ok()?;
                Some(String::from_utf8_lossy(&bytes).into_owned())
            })
            .unwrap_or_default();
    }
    if let Ok(entity) = EntityId::from_hex(text) {
        return vault.entity_text(&entity).unwrap_or_default();
    }
    text.to_owned()
}

impl ServeReplayJudge {
    /// The skill's already-read goal as a judge question reads it: the joined
    /// project's goal, its why, and each axis's measure and bound. `None` when
    /// the goal joins no project, or the project states no goal record.
    fn goal_brief(&self, goal: &SkillEditGoal) -> Result<Option<Value>> {
        let Some((project, _)) = goal.project else {
            return Ok(None);
        };
        Ok(self.vault.project_intake_goal(project)?.map(|record| {
            let axes: Vec<Value> = record
                .primary_axes
                .iter()
                .chain(&record.floor_axes)
                .chain(&record.cost_axes)
                .map(
                    |axis| json!({"name": axis.name, "measure": axis.measure, "bound": axis.bound}),
                )
                .collect();
            json!({"goal": record.goal, "why": record.why, "axes": axes})
        }))
    }

    /// A reserved receipt's run as a replay reads it: its kind, task and
    /// response. `None` when its row is no longer kept.
    fn replay_texts(&self, receipt: &str) -> Result<Option<(String, String, String)>> {
        Ok(attempt_of(&self.vault, receipt)?.map(|attempt| {
            let task = task_text(&attempt);
            let response = response_text(&self.vault, &attempt);
            (attempt.kind, task, response)
        }))
    }

    /// A reviewer receipt (`health_review:` and 64 hex) as a replay reads
    /// it: the evaluator as its kind, the evidence its card held when the
    /// outcome froze it as its task, and the evaluator's decision on that
    /// evidence as its response; never the outcome, who set it or its label.
    /// `None` when no card holds it.
    fn health_review_texts(&self, receipt: &str) -> Result<Option<(String, String, String)>> {
        let Some((card, held)) = self.vault.health_review_receipt(receipt)? else {
            return Ok(None);
        };
        let hex = |ids: &[EntityId]| ids.iter().map(EntityId::to_hex).collect::<Vec<_>>();
        let task = json!({
            "signal": card.signal.as_str(),
            "subject": card.subject.to_hex(),
            "task": card.task.as_ref().map(EntityId::to_hex),
            "dial": held.dial,
            "measured": held.measured,
            "diagnostics": hex(&held.diagnostics),
            "evidence": hex(&held.evidence),
            "observed_brief": held.observed_brief,
        });
        let response = json!({
            "reviewer": held.reviewer,
            "raised": AgentHealthTone::of(card.signal).as_str(),
            "moves": card.moves,
        });
        Ok(Some((
            held.reviewer,
            task.to_string(),
            response.to_string(),
        )))
    }

    /// A reviewer receipt's honesty objective: its frozen evidence, beside
    /// the evaluator's decision, as [`Self::honesty_objectives`] reads a run.
    /// `None` when `receipt` is no reviewer receipt.
    fn health_review_honesty(
        &self,
        case_fields: usize,
        receipt: &str,
    ) -> Result<Option<HonestyReplay>> {
        if !receipt.starts_with(HEALTH_REVIEW_RECEIPT_PREFIX) {
            return Ok(None);
        }
        let Some((kind, task, response)) = self.health_review_texts(receipt)? else {
            return Ok(Some(HonestyReplay {
                receipt: receipt.to_owned(),
                state: json!({"receipt": receipt, "kept": false}),
                objectives: vec![self.phrasing.missing_objective(receipt)],
            }));
        };
        // Read whole; past its `[limits]` row it asks whether all is well.
        self.measure(
            EngineLimit::JudgeReplayTextBytes,
            task.len() + response.len(),
        );
        let state = |at: Option<usize>| {
            cut_at(
                json!({"receipt": receipt, "kind": kind, "response": cut(&response, at)}),
                at,
            )
        };
        let at = fit(
            case_fields + json_len(receipt),
            task.len().max(response.len()),
            |at| json!({"replay": state(at), "objective": cut(&task, at)}),
        );
        Ok(Some(HonestyReplay {
            receipt: receipt.to_owned(),
            state: state(at),
            objectives: vec![cut(&task, at).to_owned()],
        }))
    }

    /// Measures `bytes` against `row`: past it the row asks whether all is
    /// well, and the text still rides whole.
    fn measure(&self, row: EngineLimit, bytes: usize) {
        self.vault
            .measure_limit(row, u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    /// Each reserved receipt's task and response, whole while the
    /// judgment's state fits the ladder's bound (else [`fit`]'s cut); never
    /// its status, verdict or success. The skill's instructions ride whole
    /// in the case the gate puts around this state. The goal's own words
    /// ride beside the replays when the skill's goal joins a project that
    /// states them, and the judge's rubric (the active shared `judge`
    /// skill's text) when one is in force, so an edit of it changes what
    /// every case is judged by.
    pub(super) fn case_replays(&self, case: &HeldOutReplayCase<'_>) -> Result<Value> {
        let receipts = case.held_out_receipts;
        let mut replays = Vec::with_capacity(receipts.len());
        for receipt in receipts {
            // A reviewer receipt replays its card's frozen evidence.
            if receipt.starts_with(HEALTH_REVIEW_RECEIPT_PREFIX) {
                replays.push((receipt, self.health_review_texts(receipt)?));
                continue;
            }
            replays.push((receipt, self.replay_texts(receipt)?));
        }
        let texts = || replays.iter().filter_map(|(_, texts)| texts.as_ref());
        // One goal read: the revision the case is judged under rides beside
        // the brief it was worded from.
        let edit_goal = skill_edit_goal(&self.vault, &case.skill).ok();
        let goal = match &edit_goal {
            Some(edit_goal) => self.goal_brief(edit_goal)?,
            None => None,
        };
        let rubric = judge_rubric(&self.vault)?;
        // Each read whole; past its `[limits]` row it asks whether all is well.
        self.measure(EngineLimit::JudgeInstructionsBytes, case.instructions.len());
        self.measure(
            EngineLimit::JudgeReplayTextBytes,
            texts()
                .map(|(_, task, response)| task.len() + response.len())
                .sum(),
        );
        if let Some(rubric) = &rubric {
            self.measure(EngineLimit::JudgeRubricBytes, rubric.text.len());
        }
        let state = |at: Option<usize>| {
            let replays: Vec<Value> = replays
                .iter()
                .map(|(receipt, texts)| match texts {
                    None => json!({"receipt": receipt, "kept": false}),
                    Some((kind, task, response)) => json!({
                        "receipt": receipt,
                        "kind": kind,
                        "task": cut(task, at),
                        "response": cut(response, at),
                    }),
                })
                .collect();
            let mut state = json!({
                "skill_id": case.skill_id,
                "version": case.version,
                "replays": replays,
            });
            if let Some(edit_goal) = &edit_goal {
                state["goal_revision"] = json!(edit_goal.revision);
            }
            if let Some(goal) = &goal {
                state["goal"] = goal.clone();
            }
            if let Some(rubric) = &rubric {
                state["judge_rubric"] = json!(rubric.text);
                state["judge_rubric_pin"] = json!({
                    "skill": rubric.skill.to_hex(),
                    "version": rubric.version,
                    "digest": bytes_to_hex_lower(&rubric.digest),
                });
            }
            cut_at(state, at)
        };
        // The gate's case carries the instructions and receipts beside it.
        let beside = json_len(&json!({
            "skill": case.skill.to_hex(), "skill_id": case.skill_id,
            "version": case.version, "instructions": case.instructions,
            "held_out_receipts": receipts,
        }));
        let longest = texts()
            .map(|(_, task, response)| task.len().max(response.len()))
            .max()
            .unwrap_or(0);
        Ok(state(fit(beside, longest, &state)))
    }

    /// One objective per reserved run, its task, beside the run's response;
    /// never its status, verdict or success. A run whose row is gone keeps an
    /// objective naming its receipt, so both arms check the same objectives.
    pub(super) fn honesty_objectives(
        &self,
        case: &HeldOutReplayCase<'_>,
    ) -> Result<Vec<HonestyReplay>> {
        // The hidden-flaw question puts the case and the receipt beside each
        // state and its objective.
        let case_fields = json_len(&json!({
            "skill": case.skill.to_hex(), "skill_id": case.skill_id,
            "version": case.version, "instructions": case.instructions,
        }));
        case.held_out_receipts
            .iter()
            .map(|receipt| {
                if let Some(replay) = self.health_review_honesty(case_fields, receipt)? {
                    return Ok(replay);
                }
                Ok(match self.replay_texts(receipt)? {
                    None => HonestyReplay {
                        receipt: receipt.clone(),
                        state: json!({"receipt": receipt, "kept": false}),
                        objectives: vec![self.phrasing.missing_objective(receipt)],
                    },
                    Some((kind, task, response)) => {
                        // Read whole; past its `[limits]` row it asks whether
                        // all is well.
                        self.measure(
                            EngineLimit::JudgeReplayTextBytes,
                            task.len() + response.len(),
                        );
                        let state = |at: Option<usize>| {
                            cut_at(
                                json!({
                                    "receipt": receipt,
                                    "kind": kind,
                                    "response": cut(&response, at),
                                }),
                                at,
                            )
                        };
                        let at = fit(
                            case_fields + json_len(receipt),
                            task.len().max(response.len()),
                            |at| json!({"replay": state(at), "objective": cut(&task, at)}),
                        );
                        HonestyReplay {
                            receipt: receipt.clone(),
                            state: state(at),
                            objectives: vec![cut(&task, at).to_owned()],
                        }
                    }
                })
            })
            .collect()
    }

    /// Each reserved receipt's task and response, read whole, for the shared
    /// decision path to score and pair, and the judge's rubric beside them;
    /// never its status, verdict, success or the instructions it ran under.
    /// A receipt whose row is gone, or whose response is empty, is left out.
    pub(super) fn response_basis(&self, receipts: &[String]) -> Result<SkillReplayResponses> {
        let mut responses = Vec::with_capacity(receipts.len());
        for receipt in receipts {
            // A reviewer receipt's decision is scored like a run's response.
            if receipt.starts_with(HEALTH_REVIEW_RECEIPT_PREFIX) {
                if let Some((_, task, response)) = self.health_review_texts(receipt)? {
                    self.measure(
                        EngineLimit::JudgeReplayTextBytes,
                        task.len() + response.len(),
                    );
                    responses.push(SkillReplayResponse {
                        receipt: receipt.clone(),
                        task,
                        response,
                    });
                }
                continue;
            }
            let Some(attempt) = attempt_of(&self.vault, receipt)? else {
                continue;
            };
            let response = response_text(&self.vault, &attempt);
            if response.trim().is_empty() {
                continue;
            }
            let task = task_text(&attempt);
            // Read whole; past its `[limits]` row it asks whether all is well.
            self.measure(
                EngineLimit::JudgeReplayTextBytes,
                task.len() + response.len(),
            );
            responses.push(SkillReplayResponse {
                receipt: receipt.clone(),
                task,
                response,
            });
        }
        Ok(SkillReplayResponses {
            responses,
            rubric: self.rubric()?,
        })
    }

    /// The judge's rubric, the active shared `judge` skill's text, when one
    /// is in force: every response is scored by it. Read whole; past its
    /// `[limits]` row it asks whether all is well.
    pub(crate) fn rubric(&self) -> Result<Option<JudgeRubric>> {
        let rubric = judge_rubric(&self.vault)?;
        if let Some(rubric) = &rubric {
            self.measure(EngineLimit::JudgeRubricBytes, rubric.text.len());
        }
        Ok(rubric)
    }
}
