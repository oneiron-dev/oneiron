//! The serve judge's replay evidence: each reserved receipt's task and
//! response, read whole from its attempt, and the states the judge's
//! questions read them in, cut only where the ladder's state bound needs.
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use oneiron::compaction::output::{OutputRef, restore_output};
use oneiron::dispatch_byoa::{decode_byoa_exhaust, parse_byoa_result_ref};
use oneiron::dreamer_runner::decode_dreamer_attempt_payload;
use oneiron::limit_ask::EngineLimit;
use oneiron::llm::decision::MAX_DECISION_STATE_BYTES;
use oneiron::skill_optimize::{
    HeldOutReplayCase, HonestyReplay, SkillEditGoal, judge_rubric, skill_edit_goal,
};
use oneiron::{EntityId, Result, Vault};
use serde::Serialize;
use serde_json::{Value, json};

use super::{ATTEMPT_RECEIPT, ServeReplayJudge};

/// Room a judgment's call puts around a state the judge builds, past the
/// case fields [`fit`] is told of: the question's axis and kind, a
/// decorator's coverage floor, the JSON around them.
const CALL_ROOM: usize = 1_024;

/// `text` whole, or cut to `at` bytes on a character boundary.
pub(super) fn cut(text: &str, at: Option<usize>) -> &str {
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
pub(super) fn json_len<T: Serialize + ?Sized>(value: &T) -> usize {
    serde_json::to_vec(value).map_or(0, |bytes| bytes.len())
}

/// The cut a judgment's state is built at: `None` while `state` with every
/// text whole, and the `beside` bytes its call puts around it, fits the
/// ladder's state bound ([`MAX_DECISION_STATE_BYTES`]), which refuses a
/// larger state. Past it, half the `longest` text, halving until it fits.
/// The texts' own `[limits]` rows never cut; only the ladder's bound does.
pub(super) fn fit(
    beside: usize,
    longest: usize,
    state: impl Fn(Option<usize>) -> Value,
) -> Option<usize> {
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
pub(super) fn cut_at(mut state: Value, at: Option<usize>) -> Value {
    if let Some(bytes) = at {
        state["cut_at_bytes"] = json!(bytes);
    }
    state
}

/// The attempt behind a terminal pack receipt (`attempt:<32 hex>`), when its
/// row is still kept.
pub(super) fn attempt_of(vault: &Vault, receipt: &str) -> Result<Option<AttemptRecord>> {
    let Some(hex) = receipt.strip_prefix(ATTEMPT_RECEIPT) else {
        return Ok(None);
    };
    let id = EntityId::from_hex(hex)?;
    AttemptQueue::new(vault).get(AttemptId::from_bytes(id.as_bytes())?)
}

/// The task an attempt was given: a Dreamer or agent payload's input, else
/// the payload as text.
pub(super) fn task_text(attempt: &AttemptRecord) -> String {
    decode_dreamer_attempt_payload(&attempt.payload).map_or_else(
        |_| String::from_utf8_lossy(&attempt.payload).into_owned(),
        |payload| payload.input.to_string(),
    )
}

/// What an attempt answered, through its result ref: a code-run output, a
/// BYOA run's transcript (else its stdout), an entity's text, or the ref
/// itself when nothing here resolves it.
pub(super) fn response_text(vault: &Vault, attempt: &AttemptRecord) -> String {
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

    /// Measures `bytes` against `row`: past it the row asks whether all is
    /// well, and the text still rides whole.
    pub(super) fn measure(&self, row: EngineLimit, bytes: usize) {
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
                Ok(match self.replay_texts(receipt)? {
                    None => HonestyReplay {
                        receipt: receipt.clone(),
                        state: json!({"receipt": receipt, "kept": false}),
                        objectives: vec![format!("the task of run {receipt}")],
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
}
