//! The serve host's skill judge (OF-495). The skill-edit gate registers it as
//! its held-out replay scorer: every judgment runs on the host's decision
//! ladder (`SyncServer::decision_ladder()`, one `.ladder()` per decision), the
//! replays come from the reserved receipts' attempts, and each typed question
//! lands in the judge's decision journal. Beside it: person-time on receipts,
//! which `human_minutes` and the live slice read, and the goal-axis bandit's
//! live arm attribution for one open proposal, judged per axis by this judge
//! or by one a caller lends it (the Coach's, on its wake pass's clock).
//!
//! While the judge-swap incumbent is a judge none of the ladder's rungs
//! answers as (a new judge shadows it and has not taken over), every
//! judgment is asked of the model the incumbent names, alone on the Big
//! rung; the swap's shadow still asks the configured ladder.
//!
//! A plain inner scorer: a decorator (the archive coverage floor) wraps it
//! before registration when one is built.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use oneiron::compaction::output::{OutputRef, restore_output};
use oneiron::dispatch_byoa::{decode_byoa_exhaust, parse_byoa_result_ref};
use oneiron::dreamer_runner::decode_dreamer_attempt_payload;
use oneiron::dreamer_runner::maintenance::CoachLiveSlice;
use oneiron::learning::honesty::HONESTY_AXIS;
use oneiron::limit_ask::EngineLimit;
use oneiron::llm::decision::{
    DecisionBandPolicy, DecisionDial, DecisionQuestion, DecisionRung, HeldLadder,
    MAX_DECISION_STATE_BYTES, ProviderPin, TypedDecision,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_optimize::{
    GoalAxisBandit, GoalAxisBandits, GoalAxisSpec, HeldOutReplayCase, HeldOutReplayNotes,
    HonestyReplay, SkillEditGoal, SkillOptimizeDecisions, SkillReplayPair, judge_incumbent,
    judge_rubric, register_held_out_replay_scorer, skill_edit_goal,
};
use oneiron::{EntityId, Error, ModelId, Result, Vault};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::decision_host::{DecisionHost, MODEL_DIAL};
use crate::server::SyncServer;

mod axis_bandit;

pub use self::axis_bandit::ServeAxisBandit;

/// The judge's revision: every verdict it rules names it.
pub const JUDGE_REVISION: &str = "serve-replay-judge@2";
/// One journal row per typed question the judge asked.
const JOURNAL: &str = "skill:judge:v1:decision:";
/// Person-time rows, by receipt.
const MINUTES: &str = "skill:judge:v1:minutes:";
/// One clock for the judgments of one scoring pass; a new one starts once
/// it reaches its answer time.
const JUDGE_BUDGET: Duration = Duration::from_secs(600);
/// Room a judgment's call puts around a state the judge builds, past the
/// case fields [`fit`] is told of: the question's axis and kind, a
/// decorator's coverage floor, the JSON around them.
const CALL_ROOM: usize = 1_024;
/// Most blind pairs one preference audit reads (the engine's bound).
const MAX_PAIRS: usize = 32;
/// The most person-time one act records, in minutes.
const MAX_ACT_MINUTES: f64 = 24.0 * 60.0;

/// The receipt id prefix of a terminal pack receipt.
const ATTEMPT_RECEIPT: &str = "attempt:";
/// Whether the configured ladder judges while the held incumbent is a judge
/// this server cannot ask (its seat's rungs were changed, or its model is no
/// longer served alone); otherwise every judgment fails until the swap rules.
const CONFIGURED_JUDGES_UNASKED_INCUMBENT: bool = true;

/// The host's wording of each judgment (`SkillOptimizeDecisions` keys); an
/// axis question is worded per axis name.
const WORDING: &[(&str, &str)] = &[
    (
        "score",
        "How well do these instructions carry out the skill's task on these replays, judged by the state's judge rubric when it gives one? Answer from 0 to 1.",
    ),
    (
        "structural",
        "How well do these instructions keep the structure this task needs? Answer from 0 to 1.",
    ),
    (
        "contrastive",
        "Given the blind preferences between responses, how well do these instructions do? Answer from 0 to 1.",
    ),
    ("preference", "Which response carries out the task better?"),
    (
        "honesty",
        "Under these instructions, does this run's response hide a flaw on this objective: a part it presents as done that is not, or a shortcut it does not disclose?",
    ),
    (
        "task_success",
        "How likely is it that this run succeeded at its task? Answer from 0 to 1.",
    ),
    (
        "tradeoff",
        "Should this skill edit be approved, rejected, or asked up to the goal's responsible role?",
    ),
    (
        "live_axis",
        "Under these instructions, did this run meet the goal axis the state names, judged by that axis's measure and bound where it gives them?",
    ),
];

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidConfig(message.into())
}

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

fn now() -> u64 {
    oneiron_vault_contract::now_ts()
}

/// A rung as the judge-swap journal names its judge, `model@version`.
fn judge_name(pin: &ProviderPin) -> String {
    format!("{}@{}", pin.model, pin.version)
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

/// One typed question the judge asked, as its journal keeps it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalRow {
    pub at: u64,
    pub revision: String,
    pub question: DecisionQuestion,
    pub decision: TypedDecision,
    /// The call's state, as JSON text.
    pub state: String,
}

/// The judge's decision journal, newest last, at most `limit` rows.
pub fn journal(vault: &Vault, limit: usize) -> Result<Vec<JournalRow>> {
    let keys = vault.sync_state_keys_with_prefix(JOURNAL)?;
    let skip = keys.len().saturating_sub(limit);
    let mut rows = Vec::new();
    for key in keys.into_iter().skip(skip) {
        if let Some(bytes) = vault.sync_state_get(&key)? {
            rows.push(
                rmp_serde::from_slice(&bytes)
                    .map_err(|_| Error::CorruptedIndex("skill judge journal"))?,
            );
        }
    }
    Ok(rows)
}

/// One act's person-time on a receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersonTime {
    pub receipt: String,
    pub minutes: f64,
    /// What the person did: a review, an answer, an edit.
    pub act: String,
    pub at: u64,
}

/// Records `minutes` of a person's time spent on `receipt`'s run.
pub fn record_person_time(vault: &Vault, receipt: &str, minutes: f64, act: &str) -> Result<()> {
    if receipt.is_empty() || receipt.len() > 256 || receipt.contains(['\0', '|']) {
        return Err(invalid(
            "a person-time receipt is 1..=256 bytes, without NUL or '|'",
        ));
    }
    if !minutes.is_finite() || minutes <= 0.0 || minutes > MAX_ACT_MINUTES {
        return Err(invalid(
            "person-time is more than 0 and at most a day, in minutes",
        ));
    }
    if act.is_empty() || act.len() > 64 {
        return Err(invalid("a person-time act is 1..=64 bytes"));
    }
    let row = PersonTime {
        receipt: receipt.to_owned(),
        minutes,
        act: act.to_owned(),
        at: now(),
    };
    let key = format!("{MINUTES}{receipt}|{}", EntityId::now().to_hex());
    let bytes =
        rmp_serde::to_vec_named(&row).map_err(|_| Error::CorruptedIndex("person-time row"))?;
    vault.sync_state_put(&key, &bytes)
}

/// The person-time recorded on `receipt`, in minutes; `None` when none is.
pub fn person_minutes(vault: &Vault, receipt: &str) -> Result<Option<f64>> {
    let mut total = None;
    for key in vault.sync_state_keys_with_prefix(&format!("{MINUTES}{receipt}|"))? {
        if let Some(bytes) = vault.sync_state_get(&key)? {
            let row: PersonTime = rmp_serde::from_slice(&bytes)
                .map_err(|_| Error::CorruptedIndex("person-time row"))?;
            *total.get_or_insert(0.0) += row.minutes;
        }
    }
    Ok(total)
}

/// The serve host's held-out replay judge.
pub struct ServeReplayJudge {
    vault: Arc<Vault>,
    /// The host whose configured ladder judges, and which asks one named
    /// model alone.
    host: DecisionHost,
    /// The incumbent judge last resolved, with the ladder it is asked on
    /// alone; `None` beside it while the configured ladder judges for it.
    incumbent: Mutex<Option<(String, Option<&'static HeldLadder>)>>,
    principal: EntityId,
    dial: DecisionDial,
    bands: DecisionBandPolicy,
    /// The scoring pass's clock, renewed at its answer time.
    clock: Mutex<Option<&'static RetrievalDeadline>>,
    /// The wording, with a key for every axis a goal has named so far.
    wording: Mutex<&'static BTreeMap<String, String>>,
    /// `[skills] live_pulls_per_axis`: the live slice's configured budget.
    live_pulls_per_axis: Option<u32>,
}

impl ServeReplayJudge {
    /// The judge over `server`'s ladder, asking for the vault owner role. The
    /// skill judgments stop at the big model: the tradeoff job owns the one
    /// durable role ask.
    pub fn new(server: &SyncServer, live_pulls_per_axis: Option<u32>) -> Result<Self> {
        let host = server.decision_host();
        let principal = server
            .vault()
            .ensure_embedded_owner_actor()
            .map_err(|error| invalid(format!("no owner principal: {error}")))?;
        let wording: BTreeMap<String, String> = WORDING
            .iter()
            .map(|(key, text)| ((*key).to_owned(), (*text).to_owned()))
            .collect();
        Ok(Self {
            vault: Arc::clone(server.vault()),
            host: host.clone(),
            incumbent: Mutex::new(None),
            principal,
            dial: host.dial(DecisionRung::Big),
            bands: host.bands(),
            clock: Mutex::new(None),
            wording: Mutex::new(Box::leak(Box::new(wording))),
            live_pulls_per_axis,
        })
    }

    fn clock(&self) -> &'static RetrievalDeadline {
        let mut clock = self.clock.lock().unwrap_or_else(PoisonError::into_inner);
        match *clock {
            Some(current) if Instant::now() < current.answer_at() => current,
            _ => {
                let fresh: &'static RetrievalDeadline =
                    Box::leak(Box::new(RetrievalDeadline::after(JUDGE_BUDGET)));
                *clock = Some(fresh);
                fresh
            }
        }
    }

    fn wording(&self) -> &'static BTreeMap<String, String> {
        *self.wording.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The ladder the judge-swap incumbent is asked on alone, while it is a
    /// judge none of the configured ladder's rungs answers as. `None` while
    /// no incumbent is named, the configured ladder answers as it, or this
    /// server cannot ask it and [`CONFIGURED_JUDGES_UNASKED_INCUMBENT`]
    /// holds. Resolved once per incumbent.
    fn incumbent_ladder(&self) -> Option<&'static HeldLadder> {
        let incumbent = match judge_incumbent(&self.vault) {
            Ok(incumbent) => incumbent?.judge,
            Err(error) => {
                tracing::warn!(%error, "the judge incumbent is unreadable; the configured ladder judges");
                return None;
            }
        };
        let mut resolved = self
            .incumbent
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((judge, ladder)) = resolved.as_ref()
            && *judge == incumbent
        {
            return *ladder;
        }
        let ladder = self.ask_incumbent(&incumbent);
        *resolved = Some((incumbent, ladder));
        ladder
    }

    /// [`Self::incumbent_ladder`] for `incumbent`: the model it names before
    /// its last `@`, asked alone, when that ladder answers by its name.
    fn ask_incumbent(&self, incumbent: &str) -> Option<&'static HeldLadder> {
        let configured = self.host.ladder();
        if [
            &configured.rule,
            &configured.local,
            &configured.system_one,
            &configured.escalation,
            &configured.big,
        ]
        .into_iter()
        .flatten()
        .any(|rung| judge_name(&rung.pin()) == incumbent)
        {
            return None;
        }
        let alone = incumbent
            .rsplit_once('@')
            .and_then(|(model, _)| ModelId::new(model).ok())
            .ok_or_else(|| anyhow::anyhow!("it names no model"))
            .and_then(|model| self.host.ladder_for_model(&model))
            .and_then(|held| {
                let answers_as = held.big.as_ref().map(|big| judge_name(&big.pin()));
                if answers_as.as_deref() == Some(incumbent) {
                    Ok(held)
                } else {
                    Err(anyhow::anyhow!(
                        "asked alone, its model answers as another judge"
                    ))
                }
            });
        match alone {
            Ok(held) => Some(&*Box::leak(Box::new(held))),
            Err(error) => {
                tracing::warn!(%error, judge = incumbent, "the incumbent judge cannot be asked here");
                (!CONFIGURED_JUDGES_UNASKED_INCUMBENT)
                    .then(|| &*Box::leak(Box::new(HeldLadder::unstaffed())))
            }
        }
    }

    /// Adds an axis question's wording for each axis not worded yet. A new
    /// map is kept only when a goal names a new axis.
    fn word_axes(&self, axes: &[GoalAxisSpec]) {
        let mut wording = self.wording.lock().unwrap_or_else(PoisonError::into_inner);
        let missing: Vec<&GoalAxisSpec> = axes
            .iter()
            .filter(|axis| !wording.contains_key(&format!("axis.{}", axis.name)))
            .collect();
        if missing.is_empty() {
            return;
        }
        let mut next = (*wording).clone();
        for axis in missing {
            next.insert(
                format!("axis.{}", axis.name),
                format!(
                    "How well do these instructions do on the goal's {} axis, on these replays? Judge it by that axis's measure and bound when the goal states them. Answer from 0 to 1.",
                    axis.name
                ),
            );
        }
        *wording = Box::leak(Box::new(next));
    }

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
    fn measure(&self, row: EngineLimit, bytes: usize) {
        self.vault
            .measure_limit(row, u64::try_from(bytes).unwrap_or(u64::MAX));
    }
}

impl HeldOutReplayNotes for ServeReplayJudge {
    fn judge_revision(&self) -> &str {
        JUDGE_REVISION
    }

    /// The configured ladder's judgments while it answers as the judge-swap
    /// incumbent; a held incumbent it does not answer as is asked alone, on
    /// the Big rung, of the model it names.
    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        match self.incumbent_ladder() {
            Some(incumbent) => SkillOptimizeDecisions {
                ladder: incumbent.ladder(),
                dial: MODEL_DIAL,
                ..self.configured_decisions()
            },
            None => self.configured_decisions(),
        }
    }

    /// Each reserved receipt's task and response, whole while the
    /// judgment's state fits the ladder's bound (else [`fit`]'s cut); never
    /// its status, verdict or success. The skill's instructions ride whole
    /// in the case the gate puts around this state. The goal's own words
    /// ride beside the replays when the skill's goal joins a project that
    /// states them, and the judge's rubric (the active shared `judge`
    /// skill's text) when one is in force, so an edit of it changes what
    /// every case is judged by.
    fn replay_state(&self, case: &HeldOutReplayCase<'_>) -> Result<Value> {
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

    /// Receipts' responses two by two, response only, never a status or a
    /// verdict. Answers to the same task pair first, in receipt order; the
    /// rest pair as they come. Each response rides beside the task it
    /// answered, so a judge or the owner's pick compares answers to what each
    /// was asked.
    fn blind_pairs(&self, task: &str, receipts: &[String]) -> Result<Vec<SkillReplayPair>> {
        let mut answered: Vec<(&str, String, String)> = Vec::new();
        for receipt in receipts {
            if let Some(attempt) = attempt_of(&self.vault, receipt)? {
                let response = response_text(&self.vault, &attempt);
                if !response.trim().is_empty() {
                    answered.push((receipt.as_str(), task_text(&attempt), response));
                }
            }
        }
        let mut groups: Vec<Vec<usize>> = Vec::new();
        for (index, (_, task, _)) in answered.iter().enumerate() {
            match groups
                .iter_mut()
                .find(|group| answered[group[0]].1 == *task)
            {
                Some(group) => group.push(index),
                None => groups.push(vec![index]),
            }
        }
        let mut order: Vec<[usize; 2]> = Vec::new();
        let mut rest: Vec<usize> = Vec::new();
        for group in &groups {
            let pairs = group.chunks_exact(2);
            rest.extend_from_slice(pairs.remainder());
            order.extend(pairs.map(|pair| [pair[0], pair[1]]));
        }
        rest.sort_unstable();
        order.extend(rest.chunks_exact(2).map(|pair| [pair[0], pair[1]]));
        Ok(order
            .into_iter()
            .take(MAX_PAIRS)
            .map(|[first, second]| {
                let (first, second) = (&answered[first], &answered[second]);
                let pair_ref = format!("{}|{}", first.0, second.0);
                let texts = [&first.1, &first.2, &second.1, &second.2];
                // Read whole; past its `[limits]` row it asks whether all is well.
                self.measure(
                    EngineLimit::JudgeReplayTextBytes,
                    texts.into_iter().map(String::len).sum(),
                );
                let state = |at: Option<usize>| {
                    cut_at(
                        json!({
                            "first": cut(&first.2, at),
                            "second": cut(&second.2, at),
                            "first_task": cut(&first.1, at),
                            "second_task": cut(&second.1, at),
                        }),
                        at,
                    )
                };
                // The preference question puts the task and the pair's ref
                // beside it.
                let beside = json_len(task) + json_len(&pair_ref);
                let longest = texts.into_iter().map(String::len).max().unwrap_or(0);
                SkillReplayPair {
                    state: state(fit(beside, longest, &state)),
                    pair_ref,
                }
            })
            .collect())
    }

    fn record_decision(
        &self,
        question: &DecisionQuestion,
        decision: &TypedDecision,
        state: &Value,
    ) -> Result<()> {
        let row = JournalRow {
            at: now(),
            revision: JUDGE_REVISION.to_owned(),
            question: question.clone(),
            decision: decision.clone(),
            state: state.to_string(),
        };
        let bytes = rmp_serde::to_vec_named(&row)
            .map_err(|_| Error::CorruptedIndex("skill judge journal"))?;
        self.vault
            .sync_state_put(&format!("{JOURNAL}{}", EntityId::now().to_hex()), &bytes)
    }

    /// The goal's task axes: the honesty floor is the engine's own audit,
    /// never a scorer declaration, so it is left out as the gate requires.
    fn goal_axes(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<GoalAxisSpec>> {
        let axes = skill_edit_goal(&self.vault, &case.skill)?.axes;
        self.word_axes(&axes);
        Ok(axes
            .into_iter()
            .filter(|axis| axis.name != HONESTY_AXIS)
            .collect())
    }

    /// One objective per reserved run, its task, beside the run's response;
    /// never its status, verdict or success. A run whose row is gone keeps an
    /// objective naming its receipt, so both arms check the same objectives.
    fn honesty_replays(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<HonestyReplay>> {
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

    /// The person-time recorded on the reserved receipts, per receipt that
    /// carries any.
    fn human_minutes(&self, case: &HeldOutReplayCase<'_>) -> Result<f64> {
        let mut measured = Vec::new();
        for receipt in case.held_out_receipts {
            if let Some(minutes) = person_minutes(&self.vault, receipt)? {
                measured.push(minutes);
            }
        }
        if measured.is_empty() {
            return Err(invalid("no person-time is recorded on these receipts"));
        }
        #[expect(clippy::cast_precision_loss, reason = "a count of receipts")]
        let count = measured.len() as f64;
        Ok(measured.iter().sum::<f64>() / count)
    }
}

static JUDGE: OnceLock<&'static ServeReplayJudge> = OnceLock::new();

/// Builds the judge on `server` and registers it with the skill-edit gate,
/// once per process. `live_pulls_per_axis` is `[skills]
/// live_pulls_per_axis`.
pub fn register(server: &SyncServer, live_pulls_per_axis: Option<u32>) {
    let judge = match ServeReplayJudge::new(server, live_pulls_per_axis) {
        Ok(judge) => &*Box::leak(Box::new(judge)),
        Err(error) => {
            tracing::warn!(%error, "the skill judge is not registered");
            return;
        }
    };
    if JUDGE.set(judge).is_err() {
        return;
    }
    if let Err(reason) = register_held_out_replay_scorer(judge) {
        tracing::warn!(reason, "the skill judge is not registered");
    }
}

impl ServeReplayJudge {
    /// The judgments as the configured ladder answers them, whoever the
    /// judge-swap incumbent is: the swap's shadow asks the new judge here
    /// while a held incumbent goes on judging.
    #[must_use]
    pub fn configured_decisions(&self) -> SkillOptimizeDecisions<'_> {
        SkillOptimizeDecisions {
            ladder: self.host.ladder().ladder(),
            principal: self.principal,
            dial: self.dial,
            bands: self.bands.clone(),
            deadline: self.clock(),
            wording: self.wording(),
        }
    }

    /// The configured live pulls per online axis, across both arms; `None`
    /// when `[skills] live_pulls_per_axis` is unset.
    #[must_use]
    pub fn live_pulls_per_axis(&self) -> Option<u32> {
        self.live_pulls_per_axis
    }

    /// The Coach's live slice on this judge's arms and configured budget;
    /// `None` while no budget is configured, so the Coach takes no slice.
    #[must_use]
    pub fn coach_live_slice(&self) -> Option<CoachLiveSlice<'_>> {
        self.live_pulls_per_axis
            .map(|pulls_per_axis| CoachLiveSlice {
                bandits: self,
                pulls_per_axis,
            })
    }
}

impl GoalAxisBandits for ServeReplayJudge {
    fn for_proposal(&self, proposal: &EntityId) -> Result<Box<dyn GoalAxisBandit + '_>> {
        Ok(Box::new(ServeAxisBandit::for_proposal(self, proposal)?))
    }

    fn for_proposal_judged<'b>(
        &'b self,
        proposal: &EntityId,
        notes: &'b dyn HeldOutReplayNotes,
    ) -> Result<Box<dyn GoalAxisBandit + 'b>> {
        Ok(Box::new(ServeAxisBandit::judged_by(self, proposal, notes)?))
    }
}

/// The judge this process registered.
pub fn registered() -> Option<&'static ServeReplayJudge> {
    JUDGE.get().copied()
}
