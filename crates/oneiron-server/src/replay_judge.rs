//! The serve host's skill judge (OF-495). The skill-edit gate registers it as
//! its held-out replay scorer: every judgment runs on the host's decision
//! ladder (`SyncServer::decision_ladder()`, one `.ladder()` per decision), the
//! replays come from the reserved receipts' attempts, and each typed question
//! lands in the judge's decision journal. Beside it: person-time on receipts,
//! which `human_minutes` and the live slice read, and the goal-axis bandit's
//! live arm attribution for one open proposal, judged per axis.
//!
//! A plain inner scorer: a decorator (the archive coverage floor) wraps it
//! before registration when one is built.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use oneiron::compaction::output::{OutputRef, restore_output};
use oneiron::dispatch_byoa::{decode_byoa_exhaust, parse_byoa_result_ref};
use oneiron::dreamer_runner::decode_dreamer_attempt_payload;
use oneiron::dreamer_runner::maintenance::CoachLiveSlice;
use oneiron::learning::honesty::HONESTY_AXIS;
use oneiron::llm::decision::{
    DecisionBandPolicy, DecisionDial, DecisionQuestion, DecisionRung, HeldLadder, TypedDecision,
};
use oneiron::posterior::Posterior;
use oneiron::receipt::{ReceiptKind, ReceiptQuery};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill::SkillRecord;
use oneiron::skill_attribution::{AttributionVerdict, attribution_judgments};
use oneiron::skill_optimize::{
    AxisArm, ConfidenceInterval, GoalAxisBandit, GoalAxisBandits, GoalAxisSpec, HeldOutReplayCase,
    HeldOutReplayNotes, HonestyReplay, OnlineAxisSample, PROVENANCE_OPTIMIZE_OF_ENTITY_KEY,
    SkillOptimizeDecisions, SkillReplayPair, register_held_out_replay_scorer, skill_edit_goal,
};
use oneiron::skill_reliability::SkillReliabilityPosterior;
use oneiron::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::server::SyncServer;

/// The judge's revision: every verdict it rules names it.
pub const JUDGE_REVISION: &str = "serve-replay-judge@2";
/// One journal row per typed question the judge asked.
const JOURNAL: &str = "skill:judge:v1:decision:";
/// Person-time rows, by receipt.
const MINUTES: &str = "skill:judge:v1:minutes:";
/// One clock for the judgments of one scoring pass; a new one starts once
/// it reaches its answer time.
const JUDGE_BUDGET: Duration = Duration::from_secs(600);
/// The instructions' share of a replay state, in bytes.
const MAX_INSTRUCTIONS: usize = 8_192;
/// The replays' share of a replay state, in bytes: the ladder takes at most
/// 64 KiB of state.
const MAX_REPLAY_TEXT: usize = 40_000;
/// The least a replay text is cut to.
const MIN_REPLAY_TEXT: usize = 128;
/// Most blind pairs one preference audit reads (the engine's bound).
const MAX_PAIRS: usize = 32;
/// How far back live arm attribution looks for loaded runs.
const LIVE_WINDOW_SECS: u64 = 30 * 86_400;
/// Most receipts one live pull scans.
const LIVE_SCAN_LIMIT: usize = 2_000;
/// The most person-time one act records, in minutes.
const MAX_ACT_MINUTES: f64 = 24.0 * 60.0;

/// The receipt id prefix of a terminal pack receipt.
const ATTEMPT_RECEIPT: &str = "attempt:";
/// The attempt state of a run that finished.
const COMPLETED: &str = "completed";

/// The host's wording of each judgment (`SkillOptimizeDecisions` keys); an
/// axis question is worded per axis name.
const WORDING: &[(&str, &str)] = &[
    (
        "score",
        "How well do these instructions carry out the skill's task on these replays? Answer from 0 to 1.",
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

fn cut(text: &str, bytes: usize) -> &str {
    let mut end = text.len().min(bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn now() -> u64 {
    oneiron_vault_contract::now_ts()
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
        return vault
            .read_blob_artifact_version(&artifact, version)
            .ok()
            .flatten()
            .and_then(|bytes| decode_byoa_exhaust(&bytes).ok())
            .map(|(_, _, exhaust)| {
                String::from_utf8_lossy(
                    exhaust
                        .transcript
                        .as_deref()
                        .unwrap_or(exhaust.stdout.as_slice()),
                )
                .into_owned()
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
    ladder: HeldLadder,
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
            ladder: host.ladder().clone(),
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

    /// The skill's goal as a judge question reads it: the joined project's
    /// goal, its why, and each axis's measure and bound. `None` when the
    /// skill has no goal, its goal joins no project, or the project states
    /// no goal record.
    fn goal_brief(&self, skill: &EntityId) -> Result<Option<Value>> {
        let Ok(goal) = skill_edit_goal(&self.vault, skill) else {
            return Ok(None);
        };
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

    fn replay(&self, receipt: &str, bytes: usize) -> Result<Value> {
        Ok(match attempt_of(&self.vault, receipt)? {
            None => json!({"receipt": receipt, "kept": false}),
            Some(attempt) => json!({
                "receipt": receipt,
                "kind": attempt.kind,
                "task": cut(&task_text(&attempt), bytes),
                "response": cut(&response_text(&self.vault, &attempt), bytes),
            }),
        })
    }
}

impl HeldOutReplayNotes for ServeReplayJudge {
    fn judge_revision(&self) -> &str {
        JUDGE_REVISION
    }

    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        SkillOptimizeDecisions {
            ladder: self.ladder.ladder(),
            principal: self.principal,
            dial: self.dial,
            bands: self.bands.clone(),
            deadline: self.clock(),
            wording: self.wording(),
        }
    }

    /// Each reserved receipt's task and response, cut to share the state;
    /// never its status, verdict or success. The goal's own words ride
    /// beside them when the skill's goal joins a project that states them.
    fn replay_state(&self, case: &HeldOutReplayCase<'_>) -> Result<Value> {
        let receipts = case.held_out_receipts;
        let bytes = (MAX_REPLAY_TEXT / receipts.len().max(1) / 2).max(MIN_REPLAY_TEXT);
        let replays = receipts
            .iter()
            .map(|receipt| self.replay(receipt, bytes))
            .collect::<Result<Vec<_>>>()?;
        let mut state = json!({
            "skill_id": case.skill_id,
            "version": case.version,
            "instructions": cut(case.instructions, MAX_INSTRUCTIONS),
            "replays": replays,
        });
        if let Some(goal) = self.goal_brief(&case.skill)? {
            state["goal"] = goal;
        }
        Ok(state)
    }

    /// Neighbouring receipts' responses, two by two, response only.
    fn blind_pairs(&self, _task: &str, receipts: &[String]) -> Result<Vec<SkillReplayPair>> {
        let bytes = MAX_REPLAY_TEXT / 2;
        let mut answered = Vec::new();
        for receipt in receipts {
            if let Some(attempt) = attempt_of(&self.vault, receipt)? {
                let response = response_text(&self.vault, &attempt);
                if !response.trim().is_empty() {
                    answered.push((receipt.as_str(), response));
                }
            }
        }
        Ok(answered
            .chunks_exact(2)
            .take(MAX_PAIRS)
            .map(|pair| SkillReplayPair {
                pair_ref: format!("{}|{}", pair[0].0, pair[1].0),
                state: json!({
                    "first": cut(&pair[0].1, bytes),
                    "second": cut(&pair[1].1, bytes),
                }),
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
        let bytes = MAX_REPLAY_TEXT / 2;
        case.held_out_receipts
            .iter()
            .map(|receipt| {
                Ok(match attempt_of(&self.vault, receipt)? {
                    None => HonestyReplay {
                        receipt: receipt.clone(),
                        state: json!({"receipt": receipt, "kept": false}),
                        objectives: vec![format!("the task of run {receipt}")],
                    },
                    Some(attempt) => HonestyReplay {
                        receipt: receipt.clone(),
                        state: json!({
                            "receipt": receipt,
                            "kind": attempt.kind,
                            "response": cut(&response_text(&self.vault, &attempt), bytes),
                        }),
                        objectives: vec![cut(&task_text(&attempt), bytes).to_owned()],
                    },
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
}

/// The judge this process registered.
pub fn registered() -> Option<&'static ServeReplayJudge> {
    JUDGE.get().copied()
}

/// One arm of a live slice: the skill version its runs loaded, and the
/// record whose instructions an axis question reads beside each of them.
struct Arm {
    loaded: String,
    skill: EntityId,
    record: SkillRecord,
}

/// Live arm attribution for one open optimizer proposal: the incumbent arm
/// is the skill version it revises, the candidate arm the proposal. A pull
/// takes the newest run its axis has not taken yet that loaded the arm's
/// version. It met
/// the pulled axis when it completed, no skill-defect judgment names it, and
/// the judge decides it met that axis by the axis's measure and bound. Its
/// person-time is what is recorded on its receipt, unknown when none is.
pub struct ServeAxisBandit<'a> {
    judge: &'a ServeReplayJudge,
    /// The active skill the proposal revises, whose goal it is measured on.
    target: EntityId,
    incumbent: Arm,
    candidate: Arm,
    /// Each axis of the goal, with its measure and bound, and the goal and
    /// its why, where the joined project's goal record states them.
    criteria: BTreeMap<String, Value>,
    /// The runs each axis has pulled, by axis: every routed run is judged
    /// once on each axis.
    taken: Mutex<BTreeSet<(String, String)>>,
}

fn provenance_str(provenance: &rmpv::Value, key: &str) -> Option<String> {
    let rmpv::Value::Map(entries) = provenance else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str().map(str::to_owned))
}

impl<'a> ServeAxisBandit<'a> {
    /// The slice of `proposal` on `judge`. It words the goal's axes first, so
    /// a measure in a fresh process asks worded questions.
    /// # Errors
    /// A proposal that names no skill it revises, an unreadable goal or
    /// project goal record, or storage errors.
    pub fn for_proposal(judge: &'a ServeReplayJudge, proposal: &EntityId) -> Result<Self> {
        let vault = &judge.vault;
        let staged = vault
            .get_skill_record(proposal)?
            .ok_or(Error::EntityNotFound)?;
        let target = provenance_str(&staged.provenance, PROVENANCE_OPTIMIZE_OF_ENTITY_KEY)
            .and_then(|hex| EntityId::from_hex(&hex).ok())
            .ok_or_else(|| invalid("an optimizer proposal names the skill it revises"))?;
        let current = vault
            .get_skill_record(&target)?
            .ok_or(Error::EntityNotFound)?;
        let goal = skill_edit_goal(vault, &target)?;
        judge.word_axes(&goal.axes);
        let mut criteria: BTreeMap<String, Value> = goal
            .axes
            .iter()
            .map(|axis| (axis.name.clone(), json!({"name": axis.name})))
            .collect();
        if let Some((project, _)) = goal.project
            && let Some(record) = vault.project_intake_goal(project)?
        {
            for axis in record
                .primary_axes
                .iter()
                .chain(&record.floor_axes)
                .chain(&record.cost_axes)
            {
                if let Some(criterion) = criteria.get_mut(&axis.name) {
                    *criterion = json!({
                        "name": axis.name, "measure": axis.measure, "bound": axis.bound,
                        "goal": record.goal, "why": record.why,
                    });
                }
            }
        }
        Ok(Self {
            judge,
            target,
            incumbent: Arm {
                loaded: format!("{}@{}", current.skill_id, current.version),
                skill: target,
                record: current,
            },
            candidate: Arm {
                loaded: format!("{}@{}", staged.skill_id, staged.version),
                skill: *proposal,
                record: staged,
            },
            criteria,
            taken: Mutex::new(BTreeSet::new()),
        })
    }

    /// Whether `receipt`'s run met `criterion` under `arm`'s instructions.
    fn met(&self, arm: &Arm, receipt: &str, criterion: &Value) -> Result<bool> {
        (self.judge as &dyn HeldOutReplayNotes).live_axis_met(
            self.target,
            &arm.record,
            receipt,
            criterion,
        )
    }
}

impl GoalAxisBandit for ServeAxisBandit<'_> {
    fn pull(&self, axis: &str, arm: AxisArm) -> Result<OnlineAxisSample> {
        let criterion = self
            .criteria
            .get(axis)
            .ok_or_else(|| invalid(format!("the goal names no {axis} axis")))?;
        let arm = match arm {
            AxisArm::Incumbent => &self.incumbent,
            AxisArm::Candidate => &self.candidate,
        };
        let vault = &self.judge.vault;
        let since = now().saturating_sub(LIVE_WINDOW_SECS);
        let mut scan = vault
            .scan_receipts(
                ReceiptQuery::new(LIVE_SCAN_LIMIT)
                    .with_kind(ReceiptKind::Outbound)
                    .with_time_bounds(Some(since), None),
            )?
            .records;
        scan.sort_by(|a, b| b.occurred_at.cmp(&a.occurred_at));
        let mut taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
        let run = scan
            .into_iter()
            .find(|receipt| {
                receipt.receipt_id.starts_with(ATTEMPT_RECEIPT)
                    && !taken.contains(&(axis.to_owned(), receipt.receipt_id.clone()))
                    && receipt
                        .pack_manifest_skills()
                        .is_some_and(|skills| skills.contains(&arm.loaded))
            })
            .ok_or_else(|| invalid(format!("no live run of {} is left to pull", arm.loaded)))?;
        taken.insert((axis.to_owned(), run.receipt_id.clone()));
        drop(taken);
        let defect = attribution_judgments(vault)?.into_iter().any(|judgment| {
            judgment.verdict == AttributionVerdict::SkillDefect
                && judgment.subject == arm.skill
                && judgment.evidence_receipts.contains(&run.receipt_id)
        });
        // A run that failed or carries a defect misses every axis; only a
        // clean run is put to the axis question.
        let success =
            run.outcome == COMPLETED && !defect && self.met(arm, &run.receipt_id, criterion)?;
        Ok(OnlineAxisSample {
            success,
            human_minutes: person_minutes(vault, &run.receipt_id)?,
        })
    }

    /// The Beta posterior over the arm's wins from a flat prior: its lower
    /// bound, and as the upper bound one less the lower bound of its mirror.
    fn confidence_interval(
        &self,
        _axis: &str,
        _arm: AxisArm,
        wins: u32,
        pulls: u32,
    ) -> Result<ConfidenceInterval> {
        if wins > pulls {
            return Err(invalid("more wins than pulls"));
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "pull counts stay far below 2^24"
        )]
        let posterior = SkillReliabilityPosterior {
            alpha: 1.0 + wins as f32,
            beta: 1.0 + (pulls - wins) as f32,
        };
        let mirror = SkillReliabilityPosterior {
            alpha: posterior.beta,
            beta: posterior.alpha,
        };
        Ok(ConfidenceInterval {
            lower: Posterior::lower_bound(&posterior),
            upper: 1.0 - Posterior::lower_bound(&mirror),
        })
    }
}
