//! The serve host's skill judge (OF-495). The skill-edit gate registers it as
//! its held-out replay scorer: every judgment runs on the host's decision
//! ladder (`SyncServer::decision_ladder()`, one `.ladder()` per decision), the
//! replays come from the reserved receipts' attempts, and each typed question
//! lands in the judge's decision journal. Every question's wording is the
//! resolved `[skills.replay_judge]` section (shipped in
//! `prompts/replay_judge.toml`), and the judge's revision names its digest.
//! Blind preference pairs are chosen on the shared decision path: the host
//! reads each reserved response and the common rubric, and the engine scores
//! and pairs them. Beside it: person-time on receipts,
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

use oneiron::dreamer_runner::maintenance::CoachLiveSlice;
use oneiron::learning::honesty::HONESTY_AXIS;
use oneiron::llm::decision::{
    DecisionBandPolicy, DecisionDial, DecisionQuestion, DecisionRung, HeldLadder, ProviderPin,
    TypedDecision,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_optimize::{
    GoalAxisBandit, GoalAxisBandits, GoalAxisSpec, HeldOutReplayCase, HeldOutReplayNotes,
    HonestyReplay, JudgeRubric, SkillOptimizeDecisions, SkillReplayResponses, judge_incumbent,
    register_held_out_replay_scorer, skill_edit_goal,
};
use oneiron::{EntityId, Error, ModelId, Result, Vault};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::ReplayJudgeWording;
use crate::decision_host::{DecisionHost, MODEL_DIAL};
use crate::server::SyncServer;

mod axis_bandit;
mod replays;

pub use self::axis_bandit::ServeAxisBandit;

/// The judge's algorithm. Its revision, which every verdict it rules and
/// every journal row names, is this and its wording's digest
/// (`serve-replay-judge@3+<16 hex>`).
pub const JUDGE_REVISION: &str = "serve-replay-judge@3";
/// One journal row per typed question the judge asked.
const JOURNAL: &str = "skill:judge:v1:decision:";
/// Person-time rows, by receipt.
const MINUTES: &str = "skill:judge:v1:minutes:";
/// One clock for the judgments of one scoring pass; a new one starts once
/// it reaches its answer time.
const JUDGE_BUDGET: Duration = Duration::from_secs(600);
/// The most person-time one act records, in minutes.
const MAX_ACT_MINUTES: f64 = 24.0 * 60.0;

/// The receipt id prefix of a terminal pack receipt.
const ATTEMPT_RECEIPT: &str = "attempt:";
/// Whether the configured ladder judges while the held incumbent is a judge
/// this server cannot ask (its seat's rungs were changed, or its model is no
/// longer served alone); otherwise every judgment fails until the swap rules.
const CONFIGURED_JUDGES_UNASKED_INCUMBENT: bool = true;

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidConfig(message.into())
}

fn now() -> u64 {
    oneiron_vault_contract::now_ts()
}

/// A rung as the judge-swap journal names its judge, `model@version`.
fn judge_name(pin: &ProviderPin) -> String {
    format!("{}@{}", pin.model, pin.version)
}

/// The digest of the judge rubric `state` read: the first
/// `judge_rubric_pin` in it, the outermost first; `None` when it holds none.
fn rubric_digest_read(state: &Value) -> Option<String> {
    match state {
        Value::Object(fields) => fields
            .get("judge_rubric_pin")
            .and_then(|pin| pin.get("digest"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| fields.values().find_map(rubric_digest_read)),
        Value::Array(items) => items.iter().find_map(rubric_digest_read),
        _ => None,
    }
}

/// One typed question the judge asked, as its journal keeps it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalRow {
    pub at: u64,
    pub revision: String,
    /// The pin of the judge rubric the question's state read, beside
    /// `revision` (the algorithm and wording): the rubric text's BLAKE3,
    /// lower hex, from the state's `judge_rubric_pin`; `None` when the
    /// question read no rubric (FIX 3585).
    pub judge_rubric_digest: Option<String>,
    pub question: DecisionQuestion,
    pub decision: TypedDecision,
    /// The rows the decision's inputs were read from, as its caller
    /// assembled them beside the question and state (FIX 7105): `Some` only
    /// when every constituent has a typed witness, `None` when any lacks one
    /// or the caller handed none. `None` is unknown, never an empty set.
    pub decision_sources: Option<Vec<EntityId>>,
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
    /// `[skills.replay_judge]`: what each question, each axis's question and
    /// a missing run's objective are worded from.
    phrasing: ReplayJudgeWording,
    /// [`JUDGE_REVISION`] and the wording's digest.
    revision: String,
    /// `[skills] live_pulls_per_axis`: the live slice's configured budget.
    live_pulls_per_axis: Option<u32>,
}

impl ServeReplayJudge {
    /// The judge over `server`'s ladder, asking for the vault owner role, in
    /// the server's resolved `[skills.replay_judge]` wording. The skill
    /// judgments stop at the big model: the tradeoff job owns the one durable
    /// role ask.
    pub fn new(server: &SyncServer, live_pulls_per_axis: Option<u32>) -> Result<Self> {
        let host = server.decision_host();
        let principal = server
            .vault()
            .ensure_embedded_owner_actor()
            .map_err(|error| invalid(format!("no owner principal: {error}")))?;
        let phrasing = server.config.skills.replay_judge.clone();
        let wording = phrasing.questions();
        let revision = format!("{JUDGE_REVISION}+{}", phrasing.digest());
        Ok(Self {
            vault: Arc::clone(server.vault()),
            host: host.clone(),
            incumbent: Mutex::new(None),
            principal,
            dial: host.dial(DecisionRung::Big),
            bands: host.bands(),
            clock: Mutex::new(None),
            wording: Mutex::new(Box::leak(Box::new(wording))),
            phrasing,
            revision,
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

    /// Adds an axis question's wording, from `axis_template`, for each axis
    /// not worded yet. A new map is kept only when a goal names a new axis.
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
                self.phrasing.axis(&axis.name),
            );
        }
        *wording = Box::leak(Box::new(next));
    }

    /// Journals one typed question, with the rows its inputs were read from
    /// as its caller handed them (FIX 7105).
    fn journal_decision(
        &self,
        question: &DecisionQuestion,
        decision: &TypedDecision,
        state: &Value,
        decision_sources: Option<Vec<EntityId>>,
    ) -> Result<()> {
        let row = JournalRow {
            at: now(),
            revision: self.revision.clone(),
            judge_rubric_digest: rubric_digest_read(state),
            question: question.clone(),
            decision: decision.clone(),
            decision_sources,
            state: state.to_string(),
        };
        let bytes = rmp_serde::to_vec_named(&row)
            .map_err(|_| Error::CorruptedIndex("skill judge journal"))?;
        self.vault
            .sync_state_put(&format!("{JOURNAL}{}", EntityId::now().to_hex()), &bytes)
    }
}

impl HeldOutReplayNotes for ServeReplayJudge {
    fn judge_revision(&self) -> &str {
        &self.revision
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

    fn replay_state(&self, case: &HeldOutReplayCase<'_>) -> Result<Value> {
        self.case_replays(case)
    }

    fn replay_responses(&self, receipts: &[String]) -> Result<SkillReplayResponses> {
        self.response_basis(receipts)
    }

    /// The rubric every replay state and response score reads, for the
    /// tradeoff question (FIX 3584).
    fn rubric(&self) -> Result<Option<JudgeRubric>> {
        ServeReplayJudge::rubric(self)
    }

    /// A decision whose caller handed no input rows: its sources are
    /// unknown.
    fn record_decision(
        &self,
        question: &DecisionQuestion,
        decision: &TypedDecision,
        state: &Value,
    ) -> Result<()> {
        self.journal_decision(question, decision, state, None)
    }

    /// Keeps the decision's input rows on its journal row (FIX 7105).
    fn record_decision_sourced(
        &self,
        question: &DecisionQuestion,
        decision: &TypedDecision,
        state: &Value,
        decision_sources: Option<Vec<EntityId>>,
    ) -> Result<()> {
        self.journal_decision(question, decision, state, decision_sources)
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

    fn honesty_replays(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<HonestyReplay>> {
        self.honesty_objectives(case)
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
