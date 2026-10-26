//! RC42 observation-only wire counters. Thresholds ask questions; they never deny service.
use oneiron::limit_ask::{EngineLimit, LimitAsk};
pub use oneiron::task_verb::sdk::WireThresholds;
use oneiron::task_verb::sdk::{
    WIRE_THRESHOLDS_MANIFEST as MANIFEST, WireThresholdsReceipt,
    set_wire_thresholds_as_owner_in_txn,
};
use oneiron::{Error, Result, Vault};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

const RECEIPT: &str = "wire:window:v2:";
/// Each call-volume question as it was kept, under its sequence (FIX 9531).
const QUESTION_SEQ: &str = "wire:question:v2:seq:";
/// Each window's call-volume questions, under the window: their sequences.
const QUESTION_WINDOW: &str = "wire:question:v2:window:";
const LIMIT_QUESTION: &str = "wire:limit-question:v1:";
/// A row keeps one question for each window of this many seconds, and counts
/// every crossing in the window in it.
const LIMIT_QUESTION_WINDOW_SECS: u64 = 60;
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireWindowReceipt {
    pub started_at: u64,
    pub ended_at: u64,
    pub by_verb: BTreeMap<String, u64>,
    pub by_actor: BTreeMap<String, u64>,
    /// Each MCP caller's tool calls by tool (`mcp:tools/call:<name>`), under
    /// the caller the gateway resolved: who burst on which tool. Each call
    /// counts once in `by_verb` and `by_actor` too (FIX 1085).
    #[serde(default)]
    pub by_actor_tool: BTreeMap<String, BTreeMap<String, u64>>,
    /// MCP envelopes carried, by matched route: transport, never a call.
    #[serde(default)]
    pub mcp_envelopes: BTreeMap<String, u64>,
    /// MCP replies refused with no tool call's receipt over them, by fixed
    /// category and under no caller.
    #[serde(default)]
    pub mcp_errors: BTreeMap<String, u64>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WireQuestionKind {
    InspectCallVolume,
    /// Work crossed a `[limits]` row and waited for its turn, or, for a byte
    /// row, carried on past it.
    InspectLimitCrossing,
    /// A socket waits for the shared connection pool: the live check on
    /// the owner's wire-health read (FIX 7656).
    InspectConnectionPoolPressure,
}
/// One call-volume question, kept once and never rewritten: a window asks
/// again each time another actor or verb crosses its row (FIX 9531).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireQuestion {
    pub kind: WireQuestionKind,
    /// Its place among every call-volume question this vault kept, in the
    /// order they were kept, a later write to an earlier window's included.
    pub seq: u64,
    /// Every actor and verb past its row in the window when it was kept.
    pub crossed: WireCrossed,
    pub evidence: WireWindowReceipt,
}
/// Who and what crossed their rows in one window: every one of them, never
/// only the busiest.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireCrossed {
    pub actors: BTreeSet<String>,
    pub verbs: BTreeSet<String>,
}
impl WireCrossed {
    /// Every actor and verb `window` counts past its row in `thresholds`.
    fn of(window: &WireWindowReceipt, thresholds: &WireThresholds) -> Self {
        let over = |counts: &BTreeMap<String, u64>, row: u64| {
            counts
                .iter()
                .filter(|(_, calls)| **calls > row)
                .map(|(name, _)| name.clone())
                .collect()
        };
        Self {
            actors: over(&window.by_actor, thresholds.per_actor),
            verbs: over(&window.by_verb, thresholds.per_verb),
        }
    }
}

mod connection_pressure;
mod kept;
mod rows;
pub(crate) use connection_pressure::{
    BodyCredential, ConnectionPoolPressure, ObservedBody, ObservedSocket, PoolPressure,
    PressureCredentialKey, SocketHold, attach_body_credential, with_body_credential,
};
pub use rows::LimitRow;
/// The question a crossed row asks: what it is set to, the most it saw, and
/// how many times it was crossed in its window.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireLimitQuestion {
    pub kind: WireQuestionKind,
    pub row: String,
    pub bound: u64,
    pub observed: u64,
    pub raised_at: u64,
    pub crossings: u64,
}
/// Where crossed rows ask. Each crossing counts in its row's question for
/// the window; the first is logged at once, and the question is kept on this
/// server's vault at the next observation tick, so asking never waits on
/// storage. A question waits until its write succeeds, across later windows
/// too, but a row holds at most eight of them (`PENDING_WINDOWS`), so a sink no
/// vault keeps (the embedder endpoint's) stays bounded.
#[derive(Default)]
pub struct LimitQuestions {
    /// Each row's questions, oldest first: those not kept yet, and always the
    /// latest.
    asked: Mutex<BTreeMap<LimitRow, VecDeque<Asked>>>,
    /// The shared connection pool's live pressure check (FIX 7656), on a
    /// vault server's own sink only.
    pool_pressure: Option<Arc<PoolPressure>>,
}
/// A row keeps at most this many windows' questions waiting to be kept; past
/// it the oldest goes.
const PENDING_WINDOWS: usize = 8;
/// One window's question for a row.
struct Asked {
    window: u64,
    question: WireLimitQuestion,
    kept: bool,
    /// Whether what was kept for the window before this server asked (by a
    /// run before this one) is counted in `question` yet.
    restored: bool,
}
impl LimitQuestions {
    /// A vault server's sink, which keeps its connection pool's pressure
    /// check too: a sink no vault keeps observes no pool.
    fn with_pool_pressure() -> Self {
        Self {
            pool_pressure: Some(Arc::default()),
            ..Self::default()
        }
    }
    /// The connection pool's pressure check this sink keeps, if any.
    pub(crate) fn pool_pressure(&self) -> Option<&Arc<PoolPressure>> {
        self.pool_pressure.as_ref()
    }
    /// The connection pool's pressure as it stands; clear where none is kept.
    pub(crate) fn connection_pool_pressure(&self) -> ConnectionPoolPressure {
        match &self.pool_pressure {
            Some(pressure) => pressure.snapshot(),
            None => ConnectionPoolPressure::Clear,
        }
    }
    /// Nobody waits in `row`'s line since its crossing `epoch`.
    pub(crate) fn drained(&self, row: LimitRow, epoch: u64) {
        if row == LimitRow::Connections
            && let Some(pressure) = &self.pool_pressure
        {
            pressure.drain(epoch);
        }
    }
    /// `row`, set to `bound`, saw `observed`. Nothing waits on the answer.
    pub(crate) fn ask(&self, row: LimitRow, bound: u64, observed: u64) {
        self.ask_at(row, bound, observed, oneiron_vault_contract::now_ts());
    }
    fn ask_at(&self, row: LimitRow, bound: u64, observed: u64, now: u64) {
        let window = now / LIMIT_QUESTION_WINDOW_SECS * LIMIT_QUESTION_WINDOW_SECS;
        let mut asked = lock(&self.asked);
        let windows = asked.entry(row).or_default();
        if let Some(open) = windows.back_mut().filter(|open| open.window == window) {
            let question = &mut open.question;
            question.crossings = question.crossings.saturating_add(1);
            question.observed = question.observed.max(observed);
            open.kept = false;
            return;
        }
        windows.retain(|open| !open.kept);
        if windows.len() == PENDING_WINDOWS {
            windows.pop_front();
        }
        windows.push_back(Asked {
            window,
            question: WireLimitQuestion {
                kind: WireQuestionKind::InspectLimitCrossing,
                row: row.key().to_owned(),
                bound,
                observed,
                raised_at: now,
                crossings: 1,
            },
            kept: false,
            restored: false,
        });
        drop(asked);
        tracing::warn!(
            kind = "limit_crossed",
            row = row.key(),
            bound,
            observed,
            "work crossed a limits row and waits its turn; is everything okay?"
        );
    }
    /// The latest question `row` asked on this server, if any.
    pub fn latest(&self, row: LimitRow) -> Option<WireLimitQuestion> {
        lock(&self.asked)
            .get(&row)
            .and_then(VecDeque::back)
            .map(|open| open.question.clone())
    }
    /// The questions not kept yet: each one's row and window, and whether
    /// what was kept for it before is counted in yet.
    fn unkept(&self) -> Vec<(LimitRow, u64, bool)> {
        lock(&self.asked)
            .iter()
            .flat_map(|(row, windows)| {
                windows
                    .iter()
                    .filter(|open| !open.kept)
                    .map(|open| (*row, open.window, open.restored))
            })
            .collect()
    }
    /// Counts `earlier`, what was kept for `row`'s `window` before this
    /// server asked, in its question, once; the question as it now stands.
    fn restore(
        &self,
        row: LimitRow,
        window: u64,
        earlier: Option<WireLimitQuestion>,
    ) -> Option<WireLimitQuestion> {
        let mut asked = lock(&self.asked);
        let open = asked
            .get_mut(&row)?
            .iter_mut()
            .find(|open| open.window == window)?;
        if !open.restored {
            open.restored = true;
            if let Some(earlier) = earlier {
                let question = &mut open.question;
                question.crossings = question.crossings.saturating_add(earlier.crossings);
                question.observed = question.observed.max(earlier.observed);
                question.raised_at = question.raised_at.min(earlier.raised_at);
            }
        }
        Some(open.question.clone())
    }
    /// Marks `question` kept, unless a crossing since changed it, and lets
    /// go of every kept window but the latest.
    fn kept(&self, row: LimitRow, window: u64, question: &WireLimitQuestion) {
        let mut asked = lock(&self.asked);
        let Some(windows) = asked.get_mut(&row) else {
            return;
        };
        if let Some(open) = windows
            .iter_mut()
            .find(|open| open.window == window && open.question == *question)
        {
            open.kept = true;
        }
        let latest = windows.len().saturating_sub(1);
        let mut at = 0;
        windows.retain(|open| {
            at += 1;
            !open.kept || at > latest
        });
    }
}
/// The engine's rows on this server's vault ask here too (`SyncServer::new`
/// installs it).
impl LimitAsk for LimitQuestions {
    fn crossed(&self, row: EngineLimit, bound: u64, measured: u64) {
        self.ask(LimitRow::Engine(row), bound, measured);
    }
}
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
#[derive(Default)]
struct Active {
    window: Option<WireWindowReceipt>,
    /// Who and what the window's latest kept question names as crossed.
    asked: WireCrossed,
    /// The sequence the next kept question takes, once read (FIX 9531).
    next_seq: Option<u64>,
    persisted: bool,
    frozen: bool,
}
pub struct WireTelemetry {
    vault: Arc<Vault>,
    active: Mutex<Active>,
    /// Held while limit questions are written, which every request's
    /// `record` never waits for: it takes `active` only. The reap barrier
    /// takes it to wait for a write in progress.
    saving: Mutex<()>,
    flusher_started: std::sync::atomic::AtomicBool,
    limits: Arc<LimitQuestions>,
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| Error::CorruptedIndex("wire observation"))
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|_| Error::CorruptedIndex("wire observation"))
}
fn check_keys(verb: &str, actor: &str) -> Result<()> {
    if verb.is_empty() || verb.len() > 256 || actor.is_empty() || actor.len() > 512 {
        return Err(Error::InvalidConfig("invalid wire counter key".into()));
    }
    Ok(())
}
fn count_in(counts: &mut BTreeMap<String, u64>, key: &str) -> u64 {
    let count = counts.entry(key.into()).or_default();
    *count = count.saturating_add(1);
    *count
}
/// Counts into `window` what `kept`, an earlier copy of the same window,
/// counted further: a question's counts are kept before its window's are,
/// and every count only grows, so the greater of the two is the later.
fn resume(window: &mut WireWindowReceipt, kept: &WireWindowReceipt) {
    let further = |into: &mut BTreeMap<String, u64>, from: &BTreeMap<String, u64>| {
        for (key, count) in from {
            let at = into.entry(key.clone()).or_default();
            *at = (*at).max(*count);
        }
    };
    further(&mut window.by_verb, &kept.by_verb);
    further(&mut window.by_actor, &kept.by_actor);
    further(&mut window.mcp_envelopes, &kept.mcp_envelopes);
    further(&mut window.mcp_errors, &kept.mcp_errors);
    for (actor, tools) in &kept.by_actor_tool {
        further(
            window.by_actor_tool.entry(actor.clone()).or_default(),
            tools,
        );
    }
}
/// Counts one call of `verb` by `actor`; whether either is past its row and
/// not yet named by the window's questions: a new crossing (FIX 9531).
fn count_call(
    window: &mut WireWindowReceipt,
    thresholds: &WireThresholds,
    asked: &WireCrossed,
    (verb, actor): (&str, &str),
) -> bool {
    let verb_crossed = count_in(&mut window.by_verb, verb) > thresholds.per_verb;
    let actor_crossed = count_in(&mut window.by_actor, actor) > thresholds.per_actor;
    (verb_crossed && !asked.verbs.contains(verb))
        || (actor_crossed && !asked.actors.contains(actor))
}
impl WireTelemetry {
    pub fn new(vault: Arc<Vault>) -> Self {
        Self {
            vault,
            active: Mutex::new(Active::default()),
            saving: Mutex::new(()),
            flusher_started: std::sync::atomic::AtomicBool::new(false),
            limits: Arc::new(LimitQuestions::with_pool_pressure()),
        }
    }
    /// Where this server's `[limits]` rows ask when they are crossed.
    pub fn limit_questions(&self) -> &Arc<LimitQuestions> {
        &self.limits
    }
    /// The question `row` asked in the window starting `window`, as kept.
    pub fn limit_question(&self, row: LimitRow, window: u64) -> Result<Option<WireLimitQuestion>> {
        self.vault
            .sync_state_get(&format!("{LIMIT_QUESTION}{}:{window:020}", row.key()))?
            .map(|b| decode(&b))
            .transpose()
    }
    /// Keeps each pending question; one whose write fails stays pending for
    /// the next flush. A run of this server before this one may have kept a
    /// question for the same window, so its first write counts that in. Each
    /// is kept as telemetry, which moves no backup watermark (FIX 6730).
    fn save_limit_questions(&self) -> Result<()> {
        for (row, window, restored) in self.limits.unkept() {
            let key = format!("{LIMIT_QUESTION}{}:{window:020}", row.key());
            let earlier = if restored {
                None
            } else {
                self.vault
                    .sync_state_get(&key)?
                    .and_then(|bytes| decode(&bytes).ok())
            };
            let Some(question) = self.limits.restore(row, window, earlier) else {
                continue;
            };
            let bytes = encode(&question)?;
            self.vault
                .sync_state_put_telemetry_batch(&[(key.as_str(), bytes.as_slice())])?;
            self.limits.kept(row, window, &question);
        }
        Ok(())
    }
    /// Keeps the pending questions outside the lock every request takes, so
    /// no request waits on their write; unless the reap froze observation.
    fn save_pending(&self) -> Result<()> {
        let _saving = lock(&self.saving);
        let frozen = self
            .active
            .lock()
            .map_err(|_| Error::CorruptedIndex("wire counter lock"))?
            .frozen;
        if frozen {
            return Ok(());
        }
        self.save_limit_questions()
    }
    pub fn set_thresholds(&self, thresholds: &WireThresholds) -> Result<()> {
        self.write_thresholds(thresholds, |txn| {
            self.vault
                .sync_state_put_in_write_txn(txn, MANIFEST, &encode(thresholds)?)
        })
    }
    pub(crate) fn set_thresholds_as_owner(
        &self,
        owner: &oneiron::consent::AuthenticatedOwner,
        thresholds: &WireThresholds,
    ) -> Result<WireThresholdsReceipt> {
        self.write_thresholds(thresholds, |txn| {
            set_wire_thresholds_as_owner_in_txn(&self.vault, txn, owner, thresholds)
        })
    }
    /// Keeps the old window and the new policy together, holding the counter
    /// lock until the write commits. Host writes do not join a commit group
    /// while holding this lock.
    fn write_thresholds<T>(
        &self,
        thresholds: &WireThresholds,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::CorruptedIndex("wire counter lock"))?;
        let result = self.vault.with_write_txn(|txn| {
            thresholds.validate()?;
            if active.frozen {
                return Err(Error::InvalidConfig(
                    "wire observation frozen for reap".into(),
                ));
            }
            if !active.persisted
                && let Some(window) = &active.window
            {
                self.vault.sync_state_put_in_write_txn(
                    txn,
                    &format!("{RECEIPT}{:020}:{:020}", window.started_at, window.ended_at),
                    &encode(window)?,
                )?;
            }
            write(txn)
        })?;
        active.persisted = true;
        Ok(result)
    }
    pub fn thresholds(&self) -> Result<WireThresholds> {
        let value = self
            .vault
            .sync_state_get(MANIFEST)?
            .map(|b| decode(&b))
            .transpose()?
            .unwrap_or_default();
        WireThresholds::validate(&value)?;
        Ok(value)
    }
    /// Records a host-authenticated actor and a route/method, never a raw URL or
    /// credential. A persistence error is telemetry loss, NOT a service denial.
    pub fn record(&self, verb: &str, actor: &str, now: u64) -> Result<()> {
        check_keys(verb, actor)?;
        self.observe(now, Some((verb, actor)), |_| {})
    }
    /// Records one MCP `tools/call` of a registered tool, under its logical
    /// key and the caller the gateway resolved (FIX 1085): one call in the
    /// totals the thresholds read, and in which tool that caller called.
    pub(crate) fn record_mcp_call(&self, tool: &str, actor: &str, now: u64) -> Result<()> {
        check_keys(tool, actor)?;
        self.observe(now, Some((tool, actor)), |window| {
            count_in(window.by_actor_tool.entry(actor.into()).or_default(), tool);
        })
    }
    /// Records one MCP envelope on its matched route: evidence beside the
    /// calls, which no threshold counts.
    pub(crate) fn record_mcp_envelope(&self, route: &str, now: u64) -> Result<()> {
        self.observe(now, None, |window| {
            count_in(&mut window.mcp_envelopes, route);
        })
    }
    /// Records one MCP reply refused with no tool call's receipt over it,
    /// under its fixed category and no caller: evidence no threshold counts.
    pub(crate) fn record_mcp_error(&self, category: &str, now: u64) -> Result<()> {
        self.observe(now, None, |window| {
            count_in(&mut window.mcp_errors, category);
        })
    }
    /// Counts in the window `now` falls in, kept and rolled over first: a
    /// `call`'s verb and actor in the totals the rows read, and `count`'s
    /// evidence beside them. Each call that puts another verb or actor past
    /// its row asks: the window as it stands is kept as the next question.
    fn observe(
        &self,
        now: u64,
        call: Option<(&str, &str)>,
        count: impl FnOnce(&mut WireWindowReceipt),
    ) -> Result<()> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::CorruptedIndex("wire counter lock"))?;
        let active = &mut *active;
        if active.frozen {
            return Ok(());
        }
        let thresholds = self.thresholds()?;
        let start = now / thresholds.window_secs * thresholds.window_secs;
        let end = start.saturating_add(thresholds.window_secs);
        if active.window.as_ref().is_none_or(|w| {
            w.started_at != start || w.ended_at != start.saturating_add(thresholds.window_secs)
        }) {
            if let Some(prior) = &active.window {
                self.persist(prior)?;
            }
            let mut restored = self
                .receipt(start, end)?
                .unwrap_or_else(|| WireWindowReceipt {
                    started_at: start,
                    ended_at: end,
                    ..Default::default()
                });
            active.asked = match self.question(start, end)? {
                Some(question) => {
                    resume(&mut restored, &question.evidence);
                    question.crossed
                }
                None => WireCrossed::default(),
            };
            active.window = Some(restored);
            self.restore_newest(active, start, end)?;
        }
        let window = active.window.as_mut().expect("installed above");
        count(window);
        active.persisted = false;
        let crossed = call.is_some_and(|call| count_call(window, &thresholds, &active.asked, call));
        if crossed {
            let crossed = WireCrossed::of(window, &thresholds);
            let seq = self.keep_question(window, &crossed, active.next_seq)?;
            active.next_seq = Some(seq.saturating_add(1));
            active.asked = crossed;
            self.index_question(window, seq)?;
        }
        Ok(())
    }
    /// Counts into the window just installed, `start`..`end`, the newest
    /// call-volume question kept, when it is that window's: then it is the
    /// window's latest, which its index may not name, as a question is kept
    /// before its window's row names it (FIX 9531). A restart so resumes a
    /// question whose index row never committed. The sequence is read once
    /// per server, and the first question kept takes it.
    fn restore_newest(&self, active: &mut Active, start: u64, end: u64) -> Result<()> {
        let next = match active.next_seq {
            Some(next) => next,
            None => self.next_question_seq()?,
        };
        active.next_seq = Some(next);
        let Some(seq) = next.checked_sub(1) else {
            return Ok(());
        };
        let Some(question) = self
            .vault
            .sync_state_get(&format!("{QUESTION_SEQ}{seq:020}"))?
            .map(|b| decode::<WireQuestion>(&b))
            .transpose()?
        else {
            return Ok(());
        };
        if question.seq != seq {
            return Err(Error::CorruptedIndex("wire question identity"));
        }
        if question.evidence.started_at != start || question.evidence.ended_at != end {
            return Ok(());
        }
        if let Some(window) = active.window.as_mut() {
            resume(window, &question.evidence);
        }
        active.asked = question.crossed;
        Ok(())
    }
    /// Keeps `window` as the next call-volume question, naming `crossed`,
    /// under the sequence `next`, or the vault's next when this server has
    /// kept none yet or another question holds `next`. The row goes through
    /// the telemetry door that only adds (FIX 10300): a kept question is
    /// never rewritten, and no sequence is reused. The sequence it took.
    fn keep_question(
        &self,
        window: &WireWindowReceipt,
        crossed: &WireCrossed,
        next: Option<u64>,
    ) -> Result<u64> {
        let mut seq = match next {
            Some(seq) => seq,
            None => self.next_question_seq()?,
        };
        loop {
            let question = WireQuestion {
                kind: WireQuestionKind::InspectCallVolume,
                seq,
                crossed: crossed.clone(),
                evidence: window.clone(),
            };
            let (key, bytes) = (format!("{QUESTION_SEQ}{seq:020}"), encode(&question)?);
            let rows = [(key.as_str(), bytes.as_slice())];
            if self.vault.sync_state_put_telemetry_batch_if_absent(&rows)? == 1 {
                break;
            }
            seq = self.next_question_seq()?.max(seq.saturating_add(1));
        }
        Ok(seq)
    }
    /// Names question `seq`, kept for `window`, under its window, through the
    /// same door. The index speeds the window's restore, which reads the
    /// newest question kept beside it (`restore_newest`).
    fn index_question(&self, window: &WireWindowReceipt, seq: u64) -> Result<()> {
        let key = format!(
            "{QUESTION_WINDOW}{:020}:{:020}:{seq:020}",
            window.started_at, window.ended_at
        );
        let bytes = encode(&seq)?;
        self.vault
            .sync_state_put_telemetry_batch_if_absent(&[(key.as_str(), bytes.as_slice())])?;
        Ok(())
    }
    /// The sequence after the last call-volume question kept.
    fn next_question_seq(&self) -> Result<u64> {
        let last = self
            .vault
            .sync_state_keys_with_prefix(QUESTION_SEQ)?
            .last()
            .and_then(|key| key.strip_prefix(QUESTION_SEQ)?.parse::<u64>().ok());
        Ok(last.map_or(0, |seq| seq.saturating_add(1)))
    }
    /// Keeps `window` as telemetry, which moves no backup watermark (FIX
    /// 6730).
    fn persist(&self, window: &WireWindowReceipt) -> Result<()> {
        let key = format!("{RECEIPT}{:020}:{:020}", window.started_at, window.ended_at);
        let bytes = encode(window)?;
        self.vault
            .sync_state_put_telemetry_batch(&[(key.as_str(), bytes.as_slice())])
    }
    fn flush_active(&self, active: &mut Active) -> Result<()> {
        if !active.persisted
            && let Some(window) = &active.window
        {
            self.persist(window)?;
            active.persisted = true;
        }
        Ok(())
    }
    /// Called at shutdown and by the host's periodic observation tick.
    pub fn flush(&self) -> Result<()> {
        self.save_pending()?;
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::CorruptedIndex("wire counter lock"))?;
        if active.frozen {
            return Ok(());
        }
        self.flush_active(&mut active)
    }
    pub(crate) fn flush_if_expired(&self, now: u64) -> Result<()> {
        self.save_pending()?;
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::CorruptedIndex("wire counter lock"))?;
        if active.frozen {
            return Ok(());
        }
        if active.window.as_ref().is_none_or(|w| now < w.ended_at) {
            return Ok(());
        }
        self.flush_active(&mut active)
    }
    pub(crate) fn freeze_and_flush(&self) -> Result<()> {
        // A question write in progress ends first, and none starts after.
        let _saving = lock(&self.saving);
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::CorruptedIndex("wire counter lock"))?;
        active.frozen = true;
        // The barrier keeps what was asked before it, as a tick would have.
        self.save_limit_questions()?;
        self.flush_active(&mut active)
    }
    pub(crate) fn unfreeze(&self) -> Result<()> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::CorruptedIndex("wire counter lock"))?;
        active.frozen = false;
        Ok(())
    }
    pub fn snapshot(&self) -> Result<Option<WireWindowReceipt>> {
        Ok(self
            .active
            .lock()
            .map_err(|_| Error::CorruptedIndex("wire counter lock"))?
            .window
            .clone())
    }
    pub fn receipt(&self, start: u64, end: u64) -> Result<Option<WireWindowReceipt>> {
        let receipt: Option<WireWindowReceipt> = self
            .vault
            .sync_state_get(&format!("{RECEIPT}{start:020}:{end:020}"))?
            .map(|b| decode(&b))
            .transpose()?;
        if receipt
            .as_ref()
            .is_some_and(|w| w.started_at != start || w.ended_at != end)
        {
            return Err(Error::CorruptedIndex("wire window identity"));
        }
        Ok(receipt)
    }
    /// The latest call-volume question kept for the window `start`..`end`
    /// that the window's index names.
    pub fn question(&self, start: u64, end: u64) -> Result<Option<WireQuestion>> {
        let named = format!("{QUESTION_WINDOW}{start:020}:{end:020}:");
        let Some(latest) = self.vault.sync_state_keys_with_prefix(&named)?.pop() else {
            return Ok(None);
        };
        let seq: u64 = latest
            .strip_prefix(&named)
            .and_then(|seq| seq.parse().ok())
            .ok_or(Error::CorruptedIndex("wire question identity"))?;
        let question: Option<WireQuestion> = self
            .vault
            .sync_state_get(&format!("{QUESTION_SEQ}{seq:020}"))?
            .map(|b| decode(&b))
            .transpose()?;
        if question.as_ref().is_none_or(|q| {
            q.seq != seq || q.evidence.started_at != start || q.evidence.ended_at != end
        }) {
            return Err(Error::CorruptedIndex("wire question identity"));
        }
        Ok(question)
    }
}
impl Drop for WireTelemetry {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

mod http;
pub(crate) use self::http::{observe_http, start_window_receipts};

#[cfg(test)]
mod tests;
