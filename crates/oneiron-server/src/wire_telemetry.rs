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
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

const RECEIPT: &str = "wire:window:v2:";
const QUESTION: &str = "wire:question:v2:";
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireQuestion {
    pub kind: WireQuestionKind,
    pub evidence: WireWindowReceipt,
}

mod connection_pressure;
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
    asked: bool,
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
/// Counts one call of `verb` by `actor`; whether either crossed its row.
fn count_call(
    window: &mut WireWindowReceipt,
    thresholds: &WireThresholds,
    verb: &str,
    actor: &str,
) -> bool {
    let verb_crossed = count_in(&mut window.by_verb, verb) > thresholds.per_verb;
    let actor_crossed = count_in(&mut window.by_actor, actor) > thresholds.per_actor;
    verb_crossed || actor_crossed
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
    /// question for the same window, so its first write counts that in.
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
            self.vault.sync_state_put(&key, &encode(&question)?)?;
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
        self.observe(now, |window, thresholds| {
            count_call(window, thresholds, verb, actor)
        })
    }
    /// Records one MCP `tools/call` of a registered tool, under its logical
    /// key and the caller the gateway resolved (FIX 1085): one call in the
    /// totals the thresholds read, and in which tool that caller called.
    pub(crate) fn record_mcp_call(&self, tool: &str, actor: &str, now: u64) -> Result<()> {
        check_keys(tool, actor)?;
        self.observe(now, |window, thresholds| {
            count_in(window.by_actor_tool.entry(actor.into()).or_default(), tool);
            count_call(window, thresholds, tool, actor)
        })
    }
    /// Records one MCP envelope on its matched route: evidence beside the
    /// calls, which no threshold counts.
    pub(crate) fn record_mcp_envelope(&self, route: &str, now: u64) -> Result<()> {
        self.observe(now, |window, _| {
            count_in(&mut window.mcp_envelopes, route);
            false
        })
    }
    /// Records one MCP reply refused with no tool call's receipt over it,
    /// under its fixed category and no caller: evidence no threshold counts.
    pub(crate) fn record_mcp_error(&self, category: &str, now: u64) -> Result<()> {
        self.observe(now, |window, _| {
            count_in(&mut window.mcp_errors, category);
            false
        })
    }
    /// Counts in the window `now` falls in, kept and rolled over first;
    /// `count` says whether a call crossed its row, which asks once a window.
    fn observe(
        &self,
        now: u64,
        count: impl FnOnce(&mut WireWindowReceipt, &WireThresholds) -> bool,
    ) -> Result<()> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::CorruptedIndex("wire counter lock"))?;
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
            active.asked = self.question(start, end)?.is_some();
            let restored = self.receipt(start, end)?;
            active.window = Some(restored.unwrap_or_else(|| WireWindowReceipt {
                started_at: start,
                ended_at: end,
                ..Default::default()
            }));
        }
        let window = active.window.as_mut().expect("installed above");
        let crossed = count(window, &thresholds);
        active.persisted = false;
        if crossed && !active.asked {
            let question = WireQuestion {
                kind: WireQuestionKind::InspectCallVolume,
                evidence: active.window.clone().expect("window"),
            };
            let key = format!("{QUESTION}{start:020}:{end:020}");
            self.vault.with_write_txn_grouped(|txn| {
                if self.vault.sync_state_get_in_write_txn(txn, &key)?.is_none() {
                    self.vault
                        .sync_state_put_in_write_txn(txn, &key, &encode(&question)?)?;
                }
                Ok(())
            })?;
            active.asked = true;
        }
        Ok(())
    }
    fn persist(&self, window: &WireWindowReceipt) -> Result<()> {
        self.vault.sync_state_put(
            &format!("{RECEIPT}{:020}:{:020}", window.started_at, window.ended_at),
            &encode(window)?,
        )
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
    pub fn question(&self, start: u64, end: u64) -> Result<Option<WireQuestion>> {
        let question: Option<WireQuestion> = self
            .vault
            .sync_state_get(&format!("{QUESTION}{start:020}:{end:020}"))?
            .map(|b| decode(&b))
            .transpose()?;
        if question
            .as_ref()
            .is_some_and(|q| q.evidence.started_at != start || q.evidence.ended_at != end)
        {
            return Err(Error::CorruptedIndex("wire question identity"));
        }
        Ok(question)
    }
    /// Every call-volume question kept, by key, oldest window first: what the
    /// health check reads (OF-520).
    pub(crate) fn kept_questions(&self) -> Result<Vec<(String, WireQuestion)>> {
        self.kept(QUESTION)
    }
    /// Every limit question kept, by key: each row's windows, oldest first.
    pub(crate) fn kept_limit_questions(&self) -> Result<Vec<(String, WireLimitQuestion)>> {
        self.kept(LIMIT_QUESTION)
    }
    fn kept<T: serde::de::DeserializeOwned>(&self, prefix: &str) -> Result<Vec<(String, T)>> {
        let mut kept = Vec::new();
        for key in self.vault.sync_state_keys_with_prefix(prefix)? {
            if let Some(bytes) = self.vault.sync_state_get(&key)? {
                kept.push((key, decode(&bytes)?));
            }
        }
        Ok(kept)
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
