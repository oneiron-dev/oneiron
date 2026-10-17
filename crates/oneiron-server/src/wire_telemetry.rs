//! RC42 observation-only wire counters. Thresholds ask questions; they never deny service.
use oneiron::limit_ask::{EngineLimit, LimitAsk};
use oneiron::{Error, Result, Vault};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};
const MANIFEST: &str = "manifest:rc42:wire-observation:v1";
const RECEIPT: &str = "wire:window:v2:";
const QUESTION: &str = "wire:question:v2:";
const LIMIT_QUESTION: &str = "wire:limit-question:v1:";
/// A row keeps one question for each window of this many seconds, and counts
/// every crossing in the window in it.
const LIMIT_QUESTION_WINDOW_SECS: u64 = 60;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireThresholds {
    pub window_secs: u64,
    pub per_verb: u64,
    pub per_actor: u64,
}
impl Default for WireThresholds {
    fn default() -> Self {
        Self {
            window_secs: 60,
            per_verb: 50_000_000,
            per_actor: 1_000_000,
        }
    }
}
impl WireThresholds {
    fn validate(&self) -> Result<()> {
        if self.window_secs == 0 || self.per_verb == 0 || self.per_actor == 0 {
            Err(Error::InvalidConfig(
                "RC42 thresholds must be positive".into(),
            ))
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireWindowReceipt {
    pub started_at: u64,
    pub ended_at: u64,
    pub by_verb: BTreeMap<String, u64>,
    pub by_actor: BTreeMap<String, u64>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WireQuestionKind {
    InspectCallVolume,
    /// Work crossed a `[limits]` row and waited for its turn, or, for a byte
    /// row, carried on past it.
    InspectLimitCrossing,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireQuestion {
    pub kind: WireQuestionKind,
    pub evidence: WireWindowReceipt,
}

/// A `[limits]` row: a bound on work a remote caller can start, set far above
/// fleet scale. Crossing one is a question, never a refusal (OF-520).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LimitRow {
    /// Sockets open at once: the descriptor floor.
    Connections,
    /// `git http-backend` exchanges at once.
    GitExchanges,
    /// LFS transfer workers at once.
    LfsTransfers,
    /// Bytes LFS transfers hold in memory at once.
    LfsMemoryBytes,
    /// Bytes stored LFS objects and uploads in flight come to.
    LfsQuota,
    /// One LFS object's size.
    LfsObjectSize,
    /// `execute_code` runs at once.
    CodeRuns,
    /// Code-mode compaction passes at once.
    CompactionPasses,
    /// Requests the embedder endpoint holds at once.
    EmbedderRequests,
    /// Bytes the embedder endpoint's request bodies hold at once.
    EmbedderBodyBytes,
    /// Bytes the embedder endpoint's answers hold until they are delivered.
    EmbedderAnswerBytes,
    /// Windows and documents one sync socket keeps state for.
    WindowsPerConnection,
    /// Live-query sessions held at once, attached or kept for a reconnect.
    LiveSessions,
    /// Live-query subscriptions open at once.
    LiveSubscriptions,
    /// Message streams one vault holds open at once.
    MessageStreams,
    /// Text documents one vault keeps resident at once.
    LiveDocuments,
    /// Bytes app-tier state retained between frames holds: the presence hub,
    /// live-query retention and residence index projections.
    RetainedMemoryBytes,
    /// Pages one residence index projection is read in.
    ResidenceIndexPages,
    /// Bytes one residence index projection holds.
    ResidenceIndexBytes,
    /// Decision reads the owner's probe route holds at once.
    DecisionReads,
    /// Booking requests per minute under the owner's slot-list, hold and book
    /// rules: an authenticated caller past one waits for it to open.
    BookingWindows,
    /// An engine row on this server's vault (`oneiron::limit_ask`), measured
    /// where the engine serves the work, which carries on past it.
    Engine(EngineLimit),
}
impl LimitRow {
    /// Every row, the list every permit site and byte check is built from.
    pub const ALL: [Self; 21 + EngineLimit::ALL.len()] = [
        Self::Connections,
        Self::GitExchanges,
        Self::LfsTransfers,
        Self::LfsMemoryBytes,
        Self::LfsQuota,
        Self::LfsObjectSize,
        Self::CodeRuns,
        Self::CompactionPasses,
        Self::EmbedderRequests,
        Self::EmbedderBodyBytes,
        Self::EmbedderAnswerBytes,
        Self::WindowsPerConnection,
        Self::LiveSessions,
        Self::LiveSubscriptions,
        Self::MessageStreams,
        Self::LiveDocuments,
        Self::RetainedMemoryBytes,
        Self::ResidenceIndexPages,
        Self::ResidenceIndexBytes,
        Self::DecisionReads,
        Self::BookingWindows,
        Self::Engine(EngineLimit::KeyedFilterJsonBytes),
        Self::Engine(EngineLimit::CodeResultInlineBytes),
        Self::Engine(EngineLimit::CodeResultDiskFloorBytes),
        Self::Engine(EngineLimit::CodeResultScanBytes),
        Self::Engine(EngineLimit::CodeResultMemoryBytes),
        Self::Engine(EngineLimit::CodeResultSessionMemoryBytes),
        Self::Engine(EngineLimit::ImageRoomBytes),
        Self::Engine(EngineLimit::CodeReaderBacklog),
        Self::Engine(EngineLimit::AskOptions),
        Self::Engine(EngineLimit::AskOptionTextBytes),
        Self::Engine(EngineLimit::AskContextRefs),
        Self::Engine(EngineLimit::AskRecipients),
        Self::Engine(EngineLimit::AskSpecMsgpackBytes),
        Self::Engine(EngineLimit::AskReminders),
        Self::Engine(EngineLimit::AnswerProvenanceRefs),
        Self::Engine(EngineLimit::AskWaitIdentities),
    ];
    /// The config key that sets the row, or, for the memory the embedder
    /// endpoint sizes for its one model, the name it asks under.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Connections => "limits.max_connections",
            Self::GitExchanges => "limits.git_exchanges",
            Self::LfsTransfers => "limits.lfs_transfers",
            Self::LfsMemoryBytes => "limits.lfs_memory_bytes",
            Self::LfsQuota => "limits.lfs_quota_bytes",
            Self::LfsObjectSize => "max_lfs_object_bytes",
            Self::CodeRuns => "models.code_mode.max_runs",
            // As many passes as runs: at most one per run is in flight.
            Self::CompactionPasses => "models.code_mode.max_runs:compaction",
            Self::EmbedderRequests => "limits.embedder_requests",
            Self::EmbedderBodyBytes => "embedder.serve:body_bytes",
            Self::EmbedderAnswerBytes => "limits.embedder_answer_bytes",
            Self::WindowsPerConnection => "max_windows_per_connection",
            Self::LiveSessions => "limits.live_sessions",
            Self::LiveSubscriptions => "limits.live_subscriptions",
            Self::MessageStreams => "limits.message_streams",
            Self::LiveDocuments => "limits.live_documents",
            Self::RetainedMemoryBytes => "limits.retained_memory_bytes",
            Self::ResidenceIndexPages => "residence_operation_budgets.max_index_pages",
            Self::ResidenceIndexBytes => "residence_operation_budgets.index_cache_bytes",
            Self::DecisionReads => "limits.decision_reads",
            Self::BookingWindows => "booking.anti_abuse:per_minute",
            Self::Engine(row) => row.key(),
        }
    }
}
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
impl WireTelemetry {
    pub fn new(vault: Arc<Vault>) -> Self {
        Self {
            vault,
            active: Mutex::new(Active::default()),
            saving: Mutex::new(()),
            flusher_started: std::sync::atomic::AtomicBool::new(false),
            limits: Arc::default(),
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
        thresholds.validate()?;
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::CorruptedIndex("wire counter lock"))?;
        if active.frozen {
            return Err(Error::InvalidConfig(
                "wire observation frozen for reap".into(),
            ));
        }
        self.flush_active(&mut active)?;
        self.vault.sync_state_put(MANIFEST, &encode(thresholds)?)
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
        if verb.is_empty() || verb.len() > 256 || actor.is_empty() || actor.len() > 512 {
            return Err(Error::InvalidConfig("invalid wire counter key".into()));
        }
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
        let verb_count = window.by_verb.entry(verb.into()).or_default();
        *verb_count = verb_count.saturating_add(1);
        let verb_crossed = *verb_count > thresholds.per_verb;
        let actor_count = window.by_actor.entry(actor.into()).or_default();
        *actor_count = actor_count.saturating_add(1);
        let crossed = verb_crossed || *actor_count > thresholds.per_actor;
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

pub(crate) async fn observe_http(
    axum::extract::State(server): axum::extract::State<Arc<crate::server::SyncServer>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or("unmatched", axum::extract::MatchedPath::as_str);
    let verb = format!("{} {route}", request.method());
    let auth = crate::auth::CoreAuth::from_headers(
        request.headers(),
        &server.config,
        server.vault().as_ref(),
    )
    .ok();
    let actor = auth.as_ref().map_or("unauthenticated", |a| {
        a.principal_ref().unwrap_or(a.principal())
    });
    start_window_receipts(&server);
    let _ = server
        .wire_telemetry
        .record(&verb, actor, oneiron_vault_contract::now_ts());
    next.run(request).await
}
#[cfg(test)]
mod tests;

pub(crate) fn start_window_receipts(server: &Arc<crate::server::SyncServer>) {
    // Router construction may happen before its runtime exists. The first
    // runtime-backed request retries this start without losing the flush latch.
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    if server
        .wire_telemetry
        .flusher_started
        .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        return;
    }
    let weak = Arc::downgrade(server);
    runtime.spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            // The tick writes pending limit questions, and the window once it
            // has elapsed, off the runtime's workers: a write that waits for
            // the vault's writer holds back only the tick.
            let now = oneiron_vault_contract::now_ts();
            let _ =
                tokio::task::spawn_blocking(move || server.wire_telemetry.flush_if_expired(now))
                    .await;
        }
    });
}
