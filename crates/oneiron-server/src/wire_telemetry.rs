//! RC42 observation-only wire counters. Thresholds ask questions; they never deny service.
use oneiron::{Error, Result, Vault};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
const MANIFEST: &str = "manifest:rc42:wire-observation:v1";
const RECEIPT: &str = "wire:window:v2:";
const QUESTION: &str = "wire:question:v2:";
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
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireQuestion {
    pub kind: WireQuestionKind,
    pub evidence: WireWindowReceipt,
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
    flusher_started: std::sync::atomic::AtomicBool,
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
            flusher_started: std::sync::atomic::AtomicBool::new(false),
        }
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
            self.vault.with_write_txn(|txn| {
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
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::CorruptedIndex("wire counter lock"))?;
        if active.frozen || active.window.as_ref().is_none_or(|w| now < w.ended_at) {
            return Ok(());
        }
        self.flush_active(&mut active)
    }
    pub(crate) fn freeze_and_flush(&self) -> Result<()> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::CorruptedIndex("wire counter lock"))?;
        active.frozen = true;
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
            // The tick only writes after the observation window has elapsed.
            let _ = server
                .wire_telemetry
                .flush_if_expired(oneiron_vault_contract::now_ts());
        }
    });
}
