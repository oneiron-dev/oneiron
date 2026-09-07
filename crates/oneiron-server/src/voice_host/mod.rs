//! Private voice request adapter, not an audio/provider scheduler.
//!
//! The lifecycle owner supplies its already-admitted private UDS connection,
//! shared budget guard, concrete backend and resolved extraction prompt. This
//! module creates no listener, runtime, budget policy, memory store or provider.
//! Runtime route selection reuses the server summarizer route; it must contain
//! a fully revisioned TINY model. The default placeholder route fails closed.
//! The wake supervisor can attach this host to its existing backend and pass
//! meter. Serving still requires an owner-admitted stream and real output seams.

mod connection;
mod extraction;

use std::sync::{Arc, Mutex, MutexGuard};

use oneiron::llm::{BudgetGuard, LlmBackend, LlmError};
use oneiron::speculative::SpeculativeSessionConfig;
use oneiron::voice_cascade::{
    AsrEvent, AsrEventKind, AsrUpdate, OutputStop, PreparedAsr, UtteranceHandle,
    VoiceCascadeSession, VoiceSessionConfig,
};

use crate::managed::ManagedShutdown;
use crate::runtime::RuntimeConfig;
use extraction::TinyExtractor;

/// Submission-only existing brain/TTS/control seams, not provider executors.
pub(crate) struct VoiceOutputs<B, T, C> {
    pub brain: B,
    pub tts: T,
    pub control: C,
}

/// Trusted, process-local dependencies. Never deserialize these from the peer.
pub struct VoiceHostBindings {
    pub backend: Arc<dyn LlmBackend>,
    /// Clone the lifecycle owner's meter; never allocate a per-request budget.
    pub budget: BudgetGuard,
    /// Resolved host prompt for the bounded entity-label/salient-term schema.
    pub extraction_prompt: String,
    pub session: VoiceSessionConfig,
    pub shutdown: ManagedShutdown,
}

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("invalid voice request")]
    InvalidRequest,
    #[error("stale voice request")]
    Stale,
    #[error("voice host stopped")]
    Stopped,
    #[error("invalid TINY response")]
    InvalidResponse,
    #[error(transparent)]
    Llm(#[from] LlmError),
    #[error(transparent)]
    Core(#[from] oneiron::Error),
}

struct SessionState {
    core: VoiceCascadeSession,
    open: Option<(String, UtteranceHandle)>,
    next_handle: u64,
}

pub struct VoiceHost {
    state: Mutex<SessionState>,
    extractor: TinyExtractor,
    shutdown: ManagedShutdown,
}

/// Optional process-local configuration. The factory supplies the backend and
/// the supervisor supplies its already-created pass meter at attachment time.
#[derive(Clone)]
pub struct VoiceHostConfig {
    pub vault: Arc<oneiron::Vault>,
    pub runtime: RuntimeConfig,
    pub extraction_prompt: String,
    pub session: VoiceSessionConfig,
    pub shutdown: ManagedShutdown,
}

impl VoiceHost {
    /// Constructs a lifecycle attachment without constructing an HTTP server.
    /// No listener, provider, ledger or budget is created here.
    pub fn new(
        vault: Arc<oneiron::Vault>,
        runtime: &RuntimeConfig,
        bindings: VoiceHostBindings,
    ) -> Result<Self, HostError> {
        if bindings.shutdown.is_triggered() {
            return Err(HostError::Stopped);
        }
        let extractor = TinyExtractor::new(
            runtime,
            bindings.backend,
            bindings.budget,
            bindings.extraction_prompt,
        )?;
        Ok(Self {
            state: Mutex::new(SessionState {
                core: VoiceCascadeSession::new(vault, bindings.session)?,
                open: None,
                next_handle: 0,
            }),
            extractor,
            shutdown: bindings.shutdown,
        })
    }

    /// The injected backend allocation, not a new adapter.
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn LlmBackend> {
        &self.extractor.backend
    }

    /// The injected pass meter, including its lease provenance.
    #[must_use]
    pub fn budget(&self) -> &BudgetGuard {
        &self.extractor.budget
    }

    fn lock(&self) -> Result<MutexGuard<'_, SessionState>, HostError> {
        self.state.lock().map_err(|_| HostError::Stopped)
    }

    fn require_running(&self) -> Result<(), HostError> {
        if self.shutdown.is_triggered() {
            Err(HostError::Stopped)
        } else {
            Ok(())
        }
    }

    /// Opens an utterance for a trusted, process-local caller.
    pub fn open(&self, utterance_id: String) -> Result<String, HostError> {
        self.require_running()?;
        if utterance_id.trim().is_empty() || utterance_id.len() > 128 {
            return Err(HostError::InvalidRequest);
        }
        let mut state = self.lock()?;
        let serial = state.next_handle.checked_add(1).ok_or(HostError::Stopped)?;
        let handle = state.core.open_utterance(utterance_id, SpeculativeSessionConfig {
            max_fires: 4,
            fire_limit: 8,
            final_limit: 32,
        })?;
        // Connection-local, monotonically unique correlation. Not authentication.
        let token = serial.to_string();
        state.next_handle = serial;
        state.open = Some((token.clone(), handle));
        Ok(token)
    }

    fn close(&self, token: &str) -> Result<(), HostError> {
        let mut state = self.lock()?;
        let handle = state.handle(token)?;
        state.core.close_utterance(&handle);
        state.open = None;
        Ok(())
    }

    /// Prepares an observation without holding a session lock during extraction.
    pub fn prepare(
        &self,
        token: &str,
        revision: u64,
        text: String,
        final_text: bool,
    ) -> Result<EnrichmentWork<'_>, HostError> {
        self.require_running()?;
        if text.trim().is_empty() || text.len() > oneiron::voice_cascade::uds::MAX_TEXT_BYTES {
            return Err(HostError::InvalidRequest);
        }
        let mut state = self.lock()?;
        let handle = state.handle(token)?;
        let event = AsrEvent {
            kind: if final_text { AsrEventKind::Final } else { AsrEventKind::Partial },
            text,
            tokens: Vec::new(),
            provider_latency_ms: None,
            endpoint_delay_ms: None,
            error: None,
        };
        // The untrusted wire cannot clear context taint or assert owner identity.
        let prepared = state.core.prepare_asr(&handle, revision, event, true)?
            .ok_or(HostError::Stale)?;
        Ok(EnrichmentWork { host: self, prepared: Some(prepared) })
    }

    fn end(&self) -> Result<OutputStop, HostError> {
        let mut state = self.lock()?;
        state.open = None;
        Ok(state.core.end())
    }
}

impl Drop for VoiceHost {
    fn drop(&mut self) {
        // Memory cleanup even when the owning connection future is dropped.
        // Remote output cancellation still requires the owner's dispatch/ACK.
        if let Ok(state) = self.state.get_mut() {
            let _stop = state.core.end();
            state.open = None;
        }
    }
}

impl SessionState {
    fn handle(&self, token: &str) -> Result<UtteranceHandle, HostError> {
        self.open.as_ref().filter(|(current, _)| current == token)
            .map(|(_, handle)| handle.clone()).ok_or(HostError::Stale)
    }
}

/// Owns a core-minted ticket, not a revision cache. Drop cancels only this attempt.
pub struct EnrichmentWork<'a> {
    host: &'a VoiceHost,
    prepared: Option<PreparedAsr>,
}

impl EnrichmentWork<'_> {
    /// Extracts and applies only if the prepared observation is still current.
    pub async fn run(mut self) -> Result<AsrUpdate, HostError> {
        let prepared = self.prepared.as_ref().ok_or(HostError::Stale)?;
        {
            let state = self.host.lock()?;
            self.host.require_running()?;
            if !state.core.accepts_prepared_asr(prepared) {
                return Err(HostError::Stale);
            }
        }
        // Both admission and provider work happen with NO session/vault guard.
        let enrichment = tokio::select! {
            biased;
            () = self.host.shutdown.triggered() => return Err(HostError::Stopped),
            result = self.host.extractor.extract(prepared.text()) => result?,
        };
        let mut state = self.host.lock()?;
        self.host.require_running()?;
        let prepared = self.prepared.take().ok_or(HostError::Stale)?;
        let result = state.core.apply_prepared_asr(prepared, enrichment);
        if state.open.as_ref().is_some_and(|(_, handle)| !state.core.is_utterance_open(handle)) {
            state.open = None;
        }
        // Final core retrieval errors consume its handle, unlike provider errors.
        result.map_err(HostError::from)
    }
}

impl Drop for EnrichmentWork<'_> {
    fn drop(&mut self) {
        if let Some(prepared) = &self.prepared
            && let Ok(mut state) = self.host.lock()
        {
            state.core.cancel_prepared_asr(prepared);
        }
    }
}

#[cfg(test)]
mod tests;
