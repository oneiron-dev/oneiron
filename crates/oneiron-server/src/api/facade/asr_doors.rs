//! The owner's host-enriched ASR door. Handles are server-minted, bound to
//! the exact opening credential and consumed at finalization or close.
//! Signature changes, fire counts and warm reuse remain OF-108 decisions.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::speculative::{SpeculativeFinal, SpeculativeFireDecision, SpeculativeSession, SpeculativeSessionConfig};
use oneiron::task_verb::sdk::*;
use oneiron::{EdgeActorClass, EntityId};

use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing, hex_rows, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

#[derive(Default)]
pub(crate) struct AsrSessions {
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}

struct Entry {
    auth: CoreAuth,
    state: Mutex<Utterance>,
}

struct Utterance {
    opened: AsrSession,
    core: Option<SpeculativeSession>,
    revision: Option<u64>,
    last_fire_receipt: Option<String>,
}

fn missing() -> MemoryError {
    MemoryError::not_found("no ASR utterance belongs to this credential")
}

impl AsrSessions {
    fn get(&self, auth: &CoreAuth, handle: &str) -> MemoryResult<Arc<Entry>> {
        self.entries.lock().map_err(|_| internal("ai.voice.asr"))?
            .get(handle).filter(|entry| entry.auth.same_authority(auth))
            .cloned().ok_or_else(missing)
    }

    fn remove(&self, handle: &str) -> MemoryResult<()> {
        self.entries.lock().map_err(|_| internal("ai.voice.asr"))?.remove(handle);
        Ok(())
    }
}

impl Utterance {
    fn check(&self, revision: u64) -> MemoryResult<()> {
        if self.core.is_none() {
            return Err(missing());
        }
        if self.revision.is_some_and(|last| revision <= last) {
            return Err(MemoryError::bad_request("ASR revision must advance"));
        }
        Ok(())
    }
}

fn admit(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<(EntityId, EdgeActorClass)> {
    owner_proof(auth, server, verb)?.revalidate(server.vault())?;
    super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)
}

pub(crate) async fn ai_voice_asr_open(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: AsrOpenRequest,
) -> Listed<AsrSession> {
    let verb = "ai.voice.asr.open";
    let caller = match admit(server, auth, verb) {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(server, auth, caller, verb, move |server, auth, memory| {
        if input.utterance_id.trim().is_empty() {
            return Err(MemoryError::bad_request("utterance_id must be nonempty"));
        }
        let defaults = SpeculativeSessionConfig::default();
        let fire_limit = input.fire_limit.unwrap_or(defaults.fire_limit);
        let final_limit = input.final_limit.unwrap_or(defaults.final_limit);
        oneiron::memory::caps::check_limit_nonzero(fire_limit)?;
        oneiron::memory::caps::check_limit_nonzero(final_limit)?;
        oneiron::memory::caps::check_deadline_ms(input.deadline_ms)?;
        let (fire_limit, fire_clamped) = oneiron::memory::caps::clamp_search_limit(fire_limit);
        let (final_limit, final_clamped) = oneiron::memory::caps::clamp_search_limit(final_limit);
        let deadline = input.deadline_ms.map(Duration::from_millis)
            .unwrap_or_else(|| server.vault().call_mode_deadline());
        let core = memory.speculative_session(
            Arc::clone(&server.vault),
            SpeculativeSessionConfig {
                max_fires: defaults.max_fires, fire_limit, final_limit, deadline: Some(deadline),
            },
            &input.scope,
        )?;
        let opened = AsrSession {
            handle: EntityId::now().to_hex(),
            utterance_id: input.utterance_id,
            scope: input.scope,
            max_fires: defaults.max_fires,
            fire_limit, final_limit,
            limit_clamped: fire_clamped || final_clamped,
            deadline_ms: u64::try_from(deadline.as_millis()).map_err(|_| internal(verb))?,
            narrowing: core.scoped_read_receipt()?,
        };
        server.asr_sessions.entries.lock().map_err(|_| internal(verb))?.insert(
            opened.handle.clone(),
            Arc::new(Entry {
                auth: auth.clone(),
                state: Mutex::new(Utterance {
                    opened: opened.clone(), core: Some(core), revision: None, last_fire_receipt: None,
                }),
            }),
        );
        Ok(opened)
    }).await
}

pub(crate) async fn ai_voice_asr_hypothesis(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: AsrHypothesisRequest,
) -> Listed<AsrHypothesisReceipt> {
    let verb = "ai.voice.asr.hypothesis";
    let caller = match admit(server, auth, verb) {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    let (output, mut rows) = credential_listing(server, auth, caller, verb, move |server, auth, _| {
        input.validate()?;
        let entry = server.asr_sessions.get(auth, &input.handle)?;
        let mut state = entry.state.lock().map_err(|_| internal(verb))?;
        state.check(input.revision)?;
        let core = state.core.as_mut().ok_or_else(missing)?;
        let decision = core.observe_partial(input.partial())?;
        let fires_used = core.fires_used();
        let mut narrowing = core.scoped_read_receipt()?;
        let (decision, run_id, partial, scores) = match decision {
            SpeculativeFireDecision::Fired { run_id, partial } => {
                let released = core.scoped_warm_candidates()?;
                narrowing.restrict_with(&released.receipt);
                (AsrFireDecision::Fired, run_id, partial, released.value)
            }
            SpeculativeFireDecision::MissedDeadline => (AsrFireDecision::MissedDeadline, None, true, Vec::new()),
            SpeculativeFireDecision::SkippedUnchanged => (AsrFireDecision::SkippedUnchanged, None, false, Vec::new()),
            SpeculativeFireDecision::SkippedEmptySignature => (AsrFireDecision::SkippedEmptySignature, None, false, Vec::new()),
            SpeculativeFireDecision::SkippedCapExhausted => (AsrFireDecision::SkippedCapExhausted, None, false, Vec::new()),
        };
        let receipt_ref = EntityId::now().to_hex();
        if matches!(decision, AsrFireDecision::Fired) {
            state.last_fire_receipt = Some(receipt_ref.clone());
        }
        state.revision = Some(input.revision);
        Ok(AsrHypothesisReceipt {
            receipt_ref,
            handle: input.handle,
            utterance_id: state.opened.utterance_id.clone(),
            revision: input.revision,
            text: input.text,
            scope: state.opened.scope.clone(),
            decision, fires_used,
            run_id: run_id.map(|id| id.to_hex()),
            partial,
            result_refs: scores.iter().map(|score| score.id.to_hex()).collect(),
            narrowing,
        })
    }).await;
    if let Ok(receipt) = &output {
        rows.extend(hex_rows(&receipt.result_refs));
    }
    (output, rows)
}

pub(crate) async fn ai_voice_asr_finalize(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: AsrHypothesisRequest,
) -> Listed<AsrFinalReceipt> {
    let verb = "ai.voice.asr.finalize";
    let caller = match admit(server, auth, verb) {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    let (output, mut rows) = credential_listing(server, auth, caller, verb, move |server, auth, _| {
        input.validate()?;
        let entry = server.asr_sessions.get(auth, &input.handle)?;
        let mut state = entry.state.lock().map_err(|_| internal(verb))?;
        state.check(input.revision)?;
        let core = state.core.take().ok_or_else(missing)?;
        let fires_used = core.fires_used();
        // OF-108 consumes the session even if its final retrieval fails.
        server.asr_sessions.remove(&input.handle)?;
        let (finished, narrowing) = core.finalize_scoped(input.partial())?;
        let (decision, scores, run_id, warm_appended, partial, reused_fire_receipt) = match finished {
            SpeculativeFinal::Promoted { scores, run_id, partial } => (
                AsrFinalDecision::Promoted, scores, run_id, 0, partial, state.last_fire_receipt.clone(),
            ),
            SpeculativeFinal::Finalized { scores, run_id, warm_appended, partial } => (
                AsrFinalDecision::Finalized, scores, run_id, warm_appended, partial, None,
            ),
        };
        Ok(AsrFinalReceipt {
            receipt_ref: EntityId::now().to_hex(),
            handle: input.handle,
            utterance_id: state.opened.utterance_id.clone(),
            revision: input.revision,
            text: input.text,
            scope: state.opened.scope.clone(),
            decision, reused_fire_receipt, fires_used,
            run_id: run_id.map(|id| id.to_hex()),
            warm_appended, partial,
            result_refs: scores.iter().map(|score| score.id.to_hex()).collect(),
            narrowing,
        })
    }).await;
    if let Ok(receipt) = &output {
        rows.extend(hex_rows(&receipt.result_refs));
    }
    (output, rows)
}

pub(crate) async fn ai_voice_asr_close(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: AsrCloseRequest,
) -> Listed<AsrClosed> {
    let verb = "ai.voice.asr.close";
    let caller = match admit(server, auth, verb) {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(server, auth, caller, verb, move |server, auth, _| {
        let entry = server.asr_sessions.get(auth, &input.handle)?;
        let mut state = entry.state.lock().map_err(|_| internal(verb))?;
        state.core.take().ok_or_else(missing)?;
        server.asr_sessions.remove(&input.handle)?;
        Ok(AsrClosed { handle: input.handle })
    }).await
}
