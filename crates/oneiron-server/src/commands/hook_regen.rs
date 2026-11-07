//! One startup pass over hooks bound under an older engine contract.
//! Generation records a pending decision; only the existing owner door adopts it.

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::runtime_hooks::{
    HookRegenFailure, HookRegenFailurePhase, HookRegenOutcome, HookRegenRequest, HookRegenerator,
};
use oneiron::skill_hub::pack_catalog::HookActorClass;
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, EdgeActorClass,
    LlmMessage, LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, TierPrecedence,
    WriteActor,
};
use tokio::sync::watch;

use crate::ai_host::CHAT_ROLE;
use crate::server::{HousekeepingAdmission, SyncServer};

const PURPOSE: &str = "hook_regen";

/// The pass stays outside the general workers that shutdown aborts. Its model
/// future is cancelled on stop, then its blocking replay/record write is joined
/// while the vault and model runtime still serve.
pub(crate) struct HookRegenWorker {
    stopping: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl HookRegenWorker {
    /// No configured wording or chat seat means no generation or model spend.
    pub(crate) fn spawn(server: &Arc<SyncServer>, admit: HousekeepingAdmission) -> Option<Self> {
        server.config.skills.hook_regen_prompt.as_ref()?;
        server.ai.chat_seat()?;
        let (stopping, stopped) = watch::channel(false);
        let server = Arc::clone(server);
        let handle = tokio::runtime::Handle::current();
        let task = tokio::task::spawn_blocking(move || {
            let Some(held) = admit() else { return };
            let due = match server.vault().hooks_due_for_regen() {
                Ok(due) if !due.is_empty() => due,
                Ok(_) => return,
                Err(_) => {
                    tracing::warn!(
                        reason = "hook_regen_due_failed",
                        "hook regeneration did not start"
                    );
                    return;
                }
            };
            if *stopped.borrow() {
                return;
            }
            let runtime = match super::hook_sandbox(&server) {
                Ok(runtime) => runtime,
                Err(_) => {
                    tracing::warn!(
                        reason = "hook_regen_sandbox_unavailable",
                        "hook regeneration did not start"
                    );
                    return;
                }
            };
            drop(held);
            let regenerator = HostHookRegenerator {
                server: &server,
                handle,
                stopped,
            };
            for binding in due {
                if *regenerator.stopped.borrow() {
                    break;
                }
                let Some(_held) = admit() else { break };
                match server
                    .vault()
                    .regenerate_hook(runtime.as_ref(), &regenerator, binding)
                {
                    Ok(HookRegenOutcome::RolledBack { failure }) => {
                        tracing::warn!(?binding, phase = ?failure.phase, "hook regeneration kept its last good body");
                    }
                    Ok(_) => {
                        tracing::info!(?binding, "hook regeneration has a pending owner decision");
                    }
                    Err(_) => {
                        tracing::warn!(?binding, reason = "hook_regen_record_failed", "hook regeneration did not record a decision");
                    }
                }
            }
        });
        Some(Self {
            stopping,
            task: Some(task),
        })
    }

    pub(crate) async fn stop(mut self) {
        self.stopping.send_replace(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for HookRegenWorker {
    fn drop(&mut self) {
        // A failed start also cancels the model wait. The pass keeps the vault
        // alive until its current replay/record write ends.
        self.stopping.send_replace(true);
    }
}

/// The synchronous engine seam is called on the pass's blocking thread.
struct HostHookRegenerator<'a> {
    server: &'a SyncServer,
    handle: tokio::runtime::Handle,
    stopped: watch::Receiver<bool>,
}

impl HookRegenerator for HostHookRegenerator<'_> {
    fn regenerate(&self, request: &HookRegenRequest) -> Result<String, HookRegenFailure> {
        let vault = self.server.vault();
        let binding = vault
            .pack_hook_bindings()
            .map_err(|_| failed("hook binding did not read"))?
            .into_iter()
            .find(|(id, row)| {
                *id == request.binding
                    && row.pack == request.pack
                    && row.hook == request.hook
                    && row.selector == request.selector
                    && row.body_hash == blake3::hash(request.last_good.as_bytes()).to_hex().as_str()
            })
            .map(|(_, row)| row)
            .ok_or_else(|| failed("hook binding changed before generation"))?;
        let prompt = self
            .server
            .config
            .skills
            .hook_regen_prompt
            .as_deref()
            .ok_or_else(|| failed("hook generation wording is not configured"))?;
        let models = self.server.ai.model_runtime();
        let seat = models
            .seat(CHAT_ROLE)
            .ok_or_else(|| failed("hook generation has no configured chat seat"))?;
        let purpose = CallPurpose::Other {
            name: PURPOSE.to_owned(),
        };
        let data = serde_json::json!({
            "binding": request.binding.to_hex(),
            "pack": request.pack,
            "hook": request.hook,
            "selector": request.selector,
            "intent": request.intent,
            "last_good": request.last_good,
            "target": request.target,
            "hook_wit": oneiron::runtime_hooks::sandbox::HOOK_WIT,
        });
        let call = models
            .admit_role(
                vault,
                CHAT_ROLE,
                LlmRequest {
                    model: seat.model.clone(),
                    envelope: CallEnvelope {
                        seat_effort: None,
                        scope: Default::default(),
                        tier: TierPrecedence::for_purpose(
                            &purpose,
                            ModelTierRef(PURPOSE.to_owned()),
                        ),
                        purpose,
                        class: CallClass::BestEffort,
                        response_format: ResponseFormat::Text,
                        locality: seat.locality,
                        host_keyless: false,
                        host_paid: false,
                    },
                    messages: vec![
                        message(LlmMessageRole::System, prompt.to_owned()),
                        message(LlmMessageRole::User, data.to_string()),
                    ],
                    tools: Vec::new(),
                    params: BTreeMap::new(),
                    provider_options: BTreeMap::new(),
                    host_segments: None,
                },
            )
            .map_err(|_| failed("hook generation model role was refused"))?;
        let class = match binding.author_class() {
            HookActorClass::Human => EdgeActorClass::Human,
            HookActorClass::Agent => EdgeActorClass::Agent,
            HookActorClass::System => EdgeActorClass::System,
        };
        let id = format!("{PURPOSE}:{}", request.binding.to_hex());
        let units = self.server.ai.chat_settings().turn_budget_units;
        let meter = vault
            .policy_budget_guard(
                id.clone(),
                units,
                oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(units),
                BudgetExhaustionPolicy::Suspend,
                WriteActor::new(binding.author_id(), class),
            )
            .map_err(|_| failed("hook generation budget did not admit"))?;
        // Intent can come from the retained regen record, not just the current
        // pack source. Do not assert complete source lineage for that fallback.
        let pack_intent = vault
            .get_pack_source(&binding.source)
            .map_err(|_| failed("hook generation source did not read"))?
            .and_then(|source| {
                source
                    .hooks()
                    .iter()
                    .find(|hook| hook.name == request.hook)
                    .and_then(|hook| hook.intent.clone())
            });
        let rows = (pack_intent.as_deref() == Some(request.intent.as_str()))
            .then(|| vec![request.binding, binding.source]);
        let run = models.undeclared_run(id, meter).sourced(rows);
        let mut stopped = self.stopped.clone();
        let may_send = || !*self.stopped.borrow();
        let response = self.handle.block_on(async {
            tokio::select! {
                biased;
                _ = stopped.wait_for(|stop| *stop) => Err(failed("hook generation stopped")),
                response = call.ladder.generate_while(&run, call.request, None, &may_send) =>
                    response.map_err(|_| failed("hook generation model call failed")),
            }
        })?;
        Ok(response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect())
    }
}

fn failed(message: &str) -> HookRegenFailure {
    HookRegenFailure::new(HookRegenFailurePhase::Generate, message)
}

fn message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    }
}
