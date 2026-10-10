//! Compaction for code mode's runs (agent-runtime-v1 §d7).
//!
//! Past its threshold a run's window compacts by itself: the engine seals the
//! steps behind the hot window and hands them to this backend off the step
//! loop, on a cheap seat, under the prompt package's compaction block. A
//! reply replaces those steps only after the engine's six-check gate. With no
//! seat or no compaction block, compaction is off and says why; an off seat
//! never calls a model.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use oneiron::compaction::{
    CompactionBackend, CompactionBackendRegistry, CompactionCheck, CompactionDriver,
    CompactionGatePolicy, CompactionOff, CompactionProduct, CompactionRefusal, CompactionRequest,
    CompactionSuppression, CompactionTierClass, compaction_reply_schema, compaction_request_input,
};
use oneiron::engine_executor::{
    CompactionSpawn, ENGINE_EXECUTOR_COMPACTION_PURPOSE_NAME, RunCompaction,
};
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, FatalLlmError, LlmError, LlmMessage,
    LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};
use oneiron::{BudgetGuard, CompactionOwnership, MemoryProfile, Vault, WriteActor};

use super::CHAT_ROLE;
use super::status::{CompactionState, CompactionStatus, StatusCell};
use crate::config::models::{ModelsConfig, role_key};
use crate::mcp::McpQuickJsProvider;
use crate::models::{ModelRuntime, RoleRefusal, settle_answered};

/// The registry key a run's memory profile names.
const BACKEND_KEY: &str = "code-mode-compaction";

/// What one provider call costs on the meter when it reports no usage.
const CALL_FLOOR_UNITS: u64 = oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS;

/// Output room for the reply's JSON frame around a summary the provider's
/// tokenizer may count up to twice as long as the engine's.
const REPLY_FRAME_TOKENS: u64 = 64;

/// Code mode's compaction, settled once when code mode is bound.
pub(super) enum CodeModeCompaction {
    Off(CompactionOff),
    Live(Arc<LiveCompaction>),
}

pub(super) struct LiveCompaction {
    registry: CompactionBackendRegistry,
    profile: MemoryProfile,
    policy: CompactionGatePolicy,
    hot_steps: u64,
    role: ModelRole,
}

impl CodeModeCompaction {
    /// On when `[models.code_mode.compaction]` leaves it on, a seat serves
    /// its role and `prompt_package` holds the compaction block. Call from
    /// the runtime its passes will block on.
    pub(super) fn resolve(
        vault: &Arc<Vault>,
        runtime: &Arc<ModelRuntime>,
        models: &ModelsConfig,
        prompt_package: &std::path::Path,
        guard: BudgetGuard,
    ) -> Self {
        let settings = models.code_mode.compaction;
        if !settings.enabled {
            return Self::Off(CompactionOff::Disabled);
        }
        let role = settings
            .role
            .unwrap_or(if runtime.seat(ModelRole::Checker).is_some() {
                ModelRole::Checker
            } else {
                CHAT_ROLE
            });
        let Some(seat) = runtime.seat(role) else {
            return Self::Off(CompactionOff::NoSeat);
        };
        let prompt = match oneiron::prompt::resolve_engine_executor_compaction_prompt(
            prompt_package,
        ) {
            Ok(prompt) => prompt.text,
            Err(error) => {
                tracing::warn!(
                    %error,
                    prompt_package = %prompt_package.display(),
                    "code mode's prompt package holds no compaction prompt; runs keep their raw window"
                );
                return Self::Off(CompactionOff::NoPrompt);
            }
        };
        let Some(window_tokens) = settings
            .window_tokens
            .or_else(|| code_mode_input_tokens(models))
        else {
            return Self::Off(CompactionOff::NoSeat);
        };
        let backend = Arc::new(ServedCompactionBackend {
            vault: Arc::clone(vault),
            models: Arc::clone(runtime),
            guard,
            role,
            model: seat.model.clone(),
            locality: seat.locality,
            prompt,
            handle: tokio::runtime::Handle::current(),
        });
        let mut registry = CompactionBackendRegistry::new();
        if let Err(error) = registry.register(backend) {
            tracing::error!(%error, "the compaction backend did not register");
            return Self::Off(CompactionOff::BackendFailed);
        }
        Self::Live(Arc::new(LiveCompaction {
            registry,
            profile: MemoryProfile::new(
                window_tokens,
                ModelTierRef(BACKEND_KEY.to_owned()),
                CompactionOwnership::Engine,
            ),
            policy: CompactionGatePolicy {
                tries: settings.tries,
                ..CompactionGatePolicy::default()
            },
            hot_steps: settings.hot_steps,
            role,
        }))
    }

    pub(super) fn status(&self) -> CompactionStatus {
        match self {
            Self::Off(why) => CompactionStatus::off(why.as_str()),
            Self::Live(live) => CompactionStatus {
                state: CompactionState::On,
                reason: None,
                role: Some(role_key(live.role)),
                window_tokens: Some(live.profile.window_token_budget),
            },
        }
    }

    /// Hands `provider` a fresh seat per run and reports the state.
    pub(super) fn attach(
        self,
        provider: McpQuickJsProvider,
        status: &StatusCell,
    ) -> McpQuickJsProvider {
        status.update(|status| status.compaction = self.status());
        provider.with_compaction(Arc::new(move |byline| self.for_run(byline)))
    }

    /// A fresh seat for one run, its summaries bylined `byline`.
    pub(super) fn for_run(&self, byline: WriteActor) -> RunCompaction {
        let live = match self {
            Self::Off(why) => return RunCompaction::off(*why),
            Self::Live(live) => live,
        };
        match CompactionDriver::for_profile(&live.profile, &live.registry) {
            Ok(Some(driver)) => RunCompaction::live(
                driver,
                live.policy,
                byline,
                live.hot_steps,
                Arc::new(ThreadSpawn),
            ),
            Ok(None) => RunCompaction::off(CompactionOff::Disabled),
            Err(error) => {
                tracing::error!(%error, "a run's compaction driver did not build");
                RunCompaction::off(CompactionOff::BackendFailed)
            }
        }
    }
}

/// The input a code-mode call may fill on its smallest rung: its context
/// less the output its provider reserves.
fn code_mode_input_tokens(models: &ModelsConfig) -> Option<u64> {
    models
        .roles
        .get(&CHAT_ROLE)?
        .iter()
        .filter_map(|rung| {
            let provider = models.providers.get(&rung.model.provider)?;
            let output = provider
                .max_output_tokens
                .filter(|output| *output < provider.context_tokens)
                .unwrap_or(0);
            Some(provider.context_tokens - output)
        })
        .min()
}

/// Each pass runs on its own thread; the run never waits for it.
struct ThreadSpawn;

impl CompactionSpawn for ThreadSpawn {
    fn spawn(&self, pass: Box<dyn FnOnce() + Send + 'static>) {
        if let Err(error) = std::thread::Builder::new()
            .name("code-mode-compaction".to_owned())
            .spawn(pass)
        {
            // The pass's sender drops with it, so the run reads a refused pass.
            tracing::error!(%error, "a compaction pass thread did not start");
        }
    }
}

/// A pass's model call: admitted on the configured role against the vault's
/// live model policy, metered on code mode's budget.
struct ServedCompactionBackend {
    vault: Arc<Vault>,
    models: Arc<ModelRuntime>,
    guard: BudgetGuard,
    role: ModelRole,
    /// The role's seat at bind; its admission names the call's model and
    /// route.
    model: ModelId,
    locality: ModelLocality,
    prompt: String,
    handle: tokio::runtime::Handle,
}

impl ServedCompactionBackend {
    fn llm_request(
        &self,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> LlmRequest {
        let purpose = CallPurpose::Other {
            name: ENGINE_EXECUTOR_COMPACTION_PURPOSE_NAME.to_owned(),
        };
        let tier = ModelTierRef(BACKEND_KEY.to_owned());
        LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: oneiron::llm::Scope::default(),
                tier: TierPrecedence::for_purpose(&purpose, tier),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Json {
                    schema: compaction_reply_schema(),
                },
                locality: self.locality,
            },
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: self.prompt.clone(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text {
                        text: compaction_request_input(request, retry).to_string(),
                    }],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::from([(
                "max_output_tokens".to_owned(),
                serde_json::json!(
                    request
                        .summary_token_budget
                        .saturating_mul(2)
                        .saturating_add(REPLY_FRAME_TOKENS)
                ),
            )]),
            provider_options: BTreeMap::new(),
        }
    }
}

impl CompactionBackend for ServedCompactionBackend {
    fn backend_key(&self) -> &str {
        BACKEND_KEY
    }

    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }

    fn compact(
        &self,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> Result<CompactionProduct, CompactionRefusal> {
        let started = Instant::now();
        let call = self
            .models
            .admit_role(&self.vault, self.role, self.llm_request(request, retry))
            .map_err(|refusal| {
                let suppression = match refusal {
                    RoleRefusal::NoSeat => CompactionSuppression::Sticky {
                        why: CompactionOff::NoSeat,
                    },
                    _ => CompactionSuppression::TurnScoped { check: None },
                };
                refused(suppression, refusal.to_string())
            })?;
        let lease = self
            .guard
            .admit_for_request(&call.request)
            .map_err(|denied| refused(CompactionSuppression::NoCredit, denied.to_string()))?
            .lease;
        // A call that failed made every attempt its backend makes.
        let every_attempt = (call.attempts as u64).saturating_mul(CALL_FLOOR_UNITS);
        let reply = self
            .handle
            .block_on(call.backend.generate(call.request, &lease));
        match reply {
            Ok(response) => {
                settle_answered(&self.guard, &lease, &response.usage, CALL_FLOOR_UNITS).map_err(
                    |denied| refused(CompactionSuppression::NoCredit, denied.to_string()),
                )?;
                let summary_text = response
                    .message
                    .content
                    .iter()
                    .filter_map(|part| match part {
                        ContentPart::Text { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                Ok(CompactionProduct {
                    summary_text,
                    finish: response.finish_reason,
                    latency: started.elapsed(),
                })
            }
            Err(error) => {
                if let Err(denied) = self.guard.settle_usage(&lease, every_attempt) {
                    tracing::error!(%denied, "a failed compaction call's settlement was refused");
                }
                let suppression = match &error {
                    LlmError::Fatal(FatalLlmError::Auth) => CompactionSuppression::Auth,
                    LlmError::BudgetDenied(_) => CompactionSuppression::NoCredit,
                    _ => CompactionSuppression::TurnScoped { check: None },
                };
                Err(refused(suppression, error.to_string()))
            }
        }
    }
}

fn refused(suppression: CompactionSuppression, detail: String) -> CompactionRefusal {
    CompactionRefusal {
        suppression,
        detail,
    }
}
