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
    CallClass, CallEnvelope, CallPurpose, ContentPart, FatalLlmError, LlmCapability, LlmError,
    LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};
use oneiron::{BudgetGuard, CompactionOwnership, MemoryProfile, Vault, WriteActor};

use super::CHAT_ROLE;
use super::status::{CompactionState, CompactionStatus, StatusCell};
use crate::config::models::{ModelsConfig, Rung, role_key};
use crate::mcp::McpQuickJsProvider;
use crate::models::{ModelRuntime, RoleRefusal};

/// The registry key a run's memory profile names.
const BACKEND_KEY: &str = "code-mode-compaction";

/// The run each pass's model call is admitted under, one run per call so the
/// server keeps no per-pass state.
const COMPACTION_RUN: &str = "code-mode-compaction";

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
        let Some(window_tokens) = settings
            .window_tokens
            .or_else(|| input_tokens(models, CHAT_ROLE))
        else {
            return Self::Off(CompactionOff::NoSeat);
        };
        // A sealed window is at most the run's window: the seat must take it
        // whole on its smallest rung.
        let fits = |role| input_tokens(models, role).is_some_and(|room| room >= window_tokens);
        let role = settings.role.unwrap_or(
            if runtime.seat(ModelRole::Checker).is_some() && fits(ModelRole::Checker) {
                ModelRole::Checker
            } else {
                CHAT_ROLE
            },
        );
        let Some(seat) = runtime.seat(role) else {
            return Self::Off(CompactionOff::NoSeat);
        };
        if !fits(role) {
            tracing::warn!(
                role = %role_key(role),
                window_tokens,
                "the compaction seat leaves less input room than a run's window; runs keep their raw window"
            );
            return Self::Off(CompactionOff::SeatTooSmall);
        }
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
        let backend = Arc::new(ServedCompactionBackend {
            vault: Arc::clone(vault),
            models: Arc::clone(runtime),
            guard,
            role,
            model: seat.model.clone(),
            locality: seat.locality,
            prompt_tokens: oneiron::count_context_pack_tokens(&prompt) as u64,
            prompt,
            allowances: input_allowances(models, runtime),
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

/// The prompt a rung prepends to every call it serves.
fn rung_prompt_tokens(rung: &Rung) -> u64 {
    rung.prompt.as_deref().map_or(0, |prompt| {
        oneiron::count_context_pack_tokens(prompt) as u64
    })
}

/// The input a call on `role` may fill on its smallest rung: its context
/// less the output its provider reserves and the prompt the rung prepends.
fn input_tokens(models: &ModelsConfig, role: ModelRole) -> Option<u64> {
    models
        .roles
        .get(&role)?
        .iter()
        .filter_map(|rung| {
            let provider = models.providers.get(&rung.model.provider)?;
            let output = provider
                .max_output_tokens
                .filter(|output| *output < provider.context_tokens)
                .unwrap_or(0);
            Some((provider.context_tokens - output).saturating_sub(rung_prompt_tokens(rung)))
        })
        .min()
}

/// What one call may fill with input and output on each model id a route
/// can name: a rung's model, its provider's context less the prompt the
/// rung prepends (the smallest where several rungs serve it); a seat, its
/// ladder's smallest.
fn input_allowances(models: &ModelsConfig, runtime: &ModelRuntime) -> BTreeMap<ModelId, u64> {
    let mut allowances = BTreeMap::new();
    for (role, rungs) in &models.roles {
        let mut ladder: Option<u64> = None;
        for rung in rungs {
            let Some(provider) = models.providers.get(&rung.model.provider) else {
                continue;
            };
            let Ok(model) = rung.model.engine_id(&provider.revision) else {
                continue;
            };
            let room = provider
                .context_tokens
                .saturating_sub(rung_prompt_tokens(rung));
            allowances
                .entry(model)
                .and_modify(|held: &mut u64| *held = (*held).min(room))
                .or_insert(room);
            ladder = Some(ladder.map_or(room, |held| held.min(room)));
        }
        if let (Some(seat), Some(room)) = (runtime.seat(*role), ladder) {
            allowances.insert(seat.model.clone(), room);
        }
    }
    allowances
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
/// live model policy, then sent as a run on code mode's budget: each provider
/// call takes its own permit, goes through the run's gate and settles itself
/// (its usage, or its reservation when it reports none or fails after it went
/// out).
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
    prompt_tokens: u64,
    /// See [`input_allowances`]. A model id not here is trusted with no
    /// window.
    allowances: BTreeMap<ModelId, u64>,
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
                serde_json::json!(output_tokens(request.summary_token_budget)),
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

    /// Read on the vault's live route, as a pass is admitted: what its
    /// context holds beside the reply and the prompt, as [`Self::compact`]
    /// counts it.
    fn input_token_limit(&self, summary_token_budget: u64) -> Option<u64> {
        let context = self
            .models
            .seat(self.role)
            .and_then(|seat| self.models.route_role(&self.vault, self.role, seat).ok())
            .and_then(|route| self.allowances.get(&route.model).copied())
            .unwrap_or(0);
        Some(
            context
                .saturating_sub(output_tokens(summary_token_budget))
                .saturating_sub(self.prompt_tokens),
        )
    }

    fn compact(
        &self,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> Result<CompactionProduct, CompactionRefusal> {
        let started = Instant::now();
        let mut call = self
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
        // The admitted model, not the configured ladder, must hold the call.
        let Some(&context) = self.allowances.get(&call.request.model) else {
            return Err(refused(
                CompactionSuppression::TurnScoped { check: None },
                format!("no context is known for {}", call.request.model),
            ));
        };
        let input = call
            .request
            .messages
            .iter()
            .flat_map(|message| &message.content)
            .map(|part| match part {
                ContentPart::Text { text } => oneiron::count_context_pack_tokens(text) as u64,
                _ => 0,
            })
            .sum::<u64>();
        if input.saturating_add(output_tokens(request.summary_token_budget)) > context {
            return Err(refused(
                CompactionSuppression::TurnScoped { check: None },
                format!(
                    "a {input}-token window and its reply exceed {}'s {context}-token context",
                    call.request.model
                ),
            ));
        }
        // A route that cannot hold a reply to a schema (an Anthropic-style
        // one) is asked in plain text: the prompt asks for the same JSON, and
        // the gate's schema check refuses anything else.
        if !call
            .ladder
            .supports(&call.request.model, &LlmCapability::JsonResponse)
        {
            call.request.envelope.response_format = ResponseFormat::Text;
        }
        let run = self
            .models
            .undeclared_run(COMPACTION_RUN, self.guard.clone());
        let reply = self
            .handle
            .block_on(call.ladder.generate(&run, call.request, None));
        match reply {
            Ok(response) => {
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

/// The output a pass reserves: a summary the provider's tokenizer may count
/// up to twice as long as the engine's, and its reply frame.
const fn output_tokens(summary_token_budget: u64) -> u64 {
    summary_token_budget
        .saturating_mul(2)
        .saturating_add(REPLY_FRAME_TOKENS)
}

fn refused(suppression: CompactionSuppression, detail: String) -> CompactionRefusal {
    CompactionRefusal {
        suppression,
        detail,
    }
}
