//! Compaction for code mode's runs (agent-runtime-v1 §d7).
//!
//! Past its threshold a run's window compacts by itself: the engine seals the
//! steps behind the hot window and hands them to this backend off the step
//! loop, on a cheap seat, under the prompt package's compaction block. A
//! reply replaces those steps only after the engine's six-check gate. With no
//! seat or no compaction block, compaction is off and says why; an off seat
//! never calls a model. An agent whose profile names `self` writes its own
//! summaries (FIX 4465): the same cheap route, wearing its home, on its own
//! compaction model when its definition names one.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use oneiron::agent_dispatch::SpendScopeId;
use oneiron::code_run::CompactionHostBinding;
use oneiron::compaction::{
    CompactionBackend, CompactionBackendRegistry, CompactionDriver, CompactionGatePolicy,
    CompactionOff, CompactionRefusal, CompactionSuppression, EpochEmbedder,
};
use oneiron::embed::Embedder;
use oneiron::engine_executor::{CompactionSpawn, RunCompaction};
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::{ModelId, ModelLocality, ModelTierRef};
use oneiron::{BudgetGuard, CompactionOwnership, EdgeActorClass, MemoryProfile, Vault, WriteActor};

use super::CHAT_ROLE;
use super::status::{CompactionState, CompactionStatus, StatusCell};
use crate::admission::Admission;
use crate::config::models::{ModelsConfig, Rung, role_key};
use crate::embedder::EmbedderSlot;
use crate::mcp::McpQuickJsProvider;
use crate::models::ModelRuntime;
use crate::wire_telemetry::{LimitQuestions, LimitRow};

mod self_writer;
mod serve;

/// The registry key a run's memory profile names.
const BACKEND_KEY: &str = "code-mode-compaction";

/// The reasoning seats an agent's memory profile may name as its compaction
/// backend, each by its role's key (agent-runtime-v1 §d7: a cheap specialist,
/// the on-device track, or code mode's own seat).
const PROFILE_ROLES: [ModelRole; 3] = [
    ModelRole::Checker,
    ModelRole::LocalReasoner,
    ModelRole::GenerativeReasoner,
];

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
    vault: Arc<Vault>,
    registry: CompactionBackendRegistry,
    /// The backends `registry` serves, the default first: a run that spends
    /// under a scope compacts on copies of them metered on that scope.
    served: Vec<Arc<ServedCompactionBackend>>,
    /// The host's profile: a run whose agent carries none compacts by it.
    profile: MemoryProfile,
    policy: CompactionGatePolicy,
    hot_steps: u64,
    role: ModelRole,
    /// Passes running at once, across every run, queued by the credential
    /// whose run started them. A pass outlives the call that started it, so
    /// it holds a permit of its own, never the run's.
    passes: Arc<Admission<String>>,
    /// Where a pass waits for its turn: a task, never a thread of its own.
    runtime: tokio::runtime::Handle,
}

impl CodeModeCompaction {
    /// The registered cheap route already used by code mode, for an
    /// owner's explicit host compaction. An off route has no replacement.
    pub(super) fn host_backend(
        &self,
    ) -> Option<(Arc<dyn CompactionBackend>, CompactionGatePolicy)> {
        match self {
            Self::Off(_) => None,
            Self::Live(live) => live.served.first().map(|backend| {
                (
                    Arc::clone(backend) as Arc<dyn CompactionBackend>,
                    live.policy,
                )
            }),
        }
    }

    /// On when `[models.code_mode.compaction]` leaves it on, a seat serves
    /// its role and `prompt_package` holds the compaction block. Call from
    /// the runtime its passes will block on.
    pub(super) fn resolve(
        vault: &Arc<Vault>,
        runtime: &Arc<ModelRuntime>,
        models: &ModelsConfig,
        prompt_package: &std::path::Path,
        guard: BudgetGuard,
        questions: Arc<LimitQuestions>,
        wait: Duration,
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
                    kind = ?error.kind(),
                    prompt_package = %prompt_package.display(),
                    "code mode's prompt package holds no compaction prompt; runs keep their raw window"
                );
                return Self::Off(CompactionOff::NoPrompt);
            }
        };
        let prompt_tokens = oneiron::count_context_pack_tokens(&prompt) as u64;
        let allowances = input_allowances(models, runtime);
        let served = |key: String, role: ModelRole, seat: &crate::models::Seat| {
            Arc::new(ServedCompactionBackend {
                key,
                vault: Arc::clone(vault),
                models: Arc::clone(runtime),
                meter: CompactionMeter::CodeMode(guard.clone()),
                role,
                model: seat.model.clone(),
                locality: seat.locality,
                prompt: prompt.clone(),
                prompt_tokens,
                allowances: allowances.clone(),
                handle: tokio::runtime::Handle::current(),
            })
        };
        let mut registry = CompactionBackendRegistry::new();
        let default = served(BACKEND_KEY.to_owned(), role, seat);
        if let Err(error) = registry.register(Arc::clone(&default) as Arc<dyn CompactionBackend>) {
            tracing::error!(kind = ?error.kind(), "the compaction backend did not register");
            return Self::Off(CompactionOff::BackendFailed);
        }
        let mut backends = vec![default];
        // A profile may name another reasoning seat, by its role's key. A
        // window longer than that seat takes compacts in prefixes.
        for other in PROFILE_ROLES {
            let Some(seat) = runtime.seat(other) else {
                continue;
            };
            let backend = served(role_key(other), other, seat);
            match registry.register(Arc::clone(&backend) as Arc<dyn CompactionBackend>) {
                Ok(()) => backends.push(backend),
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    role = %role_key(other),
                    "a profile's compaction seat did not register"
                ),
            }
        }
        Self::Live(Arc::new(LiveCompaction {
            vault: Arc::clone(vault),
            registry,
            served: backends,
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
            // At most one pass per run is in flight, so as many as the runs
            // code mode works on at once.
            passes: Arc::new(Admission::new(
                LimitRow::CompactionPasses,
                questions,
                models.code_mode.max_runs,
                wait,
            )),
            runtime: tokio::runtime::Handle::current(),
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

    /// Hands `provider` a fresh seat per run and reports the state. A run in
    /// an off-record room embeds its summaries on `embedder`, the server's
    /// own, while it serves on this device (FIX 522).
    pub(super) fn attach(
        self,
        provider: McpQuickJsProvider,
        status: &StatusCell,
        embedder: Option<Arc<EmbedderSlot>>,
    ) -> McpQuickJsProvider {
        status.update(|status| status.compaction = self.status());
        let vectors = embedder.map(|slot| slot as Arc<dyn EpochEmbedder>);
        provider.with_compaction(Arc::new(
            move |host: CompactionHostBinding, credential: &str, spend: Option<&SpendScopeId>| {
                let seat = self.for_run(host, credential, spend);
                match &vectors {
                    Some(vectors) => seat.with_room_vectors(Arc::clone(vectors)),
                    None => seat,
                }
            },
        ))
    }

    /// A fresh seat for one run, its summaries bylined by the actor `host`
    /// authenticated, its passes queued in `credential`'s turn, on the memory
    /// profile of the agent that actor names. A run that spends under
    /// `spend` compacts on that scope's meter (OF-533); any other on code
    /// mode's. An agent whose profile names `self` compacts as itself
    /// (FIX 4465), wherever its run is served.
    pub(super) fn for_run(
        &self,
        host: CompactionHostBinding,
        credential: &str,
        spend: Option<&SpendScopeId>,
    ) -> RunCompaction {
        let live = match self {
            Self::Off(why) => return RunCompaction::off(*why),
            Self::Live(live) => live,
        };
        let byline = host.actor();
        let (profile, definition) = live.run_profile(byline);
        // Docs Q13: the agent's own hot window, when its profile names one.
        let hot_steps = profile.hot_steps.unwrap_or(live.hot_steps);
        let scoped;
        let registry = match (definition, spend) {
            (Some(definition), _) => match live.self_registry(&profile, definition, host, spend) {
                Ok(registry) => {
                    scoped = registry;
                    &scoped
                }
                Err(error) => {
                    tracing::error!(kind = ?error.kind(), "a run's own compaction writer did not register");
                    return RunCompaction::off(CompactionOff::BackendFailed);
                }
            },
            (None, None) => &live.registry,
            (None, Some(scope)) => match live.scoped_registry(scope) {
                Ok(registry) => {
                    scoped = registry;
                    &scoped
                }
                Err(error) => {
                    tracing::error!(kind = ?error.kind(), "a run's scoped compaction backends did not register");
                    return RunCompaction::off(CompactionOff::BackendFailed);
                }
            },
        };
        match CompactionDriver::for_profile(&profile, registry) {
            Ok(Some(driver)) => RunCompaction::live(
                driver,
                live.policy,
                byline,
                hot_steps,
                Arc::new(ThreadSpawn {
                    passes: Arc::clone(&live.passes),
                    credential: credential.to_owned(),
                    runtime: live.runtime.clone(),
                }),
            ),
            Ok(None) => RunCompaction::off(CompactionOff::HarnessCompacts),
            Err(error) => {
                tracing::error!(kind = ?error.kind(), "a run's compaction driver did not build");
                RunCompaction::off(CompactionOff::BackendFailed)
            }
        }
    }
}

impl LiveCompaction {
    /// The registry a run that spends under `scope` compacts on: each served
    /// backend, its calls metered on `scope` in place of code mode's.
    fn scoped_registry(&self, scope: &SpendScopeId) -> oneiron::Result<CompactionBackendRegistry> {
        let mut registry = CompactionBackendRegistry::new();
        for backend in &self.served {
            registry.register(Arc::new(ServedCompactionBackend {
                meter: CompactionMeter::Scope(scope.clone()),
                ..ServedCompactionBackend::clone(backend)
            }))?;
        }
        Ok(registry)
    }

    /// The registry a run whose agent writes its own compaction compacts on
    /// (FIX 4465): one writer, bound to the run's authenticated actor, on
    /// the house compaction seat's route, metered as the run's other passes
    /// are. It wears the agent's home and, when its definition names one,
    /// its own compaction model.
    fn self_registry(
        &self,
        profile: &MemoryProfile,
        definition: oneiron::agent_def::AgentDefinition,
        host: CompactionHostBinding,
        spend: Option<&SpendScopeId>,
    ) -> oneiron::Result<CompactionBackendRegistry> {
        let house = self
            .served
            .first()
            .ok_or(oneiron::Error::InvariantViolation(
                "code mode's compaction serves no house seat",
            ))?;
        let route = ServedCompactionBackend {
            meter: spend.map_or_else(
                || house.meter.clone(),
                |scope| CompactionMeter::Scope(scope.clone()),
            ),
            ..ServedCompactionBackend::clone(house)
        };
        let mut registry = CompactionBackendRegistry::new();
        registry.register(Arc::new(self_writer::SelfCompactionBackend::new(
            profile.compaction_backend.as_str().to_owned(),
            route,
            definition,
            host,
        )))?;
        Ok(registry)
    }

    /// The run's memory profile (agent-runtime-v1 §d7): the profile on the
    /// agent definition its byline names, when it is one and carries one,
    /// else the host's. The profile's window, owner and summary split apply;
    /// a backend this host does not serve falls back to the host's own seat,
    /// so the run still compacts. A profile naming `self` (FIX 4465) is
    /// recognized first and never falls back: its definition comes back with
    /// it, for the run's own writer.
    fn run_profile(
        &self,
        byline: WriteActor,
    ) -> (MemoryProfile, Option<oneiron::agent_def::AgentDefinition>) {
        if byline.actor_class() != EdgeActorClass::Agent {
            return (self.profile.clone(), None);
        }
        // An agent actor that is not a definition (a person-backed agent, a
        // connector) has no profile.
        let Some(definition) = self
            .vault
            .get_agent_definition(&byline.entity_ref())
            .ok()
            .flatten()
        else {
            return (self.profile.clone(), None);
        };
        let Some(mut profile) = definition.memory_profile.clone() else {
            return (self.profile.clone(), None);
        };
        if profile.compaction == CompactionOwnership::Engine && profile.writes_as_self() {
            return (profile, Some(definition));
        }
        if profile.compaction == CompactionOwnership::Engine
            && self.registry.resolve(&profile).is_err()
        {
            tracing::warn!(
                backend = %profile.compaction_backend.as_str(),
                "an agent's memory profile names a compaction backend this host does not serve; its run compacts on the host's seat"
            );
            profile.compaction_backend = self.profile.compaction_backend.clone();
        }
        (profile, None)
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

/// Each pass runs on its own thread; the run never waits for it. A pass
/// takes its place in line when it is spawned and waits its credential's
/// turn past the bound (round-robin across credentials, so one credential's
/// backlog never holds another's pass back) as a task on the runtime: its
/// thread starts only with the permit, which it holds until the pass ends,
/// whether or not the run that started it is still there. So the bound is on
/// threads too, not only on passes running.
struct ThreadSpawn {
    passes: Arc<Admission<String>>,
    credential: String,
    runtime: tokio::runtime::Handle,
}

/// The server's embedder, for a room's epoch summaries: only once the vault
/// has admitted it, the same provider its embedding worker fills `pe:` rows
/// with.
impl EpochEmbedder for EmbedderSlot {
    fn serving(&self) -> Option<Arc<dyn Embedder>> {
        self.admitted_provider()
            .map(|embedder| embedder as Arc<dyn Embedder>)
    }
}

impl CompactionSpawn for ThreadSpawn {
    fn spawn(&self, pass: Box<dyn FnOnce() + Send + 'static>) {
        let turn = self.passes.admit_in_line(self.credential.clone());
        self.runtime.spawn(async move {
            let Ok(permit) = turn.await else {
                // The pass's sender drops with it, so the run reads a pass
                // that never ran.
                tracing::debug!(
                    reason = "compaction_waited_out",
                    "a compaction pass waited past its deadline for its turn"
                );
                return;
            };
            if let Err(error) = std::thread::Builder::new()
                .name("code-mode-compaction".to_owned())
                .spawn(move || {
                    let _permit = permit;
                    pass();
                })
            {
                // The pass's sender drops with it, so the run reads a pass
                // that never ran.
                tracing::error!(kind = ?error.kind(), "a compaction pass thread did not start");
            }
        });
    }
}

/// What a pass's model calls spend on.
#[derive(Clone)]
enum CompactionMeter {
    /// Code mode's own budget, for a run that spends under no scope.
    CodeMode(BudgetGuard),
    /// A run's spend scope: each call takes a fresh guard on the scope and
    /// books what it used once it returns, paid or failed, so a pass that
    /// outlives its run still books.
    Scope(SpendScopeId),
}

/// A pass's model call: admitted on the configured role against the vault's
/// live model policy, then sent as a run on its meter's budget: each provider
/// call takes its own permit, goes through the run's gate and settles itself
/// (its usage, or its reservation when it reports none or fails after it went
/// out).
#[derive(Clone)]
struct ServedCompactionBackend {
    /// The registry key a profile names this seat by.
    key: String,
    vault: Arc<Vault>,
    models: Arc<ModelRuntime>,
    meter: CompactionMeter,
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

#[cfg(test)]
pub(crate) mod tests;
