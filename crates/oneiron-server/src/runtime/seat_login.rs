//! Host surface for official subscription seats (OF-375).
//!
//! The engine owns the seat contract (`oneiron::dispatch_byoa::official_seats`);
//! this module is the host half: owner settings in, a sign-in surface out, a
//! local executor for the official signed-in CLIs, and the Dreamer executor
//! that dispatches admitted work onto a seat. No type here can hold a vendor
//! token either: settings carry labels and custody handles, the surface
//! carries an argv or a browser URL the PERSON runs, and the control plane
//! holds nothing.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use oneiron::checkout::{CheckoutId, CheckoutLeaseAct};
use oneiron::code_sandbox::SandboxBoundaryContract;
use oneiron::code_sandbox::SandboxCredentialHandle;
use oneiron::code_sandbox::microvm::ExecutionBudget;
use oneiron::dispatch_byoa::{
    ByoEndpointBackendFactory, ByoaCliExecutor, ByoaConnectorSpec, ByoaDispatcher, ByoaEgressLease,
    ByoaEgressPort, ByoaError, ByoaExhaust, ByoaResult, ByoaStream, CaptureByoaExhaust,
    ClaudeCodeRunner, CliSandboxSpec, CodexRunner, DispatchOfficialSeat, DreamerProviderAdapter,
    OfficialDreamerSeat, OfficialSeatAdapter, OfficialSeatDispatchOutcome, OfficialSeatRegistry,
    OfficialSeatRoute, OfficialSeatSpec, OnSeatSpent, OpenCodeRunner, ProviderAdapterRegistry,
    RunnerSeat, RunnerSeatPolicy, SeatAuth, SeatIdentity, SeatPlacementApproval, SeatRoute,
    SeatSpent, check_seat_placement, hosted_seat_bound, register_official_dreamer_providers,
    skipped_seats_note,
};
use oneiron::origin::smart_http::SpillFloor;
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor, DreamerParkCause,
    HostingPrivacyPosture, WakeAttemptContext,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::secret_destinations::RunSecretDestinations;

mod runner_work;
mod surface;
pub use surface::{
    SeatLoginSurface, SeatRouteRow, SeatSettings, seat_login_surface, seat_route_catalog,
    siwc_authorize_request,
};

/// Env names that would hand the official CLI a credential from OUR process
/// instead of the login the person made in the CLI's own store. The seat
/// runs on the person's sign-in, so these never cross into the child.
const SEAT_ENV_REMOVED: [&str; 5] = [
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
];

/// Runs an official signed-in CLI (`claude`, `codex`, `opencode`) as a
/// local argv-only process in a checkout directory the host resolved.
///
/// This is the own-runtime executor: the person's machine, the person's
/// network, the person's login inside the unmodified binary. It enforces the
/// wall-clock budget and captures its output whole, but it is NOT a sandbox: guest
/// network reaches are not routed through `authorize`, because a local
/// process cannot be mediated that way. A hosted deployment must run the
/// seat behind the microVM executor instead; placement rules keep only the
/// logins a provider's terms bar off hosted nodes, and this executor must not
/// be the one serving a hosted login.
#[derive(Clone)]
pub struct OfficialCliSeatExecutor {
    /// Directory the host resolved the live checkout into.
    pub workdir: PathBuf,
    /// The T1 secret destinations the host registered for the run this
    /// executor starts processes for (DOOR-124): each filled one is set in
    /// the process's environment, and the variables the seat removes stay
    /// removed. `None` for a run with none.
    pub secret_destinations: Option<RunSecretDestinations>,
    /// The free disk the host keeps under the output this executor spools
    /// past memory (the server's `DiskFloor`): a write that would go below it
    /// stops the run with [`ByoaError::SpoolAtDiskFloor`]. `None` keeps none.
    pub floor: Option<Arc<dyn SpillFloor>>,
    /// Raised by the host when the run's claim is lost under it (FIX 9320):
    /// the run's process is to stop. `None` watches nothing.
    pub stop: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl std::fmt::Debug for OfficialCliSeatExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfficialCliSeatExecutor")
            .field("workdir", &self.workdir)
            .field("secret_destinations", &self.secret_destinations)
            .field("floor", &self.floor.is_some())
            .finish()
    }
}

/// Drains every byte `reader` yields into a spooled stream on its own thread.
/// The disk floor and the run's deadline are its only stops; a read failure
/// is an error, never an early end of the stream.
fn drain_spooled(
    mut reader: impl Read + Send + 'static,
    floor: Option<Arc<dyn SpillFloor>>,
    deadline: Instant,
) -> mpsc::Receiver<ByoaResult<ByoaStream>> {
    let (done, drain) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut stream = ByoaStream::writer(floor, Some(deadline));
        let mut chunk = [0_u8; 8192];
        let spooled = loop {
            match reader.read(&mut chunk) {
                Ok(0) => break stream.finish(),
                Ok(read) => {
                    if let Err(error) = stream.append(&chunk[..read]) {
                        break Err(error);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    break Err(ByoaError::Backend(
                        "official seat output read failed".to_owned(),
                    ));
                }
            }
        };
        let _ = done.send(spooled);
    });
    drain
}

/// A drain's stream, waited for no later than the run's deadline.
fn drained(
    drain: &mpsc::Receiver<ByoaResult<ByoaStream>>,
    deadline: Instant,
) -> ByoaResult<ByoaStream> {
    drain
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .unwrap_or_else(|error| {
            Err(match error {
                mpsc::RecvTimeoutError::Timeout => ByoaError::SpoolDeadline,
                mpsc::RecvTimeoutError::Disconnected => {
                    ByoaError::Backend("official seat output drain stopped".to_owned())
                }
            })
        })
}

impl ByoaCliExecutor for OfficialCliSeatExecutor {
    fn run(
        &mut self,
        spec: &CliSandboxSpec,
        checkout: &CheckoutLeaseAct,
        _boundary: SandboxBoundaryContract,
        budget: ExecutionBudget,
        _authorize: &mut dyn FnMut(&str, u64) -> ByoaResult<ByoaEgressLease>,
    ) -> ByoaResult<ByoaExhaust> {
        if checkout.checkout_id != spec.checkout_id {
            return Err(ByoaError::Backend(
                "official seat checkout does not match the connector".to_owned(),
            ));
        }
        if !matches!(spec.program.as_str(), "claude" | "codex" | "opencode") {
            return Err(ByoaError::Backend(
                "official seat executor runs only the official claude/codex/opencode binaries"
                    .to_owned(),
            ));
        }
        if !spec.credential_handles.is_empty() {
            // A login seat's credential stays inside the official CLI. A
            // connector asking this executor to inject custody material is
            // refused rather than silently half-served.
            return Err(ByoaError::Backend(
                "official seat executor does not inject credential handles".to_owned(),
            ));
        }
        let mut command = Command::new(&spec.program);
        command
            .args(&spec.argv)
            .current_dir(&self.workdir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(destinations) = &self.secret_destinations {
            destinations.apply_env(&mut command);
        }
        for name in SEAT_ENV_REMOVED {
            command.env_remove(name);
        }
        let mut child = command
            .spawn()
            .map_err(|_| ByoaError::Backend("official seat spawn failed".to_owned()))?;
        // One deadline bounds the run, its drains and the wait for them.
        let deadline = Instant::now() + Duration::from_secs(budget.wall_clock_secs.max(1));
        let stdout = child
            .stdout
            .take()
            .map(|pipe| drain_spooled(pipe, self.floor.clone(), deadline))
            .ok_or_else(|| ByoaError::Backend("official seat stdout unavailable".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .map(|pipe| drain_spooled(pipe, self.floor.clone(), deadline))
            .ok_or_else(|| ByoaError::Backend("official seat stderr unavailable".to_owned()))?;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                // The host's claim on the run ended under it (FIX 9320): its
                // process stops, and nothing it would still print is kept.
                Ok(None)
                    if self
                        .stop
                        .as_ref()
                        .is_some_and(|stop| stop.load(std::sync::atomic::Ordering::SeqCst)) =>
                {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ByoaError::Backend(
                        "official seat stopped: its claim ended".to_owned(),
                    ));
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ByoaError::SpoolDeadline);
                }
                Err(_) => {
                    return Err(ByoaError::Backend("official seat wait failed".to_owned()));
                }
            }
        };
        let mut exhaust = ByoaExhaust {
            stdout: drained(&stdout, deadline)?,
            stderr: drained(&stderr, deadline)?,
            ..ByoaExhaust::default()
        };
        if !status.success() && exhaust.stderr.is_empty() {
            exhaust.stderr = format!("official seat exited with {status}")
                .into_bytes()
                .into();
        }
        Ok(exhaust)
    }
}

fn attempt_hex(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The Dreamer executor for an official seat: admitted work is dispatched
/// onto the seat, and the seat's answer becomes the Dreamer outcome.
///
/// A dispatched seat attempt parks the Dreamer attempt until the foreign
/// exhaust is captured through the BYOA terminal door; a dry seat parks
/// naming its reset, or falls through to `inner` (the internal role ladder)
/// when the owner pre-chose local/overdraft routing. The factory and egress
/// port are cloned per dispatch, so they should be cheap handles (the usual
/// `Arc`-backed host wiring).
pub struct OfficialSeatDreamerExecutor<B, E, I> {
    pub endpoint_factory: B,
    pub egress: E,
    pub seat: OfficialSeatSpec,
    /// Connector the host built for this seat (see `OfficialSeatRegistry`).
    pub connector: ByoaConnectorSpec,
    pub inner: I,
}

impl<B, E, I> DreamerAttemptExecutor for OfficialSeatDreamerExecutor<B, E, I>
where
    B: ByoEndpointBackendFactory + Clone,
    E: ByoaEgressPort + Clone,
    I: DreamerAttemptExecutor,
{
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let parent = attempt.status.attempt.id.clone();
        let dispatched = {
            let mut dispatcher = ByoaDispatcher::new(
                ctx.vault,
                self.endpoint_factory.clone(),
                self.egress.clone(),
            );
            dispatcher.dispatch_official_seat(DispatchOfficialSeat {
                seat: self.seat.clone(),
                connector: self.connector.clone(),
                task_ref: None,
                parent_attempt_id: Some(parent),
                run_id: None,
                dedupe_key: Some(format!(
                    "byoa.seat.dreamer:{}",
                    attempt_hex(parent.as_bytes())
                )),
                now: ctx.now_ms / 1000,
            })
        };
        match dispatched {
            Ok(OfficialSeatDispatchOutcome::Dispatched(outcome)) => {
                Ok(DreamerAttemptExecution::Park {
                    reason: format!(
                        "official seat attempt {} dispatched; awaiting foreign exhaust",
                        attempt_hex(outcome.status().attempt.id.as_bytes())
                    ),
                    cause: DreamerParkCause::Signal,
                })
            }
            Ok(OfficialSeatDispatchOutcome::Parked { resets_at }) => {
                Ok(DreamerAttemptExecution::Park {
                    reason: format!("official seat dry; plan window resets at {resets_at}"),
                    cause: DreamerParkCause::Signal,
                })
            }
            Ok(OfficialSeatDispatchOutcome::DryFallback(_)) => {
                self.inner.execute(attempt, ctx).await
            }
            Err(ByoaError::Store(error)) => Err(error),
            Err(other) => Ok(DreamerAttemptExecution::Park {
                reason: format!("official seat refused: {other}"),
                cause: DreamerParkCause::Other,
            }),
        }
    }
}

/// The owner's settings for one runner seat (OF-137's [`RunnerSeat`]).
/// Labels and custody handle names only, like every surface here: a
/// vendor-login seat names no handle at all, because the login stays with
/// the official CLI on its runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RunnerSeatSettings {
    /// Registered runner name ("claude-code", "codex", "opencode").
    pub runner: String,
    /// `vendor_login` (default) or `api_key`.
    #[serde(default = "default_seat_auth")]
    pub auth: String,
    pub egress_profile_ref: String,
    /// Custody handle names for an API-key seat. Empty for a login seat.
    #[serde(default)]
    pub credential_handles: Vec<String>,
}

fn default_seat_auth() -> String {
    "vendor_login".to_owned()
}

/// One official seat the owner holds, registered as a named Dreamer
/// provider under its adapter's name (OF-137): the seat settings, plus the
/// endpoint bindings a CLI seat ignores. Labels and custody handles only,
/// like [`SeatSettings`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OfficialRunnerSeatSettings {
    #[serde(flatten)]
    pub seat: SeatSettings,
    /// Slug-to-model bindings for endpoint-shaped seats (Agent SDK, Sign
    /// in with ChatGPT, API keys).
    #[serde(default)]
    pub models: BTreeMap<String, String>,
    /// Overrides the adapter's default endpoint base URL.
    #[serde(default)]
    pub base_url: Option<String>,
}

impl OfficialRunnerSeatSettings {
    fn dreamer_seat(&self) -> Result<OfficialDreamerSeat, String> {
        let mut model_slug_map = BTreeMap::new();
        for (slug, model) in &self.models {
            let model = oneiron::ModelId::new(model.clone())
                .map_err(|error| format!("runner seat model for slug {slug:?}: {error}"))?;
            model_slug_map.insert(slug.clone(), model);
        }
        Ok(OfficialDreamerSeat {
            spec: self.seat.spec()?,
            model_slug_map,
            base_url: self.base_url.clone(),
        })
    }
}

/// The owner's ordered runner seats and what a spent one does, as settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RunnerSeatPolicySettings {
    pub seats: Vec<RunnerSeatSettings>,
    /// `stop` (default), `next_seat`, or `internal_models`.
    #[serde(default = "default_on_spent")]
    pub on_spent: String,
    /// Official seats registered as named Dreamer providers the seats
    /// above may name beside the plain CLI runners.
    #[serde(default)]
    pub official: Vec<OfficialRunnerSeatSettings>,
}

fn default_on_spent() -> String {
    "stop".to_owned()
}

impl RunnerSeatPolicySettings {
    /// The Dreamer provider registry these settings name runners against:
    /// the owner's official seats registered under their adapter names,
    /// then the plain CLI runners for every name no official seat took
    /// (an official "claude-code" seat IS that runner, login attached).
    ///
    /// # Errors
    ///
    /// Returns a message naming the seat that does not fold, the route with
    /// no adapter, or the malformed model binding.
    pub fn registry(&self) -> Result<ProviderAdapterRegistry, String> {
        let official = OfficialSeatRegistry::standard();
        let mut seats = Vec::with_capacity(self.official.len());
        for seat in &self.official {
            seats.push(seat.dreamer_seat()?);
        }
        let mut registry = ProviderAdapterRegistry::default();
        register_official_dreamer_providers(&mut registry, &official, seats)
            .map_err(|error| error.to_string())?;
        for runner in [
            Arc::new(ClaudeCodeRunner) as Arc<dyn DreamerProviderAdapter>,
            Arc::new(CodexRunner),
            Arc::new(OpenCodeRunner),
        ] {
            if !registry.contains(runner.name()) {
                registry
                    .register(runner)
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(registry)
    }

    /// Folds the settings into the engine policy dispatch judges, validated
    /// against the registry the same settings build.
    ///
    /// # Errors
    ///
    /// Returns a message naming the unknown auth/fallback label, the
    /// malformed custody handle, or the first seat the policy refuses.
    pub fn policy(&self) -> Result<RunnerSeatPolicy, String> {
        self.policy_in(&self.registry()?)
    }

    fn policy_in(&self, registry: &ProviderAdapterRegistry) -> Result<RunnerSeatPolicy, String> {
        let mut seats = Vec::with_capacity(self.seats.len());
        for seat in &self.seats {
            let auth = match seat.auth.trim().to_ascii_lowercase().as_str() {
                "vendor_login" | "login" => SeatAuth::VendorLogin,
                "api_key" | "key" => SeatAuth::ApiKey,
                other => return Err(format!("unknown runner seat auth: {other:?}")),
            };
            let mut credential_handles = Vec::with_capacity(seat.credential_handles.len());
            for handle in &seat.credential_handles {
                credential_handles.push(
                    SandboxCredentialHandle::new(handle.clone())
                        .map_err(|error| error.to_string())?,
                );
            }
            seats.push(RunnerSeat {
                runner: seat.runner.clone(),
                auth,
                egress_profile_ref: seat.egress_profile_ref.clone(),
                credential_handles,
            });
        }
        let on_spent = match self.on_spent.trim().to_ascii_lowercase().as_str() {
            "stop" | "park" => OnSeatSpent::Stop,
            "next_seat" | "next" => OnSeatSpent::NextSeat,
            "internal_models" | "internal" => OnSeatSpent::InternalModels,
            other => return Err(format!("unknown on-spent fallback: {other:?}")),
        };
        let policy = RunnerSeatPolicy { seats, on_spent };
        policy
            .validate(registry)
            .map_err(|error| error.to_string())?;
        Ok(policy)
    }

    /// The Dreamer executor over this policy: registry and policy built
    /// from the same settings, so the seats the owner ordered are the
    /// providers dispatch resolves. `inner` is the internal role ladder an
    /// `internal_models` route (and a settled capture's host) falls back to.
    ///
    /// # Errors
    ///
    /// Returns the first message [`Self::registry`] or [`Self::policy`]
    /// refuses with.
    pub fn executor<B, E, I>(
        &self,
        endpoint_factory: B,
        egress: E,
        seat: usize,
        task: String,
        checkout_id: CheckoutId,
        inner: I,
    ) -> Result<RunnerSeatDreamerExecutor<B, E, I>, String> {
        let registry = self.registry()?;
        let policy = self.policy_in(&registry)?;
        Ok(RunnerSeatDreamerExecutor {
            endpoint_factory,
            egress,
            registry,
            policy,
            seat,
            task,
            checkout_id,
            inner,
        })
    }
}

/// One row of the runner catalog: every named Dreamer provider this build
/// registers, and where a vendor-login seat on it may run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RunnerProviderRow {
    /// The name a runner seat names ("claude-code", "chatgpt-signin", …).
    pub name: String,
    /// The CLI program, for CLI runners. Endpoint providers have none.
    pub program: Option<String>,
    /// The official seat route behind the name, when one serves it.
    pub official_route: Option<String>,
    /// Argv the person runs themselves to sign in.
    pub login_argv: Vec<String>,
    /// A login seat's placement on the person's own runtime, unmodified
    /// binary, no vendor approvals: `allowed`, or the refusal.
    pub own_runtime: String,
    /// The same on an Oneiron-hosted runtime.
    pub hosted: String,
}

fn login_placement_label(
    program: Option<&str>,
    route: Option<OfficialSeatRoute>,
    hosted: bool,
) -> String {
    let posture = if hosted {
        HostingPrivacyPosture::Hosted
    } else {
        HostingPrivacyPosture::SelfHostLocal
    };
    match route {
        Some(route) => {
            match check_seat_placement(route, posture, SeatPlacementApproval::default(), true) {
                Ok(()) => "allowed".to_owned(),
                Err(error) => format!("refused: {error}"),
            }
        }
        // No official route (OpenCode): the generic login rule. A login
        // runs hosted unless a provider's terms keep its program off one.
        None => hosted_seat_bound(program.map(SeatIdentity::CliProgram), true, posture, None)
            .map_or_else(|| "allowed".to_owned(), |bound| format!("refused: {bound}")),
    }
}

fn runner_provider_row(
    name: &str,
    program: Option<&str>,
    route: Option<OfficialSeatRoute>,
) -> RunnerProviderRow {
    RunnerProviderRow {
        name: name.to_owned(),
        program: program.map(str::to_owned),
        official_route: route.map(|route| route.as_str().to_owned()),
        login_argv: route.map_or_else(Vec::new, OfficialSeatRoute::login_argv),
        own_runtime: login_placement_label(program, route, false),
        hosted: login_placement_label(program, route, true),
    }
}

/// Every named Dreamer provider: the plain CLI runners and the official
/// seat adapters, one row per name, judged with no vendor approvals
/// granted. An API-key seat runs anywhere; the placement columns judge a
/// vendor-login seat.
#[must_use]
pub fn runner_provider_catalog() -> Vec<RunnerProviderRow> {
    let official = OfficialSeatRegistry::standard();
    let mut rows = vec![
        runner_provider_row(
            "claude-code",
            Some(oneiron::dispatch_byoa::CLAUDE_CODE_PROGRAM),
            Some(OfficialSeatRoute::ClaudeCodeBinary),
        ),
        runner_provider_row(
            "codex",
            Some(oneiron::dispatch_byoa::CODEX_PROGRAM),
            Some(OfficialSeatRoute::CodexAppServerChatGptPlan),
        ),
        runner_provider_row(
            "opencode",
            Some(oneiron::dispatch_byoa::OPENCODE_PROGRAM),
            None,
        ),
    ];
    for name in official.names() {
        if rows.iter().any(|row| row.name == name) {
            continue;
        }
        if let Ok(adapter) = official.resolve(name) {
            rows.push(runner_provider_row(name, None, Some(adapter.route())));
        }
    }
    rows
}

/// The owner's effective runner-seat policy as a surface prints it: the
/// ordered seats, what a spent one does, and every provider the same
/// settings register. Handle names stay counts; no credential exists here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RunnerPolicySurface {
    /// `stop`, `next_seat`, or `internal_models`.
    pub on_spent: String,
    pub seats: Vec<RunnerPolicySeatRow>,
    pub registered_providers: Vec<String>,
}

/// One ordered seat of the effective policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RunnerPolicySeatRow {
    pub seat: usize,
    pub runner: String,
    /// `vendor_login` or `api_key`.
    pub auth: String,
    pub egress_profile_ref: String,
    /// Custody handles named. Zero for a login seat, by rule.
    pub credential_handles: usize,
}

/// Builds the effective-policy surface from owner settings.
///
/// # Errors
///
/// Returns the first message the registry or policy fold refuses with.
pub fn runner_policy_surface(
    settings: &RunnerSeatPolicySettings,
) -> Result<RunnerPolicySurface, String> {
    let registry = settings.registry()?;
    let policy = settings.policy_in(&registry)?;
    let on_spent = match policy.on_spent {
        OnSeatSpent::Stop => "stop",
        OnSeatSpent::NextSeat => "next_seat",
        OnSeatSpent::InternalModels => "internal_models",
    };
    Ok(RunnerPolicySurface {
        on_spent: on_spent.to_owned(),
        seats: policy
            .seats
            .iter()
            .enumerate()
            .map(|(seat, chosen)| RunnerPolicySeatRow {
                seat,
                runner: chosen.runner.clone(),
                auth: match chosen.auth {
                    SeatAuth::VendorLogin => "vendor_login",
                    SeatAuth::ApiKey => "api_key",
                }
                .to_owned(),
                egress_profile_ref: chosen.egress_profile_ref.clone(),
                credential_handles: chosen.credential_handles.len(),
            })
            .collect(),
        registered_providers: registry.names().into_iter().map(str::to_owned).collect(),
    })
}

/// The Dreamer executor over the owner's runner-seat policy (OF-137 +
/// OF-375): admitted work is bound to a seat and dispatched there through
/// [`ByoaDispatcher::bind_runner_work_in_txn`], and once the host has the
/// runner's terminal exhaust, [`Self::route_terminal`] folds it, on the
/// seat the work stands on, through
/// [`ByoaDispatcher::route_runner_terminal`] and maps the [`SeatRoute`]
/// onto the Dreamer outcome. The factory and egress port are cloned per
/// call, so they should be cheap `Arc`-backed handles.
pub struct RunnerSeatDreamerExecutor<B, E, I> {
    pub endpoint_factory: B,
    pub egress: E,
    pub registry: ProviderAdapterRegistry,
    pub policy: RunnerSeatPolicy,
    /// The seat new work starts on; routing continues from the same index.
    pub seat: usize,
    /// The task the host hands the runner (the argument after its `--`).
    pub task: String,
    pub checkout_id: CheckoutId,
    /// The internal role ladder an `InternalModels` route falls back to.
    pub inner: I,
}

impl<B, E, I> RunnerSeatDreamerExecutor<B, E, I>
where
    B: ByoEndpointBackendFactory + Clone,
    E: ByoaEgressPort + Clone,
    I: DreamerAttemptExecutor,
{
    /// Captures a runner attempt's terminal exhaust and routes its work
    /// under the policy: a settled capture completes the Dreamer attempt, a
    /// parked or next-seat route parks it (the child attempt carries the
    /// work on), and an internal-models route runs the inner ladder.
    ///
    /// # Errors
    ///
    /// Returns the store error when capture or dispatch refuses under the
    /// vault, or the inner executor's error on the internal route.
    pub async fn route_terminal(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
        capture: CaptureByoaExhaust,
        spent: Option<SeatSpent>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let routed = {
            let mut dispatcher = ByoaDispatcher::new(
                ctx.vault,
                self.endpoint_factory.clone(),
                self.egress.clone(),
            );
            dispatcher.route_runner_terminal(
                &self.registry,
                &self.policy,
                runner_work::bound_seat(ctx.vault, attempt.status.attempt.id, self.seat),
                capture,
                spent,
            )
        };
        match routed {
            Ok(SeatRoute::Settled(_)) => {
                Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
            }
            Ok(SeatRoute::Park { receipt, until, .. }) => Ok(DreamerAttemptExecution::Park {
                reason: match until {
                    Some(until) => format!("runner seat spent; work parked until {until}"),
                    None => "runner seat spent; work parked for the owner".to_owned(),
                } + &skipped_seats_note(&receipt.skipped_seats),
                cause: DreamerParkCause::Signal,
            }),
            Ok(SeatRoute::NextSeat { receipt, seat, .. }) => Ok(DreamerAttemptExecution::Park {
                reason: format!(
                    "runner seat spent; seat {seat} took the work, awaiting its exhaust{}",
                    skipped_seats_note(&receipt.skipped_seats)
                ),
                cause: DreamerParkCause::Signal,
            }),
            Ok(SeatRoute::InternalModels { .. }) => self.inner.execute(attempt, ctx).await,
            Ok(_) => Ok(DreamerAttemptExecution::Park {
                reason: "runner seat route is not understood by this host".to_owned(),
                cause: DreamerParkCause::Other,
            }),
            Err(ByoaError::Store(error)) => Err(error),
            Err(other) => Ok(DreamerAttemptExecution::Park {
                reason: format!("runner seat routing refused: {other}"),
                cause: DreamerParkCause::Other,
            }),
        }
    }
}

impl<B, E, I> DreamerAttemptExecutor for RunnerSeatDreamerExecutor<B, E, I>
where
    B: ByoEndpointBackendFactory + Clone,
    E: ByoaEgressPort + Clone,
    I: DreamerAttemptExecutor,
{
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let step = runner_work::dreamer_step(
            attempt.status.attempt.id,
            self.seat,
            self.task.clone(),
            self.checkout_id,
            ctx.now_ms / 1000,
        );
        let dispatcher = ByoaDispatcher::new(
            ctx.vault,
            self.endpoint_factory.clone(),
            self.egress.clone(),
        );
        runner_work::bind_step(ctx.vault, &dispatcher, &self.registry, &self.policy, step)
    }
}
