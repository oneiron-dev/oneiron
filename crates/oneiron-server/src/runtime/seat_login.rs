//! Host surface for official subscription seats (OF-375).
//!
//! The engine owns the seat contract (`oneiron::dispatch_byoa::official_seats`);
//! this module is the host half: owner settings in, a sign-in surface out, a
//! local executor for the official signed-in CLIs, and the Dreamer executor
//! that dispatches admitted work onto a seat. No type here can hold a vendor
//! token either: settings carry labels and custody handles, the surface
//! carries an argv or a browser URL the PERSON runs, and the control plane
//! holds nothing.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use oneiron::checkout::{CheckoutId, CheckoutLeaseAct};
use oneiron::code_sandbox::SandboxBoundaryContract;
use oneiron::code_sandbox::SandboxCredentialHandle;
use oneiron::code_sandbox::microvm::ExecutionBudget;
use oneiron::dispatch_byoa::{
    BYOA_MAX_EXHAUST_STREAM_BYTES, ByoEndpointBackendFactory, ByoaCliExecutor, ByoaConnectorSpec,
    ByoaDispatcher, ByoaEgressLease, ByoaEgressPort, ByoaError, ByoaExhaust, ByoaResult,
    CaptureByoaExhaust, CliSandboxSpec, DispatchOfficialSeat, DrySeatDecision, DrySeatFallback,
    OfficialSeatDispatchOutcome, OfficialSeatRoute, OfficialSeatSpec, OnSeatSpent,
    ProviderAdapterRegistry, RunnerSeat, RunnerSeatPolicy, RunnerWork, SeatAuth,
    SeatPlacementApproval, SeatPlanWindow, SeatRoute, SeatSpent, SiwcAuthorizeRequest,
    check_seat_placement, decide_dry_seat, pkce_s256_challenge, seat_login_plan,
    validate_official_seat,
};
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor, DreamerParkCause,
    HostingPrivacyPosture, WakeAttemptContext,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::mode::RuntimeMode;

/// The owner's settings for one official seat. Every field is a label, a
/// choice, or a custody handle; there is no field a vendor token could go in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SeatSettings {
    /// Route label, one of `OfficialSeatRoute::ALL` spellings.
    pub route: String,
    /// Opaque label for the person's account (never the credential).
    pub account_ref: String,
    #[serde(default)]
    pub machine_ref: Option<String>,
    /// Where the vendor's own login store lives on that machine.
    #[serde(default)]
    pub login_store_ref: Option<String>,
    /// Custody handle for endpoint-shaped seats, by name.
    #[serde(default)]
    pub credential_handle: Option<String>,
    /// The vendor binary is the unmodified build as published.
    #[serde(default = "default_true")]
    pub unmodified_binary: bool,
    #[serde(default)]
    pub anthropic_agent_sdk_approved: bool,
    #[serde(default)]
    pub openai_hosted_plan_approved: bool,
    /// `park` (default), `continue_on_local`, or `overdraft`.
    #[serde(default = "default_dry_fallback")]
    pub dry_fallback: String,
    /// The owner's spend cap when `dry_fallback` is `overdraft`.
    #[serde(default)]
    pub overdraft_cap_units: u64,
    #[serde(default)]
    pub plan_percent_used: Option<u8>,
    #[serde(default)]
    pub plan_resets_at: Option<u64>,
}

fn default_true() -> bool {
    true
}

fn default_dry_fallback() -> String {
    "park".to_owned()
}

impl SeatSettings {
    /// Folds the settings into the engine seat spec the dispatcher judges.
    ///
    /// # Errors
    ///
    /// Returns a message naming the unknown route/fallback label or the
    /// malformed custody handle.
    pub fn spec(&self) -> Result<OfficialSeatSpec, String> {
        let route = OfficialSeatRoute::from_label(self.route.trim())
            .ok_or_else(|| format!("unknown official seat route: {:?}", self.route))?;
        let credential_ref = self
            .credential_handle
            .as_deref()
            .map(str::trim)
            .filter(|handle| !handle.is_empty())
            .map(|handle| {
                SandboxCredentialHandle::new(handle.to_owned()).map_err(|error| error.to_string())
            })
            .transpose()?;
        let dry_fallback = match self.dry_fallback.trim().to_ascii_lowercase().as_str() {
            "park" | "park_until_reset" | "suspend" => DrySeatFallback::ParkUntilReset,
            "continue_on_local" | "local" => DrySeatFallback::ContinueOnLocal,
            "overdraft" | "spend" | "spend_overdraft" => DrySeatFallback::SpendOverdraft {
                cap_units: self.overdraft_cap_units,
            },
            other => return Err(format!("unknown dry-seat fallback: {other:?}")),
        };
        let plan_window = match (self.plan_percent_used, self.plan_resets_at) {
            (Some(percent_used), Some(resets_at)) => Some(SeatPlanWindow {
                percent_used,
                resets_at,
            }),
            _ => None,
        };
        Ok(OfficialSeatSpec {
            route,
            account_ref: self.account_ref.clone(),
            machine_ref: self.machine_ref.clone(),
            login_store_ref: self.login_store_ref.clone(),
            credential_ref,
            unmodified_binary: self.unmodified_binary,
            approvals: SeatPlacementApproval {
                anthropic_agent_sdk: self.anthropic_agent_sdk_approved,
                openai_hosted_plan: self.openai_hosted_plan_approved,
            },
            dry_fallback,
            plan_window,
        })
    }
}

/// Everything a sign-in surface needs to show, and nothing it must not: the
/// placement verdict, what the person runs, and what a dry seat would do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SeatLoginSurface {
    pub route: String,
    pub vendor: Option<String>,
    pub placement_ok: bool,
    pub placement_error: Option<String>,
    /// Argv the person runs themselves (the vendor's own login).
    pub login_argv: Vec<String>,
    /// Browser URL the person opens, for Sign in with ChatGPT.
    pub authorize_url: Option<String>,
    /// Always false; named so the surface states the posture.
    pub control_plane_holds_token: bool,
    /// `run`, `park`, `continue_on_local`, or `spend_overdraft`.
    pub dry_decision: String,
    pub park_until: Option<u64>,
    pub note: String,
}

/// Builds the sign-in surface for one seat under one runtime mode.
///
/// # Errors
///
/// Returns a message when the settings do not fold into a valid seat, or a
/// Sign in with ChatGPT surface is asked for without its authorize request.
pub fn seat_login_surface(
    mode: RuntimeMode,
    settings: &SeatSettings,
    now: u64,
    siwc: Option<&SiwcAuthorizeRequest>,
) -> Result<SeatLoginSurface, String> {
    let spec = settings.spec()?;
    validate_official_seat(&spec).map_err(|error| error.to_string())?;
    let placement = check_seat_placement(
        spec.route,
        mode.hosting_posture(),
        spec.approvals,
        spec.unmodified_binary,
    );
    let plan = seat_login_plan(&spec, siwc).map_err(|error| error.to_string())?;
    let decision = decide_dry_seat(spec.plan_window.as_ref(), spec.dry_fallback, now);
    let (dry_decision, park_until) = match decision {
        DrySeatDecision::Run => ("run", None),
        DrySeatDecision::Park { until } => ("park", Some(until)),
        DrySeatDecision::ContinueOnLocal => ("continue_on_local", None),
        DrySeatDecision::Spend { .. } => ("spend_overdraft", None),
    };
    Ok(SeatLoginSurface {
        route: spec.route.as_str().to_owned(),
        vendor: plan.vendor.map(|vendor| vendor.as_str().to_owned()),
        placement_ok: placement.is_ok(),
        placement_error: placement.err().map(|error| error.to_string()),
        login_argv: plan.argv,
        authorize_url: plan.authorize_url,
        control_plane_holds_token: plan.control_plane_holds_token,
        dry_decision: dry_decision.to_owned(),
        park_until,
        note: plan.note.to_owned(),
    })
}

/// One row of the seat catalog a settings surface renders.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SeatRouteRow {
    pub route: String,
    pub vendor: Option<String>,
    pub user_login: bool,
    pub login_argv: Vec<String>,
    /// Placement on the person's own runtime, unmodified binary, no approvals.
    pub own_runtime_ok: bool,
    pub own_runtime_error: Option<String>,
    /// Placement on an Oneiron-hosted runtime, same assumptions.
    pub hosted_ok: bool,
    pub hosted_error: Option<String>,
}

/// Every seat route with its placement on both runtime classes, judged with
/// no vendor approvals granted: approvals only ever widen this table.
#[must_use]
pub fn seat_route_catalog() -> Vec<SeatRouteRow> {
    let approvals = SeatPlacementApproval::default();
    OfficialSeatRoute::ALL
        .into_iter()
        .map(|route| {
            let own =
                check_seat_placement(route, HostingPrivacyPosture::SelfHostLocal, approvals, true);
            let hosted =
                check_seat_placement(route, HostingPrivacyPosture::Hosted, approvals, true);
            SeatRouteRow {
                route: route.as_str().to_owned(),
                vendor: route.vendor().map(|vendor| vendor.as_str().to_owned()),
                user_login: route.is_user_login(),
                login_argv: route.login_argv(),
                own_runtime_ok: own.is_ok(),
                own_runtime_error: own.err().map(|error| error.to_string()),
                hosted_ok: hosted.is_ok(),
                hosted_error: hosted.err().map(|error| error.to_string()),
            }
        })
        .collect()
}

/// Builds a Sign in with ChatGPT authorize request from a PKCE verifier the
/// person's runtime generated and keeps. Only the S256 challenge leaves.
///
/// # Errors
///
/// Returns a message when the verifier is outside the RFC 7636 shape.
pub fn siwc_authorize_request(
    client_id: String,
    redirect_uri: String,
    verifier: &str,
    state: String,
    scope: Option<String>,
) -> Result<SiwcAuthorizeRequest, String> {
    Ok(SiwcAuthorizeRequest {
        client_id,
        redirect_uri,
        code_challenge: pkce_s256_challenge(verifier).map_err(|error| error.to_string())?,
        state,
        scope,
    })
}

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

/// Runs an official signed-in CLI (`claude`, `codex`) as a local argv-only
/// process in a checkout directory the host resolved.
///
/// This is the own-runtime executor: the person's machine, the person's
/// network, the person's login inside the unmodified binary. It enforces the
/// wall-clock budget and the exhaust caps, but it is NOT a sandbox: guest
/// network reaches are not routed through `authorize`, because a local
/// process cannot be mediated that way. A hosted deployment must run the
/// seat behind the microVM executor instead; placement rules already keep
/// every login but the hosted-permitted Claude binary off hosted nodes, and
/// this executor must not be the one serving that case.
#[derive(Clone, Debug)]
pub struct OfficialCliSeatExecutor {
    /// Directory the host resolved the live checkout into.
    pub workdir: PathBuf,
}

fn drain_capped(mut reader: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let room = BYOA_MAX_EXHAUST_STREAM_BYTES.saturating_sub(kept.len());
                    kept.extend_from_slice(&chunk[..read.min(room)]);
                }
            }
        }
        kept
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
        if !matches!(spec.program.as_str(), "claude" | "codex") {
            return Err(ByoaError::Backend(
                "official seat executor runs only the official claude/codex binaries".to_owned(),
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
        for name in SEAT_ENV_REMOVED {
            command.env_remove(name);
        }
        let mut child = command
            .spawn()
            .map_err(|_| ByoaError::Backend("official seat spawn failed".to_owned()))?;
        let stdout = child
            .stdout
            .take()
            .map(drain_capped)
            .ok_or_else(|| ByoaError::Backend("official seat stdout unavailable".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .map(drain_capped)
            .ok_or_else(|| ByoaError::Backend("official seat stderr unavailable".to_owned()))?;
        let deadline = Instant::now() + Duration::from_secs(budget.wall_clock_secs.max(1));
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ByoaError::Backend(
                        "official seat exceeded its wall-clock budget".to_owned(),
                    ));
                }
                Err(_) => {
                    return Err(ByoaError::Backend("official seat wait failed".to_owned()));
                }
            }
        };
        let mut exhaust = ByoaExhaust {
            stdout: stdout.join().unwrap_or_default(),
            stderr: stderr.join().unwrap_or_default(),
            ..ByoaExhaust::default()
        };
        if !status.success() && exhaust.stderr.is_empty() {
            exhaust.stderr = format!("official seat exited with {status}").into_bytes();
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

/// The owner's ordered runner seats and what a spent one does, as settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RunnerSeatPolicySettings {
    pub seats: Vec<RunnerSeatSettings>,
    /// `stop` (default), `next_seat`, or `internal_models`.
    #[serde(default = "default_on_spent")]
    pub on_spent: String,
}

fn default_on_spent() -> String {
    "stop".to_owned()
}

impl RunnerSeatPolicySettings {
    /// Folds the settings into the engine policy dispatch judges, validated
    /// against the standard runner registry.
    ///
    /// # Errors
    ///
    /// Returns a message naming the unknown auth/fallback label, the
    /// malformed custody handle, or the first seat the policy refuses.
    pub fn policy(&self) -> Result<RunnerSeatPolicy, String> {
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
            .validate(&ProviderAdapterRegistry::standard())
            .map_err(|error| error.to_string())?;
        Ok(policy)
    }
}

/// The Dreamer executor over the owner's runner-seat policy (OF-137 +
/// OF-375): admitted work is dispatched to a seat through
/// [`ByoaDispatcher::dispatch_runner`], and once the host has the runner's
/// terminal exhaust, [`Self::route_terminal`] folds it through
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
                self.seat,
                capture,
                spent,
            )
        };
        match routed {
            Ok(SeatRoute::Settled(_)) => {
                Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
            }
            Ok(SeatRoute::Park { until, .. }) => Ok(DreamerAttemptExecution::Park {
                reason: match until {
                    Some(until) => format!("runner seat spent; work parked until {until}"),
                    None => "runner seat spent; work parked for the owner".to_owned(),
                },
                cause: DreamerParkCause::Signal,
            }),
            Ok(SeatRoute::NextSeat { seat, .. }) => Ok(DreamerAttemptExecution::Park {
                reason: format!(
                    "runner seat spent; seat {seat} took the work, awaiting its exhaust"
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
        let parent = attempt.status.attempt.id;
        let dispatched = {
            let mut dispatcher = ByoaDispatcher::new(
                ctx.vault,
                self.endpoint_factory.clone(),
                self.egress.clone(),
            );
            dispatcher.dispatch_runner(
                &self.registry,
                &self.policy,
                self.seat,
                RunnerWork {
                    task: self.task.clone(),
                    checkout_id: self.checkout_id,
                    task_ref: None,
                    parent_attempt_id: Some(parent),
                    run_id: None,
                    dedupe_key: Some(format!(
                        "byoa.runner.dreamer:{}",
                        attempt_hex(parent.as_bytes())
                    )),
                    now: ctx.now_ms / 1000,
                },
            )
        };
        match dispatched {
            Ok(outcome) => Ok(DreamerAttemptExecution::Park {
                reason: format!(
                    "runner seat attempt {} dispatched; awaiting foreign exhaust",
                    attempt_hex(outcome.status().attempt.id.as_bytes())
                ),
                cause: DreamerParkCause::Signal,
            }),
            Err(ByoaError::Store(error)) => Err(error),
            Err(other) => Ok(DreamerAttemptExecution::Park {
                reason: format!("runner seat refused: {other}"),
                cause: DreamerParkCause::Other,
            }),
        }
    }
}
