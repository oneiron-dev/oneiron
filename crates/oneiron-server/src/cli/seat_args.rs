//! `oneiron seat …` arguments: the official-seat sign-in surface (OF-375).

use std::path::PathBuf;

use clap::{Args, Subcommand};
use oneiron::HostingPrivacyPosture;

use crate::runtime::RuntimeMode;

#[derive(Subcommand)]
pub enum SeatCommand {
    /// List every seat route with its placement on your own runtime and on
    /// an Oneiron-hosted one (no vendor approvals assumed).
    Routes,
    /// Print the sign-in plan for one seat: placement verdict, the login you
    /// run yourself, and what the seat does when its plan window is dry.
    LoginPlan(Box<SeatLoginPlanArgs>),
    /// List every named Dreamer runner a seat policy may name — the CLI
    /// runners and the official seat adapters — with where a login seat on
    /// each may run (no vendor approvals assumed).
    Runners,
    /// Validate an owner runner-seat policy (JSON settings) and print the
    /// effective order: which runner takes Dreamer work, and where the work
    /// goes when a seat's quota is spent.
    RunnerPolicy(Box<SeatRunnerPolicyArgs>),
    /// Sign in locally with ChatGPT and save one protected account record.
    /// Prints the URL for you to open; never starts a browser or prints tokens.
    SiwcLogin(Box<SiwcLoginArgs>),
    /// Clear only local SIWC tokens, keeping the account registration.
    /// Does not revoke the remote grant.
    SiwcClear(Box<SiwcCredentialArgs>),
    /// Stop local SIWC use, revoke the renewable session, then clear tokens.
    /// Keeps the account registration even when remote revocation is unconfirmed.
    SiwcRevoke(Box<SiwcRevokeArgs>),
}

const DEFAULT_SIWC_REVOKE_RETRIES: u32 = 2;
const DEFAULT_SIWC_REVOKE_BACKOFF_MS: u64 = 1000;
const DEFAULT_SIWC_REVOKE_TIMEOUT_SECS: u64 = 120;

#[derive(Args, Clone, Debug)]
pub struct SiwcCredentialArgs {
    /// Protected local SIWC account record; its registration is retained.
    #[arg(long)]
    pub credential_file: PathBuf,
}

#[derive(Args, Clone, Debug)]
pub struct SiwcRevokeArgs {
    /// Protected local SIWC account record; its registration is retained.
    #[arg(long)]
    pub credential_file: PathBuf,
    /// Extra attempts after a network failure or HTTP 5xx; zero makes one attempt.
    #[arg(long, default_value_t = DEFAULT_SIWC_REVOKE_RETRIES)]
    pub retries: u32,
    /// Initial retry delay in milliseconds, multiplied by the retry number.
    /// Zero retries without waiting.
    #[arg(long, default_value_t = DEFAULT_SIWC_REVOKE_BACKOFF_MS)]
    pub backoff_ms: u64,
    /// Total timeout in seconds for each revocation HTTP request.
    /// Zero expires immediately, not an unlimited wait.
    #[arg(long, default_value_t = DEFAULT_SIWC_REVOKE_TIMEOUT_SECS)]
    pub timeout_secs: u64,
}

const DEFAULT_SIWC_LOGIN_TIMEOUT_SECS: u64 = 120;

#[derive(Args, Clone, Debug)]
pub struct SiwcLoginArgs {
    /// Protected local record for this account, outside every vault and repo.
    #[arg(long)]
    pub credential_file: PathBuf,
    /// Protected stable host identifier, shared by this host's SIWC accounts.
    #[arg(long)]
    pub host_id_file: PathBuf,
    /// Registered HTTP callback on 127.0.0.1. Port 0 selects an available port;
    /// the scheme, host and path stay fixed on later sign-ins.
    #[arg(long)]
    pub callback_uri: String,
    /// Your app's actual name, kept consistent across installations.
    #[arg(long)]
    pub agent_name: String,
    /// Total HTTP timeout for the code exchange, not the human callback wait.
    /// Zero expires immediately instead of allowing an unlimited wait.
    #[arg(long, default_value_t = DEFAULT_SIWC_LOGIN_TIMEOUT_SECS)]
    pub timeout_secs: u64,
}

#[derive(Args, Clone, Debug)]
pub struct SeatRunnerPolicyArgs {
    /// Runner-seat policy settings as JSON (`seats`, `on_spent`, optional
    /// `official` seat registrations). `-` reads stdin.
    #[arg(long)]
    pub settings: PathBuf,
}

#[derive(Args, Clone, Debug)]
pub struct SeatLoginPlanArgs {
    /// Seat route label (see `seat routes`).
    #[arg(long)]
    pub route: String,
    /// Your own label for the account. A label only, never a credential.
    #[arg(long)]
    pub account: String,
    /// Runtime mode the seat would run under.
    #[arg(long, default_value = "local_free")]
    pub mode: RuntimeMode,
    /// Hosting posture of the runtime the seat would run on, apart from its
    /// inference mode: `managed` (Oneiron-hosted, with bring-your-own or
    /// local inference too), `relay` or `self-host`. Unset, a standalone
    /// plan reads it from --mode (FIX 9533).
    #[arg(long = "privacy-posture", value_parser = parse_privacy_posture)]
    pub privacy_posture: Option<HostingPrivacyPosture>,
    /// Which of your machines holds the login.
    #[arg(long)]
    pub machine: Option<String>,
    /// Where the vendor's own login store lives on that machine.
    #[arg(long = "login-store")]
    pub login_store: Option<String>,
    /// Custody handle name for endpoint-shaped seats.
    #[arg(long = "credential-handle")]
    pub credential_handle: Option<String>,
    /// Say the vendor binary is modified. A Claude login seat then refuses:
    /// the hosting permission covers the unmodified binary only.
    #[arg(long = "modified-binary")]
    pub modified_binary: bool,
    /// Anthropic has approved offering a Claude.ai login via the Agent SDK.
    #[arg(long = "anthropic-sdk-approved")]
    pub anthropic_sdk_approved: bool,
    /// OpenAI has approved hosted ChatGPT-plan use.
    #[arg(long = "openai-hosted-approved")]
    pub openai_hosted_approved: bool,
    /// What a dry seat does: park (default), continue_on_local, overdraft.
    #[arg(long, default_value = "park")]
    pub dry: String,
    /// Spend cap units when --dry is overdraft. Zero parks instead.
    #[arg(long = "overdraft-cap", default_value_t = 0)]
    pub overdraft_cap: u64,
    /// Plan-window percent already used, when known.
    #[arg(long = "plan-percent-used")]
    pub plan_percent_used: Option<u8>,
    /// Plan-window reset (epoch seconds), when known.
    #[arg(long = "plan-resets-at")]
    pub plan_resets_at: Option<u64>,
    /// Judge dryness at this epoch second instead of the host clock.
    #[arg(long, default_value_t = 0)]
    pub now: u64,
    /// Sign in with ChatGPT: dynamic_agent_client for initial registration,
    /// or the issued client id for this account's later sign-ins.
    #[arg(long = "siwc-client-id")]
    pub siwc_client_id: Option<String>,
    /// Sign in with ChatGPT: the exact registered 127.0.0.1 loopback URI.
    #[arg(long = "siwc-redirect-uri")]
    pub siwc_redirect_uri: Option<String>,
    /// Sign in with ChatGPT: your PKCE verifier. Only its S256 challenge is
    /// printed, inside the authorize URL; the verifier is never stored.
    #[arg(long = "siwc-verifier")]
    pub siwc_verifier: Option<String>,
    /// Sign in with ChatGPT: fresh OAuth state, kept to validate the callback.
    #[arg(long = "siwc-state")]
    pub siwc_state: Option<String>,
    /// Sign in with ChatGPT: fresh OIDC nonce, kept for ID-token validation.
    #[arg(long = "siwc-nonce")]
    pub siwc_nonce: Option<String>,
    /// Sign in with ChatGPT: this host's stable id, reused across sign-ins.
    #[arg(long = "siwc-agent-host-id")]
    pub siwc_agent_host_id: Option<String>,
    /// Sign in with ChatGPT: the app's actual name, required and sent only
    /// for initial dynamic_agent_client registration.
    #[arg(long = "siwc-agent-name-hint")]
    pub siwc_agent_name_hint: Option<String>,
    /// Sign in with ChatGPT: explicit scope override; otherwise the official
    /// direct-token identity and plan-use scopes are requested.
    #[arg(long = "siwc-scope")]
    pub siwc_scope: Option<String>,
}

impl SeatLoginPlanArgs {
    /// The hosting posture the plan judges the login under: the one given,
    /// else what a standalone plan has always read from its mode.
    #[must_use]
    pub fn hosting_posture(&self) -> HostingPrivacyPosture {
        self.privacy_posture
            .unwrap_or_else(|| standalone_posture(self.mode))
    }
}

/// A standalone plan's posture when none is given: Oneiron Cloud inference
/// plans for a hosted runtime, every other mode for the person's own. Only
/// this CLI falls back to it; a hosted caller passes its posture, Hosted
/// with any inference (FIX 9533).
fn standalone_posture(mode: RuntimeMode) -> HostingPrivacyPosture {
    match mode {
        RuntimeMode::OneironCloud => HostingPrivacyPosture::Hosted,
        RuntimeMode::LocalFree | RuntimeMode::ByoCloudKey => HostingPrivacyPosture::SelfHostLocal,
    }
}

/// Clap value parser for `--privacy-posture`: only the three exact wire
/// values (`managed`, `relay`, `self-host`).
fn parse_privacy_posture(value: &str) -> Result<HostingPrivacyPosture, String> {
    value.parse()
}
