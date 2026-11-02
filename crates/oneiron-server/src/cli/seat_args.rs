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
    /// Sign in with ChatGPT: our app registration's client id.
    #[arg(long = "siwc-client-id")]
    pub siwc_client_id: Option<String>,
    /// Sign in with ChatGPT: the registered redirect URI.
    #[arg(long = "siwc-redirect-uri")]
    pub siwc_redirect_uri: Option<String>,
    /// Sign in with ChatGPT: your PKCE verifier. Only its S256 challenge is
    /// printed, inside the authorize URL; the verifier is never stored.
    #[arg(long = "siwc-verifier")]
    pub siwc_verifier: Option<String>,
    /// Sign in with ChatGPT: OAuth state value.
    #[arg(long = "siwc-state")]
    pub siwc_state: Option<String>,
    /// Sign in with ChatGPT: OAuth scope, when the registration asks for one.
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
