//! Official subscription seats (OF-375): the owner's own vendor login,
//! reached only through the vendor's official surface.
//!
//! The rules this module encodes, per the 2026-10-10 P4 posture:
//! - The unmodified Claude Code binary, signed in by the person, may run in
//!   their vault VM, cloud included. Anthropic's legal page permits hosting
//!   the unmodified binary; it bars intermediating the credential.
//! - A ChatGPT-plan Codex app-server login, and Sign in with ChatGPT plan
//!   use, stay on the person's own machine or self-hosted runtime until
//!   OpenAI approves hosted use.
//! - A Claude.ai login offered through the Agent SDK needs Anthropic's
//!   prior approval; without it the route refuses.
//! - xAI bills Grok and the API separately, so no Grok subscription bridge
//!   exists. Grok runs on an API key, which is not a login seat.
//! - An API key is not a login and runs on any runtime.
//! - The control plane never holds a vendor login and Oneiron never
//!   presents a vendor's client identity. No type here can hold a token:
//!   seats carry custody handles and opaque account labels only, and the
//!   login itself is an argv or a browser URL the PERSON runs.
//!
//! A dry seat (plan window spent) parks by default. Spending money instead
//! is the owner's explicit choice, made in [`DrySeatFallback`] before any
//! dispatch; there is no silent spend and no account rotation here, because
//! the vendors' terms bar rotating accounts to get around limits.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attempt_queue::AttemptId;
use crate::checkout::CheckoutId;
use crate::code_sandbox::SandboxCredentialHandle;
use crate::config::HostingPrivacyPosture;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error};
use crate::llm::{BudgetExhaustionPolicy, ModelId};

use super::connector::{
    ByoEndpointProtocol, ByoEndpointSpec, ByoaConnectorSpec, ByoaDispatchOutcome, CliSandboxSpec,
};
use super::error::{
    ByoaError, ByoaResult, ERR_PKCE_VERIFIER, ERR_SEAT_ROUTE, ERR_SEAT_SPEC, invalid,
};

/// Sign in with ChatGPT authorize endpoint (OpenAI's public OAuth host).
pub const SIWC_AUTHORIZE_ENDPOINT: &str = "https://auth.openai.com/oauth/authorize";

/// Responses API base a Sign in with ChatGPT seat calls.
pub const SIWC_RESPONSES_BASE_URL: &str = "https://api.openai.com/v1";

/// Anthropic API base behind an approved Agent-SDK seat.
pub const ANTHROPIC_API_BASE_URL: &str = "https://api.anthropic.com";

/// xAI API base for a Grok API-key seat.
pub const XAI_API_BASE_URL: &str = "https://api.x.ai/v1";

const MAX_ACCOUNT_REF_LEN: usize = 128;
const MAX_MACHINE_REF_LEN: usize = 128;
const MAX_LOGIN_STORE_REF_LEN: usize = 512;

/// The vendor whose plan a seat spends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OfficialSeatVendor {
    Claude,
    ChatGpt,
    Grok,
}

impl OfficialSeatVendor {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::ChatGpt => "chatgpt",
            Self::Grok => "grok",
        }
    }
}

/// How a seat reaches the vendor. Encoded as its label so a durable payload
/// stays readable if variant order changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum OfficialSeatRoute {
    /// The unmodified `claude` binary, signed in by the person (`claude -p`).
    ClaudeCodeBinary,
    /// A Claude.ai login offered through the Agent SDK. Approval-gated.
    ClaudeAgentSdkSubscription,
    /// Codex signed in with a ChatGPT plan, driven through the app-server.
    CodexAppServerChatGptPlan,
    /// Our own app's Sign in with ChatGPT registration (PKCE OAuth),
    /// billed to the person's plan through the Responses API.
    SignInWithChatGpt,
    /// No such bridge exists: xAI bills Grok and the API separately.
    GrokSubscription,
    /// A plain vendor API key. Not a login; runs anywhere.
    VendorApiKey,
}

impl OfficialSeatRoute {
    pub const ALL: [Self; 6] = [
        Self::ClaudeCodeBinary,
        Self::ClaudeAgentSdkSubscription,
        Self::CodexAppServerChatGptPlan,
        Self::SignInWithChatGpt,
        Self::GrokSubscription,
        Self::VendorApiKey,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCodeBinary => "claude_code_binary",
            Self::ClaudeAgentSdkSubscription => "claude_agent_sdk_subscription",
            Self::CodexAppServerChatGptPlan => "codex_app_server_chatgpt_plan",
            Self::SignInWithChatGpt => "sign_in_with_chatgpt",
            Self::GrokSubscription => "grok_subscription",
            Self::VendorApiKey => "vendor_api_key",
        }
    }

    /// Parses the stable label [`Self::as_str`] produces.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|route| route.as_str() == label)
    }

    #[must_use]
    pub const fn vendor(self) -> Option<OfficialSeatVendor> {
        match self {
            Self::ClaudeCodeBinary | Self::ClaudeAgentSdkSubscription => {
                Some(OfficialSeatVendor::Claude)
            }
            Self::CodexAppServerChatGptPlan | Self::SignInWithChatGpt => {
                Some(OfficialSeatVendor::ChatGpt)
            }
            Self::GrokSubscription => Some(OfficialSeatVendor::Grok),
            Self::VendorApiKey => None,
        }
    }

    /// A user login is a credential the PERSON signed in with. An API key
    /// the owner provisioned is not one and carries no placement limit.
    #[must_use]
    pub const fn is_user_login(self) -> bool {
        !matches!(self, Self::VendorApiKey)
    }

    /// The official login the person runs themselves. Empty for routes
    /// whose login is a browser flow (Sign in with ChatGPT) or absent.
    #[must_use]
    pub fn login_argv(self) -> Vec<String> {
        match self {
            Self::ClaudeCodeBinary | Self::ClaudeAgentSdkSubscription => {
                vec!["claude".into(), "auth".into(), "login".into()]
            }
            Self::CodexAppServerChatGptPlan => vec!["codex".into(), "login".into()],
            Self::SignInWithChatGpt | Self::GrokSubscription | Self::VendorApiKey => Vec::new(),
        }
    }
}

impl From<OfficialSeatRoute> for String {
    fn from(route: OfficialSeatRoute) -> Self {
        route.as_str().to_owned()
    }
}

impl TryFrom<String> for OfficialSeatRoute {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_label(&value).ok_or_else(|| {
            Error::Artifact(ArtifactError::InvalidAgentDispatchInput(ERR_SEAT_ROUTE))
        })
    }
}

/// Vendor approvals that widen placement. Both default to NOT granted: the
/// hosted shapes stay refused until the vendor actually approves them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatPlacementApproval {
    /// Anthropic previously approved offering a Claude.ai login via the SDK.
    #[serde(default)]
    pub anthropic_agent_sdk: bool,
    /// OpenAI approved hosted ChatGPT-plan use (OC2; apply near Cloud launch).
    #[serde(default)]
    pub openai_hosted_plan: bool,
}

/// Whether `route` may run under `posture`. This is the P4 placement table:
/// each vendor's terms set where its login runs, never ours alone.
///
/// # Errors
/// Refuses with the typed reason the terms demand: unsupported route,
/// missing vendor approval, a modified binary, or a cloud login refusal.
pub fn check_seat_placement(
    route: OfficialSeatRoute,
    posture: HostingPrivacyPosture,
    approvals: SeatPlacementApproval,
    unmodified_binary: bool,
) -> ByoaResult<()> {
    let hosted = posture == HostingPrivacyPosture::Hosted;
    match route {
        // An API key runs on any runtime; it is not a login seat.
        OfficialSeatRoute::VendorApiKey => Ok(()),
        // No Grok subscription bridge exists; use an API key seat instead.
        OfficialSeatRoute::GrokSubscription => {
            Err(ByoaError::SeatRouteUnsupported(route.as_str().to_owned()))
        }
        // The unmodified binary, signed in by the person, runs anywhere —
        // cloud included. A modified binary voids that permission.
        OfficialSeatRoute::ClaudeCodeBinary => {
            if unmodified_binary {
                Ok(())
            } else {
                Err(ByoaError::SeatModifiedBinaryRefused)
            }
        }
        // "Unless previously approved", no Claude.ai login through the SDK.
        OfficialSeatRoute::ClaudeAgentSdkSubscription => {
            if approvals.anthropic_agent_sdk {
                Ok(())
            } else {
                Err(ByoaError::SeatLoginNotApproved(route.as_str().to_owned()))
            }
        }
        // ChatGPT-plan logins stay on the person's own runtime until
        // OpenAI approves hosted plan use.
        OfficialSeatRoute::CodexAppServerChatGptPlan | OfficialSeatRoute::SignInWithChatGpt => {
            if hosted && !approvals.openai_hosted_plan {
                Err(ByoaError::CloudLoginRefused)
            } else {
                Ok(())
            }
        }
    }
}

/// What a dry seat does. The owner picks this BEFORE dispatch; the default
/// parks and spends nothing. Only `SpendOverdraft` spends money, only up to
/// the owner's cap, and only because the owner wrote that cap down.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DrySeatFallback {
    /// Park with a typed wait naming the plan-window reset. The default.
    #[default]
    ParkUntilReset,
    /// Keep working on the local model until the window resets.
    ContinueOnLocal,
    /// Spend past the dry seat, capped: the ratified LLMB overdraft rung.
    SpendOverdraft { cap_units: u64 },
}

impl DrySeatFallback {
    #[must_use]
    pub const fn spends_money(self) -> bool {
        matches!(self, Self::SpendOverdraft { cap_units } if cap_units > 0)
    }

    /// The LLMB depletion-ladder policy this fallback is, so a dry seat
    /// settles through the one budget ladder every other meter uses.
    #[must_use]
    pub const fn budget_policy(self) -> BudgetExhaustionPolicy {
        match self {
            Self::ParkUntilReset => BudgetExhaustionPolicy::Suspend,
            Self::ContinueOnLocal => BudgetExhaustionPolicy::ContinueOnLocal,
            Self::SpendOverdraft { cap_units } => {
                BudgetExhaustionPolicy::Overdraft { cap: cap_units }
            }
        }
    }
}

/// A subscription seat's plan window, in the seat's own unit: plan percent
/// used and when the window resets (host clock seconds). Units of different
/// kinds never mix, so this is percent of THIS seat's window only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatPlanWindow {
    pub percent_used: u8,
    pub resets_at: u64,
}

impl SeatPlanWindow {
    /// Dry = the window is spent and has not reset yet.
    #[must_use]
    pub const fn is_dry(self, now: u64) -> bool {
        self.percent_used >= 100 && now < self.resets_at
    }
}

/// What dispatch should do with a seat right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrySeatDecision {
    Run,
    /// Wait for the window. Never rotate accounts to dodge the limit.
    Park {
        until: u64,
    },
    ContinueOnLocal,
    /// The owner pre-chose capped spend; the host routes the spend itself
    /// under this policy. The seat attempt is not enqueued.
    Spend {
        cap_units: u64,
        policy: BudgetExhaustionPolicy,
    },
}

/// Folds a plan window and the owner's fallback choice into one decision.
#[must_use]
pub fn decide_dry_seat(
    window: Option<&SeatPlanWindow>,
    fallback: DrySeatFallback,
    now: u64,
) -> DrySeatDecision {
    let Some(window) = window else {
        return DrySeatDecision::Run;
    };
    if !window.is_dry(now) {
        return DrySeatDecision::Run;
    }
    match fallback {
        DrySeatFallback::ParkUntilReset => DrySeatDecision::Park {
            until: window.resets_at,
        },
        DrySeatFallback::ContinueOnLocal => DrySeatDecision::ContinueOnLocal,
        // A zero cap is no permission to spend; it parks like the default.
        DrySeatFallback::SpendOverdraft { cap_units: 0 } => DrySeatDecision::Park {
            until: window.resets_at,
        },
        DrySeatFallback::SpendOverdraft { cap_units } => DrySeatDecision::Spend {
            cap_units,
            policy: fallback.budget_policy(),
        },
    }
}

/// One person's official seat: vendor, account label, machine, login-store
/// reference, plan window. Every field is a label or a custody HANDLE.
/// There is deliberately no field that could hold a vendor token, a session
/// cookie, or a scraped credential — that is the whole custody story.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficialSeatSpec {
    pub route: OfficialSeatRoute,
    /// Opaque label for the person's account (never the credential).
    pub account_ref: String,
    /// Which of the person's machines holds the login, when it matters.
    pub machine_ref: Option<String>,
    /// Where the vendor's own login store lives on that machine. A path
    /// reference under the person's seal; its contents never cross here.
    pub login_store_ref: Option<String>,
    /// Custody handle for endpoint-shaped seats (SIWC / SDK / API key).
    pub credential_ref: Option<SandboxCredentialHandle>,
    /// The vendor binary is the unmodified build as published.
    pub unmodified_binary: bool,
    pub approvals: SeatPlacementApproval,
    /// The owner's pre-chosen dry-seat behavior. Default: park, spend 0.
    pub dry_fallback: DrySeatFallback,
    pub plan_window: Option<SeatPlanWindow>,
}

impl OfficialSeatSpec {
    /// The durable stamp an attempt row carries so execution re-checks the
    /// same placement dispatch checked.
    #[must_use]
    pub fn stamp(&self) -> OfficialSeatStamp {
        OfficialSeatStamp {
            route: self.route,
            unmodified_binary: self.unmodified_binary,
            approvals: self.approvals,
            dry_fallback: self.dry_fallback,
        }
    }
}

/// The seat facts persisted on a BYOA attempt payload. Labels and choices
/// only — safe to store, render, and receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficialSeatStamp {
    pub route: OfficialSeatRoute,
    pub unmodified_binary: bool,
    #[serde(default)]
    pub approvals: SeatPlacementApproval,
    #[serde(default)]
    pub dry_fallback: DrySeatFallback,
}

fn check_ref(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && value.chars().all(|c| !c.is_control())
}

/// Door check for a seat spec. Shape only; placement is separate because it
/// depends on where the seat would run.
///
/// # Errors
/// Refuses unbounded or unprintable labels and impossible plan percents.
pub fn validate_official_seat(spec: &OfficialSeatSpec) -> ByoaResult<()> {
    if !check_ref(&spec.account_ref, MAX_ACCOUNT_REF_LEN) {
        return Err(invalid(ERR_SEAT_SPEC));
    }
    if let Some(machine) = &spec.machine_ref
        && !check_ref(machine, MAX_MACHINE_REF_LEN)
    {
        return Err(invalid(ERR_SEAT_SPEC));
    }
    if let Some(store) = &spec.login_store_ref
        && !check_ref(store, MAX_LOGIN_STORE_REF_LEN)
    {
        return Err(invalid(ERR_SEAT_SPEC));
    }
    if let Some(window) = &spec.plan_window
        && window.percent_used > 100
    {
        return Err(invalid(ERR_SEAT_SPEC));
    }
    Ok(())
}

/// A request to dispatch one official seat. The connector is built by an
/// [`OfficialSeatAdapter`] first; dispatch re-validates everything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchOfficialSeat {
    pub seat: OfficialSeatSpec,
    pub connector: ByoaConnectorSpec,
    pub task_ref: Option<EntityId>,
    pub parent_attempt_id: Option<AttemptId>,
    pub run_id: Option<String>,
    pub dedupe_key: Option<String>,
    pub now: u64,
}

/// Outcome of a seat dispatch. A dry seat is an outcome, not an error:
/// parking is what the terms and the owner's default both ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfficialSeatDispatchOutcome {
    Dispatched(ByoaDispatchOutcome),
    /// Plan window spent; wait for `resets_at`. Nothing was enqueued.
    Parked {
        resets_at: u64,
    },
    /// Plan window spent; the owner's fallback routes elsewhere (local
    /// model, or capped spend the host performs under the named policy).
    /// Nothing was enqueued on the seat.
    DryFallback(DrySeatDecision),
}

/// Inputs an adapter needs to shape one seat connector.
#[derive(Debug, Clone)]
pub struct OfficialSeatInput {
    pub task: String,
    pub checkout_id: Option<CheckoutId>,
    pub egress_profile_ref: String,
    pub credential_handles: Vec<SandboxCredentialHandle>,
    /// Slug bindings for endpoint-shaped seats; ignored by CLI seats.
    pub model_slug_map: BTreeMap<String, ModelId>,
    /// Overrides the adapter's default endpoint base URL.
    pub base_url: Option<String>,
}

/// Builds the connector one official seat runs through. Adapters shape
/// config only: execution, custody, and transport stay host-owned, exactly
/// as on the generic BYOA seam.
pub trait OfficialSeatAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn route(&self) -> OfficialSeatRoute;
    /// The login the person runs themselves (argv, never a shell string).
    fn login_argv(&self) -> Vec<String> {
        self.route().login_argv()
    }
    fn connector(
        &self,
        seat: &OfficialSeatSpec,
        input: OfficialSeatInput,
    ) -> ByoaResult<ByoaConnectorSpec>;
}

fn cli_connector(
    program: &str,
    args: &[&str],
    input: OfficialSeatInput,
) -> ByoaResult<ByoaConnectorSpec> {
    let checkout_id = input.checkout_id.ok_or_else(|| invalid(ERR_SEAT_SPEC))?;
    let mut argv: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    argv.push("--".to_owned());
    argv.push(input.task);
    let connector = ByoaConnectorSpec::CliSandbox(CliSandboxSpec {
        program: program.to_owned(),
        argv,
        checkout_id,
        egress_profile_ref: input.egress_profile_ref,
        credential_handles: input.credential_handles,
    });
    super::validate::validate_connector(&connector)?;
    Ok(connector)
}

fn endpoint_connector(
    seat: &OfficialSeatSpec,
    input: OfficialSeatInput,
    default_base_url: &str,
    protocol: ByoEndpointProtocol,
) -> ByoaResult<ByoaConnectorSpec> {
    let credential_ref = seat
        .credential_ref
        .clone()
        .or_else(|| input.credential_handles.into_iter().next())
        .ok_or_else(|| invalid(ERR_SEAT_SPEC))?;
    let connector = ByoaConnectorSpec::Endpoint(ByoEndpointSpec {
        base_url: input
            .base_url
            .unwrap_or_else(|| default_base_url.to_owned()),
        credential_ref,
        protocol,
        model_slug_map: input.model_slug_map,
    });
    super::validate::validate_connector(&connector)?;
    Ok(connector)
}

/// `claude -p` over stream-json: the unmodified binary the person signed in.
pub struct ClaudeCodeSeatAdapter;
impl OfficialSeatAdapter for ClaudeCodeSeatAdapter {
    fn name(&self) -> &'static str {
        "claude-code"
    }
    fn route(&self) -> OfficialSeatRoute {
        OfficialSeatRoute::ClaudeCodeBinary
    }
    fn connector(
        &self,
        _seat: &OfficialSeatSpec,
        input: OfficialSeatInput,
    ) -> ByoaResult<ByoaConnectorSpec> {
        cli_connector("claude", &["-p", "--output-format", "stream-json"], input)
    }
}

/// The Agent-SDK seat. Subscription login through the SDK is refused until
/// Anthropic has previously approved it; the host factory realizes the SDK
/// backend behind the endpoint seam when it has.
pub struct ClaudeAgentSdkSeatAdapter;
impl OfficialSeatAdapter for ClaudeAgentSdkSeatAdapter {
    fn name(&self) -> &'static str {
        "claude-agent-sdk"
    }
    fn route(&self) -> OfficialSeatRoute {
        OfficialSeatRoute::ClaudeAgentSdkSubscription
    }
    fn connector(
        &self,
        seat: &OfficialSeatSpec,
        input: OfficialSeatInput,
    ) -> ByoaResult<ByoaConnectorSpec> {
        if !seat.approvals.anthropic_agent_sdk {
            return Err(ByoaError::SeatLoginNotApproved(
                self.route().as_str().to_owned(),
            ));
        }
        endpoint_connector(
            seat,
            input,
            ANTHROPIC_API_BASE_URL,
            ByoEndpointProtocol::AnthropicMessages,
        )
    }
}

/// Codex on a ChatGPT plan. One-shot work runs `codex exec`; a host serving
/// the seat continuously runs [`CodexSeatAdapter::server_argv`].
pub struct CodexSeatAdapter;
impl CodexSeatAdapter {
    /// The long-lived app-server surface the person signed Codex into.
    #[must_use]
    pub fn server_argv() -> Vec<String> {
        vec!["codex".into(), "app-server".into()]
    }
}
impl OfficialSeatAdapter for CodexSeatAdapter {
    fn name(&self) -> &'static str {
        "codex"
    }
    fn route(&self) -> OfficialSeatRoute {
        OfficialSeatRoute::CodexAppServerChatGptPlan
    }
    fn connector(
        &self,
        _seat: &OfficialSeatSpec,
        input: OfficialSeatInput,
    ) -> ByoaResult<ByoaConnectorSpec> {
        cli_connector("codex", &["exec", "--json"], input)
    }
}

/// Sign in with ChatGPT: our own registration, the person's plan, the
/// Responses API. Tokens persist only locally under the person's control —
/// the seat holds the custody handle for that local store, never a token.
pub struct SignInWithChatGptAdapter;
impl OfficialSeatAdapter for SignInWithChatGptAdapter {
    fn name(&self) -> &'static str {
        "chatgpt-signin"
    }
    fn route(&self) -> OfficialSeatRoute {
        OfficialSeatRoute::SignInWithChatGpt
    }
    fn connector(
        &self,
        seat: &OfficialSeatSpec,
        input: OfficialSeatInput,
    ) -> ByoaResult<ByoaConnectorSpec> {
        endpoint_connector(
            seat,
            input,
            SIWC_RESPONSES_BASE_URL,
            ByoEndpointProtocol::OpenAiCompat,
        )
    }
}

/// Grok on an API key. The only Grok seat there is: the API is billed
/// separately from any Grok subscription, so this is key custody, not a
/// login, and it runs on any runtime.
pub struct GrokApiKeySeatAdapter;
impl OfficialSeatAdapter for GrokApiKeySeatAdapter {
    fn name(&self) -> &'static str {
        "grok-api-key"
    }
    fn route(&self) -> OfficialSeatRoute {
        OfficialSeatRoute::VendorApiKey
    }
    fn connector(
        &self,
        seat: &OfficialSeatSpec,
        input: OfficialSeatInput,
    ) -> ByoaResult<ByoaConnectorSpec> {
        endpoint_connector(
            seat,
            input,
            XAI_API_BASE_URL,
            ByoEndpointProtocol::OpenAiCompat,
        )
    }
}

/// Named official-seat adapters, mirroring the Dreamer provider registry.
#[derive(Default)]
pub struct OfficialSeatRegistry {
    adapters: BTreeMap<String, Arc<dyn OfficialSeatAdapter>>,
}

impl OfficialSeatRegistry {
    pub fn register(&mut self, adapter: Arc<dyn OfficialSeatAdapter>) -> ByoaResult<()> {
        let name = adapter.name();
        if self.adapters.contains_key(name) {
            return Err(ByoaError::DuplicateSeatAdapter(name.to_owned()));
        }
        self.adapters.insert(name.to_owned(), adapter);
        Ok(())
    }

    pub fn resolve(&self, name: &str) -> ByoaResult<&dyn OfficialSeatAdapter> {
        self.adapters
            .get(name)
            .map(AsRef::as_ref)
            .ok_or_else(|| ByoaError::UnknownSeatAdapter(name.to_owned()))
    }

    /// The adapter serving `route`, when this build has one. A Grok
    /// subscription has none, by design.
    #[must_use]
    pub fn adapter_for_route(
        &self,
        route: OfficialSeatRoute,
    ) -> Option<Arc<dyn OfficialSeatAdapter>> {
        self.adapters
            .values()
            .find(|adapter| adapter.route() == route)
            .map(Arc::clone)
    }

    /// Every registered adapter name, in name order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.adapters.keys().map(String::as_str).collect()
    }

    /// Every official seat this build knows. There is no Grok-subscription
    /// adapter and no token-scraping adapter, by design.
    pub fn standard() -> Self {
        let mut registry = Self::default();
        for adapter in [
            Arc::new(ClaudeCodeSeatAdapter) as Arc<dyn OfficialSeatAdapter>,
            Arc::new(ClaudeAgentSdkSeatAdapter),
            Arc::new(CodexSeatAdapter),
            Arc::new(SignInWithChatGptAdapter),
            Arc::new(GrokApiKeySeatAdapter),
        ] {
            registry.adapters.insert(adapter.name().to_owned(), adapter);
        }
        registry
    }
}

/// PKCE S256 challenge for a verifier the person keeps locally. The
/// verifier itself never leaves their runtime; only its hash rides the
/// authorize URL.
///
/// # Errors
/// Refuses verifiers outside the RFC 7636 shape (43-128 unreserved chars).
pub fn pkce_s256_challenge(verifier: &str) -> ByoaResult<String> {
    let shaped = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    if !shaped {
        return Err(invalid(ERR_PKCE_VERIFIER));
    }
    let digest = Sha256::digest(verifier.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

/// One Sign in with ChatGPT authorize request. Our own client registration
/// (open dynamic registration for local apps); no client secret exists in a
/// PKCE public-client flow, and no token is requested by this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiwcAuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    /// From [`pkce_s256_challenge`]; the verifier stays with the person.
    pub code_challenge: String,
    pub state: String,
    pub scope: Option<String>,
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Builds the browser URL the person opens to consent. The code-for-token
/// exchange that follows is the local runtime's: tokens persist only there,
/// under the person's control, and the seat afterwards names that store by
/// custody handle.
///
/// # Errors
/// Refuses empty or unprintable request fields.
pub fn siwc_authorize_url(request: &SiwcAuthorizeRequest) -> ByoaResult<String> {
    for field in [
        &request.client_id,
        &request.redirect_uri,
        &request.code_challenge,
        &request.state,
    ] {
        if !check_ref(field, 2048) {
            return Err(invalid(ERR_SEAT_SPEC));
        }
    }
    let mut url = format!(
        "{SIWC_AUTHORIZE_ENDPOINT}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}",
        percent_encode(&request.client_id),
        percent_encode(&request.redirect_uri),
        percent_encode(&request.code_challenge),
        percent_encode(&request.state),
    );
    if let Some(scope) = &request.scope {
        if !check_ref(scope, 512) {
            return Err(invalid(ERR_SEAT_SPEC));
        }
        url.push_str("&scope=");
        url.push_str(&percent_encode(scope));
    }
    Ok(url)
}

/// How a person signs a seat in. The person always runs it themselves, on
/// the runtime the login will live on; the control plane holds nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatLoginPlan {
    pub route: OfficialSeatRoute,
    pub vendor: Option<OfficialSeatVendor>,
    /// Argv the person runs (vendor's own login), when the route has one.
    pub argv: Vec<String>,
    /// Browser URL the person opens, when the route is an OAuth flow.
    pub authorize_url: Option<String>,
    /// Always false; named so surfaces can show the posture, not imply it.
    pub control_plane_holds_token: bool,
    pub note: &'static str,
}

/// The login plan for one seat.
///
/// # Errors
/// Refuses unsupported routes and a Sign in with ChatGPT plan asked for
/// without its authorize request.
pub fn seat_login_plan(
    seat: &OfficialSeatSpec,
    siwc: Option<&SiwcAuthorizeRequest>,
) -> ByoaResult<SeatLoginPlan> {
    validate_official_seat(seat)?;
    let route = seat.route;
    let base =
        |argv: Vec<String>, authorize_url: Option<String>, note: &'static str| SeatLoginPlan {
            route,
            vendor: route.vendor(),
            argv,
            authorize_url,
            control_plane_holds_token: false,
            note,
        };
    Ok(match route {
        OfficialSeatRoute::GrokSubscription => {
            return Err(ByoaError::SeatRouteUnsupported(route.as_str().to_owned()));
        }
        OfficialSeatRoute::ClaudeCodeBinary | OfficialSeatRoute::ClaudeAgentSdkSubscription => {
            base(
                route.login_argv(),
                None,
                "run this yourself where the seat will run; the unmodified binary holds your login",
            )
        }
        OfficialSeatRoute::CodexAppServerChatGptPlan => base(
            route.login_argv(),
            None,
            "run this yourself on your own machine or self-hosted runtime",
        ),
        OfficialSeatRoute::SignInWithChatGpt => {
            let request = siwc.ok_or_else(|| invalid(ERR_SEAT_SPEC))?;
            base(
                Vec::new(),
                Some(siwc_authorize_url(request)?),
                "open this in your browser; tokens persist only locally under your control",
            )
        }
        OfficialSeatRoute::VendorApiKey => base(
            Vec::new(),
            None,
            "no login: provision the API key into custody by handle",
        ),
    })
}
