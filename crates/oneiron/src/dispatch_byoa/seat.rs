//! Owner-chosen runner seats (OF-137): which named runner takes a Dreamer's
//! work under whose sign-in, and where the work goes when that seat is spent.
//!
//! A seat names a runner registered in the [`ProviderAdapterRegistry`] and
//! how it signs in. A vendor login stays with the official CLI on the runtime
//! that runs it, so a login seat names no credential at all: the control
//! plane never holds a vendor login. An API-key seat names custody handles,
//! never bytes. A login runs on any runtime, the person's hosted vault VM
//! included, unless a provider's terms keep it off a hosted node
//! ([`hosted_seat_bound`], ruled 2026-10-19): today OpenAI's, for a
//! ChatGPT-plan Codex or Sign in with ChatGPT login until OpenAI approves
//! hosted use. An API key runs anywhere.
//!
//! A spent seat is read from the runner's own structured error output with
//! the words an API refusal is read by ([`crate::llm::limit`]). What happens
//! next is the owner's pick in [`OnSeatSpent`]; nothing spends by default.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};

use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::attempt_queue::AttemptId;
use crate::checkout::CheckoutId;
use crate::code_sandbox::SandboxCredentialHandle;
use crate::config::HostingPrivacyPosture;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::llm::{RetryableLlmError, SpentKind, limit};

use super::connector::{ByoaConnectorSpec, ByoaDispatchOutcome, CliSandboxSpec};
use super::error::{
    ByoaError, ByoaResult, ERR_SEAT_EMPTY, ERR_SEAT_INDEX, ERR_SEAT_KEY_HANDLE,
    ERR_SEAT_LOGIN_HANDLE, invalid,
};
use super::exhaust::{ByoaExhaust, ByoaTerminalReceipt};
use super::official_seats::{OfficialSeatRoute, SIWC_RESPONSES_BASE_URL, SeatPlacementApproval};
use super::provider::{CODEX_PROGRAM, DreamerProviderInput, ProviderAdapterRegistry};

/// Dedupe prefix of the attempt a spent seat hands its work to. With the
/// spent attempt and the next seat's index it makes a replayed route find
/// the child it already dispatched instead of dispatching another.
pub const RUNNER_SEAT_DEDUPE_PREFIX: &str = "byoa.seat:";

/// A reset an error names as a Unix-seconds suffix ("…limit reached|1760000000")
/// is at least this, so a small number after a bar is never read as one.
const MIN_EPOCH_RESET: u64 = 1_000_000_000;

/// Why a login may not run on a hosted node. Each bound names whose it is,
/// and the same act works self-hosted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostedSeatBound {
    /// A provider's terms keep the login off a hosted node until the
    /// provider approves hosted use.
    ProviderTerms {
        vendor: &'static str,
        terms_ref: &'static str,
        approval_ref: &'static str,
    },
}

impl HostedSeatBound {
    /// The bound's kind, as a surface projects it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::ProviderTerms { .. } => "provider_terms",
        }
    }

    /// Whether the same act works self-hosted: always, since the bound holds
    /// only on a hosted node.
    #[must_use]
    pub const fn works_self_hosted(&self) -> bool {
        true
    }
}

impl std::fmt::Display for HostedSeatBound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProviderTerms {
                vendor,
                terms_ref,
                approval_ref,
            } => write!(
                f,
                "Hosted placement is refused by {vendor}'s provider terms ({terms_ref}); \
                 required approval: {approval_ref}. The same act works self-hosted."
            ),
        }
    }
}

/// The exact identity a hosted-login prohibition is keyed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatIdentity<'a> {
    /// A CLI runner, by its program.
    CliProgram(&'a str),
    /// An endpoint, by its base URL.
    EndpointBase(&'a str),
    /// An official seat route.
    OfficialRoute(OfficialSeatRoute),
}

impl<'a> SeatIdentity<'a> {
    /// The identity a generic connector carries: a CLI runner's executable
    /// name, or an endpoint's base URL without a trailing slash. An MCP
    /// attach names none.
    #[must_use]
    pub fn of(connector: &'a ByoaConnectorSpec) -> Option<Self> {
        match connector {
            ByoaConnectorSpec::CliSandbox(spec) => Some(Self::CliProgram(
                std::path::Path::new(&spec.program)
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or(spec.program.as_str()),
            )),
            ByoaConnectorSpec::Endpoint(spec) => {
                Some(Self::EndpointBase(spec.base_url.trim_end_matches('/')))
            }
            ByoaConnectorSpec::ProtocolAttach(_) => None,
        }
    }
}

/// The approval OpenAI's hosted-login bounds name.
const OPENAI_HOSTED_PLAN_APPROVAL: &str = "OpenAI hosted plan approval, OC2 (openai_hosted_plan)";

/// OpenAI's Codex app-server docs: app-server authentication was never
/// permitted for commercial or hosted services.
const OPENAI_CODEX_APP_SERVER: HostedSeatBound = HostedSeatBound::ProviderTerms {
    vendor: "OpenAI",
    terms_ref: "Codex app-server docs, RESEARCH-0382 O21",
    approval_ref: OPENAI_HOSTED_PLAN_APPROVAL,
};

/// OpenAI's Sign in with ChatGPT Terms, and its interest form for a remotely
/// hosted app.
const OPENAI_SIGN_IN_WITH_CHATGPT: HostedSeatBound = HostedSeatBound::ProviderTerms {
    vendor: "OpenAI",
    terms_ref: "Sign in with ChatGPT Terms and hosted-app interest form, RESEARCH-0382 O5/O9",
    approval_ref: OPENAI_HOSTED_PLAN_APPROVAL,
};

/// One hosted-login prohibition: the exact identity it names, its bound,
/// and the vendor approval that lifts it on a path that carries approvals.
struct HostedLoginRow {
    identity: SeatIdentity<'static>,
    bound: HostedSeatBound,
    lifted_by: fn(SeatPlacementApproval) -> bool,
}

fn openai_hosted_plan(approvals: SeatPlacementApproval) -> bool {
    approvals.openai_hosted_plan
}

/// Every hosted-login prohibition. A login no row names runs on any runtime.
const HOSTED_LOGIN_PROHIBITIONS: [HostedLoginRow; 4] = [
    // A ChatGPT-plan login behind the Codex CLI, as a plain runner or as
    // the official Codex seat.
    HostedLoginRow {
        identity: SeatIdentity::CliProgram(CODEX_PROGRAM),
        bound: OPENAI_CODEX_APP_SERVER,
        lifted_by: openai_hosted_plan,
    },
    HostedLoginRow {
        identity: SeatIdentity::OfficialRoute(OfficialSeatRoute::CodexAppServerChatGptPlan),
        bound: OPENAI_CODEX_APP_SERVER,
        lifted_by: openai_hosted_plan,
    },
    // Sign in with ChatGPT, as the official seat or as the endpoint its
    // registered adapter shapes.
    HostedLoginRow {
        identity: SeatIdentity::OfficialRoute(OfficialSeatRoute::SignInWithChatGpt),
        bound: OPENAI_SIGN_IN_WITH_CHATGPT,
        lifted_by: openai_hosted_plan,
    },
    HostedLoginRow {
        identity: SeatIdentity::EndpointBase(SIWC_RESPONSES_BASE_URL),
        bound: OPENAI_SIGN_IN_WITH_CHATGPT,
        lifted_by: openai_hosted_plan,
    },
];

/// The hosted-only bound that keeps a login off this runtime, if one does:
/// a user login on a hosted posture whose exact identity a prohibition row
/// names, unless the path's vendor `approvals` lift it. The generic runner
/// path carries no approvals. A miss is no prohibition.
#[must_use]
pub fn hosted_seat_bound(
    identity: Option<SeatIdentity<'_>>,
    user_login: bool,
    posture: HostingPrivacyPosture,
    approvals: Option<SeatPlacementApproval>,
) -> Option<HostedSeatBound> {
    if !user_login || posture != HostingPrivacyPosture::Hosted {
        return None;
    }
    let identity = identity?;
    HOSTED_LOGIN_PROHIBITIONS
        .iter()
        .find(|row| row.identity == identity)
        .filter(|row| !approvals.is_some_and(row.lifted_by))
        .map(|row| row.bound)
}

/// A fallback seat a route passed over because a hosted-only bound keeps
/// its login off this runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRunnerSeat {
    /// The seat's index in the owner's order.
    pub seat: usize,
    /// The runner the seat names.
    pub runner: String,
    pub bound: HostedSeatBound,
}

/// The passed-over seats in words, for a park reason: empty when none was,
/// else each seat with its runner and its bound, in the owner's order.
#[must_use]
pub fn skipped_seats_note(skipped: &[SkippedRunnerSeat]) -> String {
    skipped
        .iter()
        .map(|skip| {
            format!(
                "; seat {} ({}) skipped: {}",
                skip.seat, skip.runner, skip.bound
            )
        })
        .collect()
}

/// How a seat signs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeatAuth {
    /// The person's own sign-in, held by the official CLI on the runtime it
    /// runs on. The seat names no credential.
    VendorLogin,
    /// The person's own API key, named by custody handles.
    ApiKey,
}

/// One owner-chosen seat: a registered runner and how it signs in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerSeat {
    /// A runner name the registry resolves ("claude-code", "codex", …).
    pub runner: String,
    pub auth: SeatAuth,
    /// The host egress profile the runner's network reach goes through.
    pub egress_profile_ref: String,
    /// Custody handles of an API-key seat. Empty for a login seat.
    #[serde(default, with = "super::connector::credential_handle_vec_wire")]
    pub credential_handles: Vec<SandboxCredentialHandle>,
}

impl RunnerSeat {
    /// Whether this seat runs under a vendor login.
    #[must_use]
    pub const fn logs_in(&self) -> bool {
        matches!(self.auth, SeatAuth::VendorLogin)
    }

    fn validate(&self, registry: &ProviderAdapterRegistry) -> ByoaResult<()> {
        registry.resolve(&self.runner)?;
        match (self.auth, self.credential_handles.is_empty()) {
            (SeatAuth::VendorLogin, false) => Err(invalid(ERR_SEAT_LOGIN_HANDLE)),
            (SeatAuth::ApiKey, true) => Err(invalid(ERR_SEAT_KEY_HANDLE)),
            _ => Ok(()),
        }
    }

    pub(super) fn connector(
        &self,
        registry: &ProviderAdapterRegistry,
        task: String,
        checkout_id: CheckoutId,
    ) -> ByoaResult<ByoaConnectorSpec> {
        registry
            .resolve(&self.runner)?
            .connector(DreamerProviderInput {
                task,
                checkout_id,
                egress_profile_ref: self.egress_profile_ref.clone(),
                credential_handles: self.credential_handles.clone(),
            })
    }
}

/// What a spent seat does with the work. The owner picks; the default spends
/// nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnSeatSpent {
    /// Park the work until the seat is back. Spent credit waits for the owner.
    #[default]
    Stop,
    /// Hand the work to the next seat in the owner's order that this runtime
    /// may run. With none left it parks as [`Self::Stop`] does.
    NextSeat,
    /// Hand the work back to the Dreamer's own model roles, under their own
    /// admission, budget and privacy rules.
    InternalModels,
}

/// The owner's ordered seats and what a spent one does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerSeatPolicy {
    pub seats: Vec<RunnerSeat>,
    #[serde(default)]
    pub on_spent: OnSeatSpent,
}

impl RunnerSeatPolicy {
    /// Refuses an empty order, a runner the registry does not know, a login
    /// seat that names a credential, and a key seat that names none. An
    /// order holds as many seats as the owner lists.
    ///
    /// # Errors
    /// Returns the first seat's refusal.
    pub fn validate(&self, registry: &ProviderAdapterRegistry) -> ByoaResult<()> {
        if self.seats.is_empty() {
            return Err(invalid(ERR_SEAT_EMPTY));
        }
        self.seats
            .iter()
            .try_for_each(|seat| seat.validate(registry))
    }

    /// The seat at `index`.
    ///
    /// # Errors
    /// Refuses an index past the order.
    pub fn seat(&self, index: usize) -> ByoaResult<&RunnerSeat> {
        self.seats.get(index).ok_or_else(|| invalid(ERR_SEAT_INDEX))
    }
}

/// The work one runner seat takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerWork {
    pub task: String,
    pub checkout_id: CheckoutId,
    pub task_ref: Option<EntityId>,
    pub parent_attempt_id: Option<AttemptId>,
    pub run_id: Option<String>,
    pub dedupe_key: Option<String>,
    pub now: u64,
}

/// A spent seat: a rate limit (no kind), or a spent usage window or credit,
/// with the waits its refusal named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatSpent {
    pub kind: Option<SpentKind>,
    pub retry_after: Option<u64>,
    pub resets_at: Vec<u64>,
}

impl SeatSpent {
    /// The spent seat a typed provider refusal stands for. Other retryable
    /// errors are not a spent seat.
    #[must_use]
    pub fn from_retryable(error: &RetryableLlmError) -> Option<Self> {
        match error {
            RetryableLlmError::RateLimited {
                retry_after,
                resets_at,
            } => Some(Self {
                kind: None,
                retry_after: *retry_after,
                resets_at: resets_at.clone(),
            }),
            RetryableLlmError::QuotaSpent {
                kind,
                retry_after,
                resets_at,
            } => Some(Self {
                kind: Some(*kind),
                retry_after: *retry_after,
                resets_at: resets_at.clone(),
            }),
            _ => None,
        }
    }

    /// When a parked seat is back: the first reset still ahead of `now`, else
    /// `now` plus the wait it asked. Spent credit, and a refusal that names
    /// neither, wait for the owner.
    #[must_use]
    pub fn back_at(&self, now: u64) -> Option<u64> {
        if self.kind == Some(SpentKind::Credit) {
            return None;
        }
        self.resets_at
            .iter()
            .copied()
            .find(|at| *at > now)
            .or_else(|| self.retry_after.map(|wait| now.saturating_add(wait)))
    }

    /// The failure reason a spent seat's capture records.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self.kind {
            None => "runner seat rate limited",
            Some(SpentKind::Window) => "runner seat usage window spent",
            Some(SpentKind::Credit) => "runner seat credit spent",
        }
    }
}

/// Reads a runner's exhaust for a spent seat: a structured error event the
/// CLI printed (an `error` field, a `type: "error"` event, or a result
/// flagged `is_error`) whose words read as a limit. A nonzero exit or free
/// text is never one. Each stream is read whole from its start, stdout
/// first, one complete event at a time.
///
/// # Errors
///
/// Returns [`super::ByoaError::Store`] when a spooled stream cannot be read.
pub fn spent_seat_in(exhaust: &ByoaExhaust) -> ByoaResult<Option<SeatSpent>> {
    for stream in [&exhaust.stdout, &exhaust.stderr] {
        if let Some(spent) = spent_seat_from_reader(stream.reader())? {
            return Ok(Some(spent));
        }
    }
    Ok(None)
}

/// Reads one exhaust stream from its start for a spent seat. Each line is
/// one event, read whole however many buffer reads it spans; a line that
/// does not open with `{` past its leading blanks is passed over without
/// being held. The last event that reads as a limit wins. A buffer is a
/// traversal unit only: no event is skipped for its length.
///
/// # Errors
///
/// Returns [`super::ByoaError::Store`] when the stream cannot be read.
pub(crate) fn spent_seat_from_reader(reader: impl Read) -> ByoaResult<Option<SeatSpent>> {
    let mut reader = BufReader::new(reader);
    let mut event = Vec::new();
    let mut spent = None;
    loop {
        let buffered = reader.fill_buf().map_err(read_error)?;
        let Some(&first) = buffered.first() else {
            return Ok(spent);
        };
        if first.is_ascii_whitespace() {
            let blanks = buffered
                .iter()
                .take_while(|byte| byte.is_ascii_whitespace())
                .count();
            reader.consume(blanks);
        } else if first == b'{' {
            event.clear();
            reader.read_until(b'\n', &mut event).map_err(read_error)?;
            if let Some(found) = spent_in_line(&String::from_utf8_lossy(&event)) {
                spent = Some(found);
            }
        } else {
            skip_line(&mut reader)?;
        }
    }
}

/// Passes over the rest of one line without holding it.
fn skip_line(reader: &mut impl BufRead) -> ByoaResult<()> {
    loop {
        let buffered = reader.fill_buf().map_err(read_error)?;
        if buffered.is_empty() {
            return Ok(());
        }
        let (take, ends) = buffered
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or((buffered.len(), false), |at| (at + 1, true));
        reader.consume(take);
        if ends {
            return Ok(());
        }
    }
}

fn read_error(error: std::io::Error) -> ByoaError {
    ByoaError::Store(Error::from(error))
}

fn spent_in_line(line: &str) -> Option<SeatSpent> {
    let line = line.trim();
    if !line.starts_with('{') {
        return None;
    }
    let event: JsonValue = serde_json::from_str(line).ok()?;
    let body = error_body(&event)?;
    if !limit::reads_as_limit(&body) {
        return None;
    }
    let mut spent = SeatSpent::from_retryable(&limit::limit_refusal(429, &BTreeMap::new(), &body))?;
    spent.resets_at.extend(epoch_reset(&body));
    Some(spent)
}

/// The error an event carries, shaped as an API error body.
fn error_body(event: &JsonValue) -> Option<JsonValue> {
    if event.get("error").is_some_and(|error| !error.is_null()) {
        return Some(event.clone());
    }
    if event.get("type").and_then(JsonValue::as_str) == Some("error") {
        return Some(json!({ "error": event }));
    }
    if event.get("is_error").and_then(JsonValue::as_bool) == Some(true) {
        let message = event.get("result").and_then(JsonValue::as_str)?;
        return Some(json!({ "error": { "message": message } }));
    }
    None
}

/// A reset an error message names as a Unix-seconds suffix after a bar.
fn epoch_reset(body: &JsonValue) -> Option<u64> {
    let error = body.get("error").unwrap_or(body);
    let message = error
        .as_str()
        .or_else(|| error.get("message").and_then(JsonValue::as_str))?;
    let (_, suffix) = message.rsplit_once('|')?;
    suffix
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|at| *at >= MIN_EPOCH_RESET)
}

/// The task a registered runner was handed: the argument after its `--`.
pub(super) fn runner_task(spec: &CliSandboxSpec) -> Option<&str> {
    match spec.argv.as_slice() {
        [.., separator, task] if separator == "--" => Some(task.as_str()),
        _ => None,
    }
}

/// Where a runner attempt's work went once its terminal exhaust was captured.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeatRoute {
    /// The seat was not spent; the capture stands as the run's end.
    Settled(ByoaTerminalReceipt),
    /// The work waits for the seat. `until` is when it is back; none waits
    /// for the owner.
    Park {
        receipt: ByoaTerminalReceipt,
        spent: SeatSpent,
        until: Option<u64>,
    },
    /// The next seat took the work as a child of the spent attempt.
    NextSeat {
        receipt: ByoaTerminalReceipt,
        spent: SeatSpent,
        seat: usize,
        outcome: ByoaDispatchOutcome,
    },
    /// The work goes back to the Dreamer's own model roles.
    InternalModels {
        receipt: ByoaTerminalReceipt,
        spent: SeatSpent,
    },
}

impl SeatRoute {
    /// The capture every arm carries.
    #[must_use]
    pub const fn receipt(&self) -> &ByoaTerminalReceipt {
        match self {
            Self::Settled(receipt)
            | Self::Park { receipt, .. }
            | Self::NextSeat { receipt, .. }
            | Self::InternalModels { receipt, .. } => receipt,
        }
    }
}
