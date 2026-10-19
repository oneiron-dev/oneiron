//! Owner-chosen runner seats (OF-137): which named runner takes a Dreamer's
//! work under whose sign-in, and where the work goes when that seat is spent.
//!
//! A seat names a runner registered in the [`ProviderAdapterRegistry`] and
//! how it signs in. A vendor login stays with the official CLI on the runtime
//! that runs it, so a login seat names no credential at all: the control
//! plane never holds a vendor login. An API-key seat names custody handles,
//! never bytes. Where a login may run follows the runtime contract (ruled
//! 2026-10-10): Claude Code under the person's own sign-in runs on any
//! runtime, their hosted vault VM included; every other vendor login runs
//! only on the person's own machine or self-hosted runtime; an API key runs
//! anywhere.
//!
//! A spent seat is read from the runner's own structured error output with
//! the words an API refusal is read by ([`crate::llm::limit`]). What happens
//! next is the owner's pick in [`OnSeatSpent`]; nothing spends by default.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::attempt_queue::AttemptId;
use crate::checkout::CheckoutId;
use crate::code_sandbox::SandboxCredentialHandle;
use crate::entity_id::EntityId;
use crate::llm::{RetryableLlmError, SpentKind, limit};

use super::connector::{ByoaConnectorSpec, ByoaDispatchOutcome, CliSandboxSpec};
use super::error::{
    ByoaResult, ERR_SEAT_COUNT, ERR_SEAT_INDEX, ERR_SEAT_KEY_HANDLE, ERR_SEAT_LOGIN_HANDLE, invalid,
};
use super::exhaust::{ByoaExhaust, ByoaTerminalReceipt};
use super::provider::{CLAUDE_CODE_PROGRAM, DreamerProviderInput, ProviderAdapterRegistry};

/// The most seats one policy orders.
pub const MAX_RUNNER_SEATS: usize = 8;

/// Dedupe prefix of the attempt a spent seat hands its work to. With the
/// spent attempt and the next seat's index it makes a replayed route find
/// the child it already dispatched instead of dispatching another.
pub const RUNNER_SEAT_DEDUPE_PREFIX: &str = "byoa.seat:";

/// The trailing bytes of one exhaust stream read for a spent seat. A CLI
/// prints its terminal error last.
const SPENT_SCAN_BYTES: usize = 64 * 1024;

/// The most lines, from the end, read for a spent seat.
const SPENT_SCAN_LINES: usize = 64;

/// The longest line read as one structured event.
const SPENT_EVENT_BYTES: usize = 16 * 1024;

/// A reset an error names as a Unix-seconds suffix ("…limit reached|1760000000")
/// is at least this, so a small number after a bar is never read as one.
const MIN_EPOCH_RESET: u64 = 1_000_000_000;

/// Where a vendor login may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginPlacement {
    /// Any runtime, the person's hosted vault VM included.
    AnyRuntime,
    /// Only the person's own machine or self-hosted runtime.
    OwnRuntime,
}

/// Where a login behind `connector` may run. Only the unmodified Claude Code
/// binary runs anywhere. A Codex plan login, Sign in with ChatGPT and every
/// other login stay on the person's own runtime until the vendor allows more.
#[must_use]
pub fn login_placement(connector: &ByoaConnectorSpec) -> LoginPlacement {
    match connector {
        ByoaConnectorSpec::CliSandbox(spec) if spec.program == CLAUDE_CODE_PROGRAM => {
            LoginPlacement::AnyRuntime
        }
        _ => LoginPlacement::OwnRuntime,
    }
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
    /// Refuses an empty or oversized order, a runner the registry does not
    /// know, a login seat that names a credential, and a key seat that names
    /// none.
    ///
    /// # Errors
    /// Returns the first seat's refusal.
    pub fn validate(&self, registry: &ProviderAdapterRegistry) -> ByoaResult<()> {
        if self.seats.is_empty() || self.seats.len() > MAX_RUNNER_SEATS {
            return Err(invalid(ERR_SEAT_COUNT));
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
/// text is never one. Only each stream's tail is read, however long it runs.
///
/// # Errors
///
/// Returns [`super::ByoaError::Store`] when a spooled stream's tail cannot be
/// read.
pub fn spent_seat_in(exhaust: &ByoaExhaust) -> ByoaResult<Option<SeatSpent>> {
    for stream in [&exhaust.stdout, &exhaust.stderr] {
        let tail = stream.tail(SPENT_SCAN_BYTES)?;
        let spent = String::from_utf8_lossy(&tail)
            .lines()
            .rev()
            .take(SPENT_SCAN_LINES)
            .find_map(spent_in_line);
        if spent.is_some() {
            return Ok(spent);
        }
    }
    Ok(None)
}

fn spent_in_line(line: &str) -> Option<SeatSpent> {
    let line = line.trim();
    if !line.starts_with('{') || line.len() > SPENT_EVENT_BYTES {
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
