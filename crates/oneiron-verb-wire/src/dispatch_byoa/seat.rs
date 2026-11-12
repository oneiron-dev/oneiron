//! Moved from `crates/oneiron/src/dispatch_byoa/seat.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_model::llm::RetryableLlmError;
use oneiron_model::llm::SpentKind;
use serde::Deserialize;
use serde::Serialize;

/// The approval OpenAI's hosted-login bounds name.
pub const OPENAI_HOSTED_PLAN_APPROVAL: &str =
    "OpenAI hosted plan approval, OC2 (openai_hosted_plan)";

/// How a seat signs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SeatAuth {
    /// The person's own sign-in, held by the official CLI on the runtime it
    /// runs on. The seat names no credential.
    VendorLogin,
    /// The person's own API key, named by custody handles.
    ApiKey,
}

/// What a spent seat does with the work. The owner picks; the default spends
/// nothing.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
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

/// A spent seat: a rate limit (no kind), or a spent usage window or credit,
/// with the waits its refusal named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
