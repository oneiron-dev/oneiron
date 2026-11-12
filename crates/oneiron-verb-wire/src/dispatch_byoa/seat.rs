//! Moved from `crates/oneiron/src/dispatch_byoa/seat.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_model::llm::RetryableLlmError;
use oneiron_model::llm::SpentKind;
use oneiron_model::llm::limit;
use serde::Deserialize;
use serde::Serialize;

/// Why a login may not run on a hosted node. Each bound names whose it is,
/// and the same act works self-hosted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
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

impl<'de> Deserialize<'de> for HostedSeatBound {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Wire {
            ProviderTerms {
                vendor: String,
                terms_ref: String,
                approval_ref: String,
            },
        }
        let Wire::ProviderTerms {
            vendor,
            terms_ref,
            approval_ref,
        } = Wire::deserialize(deserializer)?;
        for bound in [OPENAI_CODEX_APP_SERVER, OPENAI_SIGN_IN_WITH_CHATGPT] {
            let Self::ProviderTerms {
                vendor: known_vendor,
                terms_ref: known_terms,
                approval_ref: known_approval,
            } = bound;
            if vendor == known_vendor && terms_ref == known_terms && approval_ref == known_approval
            {
                return Ok(bound);
            }
        }
        Err(serde::de::Error::custom("unknown hosted seat bound"))
    }
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

/// The approval OpenAI's hosted-login bounds name.
pub const OPENAI_HOSTED_PLAN_APPROVAL: &str =
    "OpenAI hosted plan approval, OC2 (openai_hosted_plan)";

/// OpenAI's Codex app-server docs: app-server authentication was never
/// permitted for commercial or hosted services.
pub const OPENAI_CODEX_APP_SERVER: HostedSeatBound = HostedSeatBound::ProviderTerms {
    vendor: "OpenAI",
    terms_ref: "Codex app-server docs, RESEARCH-0382 O21",
    approval_ref: OPENAI_HOSTED_PLAN_APPROVAL,
};

/// OpenAI's Sign in with ChatGPT Terms, and its interest form for a remotely
/// hosted app.
pub const OPENAI_SIGN_IN_WITH_CHATGPT: HostedSeatBound = HostedSeatBound::ProviderTerms {
    vendor: "OpenAI",
    terms_ref: "Sign in with ChatGPT Terms and hosted-app interest form, RESEARCH-0382 O5/O9",
    approval_ref: OPENAI_HOSTED_PLAN_APPROVAL,
};

/// Why a route passed over a seat in the owner's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SeatPassedOver {
    /// A hosted-only bound keeps the seat's login off this runtime.
    Hosted(HostedSeatBound),
    /// The seat's quota view ([`super::runner_seat_quotas`]) shows it spent
    /// and not back yet (FIX 7453): back at `back_at`, or `None` while it
    /// waits for the owner.
    Spent { back_at: Option<u64> },
    /// A CLI seat, and the work's original request record is erased or
    /// unreadable, or none was kept (FIX 7449): the seat has no task to run.
    TaskUnreadable,
    /// A CLI seat whose argv cannot carry the work's task: a control
    /// character in it (FIX 7505). Only an ordered
    /// search passes a seat over for this; an explicit seat keeps its
    /// refusal.
    CliArgvShape,
}

impl std::fmt::Display for SeatPassedOver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hosted(bound) => write!(f, "{bound}"),
            Self::Spent { back_at: Some(at) } => write!(f, "its quota is spent until {at}"),
            Self::Spent { back_at: None } => {
                f.write_str("its quota is spent and waits for the owner")
            }
            Self::TaskUnreadable => f.write_str(
                "the work's task record is erased or unreadable, so this CLI seat has no task",
            ),
            Self::CliArgvShape => f.write_str(
                "this CLI seat's argv cannot carry the work's task (a control character)",
            ),
        }
    }
}

/// A fallback seat a route passed over, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedRunnerSeat {
    /// The seat's index in the owner's order.
    pub seat: usize,
    /// The runner the seat names.
    pub runner: String,
    /// Why the route passed it over.
    pub reason: SeatPassedOver,
}

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
