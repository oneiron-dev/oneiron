//! Moved from `crates/oneiron/src/dispatch_byoa/official_seats.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_model::llm::BudgetExhaustionPolicy;
use serde::Deserialize;
use serde::Serialize;

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

/// The digest a seat's `machine_ref` label is stamped as: of the label
/// trimmed and lowercased, so a machine id written in either case names the
/// same machine.
pub fn seat_machine_digest(label: &str) -> [u8; 32] {
    *blake3::hash(label.trim().to_lowercase().as_bytes()).as_bytes()
}
