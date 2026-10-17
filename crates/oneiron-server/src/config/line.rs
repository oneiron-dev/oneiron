//! `[line]`: the plan of the LINE Official Account the built-in LINE pack
//! serves (OF-519). File-only, like `[browser]`. Absent means a free
//! account at LINE's free monthly push allowance.
//!
//! ```toml
//! [line]
//! plan = "paid"                   # free | paid | enterprise
//! monthly_push_allowance = 5000   # required for paid and enterprise
//! ```
//!
//! The allowance is a question, never a refusal: a push past it asks
//! whether everything is okay (OF-520) and still goes.

use oneiron::channel_identity_provider::{
    DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE, LineOfficialAccountAdapterConfig,
    LineOfficialAccountPlanTier,
};
use serde::Deserialize;

/// The LINE Official Account's plan and the pushes it includes each month.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineConfig {
    /// `free`, `paid` or `enterprise`.
    pub plan: LineOfficialAccountPlanTier,
    /// Pushes the plan includes each month. LINE sets it per account for a
    /// paid or enterprise plan, so those must name it; a free plan defaults
    /// to LINE's free allowance.
    #[serde(default)]
    pub monthly_push_allowance: Option<u32>,
}

impl Default for LineConfig {
    fn default() -> Self {
        Self {
            plan: LineOfficialAccountPlanTier::Free,
            monthly_push_allowance: None,
        }
    }
}

impl LineConfig {
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        match (self.plan, self.monthly_push_allowance) {
            (_, Some(0)) => anyhow::bail!("line.monthly_push_allowance must be at least 1"),
            (LineOfficialAccountPlanTier::Free, _) | (_, Some(_)) => Ok(()),
            (plan, None) => anyhow::bail!(
                "line.plan = \"{}\" needs line.monthly_push_allowance: LINE sets it per account",
                plan.as_str()
            ),
        }
    }

    /// The pushes the plan includes each month.
    #[must_use]
    pub fn monthly_push_allowance(&self) -> u32 {
        self.monthly_push_allowance
            .unwrap_or(DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE)
    }

    /// The LINE adapter's config for the bot `destination` under this plan.
    ///
    /// # Errors
    /// The destination is not a LINE bot id, or a paid or enterprise plan
    /// names no allowance.
    pub fn adapter_config(
        &self,
        destination: impl Into<String>,
    ) -> oneiron::Result<LineOfficialAccountAdapterConfig> {
        match self.monthly_push_allowance {
            Some(allowance) => LineOfficialAccountAdapterConfig::with_monthly_push_allowance(
                destination,
                self.plan,
                allowance,
            ),
            None => LineOfficialAccountAdapterConfig::new(destination, self.plan),
        }
    }
}
