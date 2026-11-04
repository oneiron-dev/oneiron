//! Trusted experiment-selection policy rows and their narrowing rules.

use serde::{Deserialize, Serialize};

/// Campaign-specific policy knobs resolved from trusted vault manifest rows.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPolicy {
    pub expected_gain_floor: f64,
    /// Consecutive below-floor rounds before a cause-based stop.
    pub plateau_rounds: usize,
    /// Consecutive rounds without a new top-1 quality before a diversity fork.
    pub stagnation_rounds: usize,
    /// The action on top-1 stagnation, chosen by resolved vault policy.
    pub stagnation_action: StagnationAction,
    /// Escalate instead of stopping on a confirmed plateau.
    pub escalate_plateau: bool,
}

/// Row-selected response to a top-1 quality plateau.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StagnationAction {
    /// Choose the DGM maximum even if it is the current top-quality branch.
    Dgm,
    /// Exclude the top-quality branch when another parent is measured.
    Diversify,
}

/// Scope of a manifest decision row: vault, campaign, or holder in a campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPolicyScope {
    pub campaign_id: Option<String>,
    pub holder_id: Option<String>,
}

/// Vault-row choice of how campaign and holder policies compose.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionPrecedence {
    /// Campaign narrows vault, holder narrows campaign (shipped default).
    #[default]
    NestedNarrowing,
    /// Holder supersedes the campaign row, but cannot widen the vault row.
    HolderUnderVault,
}

/// A policy-manifest row. Every row is capped by the vault row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPolicyRow {
    pub scope: SelectionPolicyScope,
    pub policy: SelectionPolicy,
    /// Only the vault row may select precedence; absent means nested narrowing.
    #[serde(default)]
    pub precedence: SelectionPrecedence,
}

impl SelectionPolicyRow {
    pub(crate) fn valid(&self) -> bool {
        self.scope
            .campaign_id
            .as_ref()
            .is_none_or(|id| !id.trim().is_empty())
            && self
                .scope
                .holder_id
                .as_ref()
                .is_none_or(|id| !id.trim().is_empty())
            && (self.scope.holder_id.is_none() || self.scope.campaign_id.is_some())
            && (self.scope.campaign_id.is_none()
                || self.precedence == SelectionPrecedence::NestedNarrowing)
            && self.policy.valid()
    }
}

impl SelectionPolicy {
    pub(crate) fn valid(self) -> bool {
        self.expected_gain_floor.is_finite()
            && self.expected_gain_floor >= 0.0
            && self.plateau_rounds > 0
            && self.stagnation_rounds > 0
    }

    /// Narrower rows cannot lower the gain floor or delay a check. A vault
    /// request to diversify cannot be undone by a holder-scoped row.
    pub(crate) fn narrow(self, row: Self) -> Self {
        Self {
            expected_gain_floor: self.expected_gain_floor.max(row.expected_gain_floor),
            plateau_rounds: self.plateau_rounds.min(row.plateau_rounds),
            stagnation_rounds: self.stagnation_rounds.min(row.stagnation_rounds),
            stagnation_action: if self.stagnation_action == StagnationAction::Diversify
                || row.stagnation_action == StagnationAction::Diversify
            {
                StagnationAction::Diversify
            } else {
                StagnationAction::Dgm
            },
            escalate_plateau: self.escalate_plateau || row.escalate_plateau,
        }
    }
}
