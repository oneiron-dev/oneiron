//! Vault-resident Dreamer failure decisions; these restrict downstream use, never grant authority.

use rmpv::Value;

use super::LlmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamerFailureClass {
    Retryable,
    Fatal,
    Budget,
}

impl DreamerFailureClass {
    fn from_str(value: &str) -> Option<Self> {
        match value {
            "retryable" => Some(Self::Retryable),
            "fatal" => Some(Self::Fatal),
            "budget" => Some(Self::Budget),
            _ => None,
        }
    }

    pub fn of(error: &LlmError) -> Self {
        match error {
            LlmError::Retryable(_) => Self::Retryable,
            LlmError::Fatal(_) => Self::Fatal,
            LlmError::BudgetDenied(_) => Self::Budget,
        }
    }
}

/// Call routing is the L6 step contract, not a permission to change model mid-seat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamerFailureRoute {
    Retry,
    Fallback,
    BudgetTrap,
}

impl DreamerFailureClass {
    pub const fn route(self) -> DreamerFailureRoute {
        match self {
            Self::Retryable => DreamerFailureRoute::Retry,
            Self::Fatal => DreamerFailureRoute::Fallback,
            Self::Budget => DreamerFailureRoute::BudgetTrap,
        }
    }
}

/// Policy composition is itself authored vault data, not an engine choice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum DreamerFailurePrecedence {
    #[default]
    NestedNarrowing,
    HolderOverrideCappedAtVault,
}

impl DreamerFailurePrecedence {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "nested_narrowing" => Some(Self::NestedNarrowing),
            "holder_override_capped_at_vault" => Some(Self::HolderOverrideCappedAtVault),
            _ => None,
        }
    }

    pub(crate) fn restrict(self, other: Self) -> Self {
        if self == Self::NestedNarrowing || other == Self::NestedNarrowing {
            Self::NestedNarrowing
        } else {
            Self::HolderOverrideCappedAtVault
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamerFailureDecision {
    pub class: DreamerFailureClass,
    pub route: DreamerFailureRoute,
    /// Effective manifest default; a holder choice cannot exceed the vault cap.
    pub consolidation_eligible: bool,
    pub effector_eligible: bool,
    pub(crate) consolidation_ceiling: bool,
    pub(crate) effector_ceiling: bool,
    pub(crate) precedence: DreamerFailurePrecedence,
}

impl DreamerFailureDecision {
    pub(crate) fn consolidation_with_stage(self, stage: Option<bool>) -> bool {
        self.compose(
            stage,
            self.consolidation_eligible,
            self.consolidation_ceiling,
        )
    }

    pub(crate) fn effector_with_stage(self, stage: Option<bool>) -> bool {
        self.compose(stage, self.effector_eligible, self.effector_ceiling)
    }

    fn compose(self, stage: Option<bool>, default: bool, ceiling: bool) -> bool {
        ceiling
            && match (self.precedence, stage) {
                (DreamerFailurePrecedence::NestedNarrowing, Some(choice)) => default && choice,
                (DreamerFailurePrecedence::HolderOverrideCappedAtVault, Some(choice)) => choice,
                (_, None) => default,
            }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DreamerFailureRule {
    pub(crate) class: DreamerFailureClass,
    /// Vault ceilings. A true ceiling is not an effect or promotion grant.
    pub(crate) consolidation_eligible: bool,
    pub(crate) effector_eligible: bool,
    /// Shipped/owner-authored default when no stage choice is present.
    pub(crate) default_consolidation_eligible: bool,
    pub(crate) default_effector_eligible: bool,
}

/// Strictly parse three optional class rows. No unknown or duplicate classes,
/// unknown keys, coercions, or route override can silently grant eligibility.
pub(crate) fn parse_failure_rules(value: &Value) -> Option<Vec<DreamerFailureRule>> {
    let Value::Array(rows) = value else {
        return None;
    };
    if rows.len() > 3 {
        return None;
    }
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        if entries.len() != 6 {
            return None;
        }
        let mut class = None;
        let mut route = None;
        let mut consolidation_eligible = None;
        let mut effector_eligible = None;
        let mut default_consolidation_eligible = None;
        let mut default_effector_eligible = None;
        for (key, value) in entries {
            match key.as_str()? {
                "failure" if class.is_none() => {
                    class = DreamerFailureClass::from_str(value.as_str()?);
                }
                "route" if route.is_none() => route = Some(value.as_str()?),
                "consolidation_eligible" if consolidation_eligible.is_none() => {
                    consolidation_eligible = value.as_bool();
                }
                "effector_eligible" if effector_eligible.is_none() => {
                    effector_eligible = value.as_bool();
                }
                "default_consolidation_eligible" if default_consolidation_eligible.is_none() => {
                    default_consolidation_eligible = Some(value.as_bool()?);
                }
                "default_effector_eligible" if default_effector_eligible.is_none() => {
                    default_effector_eligible = Some(value.as_bool()?);
                }
                _ => return None,
            }
        }
        let class = class?;
        let expected = match class.route() {
            DreamerFailureRoute::Retry => "retry",
            DreamerFailureRoute::Fallback => "fallback",
            DreamerFailureRoute::BudgetTrap => "budget_trap",
        };
        if route? != expected || parsed.iter().any(|r: &DreamerFailureRule| r.class == class) {
            return None;
        }
        parsed.push(DreamerFailureRule {
            class,
            consolidation_eligible: consolidation_eligible?,
            effector_eligible: effector_eligible?,
            default_consolidation_eligible: default_consolidation_eligible?,
            default_effector_eligible: default_effector_eligible?,
        });
    }
    Some(parsed)
}

pub(crate) fn decide_failure(
    rules: &[DreamerFailureRule],
    class: DreamerFailureClass,
    precedence: DreamerFailurePrecedence,
) -> DreamerFailureDecision {
    let matched: Vec<_> = rules.iter().filter(|rule| rule.class == class).collect();
    let ceiling_consolidation =
        !matched.is_empty() && matched.iter().all(|row| row.consolidation_eligible);
    let ceiling_effector = !matched.is_empty() && matched.iter().all(|row| row.effector_eligible);
    DreamerFailureDecision {
        class,
        route: class.route(),
        precedence,
        consolidation_ceiling: ceiling_consolidation,
        effector_ceiling: ceiling_effector,
        // Defaults and ceilings fold restrictively across all trusted packs.
        // A missing class has no cap and cannot grant through an override.
        consolidation_eligible: ceiling_consolidation
            && matched.iter().all(|row| row.default_consolidation_eligible),
        effector_eligible: ceiling_effector
            && matched.iter().all(|row| row.default_effector_eligible),
    }
}

pub(crate) fn fallback_failure_class(response: &super::LlmResponse) -> Option<DreamerFailureClass> {
    match &response.finish_reason {
        super::FinishReason::Other { name } if name.starts_with("fallback:") => {
            Some(DreamerFailureClass::Fatal)
        }
        _ => None,
    }
}
