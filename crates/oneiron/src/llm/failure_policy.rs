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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamerFailureDecision {
    pub class: DreamerFailureClass,
    pub route: DreamerFailureRoute,
    /// Additional restrictions on top of claim and effect authority gates.
    pub consolidation_eligible: bool,
    pub effector_eligible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DreamerFailureRule {
    pub(crate) class: DreamerFailureClass,
    pub(crate) consolidation_eligible: bool,
    pub(crate) effector_eligible: bool,
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
        if entries.len() != 4 {
            return None;
        }
        let mut class = None;
        let mut route = None;
        let mut consolidation_eligible = None;
        let mut effector_eligible = None;
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
        });
    }
    Some(parsed)
}

pub(crate) fn decide_failure(
    rules: &[DreamerFailureRule],
    class: DreamerFailureClass,
) -> DreamerFailureDecision {
    let matched: Vec<_> = rules.iter().filter(|rule| rule.class == class).collect();
    DreamerFailureDecision {
        class,
        route: class.route(),
        // Missing rows do not license failed outputs. Multiple trusted packs
        // compose by intersection, never last-writer-wins.
        consolidation_eligible: !matched.is_empty()
            && matched.iter().all(|r| r.consolidation_eligible),
        effector_eligible: !matched.is_empty() && matched.iter().all(|r| r.effector_eligible),
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
