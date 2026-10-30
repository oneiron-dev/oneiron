//! Tradeoff rule counts against the resolved policy limits (FIX 8771, 8847).
//!
//! The trusted `skill_tradeoff_limits` rows name how many authored and learned
//! rules a goal's holder means to keep. A crossing is an advisory, a typed and
//! logged threshold check: no preference write, ask or pick is refused or
//! hidden for a count. Every pending decision keeps its durable ask, which
//! climbs by role until someone answers it.
use super::*;
use crate::gate::{SkillTradeoffLimits, skill_tradeoff_limits_in_txn};

/// One policy limit a goal's tradeoff rules have crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TradeoffCapacityCrossing {
    /// More authored rules than `max_authored_rules`.
    AuthoredRules { held: u64, limit: u64 },
    /// More learned picks than a finite `max_learned_rules`.
    LearnedRules { held: u64, limit: u64 },
}

impl TradeoffCapacityCrossing {
    const fn reason_code(self) -> &'static str {
        match self {
            Self::AuthoredRules { .. } => "gate.tradeoff_authored_rules_over_policy",
            Self::LearnedRules { .. } => "gate.tradeoff_learned_rules_over_policy",
        }
    }

    const fn counts(self) -> (u64, u64) {
        match self {
            Self::AuthoredRules { held, limit } | Self::LearnedRules { held, limit } => {
                (held, limit)
            }
        }
    }
}

/// The crossings `preferences` makes against the limits resolved for its
/// holder in this snapshot.
pub fn crossings_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    preferences: &SkillTradeoffPreferences,
) -> Result<Vec<TradeoffCapacityCrossing>> {
    let limits: SkillTradeoffLimits =
        skill_tradeoff_limits_in_txn(&vault.store, txn, &preferences.responsible)?;
    let count = |rules: &[TradeoffRule]| u64::try_from(rules.len()).unwrap_or(u64::MAX);
    let mut crossings = Vec::new();
    if count(&preferences.rules) > limits.max_authored_rules {
        crossings.push(TradeoffCapacityCrossing::AuthoredRules {
            held: count(&preferences.rules),
            limit: limits.max_authored_rules,
        });
    }
    if let Some(limit) = limits.max_learned_rules
        && count(&preferences.learned) > limit
    {
        crossings.push(TradeoffCapacityCrossing::LearnedRules {
            held: count(&preferences.learned),
            limit,
        });
    }
    Ok(crossings)
}

/// Check the preferences being written for `goal` against their holder's
/// limits and log each crossing as an advisory. Nothing is refused, and a
/// policy that cannot be read skips the advisory, never the write.
pub(super) fn advise_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    goal: &EntityId,
    preferences: &SkillTradeoffPreferences,
) {
    let crossings = match crossings_in_txn(vault, txn, preferences) {
        Ok(crossings) => crossings,
        Err(error) => {
            tracing::warn!(
                %error,
                goal = %goal.to_hex(),
                "the tradeoff policy limits are unreadable; the advisory was skipped"
            );
            return;
        }
    };
    for crossing in crossings {
        let (held, limit) = crossing.counts();
        tracing::info!(
            reason_code = crossing.reason_code(),
            goal = %goal.to_hex(),
            held,
            limit,
            "a skill goal's tradeoff rules are over the policy limit; nothing was refused"
        );
    }
}
