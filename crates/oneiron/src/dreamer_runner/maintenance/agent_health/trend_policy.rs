//! The daily trend pass's comparison policy (OF-568 L3, agent-mind §3:
//! "Daily. A trend pass per actor and per project, over the rollups"): the
//! latest N complete UTC days against the N days before them, today's partial
//! day never read. N is the owner's dial `health.trend.period_days`, resolved
//! for the vault (every actor's comparisons and the unbound project's) and
//! for each bound project (its own). It sets how far back a comparison looks,
//! never which work runs, and it is the pass's only time bound.
//!
//! Also the owner rows that change what the review detects: a comparison
//! whose span saw one set is unknown, never read as the agents' change.

use std::collections::{BTreeMap, BTreeSet};

use super::rollups::TrendMargin;
use crate::learning_setting::{
    SettingScope, SettingSpec, list_setting_rows_in_txn, setting_value_in_scope_in_txn,
};
use crate::{EntityId, Result, Vault};

/// Seconds in one UTC calendar day: a calendar conversion, never a scan
/// bound or a retention.
pub(super) const SECONDS_PER_DAY: u64 = 86_400;

/// The complete UTC days each side of a trend comparison spans: the latest N
/// against the N before them.
pub const HEALTH_TREND_PERIOD_DAYS: SettingSpec = SettingSpec {
    key: "health.trend.period_days",
    min: 1.0,
    max: 365.0,
    seed: 7.0,
};

/// The dials that decide what the agent-health review finds. The routing
/// dials (owner copy, TTL, card floor) only route cards, so a change to one
/// leaves detection comparable.
const DETECTION_DIALS: [&str; 11] = [
    super::HEALTH_REVIEW.key,
    super::HEALTH_LOOP_REPEATS.key,
    super::HEALTH_CHECK_FAILS.key,
    super::HEALTH_WAIT_SHARE.key,
    super::HEALTH_WAIT_MINUTES.key,
    super::HEALTH_SILENT_MINUTES.key,
    super::HEALTH_WIDEN_DENIALS.key,
    super::HEALTH_COST_SPIKE.key,
    super::HEALTH_DUP_MIN_COST.key,
    super::HEALTH_REVIEW_WINDOW_HOURS.key,
    super::HEALTH_COST_MIN_RUNS.key,
];

/// The period in force for each margin, in days per side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrendPeriods {
    /// The vault's: every actor's comparisons and the unbound project's.
    pub vault: u64,
    /// Each bound project's own, as its scoped rows resolve it.
    pub projects: BTreeMap<EntityId, u64>,
}

impl TrendPeriods {
    /// The period for the vault and for each of `projects`, in the caller's
    /// snapshot.
    pub(super) fn read_in(
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        projects: &BTreeSet<EntityId>,
    ) -> Result<Self> {
        let days = |project: Option<EntityId>| -> Result<u64> {
            let value = setting_value_in_scope_in_txn(
                vault,
                rtxn,
                &HEALTH_TREND_PERIOD_DAYS,
                project,
                None,
            )?;
            Ok((value.round() as u64).max(1))
        };
        let mut periods = Self {
            vault: days(None)?,
            projects: BTreeMap::new(),
        };
        for project in projects {
            periods.projects.insert(*project, days(Some(*project))?);
        }
        Ok(periods)
    }

    /// The days per side one margin compares.
    #[must_use]
    pub fn of(&self, margin: &TrendMargin) -> u64 {
        match margin {
            TrendMargin::Actor(_) => self.vault,
            TrendMargin::Project(project) => self.of_project(*project),
        }
    }

    /// The days per side for work bound to `project`, or to none.
    pub(super) fn of_project(&self, project: Option<EntityId>) -> u64 {
        project
            .and_then(|project| self.projects.get(&project).copied())
            .unwrap_or(self.vault)
    }
}

/// One comparison's two sides, as UTC day numbers (days since the epoch),
/// each half-open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrendWindow {
    /// The N days before the latest.
    pub prior: (u64, u64),
    /// The latest N complete days: it ends where today begins.
    pub latest: (u64, u64),
}

impl TrendWindow {
    /// The window of `days` per side that ends before `today`.
    #[must_use]
    pub const fn ending(today: u64, days: u64) -> Self {
        let start = today.saturating_sub(days);
        Self {
            prior: (start.saturating_sub(days), start),
            latest: (start, today),
        }
    }
}

/// The owner rows over the detection dials, each with when it was set. A
/// row's time is its newest set, so one set inside a comparison's span may
/// have changed what was detected there.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DetectionDialChanges {
    /// Each detection dial row's scope and the unix second it was set.
    pub rows: Vec<(SettingScope, u64)>,
}

impl DetectionDialChanges {
    /// Every owner seed and pin over a detection dial, in the caller's
    /// snapshot: the one its rollups read (FIX 8358).
    pub(super) fn read_in(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<Self> {
        let rows = list_setting_rows_in_txn(vault, rtxn)?
            .into_iter()
            .filter(|(_, row, _)| DETECTION_DIALS.contains(&row.key.as_str()))
            .map(|(scope, row, _)| (scope, row.at))
            .collect();
        Ok(Self { rows })
    }

    /// Whether a row reaching work in `projects` of task type `type_node`
    /// was set at or after `since` (unix seconds). A vault row reaches all
    /// work; so does a goal row, whose project this read does not resolve.
    #[must_use]
    pub fn changed_since(
        &self,
        projects: &BTreeSet<Option<EntityId>>,
        type_node: &str,
        since: u64,
    ) -> bool {
        self.rows.iter().any(|(scope, at)| {
            *at >= since
                && match scope {
                    SettingScope::Vault | SettingScope::Goal(_) => true,
                    SettingScope::Project(project) => projects.contains(&Some(*project)),
                    SettingScope::Type(type_ref) => type_ref.node_id == type_node,
                }
        })
    }
}
