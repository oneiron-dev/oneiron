//! The campaign file behind `scorecard compare` and the sealed run.
//!
//! A candidate parameter set is compared with the incumbent on the held_out
//! slice: the engine's dominance rule decides first, then a paired bootstrap
//! on each Primary axis, then the ruler-path check rejects whatever the
//! verdict. This module loads the campaign file, plans its axes, checks that
//! scorecards sit on the judged slice, and diffs the two engine commits
//! against the ruler paths.

use oneiron::CampaignDatasetRef;
use oneiron::autoreason_campaign::general::{
    CampaignConfig, DecideRules, MetricDirection, MetricRole,
};
use oneiron_ruler::axes::{AxisComparison, AxisDirection, AxisRole, axis_value};
use oneiron_ruler::pack::{Slice, sha256_hex};
use oneiron_ruler::ruler_paths::{RULER_PATHS_FILE, RulerPaths, SHIPPED_RULER_PATHS};
use oneiron_ruler::scorecard::{SCORECARD_CONTRACT, Scorecard};

use super::ScorecardFailure;
use super::run::check_commit;

/// One campaign axis as the ruler judges it.
pub(crate) struct AxisPlan {
    /// The axis name, as `axis_value` reads it.
    pub(crate) name: String,
    /// The role of the axis in the campaign's metric set.
    pub(crate) role: AxisRole,
    /// Which way the axis improves.
    pub(crate) direction: AxisDirection,
    /// The symmetric dead band: a change of at most this much is a tie.
    pub(crate) tolerance: f64,
}

/// The ruler-path check over two engine commits.
pub(crate) struct RulerPathCheck {
    /// The changed paths that touch a ruler path, sorted.
    pub(crate) touched: Vec<String>,
    /// Where the ruler paths came from: `same_commit`, `base_commit` or `shipped`.
    pub(crate) source: &'static str,
}

/// Load a dominance campaign file: read, parse, validate.
pub(crate) fn load_campaign(path: &str) -> Result<CampaignConfig, ScorecardFailure> {
    let bytes = std::fs::read(path)
        .map_err(|error| ScorecardFailure::Input(format!("campaign read failed: {error}")))?;
    let campaign: CampaignConfig = serde_json::from_slice(&bytes)
        .map_err(|error| ScorecardFailure::Input(format!("campaign parse failed: {error}")))?;
    campaign
        .validate()
        .map_err(|error| ScorecardFailure::Input(format!("campaign invalid: {error}")))?;
    if !matches!(campaign.decide, DecideRules::Dominance) {
        return Err(ScorecardFailure::Input(
            "the ruler decides by dominance".to_owned(),
        ));
    }
    Ok(campaign)
}

/// Plan every axis of the campaign's metric set, in file order.
pub(crate) fn axis_plan(campaign: &CampaignConfig) -> Vec<AxisPlan> {
    let mut plan = Vec::with_capacity(campaign.metric_set.axes.len());
    for axis in &campaign.metric_set.axes {
        plan.push(AxisPlan {
            name: axis.name.clone(),
            role: match axis.role {
                MetricRole::Primary => AxisRole::Primary,
                MetricRole::Floor => AxisRole::Floor,
                MetricRole::Cost => AxisRole::Cost,
            },
            direction: match axis.direction {
                MetricDirection::Higher => AxisDirection::Higher,
                MetricDirection::Lower => AxisDirection::Lower,
            },
            tolerance: axis.tolerance,
        });
    }
    plan
}

/// Read one axis value per side for every planned axis.
pub(crate) fn axis_comparisons(
    plan: &[AxisPlan],
    incumbent: &Scorecard,
    candidate: &Scorecard,
) -> Result<Vec<AxisComparison>, ScorecardFailure> {
    let mut axes = Vec::with_capacity(plan.len());
    for entry in plan {
        let name = entry.name.as_str();
        let incumbent_value = axis_value(incumbent, name)
            .map_err(|error| ScorecardFailure::Input(format!("axis {name}: {error}")))?;
        let candidate_value = axis_value(candidate, name)
            .map_err(|error| ScorecardFailure::Input(format!("axis {name}: {error}")))?;
        axes.push(AxisComparison {
            axis: entry.name.clone(),
            role: entry.role,
            direction: entry.direction,
            tolerance: entry.tolerance,
            incumbent: incumbent_value,
            candidate: candidate_value,
        });
    }
    Ok(axes)
}

/// Check a scorecard against the judged split: slice, pack id, pack digest.
pub(crate) fn check_slice(
    card: &Scorecard,
    slice: Slice,
    dataset: &CampaignDatasetRef,
    label: &str,
) -> Result<(), ScorecardFailure> {
    if card.slice != slice {
        let found = card.slice.as_str();
        let wanted = slice.as_str();
        return Err(ScorecardFailure::Input(format!(
            "{label} scorecard is on slice {found}, want {wanted}"
        )));
    }
    if card.pack_id != dataset.dataset_id {
        let found = card.pack_id.as_str();
        let wanted = dataset.dataset_id.as_str();
        return Err(ScorecardFailure::Input(format!(
            "{label} scorecard pack_id is {found}, want {wanted}"
        )));
    }
    if card.pack_digest != dataset.revision {
        return Err(ScorecardFailure::Input(format!(
            "{label} scorecard pack_digest is not the campaign's revision"
        )));
    }
    Ok(())
}

/// Load a scorecard file: sha256 the file bytes, then parse and check the contract.
pub(crate) fn load_card(path: &str) -> Result<(Scorecard, String), ScorecardFailure> {
    let bytes = std::fs::read(path)
        .map_err(|error| ScorecardFailure::Input(format!("scorecard read failed: {error}")))?;
    let sha256 = sha256_hex(&bytes);
    let card: Scorecard = serde_json::from_slice(&bytes)
        .map_err(|error| ScorecardFailure::Input(format!("scorecard parse failed: {error}")))?;
    if card.contract != SCORECARD_CONTRACT {
        let found = card.contract.as_str();
        return Err(ScorecardFailure::Input(format!("wrong contract: {found}")));
    }
    Ok((card, sha256))
}

/// Diff two engine commits against the ruler paths read at the base commit.
pub(crate) fn ruler_paths_touched(
    repo: Option<&str>,
    base_commit: &str,
    candidate_commit: &str,
) -> Result<RulerPathCheck, ScorecardFailure> {
    if base_commit == candidate_commit {
        return Ok(RulerPathCheck {
            touched: Vec::new(),
            source: "same_commit",
        });
    }
    check_commit(base_commit)?;
    check_commit(candidate_commit)?;
    let Some(dir) = repo else {
        return Err(ScorecardFailure::Input(
            "--repo is required when the engine commits differ".to_owned(),
        ));
    };
    let diff = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .arg("diff")
        .arg("--name-only")
        .arg(base_commit)
        .arg(candidate_commit)
        .output()
        .map_err(|error| ScorecardFailure::Run(format!("git diff failed to run: {error}")))?;
    if !diff.status.success() {
        let stderr = String::from_utf8_lossy(&diff.stderr);
        let short: String = stderr.trim().chars().take(400).collect();
        return Err(ScorecardFailure::Input(format!("git diff failed: {short}")));
    }
    let stdout = String::from_utf8_lossy(&diff.stdout);
    let changed: Vec<&str> = stdout.lines().filter(|line| !line.is_empty()).collect();
    let pinned = format!("{base_commit}:{RULER_PATHS_FILE}");
    let show = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .arg("show")
        .arg(&pinned)
        .output()
        .map_err(|error| ScorecardFailure::Run(format!("git show failed to run: {error}")))?;
    let (text, source) = if show.status.success() {
        (
            String::from_utf8_lossy(&show.stdout).into_owned(),
            "base_commit",
        )
    } else {
        let stderr = String::from_utf8_lossy(&show.stderr);
        if stderr.contains("does not exist") || stderr.contains("exists on disk, but not in") {
            (SHIPPED_RULER_PATHS.to_owned(), "shipped")
        } else {
            let short: String = stderr.trim().chars().take(400).collect();
            return Err(ScorecardFailure::Input(format!("git show failed: {short}")));
        }
    };
    let ruler =
        RulerPaths::parse(&text).map_err(|error| ScorecardFailure::Input(error.to_string()))?;
    Ok(RulerPathCheck {
        touched: ruler.touched(&changed),
        source,
    })
}
