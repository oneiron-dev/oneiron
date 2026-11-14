//! `scorecard compare`: judge a candidate against the incumbent, on held_out or sealed.
//!
//! The held_out compare runs the engine's dominance rule first, then a paired
//! bootstrap on each Primary axis, then the ruler-path check; a Promote
//! writes the proposal record. The sealed compare is the once-only check that
//! can withdraw the proposal. Every time is a flag; output is one JSON line.

use std::collections::BTreeMap;
use std::path::Path;

use oneiron::autoreason_campaign::general::{Measurement, Verdict};
use oneiron_ruler::axes::{AxisRole, is_per_query_axis};
use oneiron_ruler::bootstrap::{
    BOOTSTRAP_RESAMPLES, bootstrap_axis, paired_differences, paired_lower_bound,
    seed_from_pack_digest,
};
use oneiron_ruler::pack::Slice;
use oneiron_ruler::proposal::{
    HeldOutProposal, PROPOSAL_CONTRACT, ProposalStore, SEALED_OUTCOME_CONTRACT, SealedOutcome,
    SealedVerdict, judge_sealed, proposal_id,
};
use oneiron_ruler::scorecard::{QueryScore, Scorecard};
use oneiron_ruler::sealed::ExperimentIdentity;

use super::{
    ScorecardFailure, campaign, flag_unix_seconds, params, parse_flags, profile, required_flag,
};

/// The flags `scorecard compare` takes on held_out.
const HELD_OUT_FLAGS: &[&str] = &[
    "campaign",
    "repo",
    "candidate-params",
    "candidate-profile",
    "reference",
    "proposals",
    "at",
];

/// The flags `scorecard compare --sealed` takes.
const SEALED_FLAGS: &[&str] = &["campaign", "proposals", "proposal", "at"];

/// Compare two scorecards: judge on held_out, or run the sealed check with `--sealed`.
pub(crate) fn run(args: &[String]) -> Result<serde_json::Value, ScorecardFailure> {
    let (sealed, flag_args, base, candidate) = split_args(args)?;
    if sealed {
        let flags = parse_flags(&flag_args, SEALED_FLAGS)?;
        sealed_compare(&flags, base, candidate)
    } else {
        let flags = parse_flags(&flag_args, HELD_OUT_FLAGS)?;
        held_out_compare(&flags, base, candidate)
    }
}

/// Split off the `--sealed` switch and the BASE and CAND positional paths.
fn split_args(args: &[String]) -> Result<(bool, Vec<String>, &str, &str), ScorecardFailure> {
    if args.len() < 2 {
        return Err(ScorecardFailure::Input(
            "scorecard compare needs BASE and CAND scorecard paths".to_owned(),
        ));
    }
    let base = args[args.len() - 2].as_str();
    let candidate = args[args.len() - 1].as_str();
    for path in [base, candidate] {
        if path.starts_with("--") {
            return Err(ScorecardFailure::Input(format!(
                "scorecard compare needs BASE and CAND scorecard paths, got flag {path}"
            )));
        }
    }
    let mut sealed = false;
    let mut flag_args = Vec::new();
    for arg in &args[..args.len() - 2] {
        if arg == "--sealed" {
            if sealed {
                return Err(ScorecardFailure::Input(
                    "repeated flag: --sealed".to_owned(),
                ));
            }
            sealed = true;
        } else {
            flag_args.push(arg.clone());
        }
    }
    Ok((sealed, flag_args, base, candidate))
}

/// Judge a candidate on held_out: dominance, then bootstrap, then ruler paths.
fn held_out_compare(
    flags: &BTreeMap<String, String>,
    base: &str,
    candidate: &str,
) -> Result<serde_json::Value, ScorecardFailure> {
    let campaign_path = required_flag(flags, "campaign")?;
    let campaign = campaign::load_campaign(campaign_path)?;
    let (incumbent, incumbent_sha256) = campaign::load_card(base)?;
    let (candidate_card, candidate_sha256) = campaign::load_card(candidate)?;
    campaign::check_slice(
        &incumbent,
        Slice::HeldOut,
        &campaign.splits.held_out,
        "incumbent",
    )?;
    campaign::check_slice(
        &candidate_card,
        Slice::HeldOut,
        &campaign.splits.held_out,
        "candidate",
    )?;
    if incumbent.model_id != candidate_card.model_id {
        return Err(ScorecardFailure::Input(
            "incumbent and candidate come from different retrievers".to_owned(),
        ));
    }
    let reference = match flags.get("reference").map(String::as_str) {
        None => None,
        Some(path) => {
            let (card, sha256) = campaign::load_card(path)?;
            campaign::check_slice(
                &card,
                Slice::HeldOut,
                &campaign.splits.held_out,
                "reference",
            )?;
            if card.budget_rows != candidate_card.budget_rows {
                let found = card.budget_rows;
                let wanted = candidate_card.budget_rows;
                return Err(ScorecardFailure::Input(format!(
                    "reference scorecard budget_rows is {found}, want {wanted}"
                )));
            }
            Some((card, sha256))
        }
    };
    let proposals_dir = flags.get("proposals").map(String::as_str);
    let decided_at = if proposals_dir.is_some() {
        Some(flag_unix_seconds(flags, "at")?)
    } else {
        if flags.contains_key("at") {
            return Err(ScorecardFailure::Input("--at needs --proposals".to_owned()));
        }
        if flags.contains_key("candidate-params") {
            return Err(ScorecardFailure::Input(
                "--candidate-params needs --proposals".to_owned(),
            ));
        }
        if flags.contains_key("candidate-profile") {
            return Err(ScorecardFailure::Input(
                "--candidate-profile needs --proposals".to_owned(),
            ));
        }
        None
    };
    let candidate_params = if proposals_dir.is_some() {
        Some(resolve_candidate_params(
            flags.get("candidate-params").map(String::as_str),
            flags.get("candidate-profile").map(String::as_str),
            &candidate_card,
        )?)
    } else {
        None
    };
    let plan = campaign::axis_plan(&campaign);
    for entry in &plan {
        if entry.role == AxisRole::Primary && !is_per_query_axis(&entry.name) {
            let name = entry.name.as_str();
            return Err(ScorecardFailure::Input(format!(
                "{name} has no per-query values to bootstrap"
            )));
        }
    }
    let axes = campaign::axis_comparisons(&plan, &incumbent, &candidate_card)?;
    let mut incumbent_scores = BTreeMap::new();
    let mut candidate_scores = BTreeMap::new();
    for axis in &axes {
        incumbent_scores.insert(axis.axis.clone(), axis.incumbent);
        candidate_scores.insert(axis.axis.clone(), axis.candidate);
    }
    let incumbent_measured = Measurement {
        dataset: campaign.splits.held_out.clone(),
        metric_set_id: campaign.metric_set.set_id.clone(),
        metric_set_revision: campaign.metric_set.revision.clone(),
        scores: incumbent_scores,
    };
    let candidate_measured = Measurement {
        dataset: campaign.splits.held_out.clone(),
        metric_set_id: campaign.metric_set.set_id.clone(),
        metric_set_revision: campaign.metric_set.revision.clone(),
        scores: candidate_scores,
    };
    let mut verdict = campaign
        .decide_held_out(&incumbent_measured, &candidate_measured)
        .map_err(|error| ScorecardFailure::Input(format!("dominance failed: {error}")))?
        .verdict();
    let mut decided_by = "dominance";
    let mut bounds = Vec::new();
    for entry in &plan {
        if entry.role == AxisRole::Primary {
            let bound = bootstrap_axis(&incumbent, &candidate_card, &entry.name)
                .map_err(|error| ScorecardFailure::Input(format!("bootstrap failed: {error}")))?;
            bounds.push(bound);
        }
    }
    if verdict == Verdict::Promote && !bounds.iter().any(|bound| bound.lower_bound > 0.0) {
        verdict = Verdict::Reject;
        decided_by = "bootstrap";
    }
    let repo = flags.get("repo").map(String::as_str);
    let ruler = campaign::ruler_paths_touched(
        repo,
        &incumbent.engine_commit,
        &candidate_card.engine_commit,
    )?;
    if !ruler.touched.is_empty() {
        verdict = Verdict::Reject;
        decided_by = "ruler_paths";
    }
    let incumbent_id = ExperimentIdentity::of_scorecard(&incumbent);
    let candidate_id = ExperimentIdentity::of_scorecard(&candidate_card);
    let proposal = proposal_id(&campaign.campaign_id, &incumbent_id, &candidate_id)
        .map_err(|error| ScorecardFailure::Run(format!("proposal id failed: {error}")))?;
    let verdict_name = match verdict {
        Verdict::Promote => "promote",
        Verdict::Reject => "reject",
        Verdict::EscalateTradeoff => "escalate_tradeoff",
    };
    let reference_report = match &reference {
        None => None,
        Some((card, sha256)) => Some(reference_report(&candidate_card, card, sha256)?),
    };
    let mut proposal_record = serde_json::Value::Null;
    if verdict == Verdict::Promote
        && let (Some(dir), Some(at), Some(candidate_params)) =
            (proposals_dir, decided_at, candidate_params)
    {
        let store = ProposalStore::open(Path::new(dir))
            .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
        let body = HeldOutProposal {
            contract: PROPOSAL_CONTRACT.to_owned(),
            proposal_id: proposal.clone(),
            campaign_id: campaign.campaign_id.clone(),
            incumbent: incumbent_id,
            candidate: candidate_id,
            candidate_params,
            incumbent_scorecard_sha256: incumbent_sha256,
            candidate_scorecard_sha256: candidate_sha256,
            axes: axes.clone(),
            bootstrap: bounds.clone(),
            decided_at: at,
        };
        let path = store
            .put_held_out(&body)
            .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
        proposal_record = serde_json::Value::from(path.to_string_lossy().into_owned());
    }
    let mut summary = serde_json::json!({
        "campaign_id": campaign.campaign_id,
        "proposal_id": proposal,
        "verdict": verdict_name,
        "decided_by": decided_by,
        "axes": axes,
        "bootstrap": bounds,
        "ruler_paths": {"touched": ruler.touched, "source": ruler.source},
        "proposal_record": proposal_record,
    });
    if let (Some(report), serde_json::Value::Object(map)) = (reference_report, &mut summary) {
        map.insert("reference".to_owned(), report);
    }
    if verdict == Verdict::Promote {
        Ok(summary)
    } else {
        Err(ScorecardFailure::Judged(summary))
    }
}

/// Resolve the candidate's parameter file: `--candidate-params` or `--candidate-profile`, never both.
///
/// The resolved digest must equal the candidate scorecard's `params_digest`;
/// the resolved file becomes the proposal's `candidate_params`.
fn resolve_candidate_params(
    params_path: Option<&str>,
    profile_path: Option<&str>,
    candidate: &Scorecard,
) -> Result<serde_json::Value, ScorecardFailure> {
    match (params_path, profile_path) {
        (Some(_), Some(_)) => Err(ScorecardFailure::Input(
            "--candidate-params and --candidate-profile are mutually exclusive".to_owned(),
        )),
        (None, Some(path)) => {
            let resolved = profile::resolve_profile(Some(path))?;
            if resolved.digest != candidate.params_digest {
                return Err(ScorecardFailure::Input(
                    "candidate profile does not match the candidate scorecard's params_digest"
                        .to_owned(),
                ));
            }
            Ok(resolved.resolved)
        }
        (params_path, None) => {
            let resolved = params::resolve(params_path)?;
            if resolved.digest != candidate.params_digest {
                return Err(ScorecardFailure::Input(
                    "candidate params do not match the candidate scorecard's params_digest"
                        .to_owned(),
                ));
            }
            Ok(resolved.resolved)
        }
    }
}

/// The reference report: ours vs a reference scorecard, overall and per category.
///
/// For `ndcg_at_10` and `recall_at_budget`: our mean, the reference mean,
/// their ratio (null when the reference is 0), and the paired bootstrap of
/// the candidate-minus-reference per-query differences. A category with no
/// non-abstention query is left out. The report never changes the judgment.
fn reference_report(
    candidate: &Scorecard,
    reference: &Scorecard,
    sha256: &str,
) -> Result<serde_json::Value, ScorecardFailure> {
    let seed = seed_from_pack_digest(&candidate.pack_digest)
        .map_err(|error| ScorecardFailure::Input(format!("reference bootstrap failed: {error}")))?;
    let mut per_category = serde_json::Map::new();
    for category in report_categories(candidate, reference) {
        let (Some(ours), Some(theirs)) = (
            candidate.per_category.get(category.as_str()),
            reference.per_category.get(category.as_str()),
        ) else {
            continue;
        };
        let ours_scores: Vec<QueryScore> = candidate
            .per_query
            .iter()
            .filter(|score| score.category == category)
            .cloned()
            .collect();
        let ref_scores: Vec<QueryScore> = reference
            .per_query
            .iter()
            .filter(|score| score.category == category)
            .cloned()
            .collect();
        let mut entry = serde_json::Map::new();
        for (metric, ours_mean, ref_mean) in [
            ("ndcg_at_10", ours.ndcg_at_10, theirs.ndcg_at_10),
            (
                "recall_at_budget",
                ours.recall_at_budget,
                theirs.recall_at_budget,
            ),
        ] {
            let differences =
                paired_differences(&ref_scores, &ours_scores, metric).map_err(|error| {
                    ScorecardFailure::Input(format!("reference bootstrap failed: {error}"))
                })?;
            entry.insert(
                metric.to_owned(),
                metric_gap(ours_mean, ref_mean, &differences, seed)?,
            );
        }
        per_category.insert(category, serde_json::Value::Object(entry));
    }
    let mut overall = serde_json::Map::new();
    for (metric, ours_mean, ref_mean) in [
        (
            "ndcg_at_10",
            candidate.metrics.ndcg_at_10,
            reference.metrics.ndcg_at_10,
        ),
        (
            "recall_at_budget",
            candidate.metrics.recall_at_budget,
            reference.metrics.recall_at_budget,
        ),
    ] {
        let differences = paired_differences(&reference.per_query, &candidate.per_query, metric)
            .map_err(|error| {
                ScorecardFailure::Input(format!("reference bootstrap failed: {error}"))
            })?;
        overall.insert(
            metric.to_owned(),
            metric_gap(ours_mean, ref_mean, &differences, seed)?,
        );
    }
    Ok(serde_json::json!({
        "scorecard_sha256": sha256,
        "retriever": reference.model_id,
        "overall": overall,
        "per_category": per_category,
    }))
}

/// The categories the reference report covers: on both cards with a non-abstention query.
fn report_categories(candidate: &Scorecard, reference: &Scorecard) -> Vec<String> {
    let mut out = Vec::new();
    for category in candidate.per_category.keys() {
        if !reference.per_category.contains_key(category) {
            continue;
        }
        let graded = candidate
            .per_query
            .iter()
            .any(|score| score.category.as_str() == category.as_str() && !score.expect_empty);
        if graded {
            out.push(category.clone());
        }
    }
    out
}

/// One metric's gap row: the two means, the ratio, and the paired bootstrap of the differences.
fn metric_gap(
    ours: f64,
    reference: f64,
    differences: &[f64],
    seed: u64,
) -> Result<serde_json::Value, ScorecardFailure> {
    let sum: f64 = differences.iter().sum();
    let mean_difference = sum / differences.len() as f64;
    let lower_bound = paired_lower_bound(differences, BOOTSTRAP_RESAMPLES, seed)
        .map_err(|error| ScorecardFailure::Input(format!("reference bootstrap failed: {error}")))?;
    let ratio = if reference == 0.0 {
        serde_json::Value::Null
    } else {
        serde_json::json!(ours / reference)
    };
    Ok(serde_json::json!({
        "ours": ours,
        "reference": reference,
        "ratio": ratio,
        "mean_difference": mean_difference,
        "lower_bound": lower_bound,
    }))
}

/// Run the sealed check once: pass, or withdraw the proposal on a judged loss.
fn sealed_compare(
    flags: &BTreeMap<String, String>,
    base: &str,
    candidate: &str,
) -> Result<serde_json::Value, ScorecardFailure> {
    let campaign_path = required_flag(flags, "campaign")?;
    let campaign = campaign::load_campaign(campaign_path)?;
    let proposals_dir = required_flag(flags, "proposals")?;
    let proposal = required_flag(flags, "proposal")?;
    let judged_at = flag_unix_seconds(flags, "at")?;
    let store = ProposalStore::open(Path::new(proposals_dir))
        .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
    let listing = store
        .get(proposal)
        .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
    if listing.sealed.is_some() {
        return Err(ScorecardFailure::Input(
            "proposal already has its sealed outcome".to_owned(),
        ));
    }
    if listing.held_out.campaign_id != campaign.campaign_id {
        return Err(ScorecardFailure::Input(
            "proposal is for another campaign".to_owned(),
        ));
    }
    let (incumbent, _) = campaign::load_card(base)?;
    let (candidate_card, _) = campaign::load_card(candidate)?;
    campaign::check_slice(
        &incumbent,
        Slice::Sealed,
        &campaign.splits.sealed,
        "incumbent",
    )?;
    campaign::check_slice(
        &candidate_card,
        Slice::Sealed,
        &campaign.splits.sealed,
        "candidate",
    )?;
    if incumbent.engine_commit != listing.held_out.incumbent.engine_commit
        || incumbent.params_digest != listing.held_out.incumbent.params_digest
    {
        return Err(ScorecardFailure::Input(
            "incumbent sealed scorecard does not match the proposal's incumbent".to_owned(),
        ));
    }
    if candidate_card.engine_commit != listing.held_out.candidate.engine_commit
        || candidate_card.params_digest != listing.held_out.candidate.params_digest
    {
        return Err(ScorecardFailure::Input(
            "candidate sealed scorecard does not match the proposal's candidate".to_owned(),
        ));
    }
    let plan = campaign::axis_plan(&campaign);
    let axes = campaign::axis_comparisons(&plan, &incumbent, &candidate_card)?;
    let (verdict, losses, reason) = judge_sealed(&axes)
        .map_err(|error| ScorecardFailure::Input(format!("sealed judge failed: {error}")))?;
    let outcome = SealedOutcome {
        contract: SEALED_OUTCOME_CONTRACT.to_owned(),
        proposal_id: proposal.to_owned(),
        verdict,
        reason: reason.clone(),
        losses: losses.clone(),
        incumbent_sealed: incumbent,
        candidate_sealed: candidate_card,
        judged_at,
    };
    let path = store
        .put_sealed(&outcome)
        .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
    let verdict_name = match verdict {
        SealedVerdict::Passed => "passed",
        SealedVerdict::Withdrawn => "withdrawn",
    };
    let summary = serde_json::json!({
        "proposal_id": proposal,
        "verdict": verdict_name,
        "reason": reason,
        "losses": losses,
        "sealed_record": path.to_string_lossy().into_owned(),
    });
    if verdict == SealedVerdict::Passed {
        Ok(summary)
    } else {
        Err(ScorecardFailure::Judged(summary))
    }
}
