//! Routes ready extraction groups against admitted priors and judge sets.
//!
//! Reads bound facts, routes ready groups and covers all-group corrections.
//! Mirrors native nomination, routing, attachment, restatement and sharing.
//! A correction binds only inside a judge set, as native's bound correction;
//! a write outside every set never supersedes, so New carries no target.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use oneiron_remote::OneironClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::extraction_observations::{CandidateObservation, Observations};
use crate::extraction_selection::{
    Error as SelectionError, ExtractionSelectionConfig, ExtractionSelectionPlan,
};

const IMPORTED: &str = "imported";
const PROVISIONAL: &str = "provisional";

/// Explains why routing could not produce a route plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Preserves a selection or observations read failure.
    Selection(SelectionError),
    /// Rejects a native-invalid threshold.
    InvalidConfig,
    /// Rejects a read under another effective policy.
    PolicyPin {
        /// Names the policy required by the caller.
        expected: String,
        /// Names the policy served or supplied instead.
        actual: String,
    },
    /// Describes missing or incorrectly indexed routing observations.
    InvalidObservations(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selection(error) => write!(formatter, "{error}"),
            Self::InvalidConfig => {
                write!(formatter, "invalid consolidation selection policy")
            }
            Self::PolicyPin { expected, actual } => {
                write!(
                    formatter,
                    "routing requires policy {expected}, not {actual}"
                )
            }
            Self::InvalidObservations(message) => {
                write!(
                    formatter,
                    "invalid extraction routing observations: {message}"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<SelectionError> for Error {
    fn from(error: SelectionError) -> Self {
        Self::Selection(error)
    }
}

/// Explains why a ready group writes nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlreadyRepresentedReason {
    /// Restates an unlisted provisional head in the same scope.
    RestatesUnlisted,
    /// Matches a listed provisional head that is not its own.
    ProvisionalHead,
}

/// Routes one ready group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Route {
    /// Writes a new claim with no supersession, as native writes outside every set.
    New,
    /// Attaches to one admitted head.
    Attach {
        /// Names the head in lowercase hexadecimal.
        head: String,
    },
    /// Joins one judge set by plan position.
    Judge {
        /// Indexes the set in plan order.
        set: usize,
    },
    /// Writes nothing because the head already represents it.
    AlreadyRepresented {
        /// Names the representing head in lowercase hexadecimal.
        head: String,
        /// States which already-said rule matched.
        reason: AlreadyRepresentedReason,
    },
}

/// Records a ready group's route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRoute {
    /// Names the group representative in original request order.
    pub representative_index: usize,
    /// Lists the group members in original request order.
    pub member_indexes: Vec<usize>,
    /// Gives the group's route.
    pub choice: Route,
}

/// Holds one routed conflict set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JudgeSet {
    /// Lists members in native slice order.
    pub candidate_indexes: Vec<usize>,
    /// Carries the identity token of the first nominated member.
    pub identity_token: String,
    /// Lists context heads in sorted claim order.
    pub prior_heads: Vec<String>,
    /// Names the single context head, when exactly one exists.
    pub prior_head: Option<String>,
}

/// Holds one surviving correction binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Correction {
    /// Names the correcting group's representative.
    pub representative_index: usize,
    /// Names the listed head in lowercase hexadecimal.
    pub head: String,
}

/// Collects ready routes with judge sets and all-group corrections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractionRoutePlan {
    /// Lists ready routes in selection ready order.
    pub routes: Vec<CandidateRoute>,
    /// Lists judge sets in component then singleton order.
    pub judge_sets: Vec<JudgeSet>,
    /// Lists surviving corrections in native claim order.
    pub corrections: Vec<Correction>,
    /// Names the effective policy the routing read under.
    pub policy_pin: String,
    /// Names the complete facts the routing read under.
    pub facts_pin: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PriorMatch {
    prior: usize,
    equal: bool,
}

/// Routes ready groups and covers corrections for all groups.
///
/// Validates the threshold even when ready is empty.
///
/// # Errors
///
/// Rejects bad pins, threshold, writes, embeddings, scores and rows.
pub fn route(
    selection: &ExtractionSelectionPlan,
    observations: &Observations,
    config: &ExtractionSelectionConfig,
) -> Result<ExtractionRoutePlan, Error> {
    if !unit(config.cosine_threshold) {
        return Err(Error::InvalidConfig);
    }
    check_policy_pin(&config.policy_pin, &observations.policy_pin)?;
    check_policy_pin(&selection.policy_pin, &observations.policy_pin)?;
    if selection.facts_pin != observations.facts_pin {
        return Err(Error::InvalidObservations(
            "selection facts differ from routing observations".to_owned(),
        ));
    }
    let groups = group_positions(selection)?;
    let observed = observations_by_index(observations, &groups)?;
    let known: BTreeSet<usize> = groups.keys().copied().collect();
    let scores = score_map(observations, &known)?;
    for rep in selection
        .ready
        .iter()
        .chain(selection.held.iter().map(|(rep, _)| rep))
    {
        if !groups.contains_key(rep) {
            return Err(Error::InvalidObservations(
                "ready or held names an unknown group".to_owned(),
            ));
        }
    }
    let all = all_matches(observations, &groups, &observed);
    let corrections = corrections(selection, observations, &observed, &all)?;
    let ready = selection.ready.clone();
    for rep in &ready {
        for matched in &all[rep] {
            if !observations.priors[matched.prior].writable {
                return Err(Error::InvalidObservations(
                    "a matched prior refuses write".to_owned(),
                ));
            }
        }
    }
    let ready_obs: Vec<&CandidateObservation> = ready.iter().map(|rep| observed[rep]).collect();
    let components = nominate(&ready_obs, &scores, config.cosine_threshold)?;
    let (mut sets, in_set) = route_sets(&ready, &ready_obs, observations, &all, components);
    let mut routes = Vec::with_capacity(ready.len());
    for (pos, rep) in ready.iter().enumerate() {
        let candidate = observed[rep];
        let group = &selection.groups[groups[rep]];
        let choice = match in_set[pos] {
            Some(set) => Route::Judge { set },
            None => write_choice(*rep, candidate, observations, &all[rep]),
        };
        routes.push(CandidateRoute {
            representative_index: *rep,
            member_indexes: group.member_indexes.clone(),
            choice,
        });
    }
    for set in &mut sets {
        set.candidate_indexes = set
            .candidate_indexes
            .iter()
            .map(|pos| ready[*pos])
            .collect();
    }
    Ok(ExtractionRoutePlan {
        routes,
        judge_sets: sets,
        corrections,
        policy_pin: observations.policy_pin.clone(),
        facts_pin: observations.facts_pin.clone(),
    })
}

/// Observes unions, selects ready groups, then routes them.
///
/// # Errors
///
/// Preserves read failures, returns route errors and refuses a bad caller pin.
pub fn observe_and_route(
    client: &OneironClient,
    attempt: &str,
    now_ms: u64,
    operands: &[Value],
    config: &ExtractionSelectionConfig,
    policy_pin: &str,
) -> Result<(ExtractionSelectionPlan, ExtractionRoutePlan), Error> {
    check_policy_pin(&config.policy_pin, policy_pin)?;
    let (groups, observations) =
        crate::extraction_selection::observe_groups(client, attempt, now_ms, operands, policy_pin)?;
    let selection = crate::extraction_selection::select(&groups, &observations, now_ms, config)?;
    let plan = route(&selection, &observations, config)?;
    Ok((selection, plan))
}

fn group_positions(selection: &ExtractionSelectionPlan) -> Result<BTreeMap<usize, usize>, Error> {
    let mut map = BTreeMap::new();
    for (at, group) in selection.groups.iter().enumerate() {
        if map.insert(group.representative_index, at).is_some() {
            return Err(Error::InvalidObservations(
                "selection repeats a representative".to_owned(),
            ));
        }
    }
    Ok(map)
}

fn observations_by_index<'a>(
    observations: &'a Observations,
    groups: &BTreeMap<usize, usize>,
) -> Result<BTreeMap<usize, &'a CandidateObservation>, Error> {
    let mut map = BTreeMap::new();
    for candidate in &observations.candidates {
        if map.insert(candidate.index, candidate).is_some() {
            return Err(Error::InvalidObservations(
                "the read repeated a candidate".to_owned(),
            ));
        }
    }
    if map.len() != groups.len() {
        return Err(Error::InvalidObservations(
            "expected one row per group".to_owned(),
        ));
    }
    for rep in groups.keys() {
        if !map.contains_key(rep) {
            return Err(Error::InvalidObservations(
                "a group representative has no row".to_owned(),
            ));
        }
    }
    Ok(map)
}

fn score_map(
    observations: &Observations,
    known: &BTreeSet<usize>,
) -> Result<BTreeMap<(usize, usize), Option<f64>>, Error> {
    let mut map = BTreeMap::new();
    for score in &observations.scores {
        if score.i >= score.j || !known.contains(&score.i) || !known.contains(&score.j) {
            return Err(Error::InvalidObservations(
                "a similarity pair names an unknown candidate".to_owned(),
            ));
        }
        let key = (score.i.min(score.j), score.i.max(score.j));
        if map.insert(key, score.cosine).is_some() {
            return Err(Error::InvalidObservations(
                "a similarity pair repeats".to_owned(),
            ));
        }
    }
    for replay in &observations.replay {
        if !known.contains(&replay.index) {
            return Err(Error::InvalidObservations(
                "a replay names an unknown candidate".to_owned(),
            ));
        }
    }
    for prior in &observations.priors {
        if prior
            .scope_equal_candidates
            .iter()
            .any(|index| !known.contains(index))
        {
            return Err(Error::InvalidObservations(
                "a scope fact names an unknown candidate".to_owned(),
            ));
        }
    }
    Ok(map)
}

fn all_matches(
    observations: &Observations,
    groups: &BTreeMap<usize, usize>,
    observed: &BTreeMap<usize, &CandidateObservation>,
) -> BTreeMap<usize, Vec<PriorMatch>> {
    let mut all = BTreeMap::new();
    for rep in groups.keys() {
        let candidate = observed[rep];
        let mut matches = Vec::new();
        for (at, prior) in observations.priors.iter().enumerate() {
            let same = prior.identity_token == candidate.identity_token
                && prior.topic_token == candidate.topic_token;
            if same {
                matches.push(PriorMatch {
                    prior: at,
                    equal: prior.value_token == candidate.value_token,
                });
            }
        }
        all.insert(*rep, matches);
    }
    all
}

fn nominate(
    candidates: &[&CandidateObservation],
    scores: &BTreeMap<(usize, usize), Option<f64>>,
    threshold: f64,
) -> Result<Vec<Vec<usize>>, Error> {
    let mut parents: Vec<usize> = (0..candidates.len()).collect();
    let mut nominated = BTreeSet::new();
    for (i, a) in candidates.iter().enumerate() {
        for (j, b) in candidates.iter().enumerate().skip(i + 1) {
            if should_nominate(a, b, scores, threshold)? {
                let ai = root(&parents, i);
                let bj = root(&parents, j);
                parents[bj] = ai;
                nominated.insert(i);
                nominated.insert(j);
            }
        }
    }
    let mut grouped: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in nominated {
        grouped
            .entry(root(&parents, index))
            .or_default()
            .push(index);
    }
    Ok(grouped.into_values().collect())
}

fn should_nominate(
    a: &CandidateObservation,
    b: &CandidateObservation,
    scores: &BTreeMap<(usize, usize), Option<f64>>,
    threshold: f64,
) -> Result<bool, Error> {
    if a.slice_token != b.slice_token {
        return Ok(false);
    }
    if a.identity_token == b.identity_token && a.topic_token == b.topic_token {
        return Ok(a.value_token != b.value_token);
    }
    if !a.has_vector || !b.has_vector {
        return Ok(false);
    }
    let key = (a.index.min(b.index), a.index.max(b.index));
    let cosine = scores
        .get(&key)
        .copied()
        .flatten()
        .filter(|cosine| cosine.is_finite())
        .ok_or_else(|| Error::InvalidObservations("invalid nomination embedding".to_owned()))?;
    Ok(cosine >= threshold)
}

fn root(parents: &[usize], mut index: usize) -> usize {
    while parents[index] != index {
        index = parents[index];
    }
    index
}

fn route_sets(
    ready: &[usize],
    ready_obs: &[&CandidateObservation],
    observations: &Observations,
    kept: &BTreeMap<usize, Vec<PriorMatch>>,
    components: Vec<Vec<usize>>,
) -> (Vec<JudgeSet>, Vec<Option<usize>>) {
    let mut exact = BTreeSet::new();
    for (pos, rep) in ready.iter().enumerate() {
        if kept[rep].len() == 1 && kept[rep][0].equal {
            exact.insert(pos);
        }
    }
    let mut sets: Vec<JudgeSet> = Vec::new();
    for members in components {
        let identity_token = ready_obs[members[0]].identity_token.clone();
        let mut ids = BTreeSet::new();
        for pos in &members {
            for matched in &kept[&ready[*pos]] {
                ids.insert(observations.priors[matched.prior].claim.clone());
            }
        }
        let prior_heads: Vec<String> = ids.into_iter().collect();
        let remaining: Vec<usize> = members
            .into_iter()
            .filter(|pos| !exact.contains(pos))
            .collect();
        if remaining.is_empty() {
            continue;
        }
        let prior_head = (prior_heads.len() == 1).then(|| prior_heads[0].clone());
        sets.push(JudgeSet {
            candidate_indexes: remaining,
            identity_token,
            prior_heads,
            prior_head,
        });
    }
    let mut in_set: Vec<Option<usize>> = vec![None; ready.len()];
    for (at, set) in sets.iter().enumerate() {
        for pos in &set.candidate_indexes {
            in_set[*pos] = Some(at);
        }
    }
    for (pos, rep) in ready.iter().enumerate() {
        if in_set[pos].is_some() {
            continue;
        }
        if kept[rep].iter().all(|matched| matched.equal) {
            continue;
        }
        let heads: Vec<String> = kept[rep]
            .iter()
            .map(|matched| observations.priors[matched.prior].claim.clone())
            .collect();
        let prior_head = (heads.len() == 1).then(|| heads[0].clone());
        in_set[pos] = Some(sets.len());
        sets.push(JudgeSet {
            candidate_indexes: vec![pos],
            identity_token: ready_obs[pos].identity_token.clone(),
            prior_heads: heads,
            prior_head,
        });
    }
    (sets, in_set)
}

#[must_use]
fn write_choice(
    rep: usize,
    candidate: &CandidateObservation,
    observations: &Observations,
    kept: &[PriorMatch],
) -> Route {
    if let Some(head) = attachment_head(rep, candidate, observations, kept) {
        let claim = observations.priors[head].claim.clone();
        if observations.priors[head].standing == PROVISIONAL && claim != candidate.claim {
            return Route::AlreadyRepresented {
                head: claim,
                reason: AlreadyRepresentedReason::ProvisionalHead,
            };
        }
        return Route::Attach { head: claim };
    }
    // Native reaches this check with no supersession on every candidate
    // outside a set: a correction never skips it.
    if kept.is_empty()
        && let Some(head) = restates_unlisted(rep, candidate, observations)
    {
        return Route::AlreadyRepresented {
            head,
            reason: AlreadyRepresentedReason::RestatesUnlisted,
        };
    }
    Route::New
}

fn attachment_head(
    rep: usize,
    candidate: &CandidateObservation,
    observations: &Observations,
    kept: &[PriorMatch],
) -> Option<usize> {
    if kept.len() == 1 && kept[0].equal {
        return Some(kept[0].prior);
    }
    if kept.len() > 1
        && candidate.meet != IMPORTED
        && kept.iter().all(|matched| matched.equal)
        && kept
            .iter()
            .all(|matched| observations.priors[matched.prior].standing != PROVISIONAL)
    {
        let first = kept[0].prior;
        let head = &observations.priors[first];
        if candidate.named_facet.as_ref() == Some(&candidate.scope_facet)
            && candidate.scope_facet == head.scope_facet
            && candidate.scope_project == head.scope_project
            && head.scope_equal_candidates.contains(&rep)
        {
            return Some(first);
        }
    }
    None
}

fn restates_unlisted(
    rep: usize,
    candidate: &CandidateObservation,
    observations: &Observations,
) -> Option<String> {
    if candidate.meet == IMPORTED {
        return None;
    }
    for replay in observations.replay.iter().filter(|row| row.index == rep) {
        if replay.claim == candidate.claim {
            continue;
        }
        if replay.identity_token != candidate.identity_token
            || replay.topic_token != candidate.topic_token
            || replay.value_token != candidate.value_token
        {
            continue;
        }
        if candidate.replay_facet != replay.scope_facet
            || candidate.scope_project != replay.scope_project
            || !replay.scope_equal
        {
            continue;
        }
        return Some(replay.claim.clone());
    }
    None
}

fn corrections(
    selection: &ExtractionSelectionPlan,
    observations: &Observations,
    observed: &BTreeMap<usize, &CandidateObservation>,
    all: &BTreeMap<usize, Vec<PriorMatch>>,
) -> Result<Vec<Correction>, Error> {
    let mut out = Vec::new();
    for group in &selection.groups {
        let Some(head) = group.corrects.as_deref() else {
            continue;
        };
        let rep = group.representative_index;
        let candidate = observed[&rep];
        if !observations.priors.iter().any(|prior| prior.claim == head) {
            return Err(Error::InvalidObservations(
                "correction names an unknown prior".to_owned(),
            ));
        }
        let shared = selection.groups.iter().any(|other| {
            let other_rep = other.representative_index;
            observed[&other_rep].claim != candidate.claim
                && all[&other_rep]
                    .iter()
                    .any(|matched| observations.priors[matched.prior].claim == head)
        });
        if !shared {
            out.push(Correction {
                representative_index: rep,
                head: head.to_owned(),
            });
        }
    }
    out.sort_by_key(|entry| observed[&entry.representative_index].claim.as_str());
    Ok(out)
}

fn check_policy_pin(expected: &str, actual: &str) -> Result<(), Error> {
    if expected != actual {
        return Err(Error::PolicyPin {
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

fn unit(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}
