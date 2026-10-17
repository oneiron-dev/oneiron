//! PACK data for provenance-aware claim ordering. Visibility gates run first.
use super::ContextEntity;
use crate::claim::{ClaimBody, ClaimSource, ClaimSubject};
use crate::error::Result;
use crate::{EntityId, Error};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRankingPolicy {
    pub pack: String,
    pub multipliers: BTreeMap<String, f32>,
}
impl Default for SourceRankingPolicy {
    fn default() -> Self {
        serde_json::from_str(include_str!("source_ranking.json"))
            .expect("shipped source ranking policy")
    }
}
impl SourceRankingPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.pack.trim().is_empty()
            || self.multipliers.iter().any(|(source, factor)| {
                ClaimSource::parse(source).is_none()
                    || !factor.is_finite()
                    || *factor < 0.0
                    || *factor > 10_000.0
            })
        {
            return Err(Error::InvalidConfig(
                "invalid claim source ranking multipliers".into(),
            ));
        }
        Ok(())
    }
    fn factor(&self, source: Option<ClaimSource>) -> f32 {
        source
            .and_then(|s| self.multipliers.get(s.as_str()))
            .copied()
            .unwrap_or(1.0)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Question {
    subject: EntityId,
    predicate: String,
    world: Option<EntityId>,
    rel: Option<EntityId>,
    project: EntityId,
    facet: EntityId,
    scope: Vec<u8>,
}
fn canonical(value: &rmpv::Value) -> rmpv::Value {
    match value {
        rmpv::Value::Map(fields) => {
            let mut fields: Vec<_> = fields
                .iter()
                .map(|(key, value)| (canonical(key), canonical(value)))
                .collect();
            fields.sort_by_cached_key(|(key, _)| bytes(key));
            rmpv::Value::Map(fields)
        }
        rmpv::Value::Array(values) => rmpv::Value::Array(values.iter().map(canonical).collect()),
        value => value.clone(),
    }
}
fn bytes(value: &rmpv::Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).expect("Vec encoding");
    out
}
fn question(body: &ClaimBody) -> Option<Question> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return None;
    };
    let fields = match &body.scope {
        Some(rmpv::Value::Map(fields)) => fields
            .iter()
            .filter(|(k, _)| matches!(k.as_str(), Some("facet_ref" | "topic_key")))
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    Some(Question {
        subject,
        predicate: body.predicate.clone(),
        world: body.world,
        rel: body.rel,
        project: body.scope_project,
        facet: body.scope_facet,
        scope: bytes(&canonical(&rmpv::Value::Map(fields))),
    })
}

pub(super) fn apply(
    results: &mut [ContextEntity],
    neighbors: &mut [ContextEntity],
    bodies: &HashMap<EntityId, ClaimBody>,
    policy: &SourceRankingPolicy,
) -> Result<()> {
    let found: Vec<_> = results
        .iter()
        .chain(neighbors.iter())
        .map(|entity| bodies.get(&entity.id))
        .collect();
    let mut scores: Vec<_> = results
        .iter()
        .chain(neighbors.iter())
        .map(|entity| entity.score)
        .collect();
    rank_scores(&found, &mut scores, policy)?;
    for (entity, score) in results.iter_mut().chain(neighbors.iter_mut()).zip(scores) {
        entity.score = score;
    }
    sort_within_worlds(results, bodies);
    sort_within_worlds(neighbors, bodies);
    Ok(())
}

/// Source ranking on a read path outside the pack. `row` yields each row's
/// score and, for a claim, its decoded body; a row without a body keeps its
/// score. The rows then sort by score, highest first, keeping their order
/// among ties. Returns the ranked scores in the new row order.
pub(crate) fn rank<T>(
    rows: &mut Vec<T>,
    policy: &SourceRankingPolicy,
    row: impl Fn(&T) -> (f32, Option<&ClaimBody>),
) -> Result<Vec<f32>> {
    let scores = {
        let views: Vec<_> = rows.iter().map(&row).collect();
        let bodies: Vec<_> = views.iter().map(|view| view.1).collect();
        let mut scores: Vec<_> = views.iter().map(|view| view.0).collect();
        rank_scores(&bodies, &mut scores, policy)?;
        scores
    };
    let mut ranked: Vec<_> = scores.into_iter().zip(rows.drain(..)).collect();
    ranked.sort_by(|(a, _), (b, _)| b.total_cmp(a));
    let mut scores = Vec::with_capacity(ranked.len());
    for (score, ranked_row) in ranked {
        scores.push(score);
        rows.push(ranked_row);
    }
    Ok(scores)
}

/// The observed-below-stated clamp alone, for an order a backend rerank set:
/// each observed claim that sits above a stated claim of its question moves
/// to just below the last one. Every other row keeps its place, and no
/// score changes. `body` yields a row's claim body, `None` for a non-claim.
pub(crate) fn clamp_order<T>(
    rows: &mut Vec<T>,
    policy: &SourceRankingPolicy,
    body: impl Fn(&T) -> Option<&ClaimBody>,
) -> Result<()> {
    clamp_order_by(rows, policy, |row| {
        let body = body(row)?;
        Some((body.source?, question(body)?))
    })
}

/// A claim's question as a fixed key a row can carry once its body is gone,
/// for [`clamp_order_by`]. `None` for a claim about an edge.
pub(crate) fn question_key(body: &ClaimBody) -> Option<[u8; 32]> {
    let question = question(body)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(question.subject.as_bytes());
    hasher.update(&(question.predicate.len() as u64).to_le_bytes());
    hasher.update(question.predicate.as_bytes());
    for id in [question.world, question.rel] {
        match id {
            Some(id) => hasher.update(&[1]).update(id.as_bytes()),
            None => hasher.update(&[0]),
        };
    }
    hasher.update(question.project.as_bytes());
    hasher.update(question.facet.as_bytes());
    hasher.update(&question.scope);
    Some(*hasher.finalize().as_bytes())
}

/// [`clamp_order`] over keys a reader already holds: `key` yields a row's
/// source and question key, `None` for a row the clamp leaves alone.
pub(crate) fn clamp_order_by<T, K: Eq + std::hash::Hash>(
    rows: &mut Vec<T>,
    policy: &SourceRankingPolicy,
    key: impl Fn(&T) -> Option<(ClaimSource, K)>,
) -> Result<()> {
    policy.validate()?;
    // The same opt-out as the scored clamp: an override favouring observations.
    if policy.factor(Some(ClaimSource::Observed)) > policy.factor(Some(ClaimSource::UserStated)) {
        return Ok(());
    }
    let mut last_stated = HashMap::<K, usize>::new();
    for (index, row) in rows.iter().enumerate() {
        if let Some((ClaimSource::UserStated, question)) = key(row) {
            last_stated.insert(question, index);
        }
    }
    let moves: Vec<Option<usize>> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let (ClaimSource::Observed, question) = key(row)? else {
                return None;
            };
            last_stated
                .get(&question)
                .copied()
                .filter(|last| *last > index)
        })
        .collect();
    if moves.iter().all(Option::is_none) {
        return Ok(());
    }
    let mut after = HashMap::<usize, Vec<T>>::new();
    let mut kept = Vec::with_capacity(rows.len());
    for (index, (row, target)) in rows.drain(..).zip(&moves).enumerate() {
        match target {
            Some(target) => after.entry(*target).or_default().push(row),
            None => kept.push((index, row)),
        }
    }
    // A move's target is a stated row, which never moves itself.
    for (index, row) in kept {
        rows.push(row);
        rows.extend(after.remove(&index).unwrap_or_default());
    }
    Ok(())
}

/// The clamp's rule for one pair of claims on a shared question, for a reader
/// that picks or cuts rather than ordering a whole list: whether a claim from
/// source `a` ranks above one from `b`. A stated claim outranks an observed
/// one, and an override favouring observations opts out, as it does for the
/// clamp. Every other pair, Generated included, ranks equal.
pub(crate) fn source_outranks(
    policy: &SourceRankingPolicy,
    a: Option<ClaimSource>,
    b: Option<ClaimSource>,
) -> bool {
    a == Some(ClaimSource::UserStated)
        && b == Some(ClaimSource::Observed)
        && policy.factor(b) <= policy.factor(a)
}

/// The multiplier and the observed-below-stated clamp, the one implementation
/// every path shares. `bodies[i]` is row i's claim body, `None` for a row
/// that is not a claim.
fn rank_scores(
    bodies: &[Option<&ClaimBody>],
    scores: &mut [f32],
    policy: &SourceRankingPolicy,
) -> Result<()> {
    policy.validate()?;
    for (body, score) in bodies.iter().copied().zip(scores.iter_mut()) {
        if let Some(body) = body {
            *score = (*score * policy.factor(body.source)).min(f32::MAX);
        }
    }
    clamp_scores(bodies, scores, policy)
}

/// The observed-below-stated clamp on scores alone, with no multiplier:
/// each observed claim scores at most just below the lowest stated claim of
/// its question. For a read whose multipliers a later pass applies once,
/// such as the pipeline ahead of the pack's assembly. `bodies[i]` is row
/// i's claim body, `None` for a row that is not a claim.
pub(crate) fn clamp_scores(
    bodies: &[Option<&ClaimBody>],
    scores: &mut [f32],
    policy: &SourceRankingPolicy,
) -> Result<()> {
    policy.validate()?;
    let mut stated = HashMap::<Question, f32>::new();
    for (body, score) in bodies.iter().copied().zip(scores.iter()) {
        let Some(body) = body else {
            continue;
        };
        if body.source == Some(ClaimSource::UserStated)
            && let Some(key) = question(body)
        {
            stated
                .entry(key)
                .and_modify(|floor| *floor = floor.min(*score))
                .or_insert(*score);
        }
    }
    // An explicit PACK override favouring observations opts out. The shipped
    // equal multipliers clamp each observed mate beneath every stated head,
    // even if its retrieval score was originally much larger.
    if policy.factor(Some(ClaimSource::Observed)) <= policy.factor(Some(ClaimSource::UserStated)) {
        for (body, score) in bodies.iter().copied().zip(scores.iter_mut()) {
            if let Some(body) = body
                && body.source == Some(ClaimSource::Observed)
                && let Some(key) = question(body)
                && let Some(floor) = stated.get(&key)
            {
                *score = score.min(floor.next_down());
            }
        }
    }
    Ok(())
}

fn sort_within_worlds(rows: &mut [ContextEntity], bodies: &HashMap<EntityId, ClaimBody>) {
    let mut sections = HashMap::new();
    for row in rows.iter() {
        let world = bodies.get(&row.id).and_then(|b| b.world);
        let next = sections.len();
        sections.entry(world).or_insert(next);
    }
    rows.sort_by(|a, b| {
        let aw = bodies.get(&a.id).and_then(|b| b.world);
        let bw = bodies.get(&b.id).and_then(|b| b.world);
        sections[&aw]
            .cmp(&sections[&bw])
            .then_with(|| b.score.total_cmp(&a.score))
            .then_with(|| a.id.cmp(&b.id))
    });
}
