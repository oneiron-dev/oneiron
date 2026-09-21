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
        scope: bytes(&canonical(&rmpv::Value::Map(fields))),
    })
}

pub(super) fn apply(
    results: &mut [ContextEntity],
    neighbors: &mut [ContextEntity],
    bodies: &HashMap<EntityId, ClaimBody>,
    policy: &SourceRankingPolicy,
) -> Result<()> {
    policy.validate()?;
    let mut stated = HashMap::<Question, f32>::new();
    for entity in results.iter_mut().chain(neighbors.iter_mut()) {
        let Some(body) = bodies.get(&entity.id) else {
            continue;
        };
        entity.score = (entity.score * policy.factor(body.source)).min(f32::MAX);
        if body.source == Some(ClaimSource::UserStated)
            && let Some(key) = question(body)
        {
            stated
                .entry(key)
                .and_modify(|floor| *floor = floor.min(entity.score))
                .or_insert(entity.score);
        }
    }
    // An explicit PACK override favouring observations opts out. The shipped
    // equal multipliers clamp each observed mate beneath every stated head,
    // even if its retrieval score was originally much larger.
    if policy.factor(Some(ClaimSource::Observed)) <= policy.factor(Some(ClaimSource::UserStated)) {
        for entity in results.iter_mut().chain(neighbors.iter_mut()) {
            let Some(body) = bodies.get(&entity.id) else {
                continue;
            };
            if body.source == Some(ClaimSource::Observed)
                && let Some(key) = question(body)
                && let Some(floor) = stated.get(&key)
            {
                entity.score = entity.score.min(floor.next_down());
            }
        }
    }
    sort_within_worlds(results, bodies);
    sort_within_worlds(neighbors, bodies);
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
