//! Nonblocking affect scorers over host-resolved, authorized edge VAD.
//! These compose with the ordinary post-blend ladder, including PPR VAD.

use super::{RerankCandidate, Reranker};
use crate::affect::Vad;
use crate::{EntityId, Error, Result};
use std::collections::BTreeMap;

/// A loop-owned sensitivity setting. No hand-tuned nonzero default is hidden
/// in the ranker; callers supply the validated floor with their policy.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ArousalFloor(f32);
impl ArousalFloor {
    pub fn new(value: f32) -> Result<Self> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(Error::InvalidConfig(
                "arousal floor must be finite within 0..=1".into(),
            ));
        }
        Ok(Self(value))
    }
    pub fn value(self) -> f32 {
        self.0
    }
}

/// The host resolves edge visibility first and supplies the maximum edge
/// arousal per candidate. This avoids reading hidden neighbors under a second
/// authority model. Unknown VAD remains neutral, never invented.
pub struct ArousalReranker {
    id: String,
    affect: BTreeMap<EntityId, Vad>,
    floor: ArousalFloor,
}
impl ArousalReranker {
    /// Resolves only actor-readable edges before entering the nonblocking
    /// rerank seam. Multiple edge annotations use maximum arousal.
    pub fn from_scoped_edges(
        scoped: &crate::claim::ScopedRead<'_>,
        sources: &[EntityId],
        floor: ArousalFloor,
    ) -> Result<Self> {
        let mut affect: BTreeMap<EntityId, Vad> = BTreeMap::new();
        for source in sources {
            for edge in scoped.edges_out(source)?.value.unwrap_or_default() {
                if let Some(vad) = edge.vad {
                    vad.validate()?;
                    let entry = affect.entry(edge.target).or_insert(vad);
                    if vad.arousal > entry.arousal {
                        *entry = vad;
                    }
                }
            }
        }
        Self::new(affect, floor)
    }
    pub fn new(affect: BTreeMap<EntityId, Vad>, floor: ArousalFloor) -> Result<Self> {
        for vad in affect.values() {
            vad.validate()?;
        }
        let id = identity(b"arousal:v1", &affect, &[floor.0]);
        Ok(Self { id, affect, floor })
    }
}
impl Reranker for ArousalReranker {
    fn id(&self) -> &str {
        &self.id
    }
    fn rerank(&self, _: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        Ok(candidates
            .iter()
            .map(|c| {
                let a = self.affect.get(&c.id).map_or(0.0, |v| v.arousal);
                // Below-floor observations are damped continuously. At floor=0
                // no division occurs; every valid observation remains finite.
                if a < self.floor.0 {
                    a * a / self.floor.0
                } else {
                    a
                }
            })
            .collect())
    }
}

pub struct EmotionSimilarityReranker {
    id: String,
    query: Vad,
    affect: BTreeMap<EntityId, Vad>,
}
impl EmotionSimilarityReranker {
    pub fn new(query: Vad, affect: BTreeMap<EntityId, Vad>) -> Result<Self> {
        query.validate()?;
        for vad in affect.values() {
            vad.validate()?;
        }
        let id = identity(
            b"emotion-similarity:v2",
            &affect,
            &[query.valence, query.arousal, query.dominance],
        );
        Ok(Self { id, query, affect })
    }
}
impl Reranker for EmotionSimilarityReranker {
    fn id(&self) -> &str {
        &self.id
    }
    fn rerank(&self, _: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        Ok(candidates
            .iter()
            .map(|c| {
                let v = self.affect.get(&c.id).copied().unwrap_or(Vad::NEUTRAL);
                // Normalize valence's double-width axis before squared distance.
                let dv = (v.valence - self.query.valence) / 2.0;
                let da = v.arousal - self.query.arousal;
                let dd = v.dominance - self.query.dominance;
                (1.0 - (dv * dv + da * da + dd * dd) / 3.0).clamp(0.0, 1.0)
            })
            .collect())
    }
}
fn identity(domain: &[u8], affect: &BTreeMap<EntityId, Vad>, params: &[f32]) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(domain);
    for value in params {
        hash.update(&value.to_le_bytes());
    }
    for (id, v) in affect {
        hash.update(id.as_bytes());
        for value in [v.valence, v.arousal, v.dominance] {
            hash.update(&value.to_le_bytes());
        }
    }
    hash.finalize().to_hex().to_string()
}
