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

#[cfg(test)]
mod tests {
    use super::*;
    fn id(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).unwrap()
    }
    #[test]
    fn affect_ranks_similar_above_neutral_and_floor_dampens() -> Result<()> {
        let query = Vad {
            valence: 0.8,
            arousal: 0.9,
            dominance: 0.7,
        };
        let affect = BTreeMap::from([
            (id(1), query),
            (id(2), Vad::NEUTRAL),
            (
                id(3),
                Vad {
                    arousal: 0.1,
                    ..Vad::NEUTRAL
                },
            ),
        ]);
        let candidates: Vec<_> = (1..=4)
            .map(|seed| RerankCandidate {
                id: id(seed),
                score: 1.0,
                rank: seed.into(),
                claim: None,
            })
            .collect();
        let emotion = EmotionSimilarityReranker::new(query, affect.clone())?;
        let scores = emotion.rerank("", &candidates)?;
        assert!(scores[0] > scores[1]);
        assert_eq!(scores[3], scores[1], "missing VAD is neutral");
        let floor = ArousalFloor::new(0.5)?;
        let arousal = ArousalReranker::new(affect, floor)?;
        let scores = arousal.rerank("", &candidates)?;
        assert!(scores[0] > scores[2]);
        assert!(scores[2] < 0.1);
        assert!(scores.iter().all(|v| v.is_finite()));
        for bad in [-0.1, 1.1, f32::NAN, f32::INFINITY] {
            assert!(ArousalFloor::new(bad).is_err());
        }
        Ok(())
    }
    #[test]
    fn edge_arousal_ranking_survives_working_set_paging() -> Result<()> {
        use crate::pipeline::{DreamerWorkingSetBudget, DreamerWorkingSetCursor};
        let dir = tempfile::tempdir()?;
        let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
        let anchor = id(0xB0);
        let low = id(0xB1);
        let high = id(0xB2);
        let mid = id(0xB3);
        for entity in [anchor, low, high, mid] {
            vault
                .batch()
                .put(
                    &entity,
                    crate::registry::ENTITY_TYPE_PERSON,
                    crate::TimeRange { start: 1, end: 1 },
                    1,
                    b"memory",
                )
                .text(&entity, &[("body", "shared memory")])
                .commit()?;
        }
        for (target, arousal) in [(low, 0.1), (high, 0.9), (mid, 0.6)] {
            vault
                .batch()
                .edge_with_created_at_and_vad(
                    &anchor,
                    crate::EdgeKind::Mentions,
                    &target,
                    0.5,
                    1,
                    Vad {
                        arousal,
                        ..Vad::NEUTRAL
                    },
                )
                .commit()?;
        }
        let scoped = vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").unwrap());
        let ranker =
            ArousalReranker::from_scoped_edges(&scoped, &[anchor], ArousalFloor::new(0.5)?)?;
        let query = || {
            vault.query().search_text("memory", 10).rerank(
                &ranker,
                super::super::RerankOptions {
                    top_n: 10,
                    query: None,
                },
            )
        };
        let full = query().run()?;
        assert_eq!(full[0].id, high);
        assert_eq!(full[1].id, mid);
        assert_eq!(full[2].id, low);
        let budget = DreamerWorkingSetBudget::new(10);
        let first = query().run_dreamer_working_set(DreamerWorkingSetCursor::start(), budget, 2)?;
        let second = query().run_dreamer_working_set(first.next_cursor.unwrap(), budget, 2)?;
        let paged = first
            .rows
            .iter()
            .chain(&second.rows)
            .map(|item| item.id)
            .collect::<Vec<_>>();
        assert_eq!(paged, full.iter().map(|hit| hit.id).collect::<Vec<_>>());
        Ok(())
    }
}
