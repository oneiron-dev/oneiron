//! Moved from `crates/oneiron/src/llm/tagger.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::ModelId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MentionTag {
    pub start: usize,
    pub end: usize,
    #[serde(with = "super::entity_refs")]
    pub entity: EntityId,
    pub weight: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PprSeed {
    #[serde(with = "super::entity_refs")]
    pub entity: EntityId,
    pub weight: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreferenceTag {
    pub mention: usize,
    pub antecedent: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RetrievalTags {
    pub mentions: Vec<MentionTag>,
    pub ppr_seeds: Vec<PprSeed>,
    pub affect: [f32; 3],
    pub coreference: Vec<CoreferenceTag>,
}

impl RetrievalTags {
    pub fn validate(&self, text: &str) -> Result<()> {
        let valid_weight = |n: f32| n.is_finite() && (0.0..=1.0).contains(&n);
        if self.mentions.iter().any(|m| {
            m.start >= m.end
                || m.end > text.len()
                || !text.is_char_boundary(m.start)
                || !text.is_char_boundary(m.end)
                || !valid_weight(m.weight)
        }) || self.ppr_seeds.iter().any(|seed| !valid_weight(seed.weight))
            || self
                .affect
                .iter()
                .any(|n| !n.is_finite() || !(-1.0..=1.0).contains(n))
            || self
                .coreference
                .iter()
                .any(|c| c.mention >= self.mentions.len() || c.antecedent >= self.mentions.len())
        {
            return Err(Error::InvalidConfig("invalid retrieval tags".into()));
        }
        Ok(())
    }

    pub fn read_refs(&self) -> Vec<EntityId> {
        self.mentions
            .iter()
            .map(|m| m.entity)
            .chain(self.ppr_seeds.iter().map(|p| p.entity))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowTagReport {
    #[serde(with = "super::entity_refs")]
    pub turn: EntityId,
    pub model: ModelId,
    pub tags: RetrievalTags,
    #[serde(with = "super::entity_refs::list")]
    pub common: Vec<EntityId>,
    #[serde(with = "super::entity_refs::list")]
    pub tag_only: Vec<EntityId>,
    #[serde(with = "super::entity_refs::list")]
    pub live_only: Vec<EntityId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputDelta {
    #[serde(with = "super::entity_refs")]
    pub turn: EntityId,
    pub text: String,
    pub before: RetrievalTags,
    pub after: RetrievalTags,
    pub threshold: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RenderReceipt {
    #[serde(with = "super::entity_refs")]
    pub turn: EntityId,
    #[serde(with = "super::entity_refs::list")]
    pub read_refs: Vec<EntityId>,
    pub input_hash: String,
    pub surprise: f32,
    pub admitted: bool,
}
