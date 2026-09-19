//! Host-injected retrieval tags and a write-free shadow comparison. Tags never author claims.
use super::{
    BudgetGuard, DurableStepContext, DurableStepResult, LlmBackend, LlmRequest, ModelId,
    StepOutcome,
};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
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
pub trait OneironerTagger: Send + Sync {
    fn model(&self) -> ModelId;
    fn tag(&self, text: &str) -> Result<RetrievalTags>;
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
/// Reads a real turn, runs the injected checkpoint, and compares with the live
/// retrieval result. Neither the tagger nor this function receives a write door.
pub fn shadow_tag_turn(
    vault: &Vault,
    turn: EntityId,
    tagger: &dyn OneironerTagger,
    live: &[EntityId],
) -> Result<ShadowTagReport> {
    let text = crate::dreamer_consolidation::turn_text_for_shadow(vault, &turn)?;
    let tags = tagger.tag(&text)?;
    tags.validate(&text)?;
    let reads = tags.read_refs();
    Ok(ShadowTagReport {
        turn,
        model: tagger.model(),
        common: reads
            .iter()
            .copied()
            .filter(|id| live.contains(id))
            .collect(),
        tag_only: reads
            .iter()
            .copied()
            .filter(|id| !live.contains(id))
            .collect(),
        live_only: live
            .iter()
            .copied()
            .filter(|id| !reads.contains(id))
            .collect(),
        tags,
    })
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
#[derive(Debug, Clone, PartialEq)]
pub struct GatedRender {
    pub receipt: RenderReceipt,
    pub step: Option<StepOutcome>,
}
/// Changed retrieval identities, changed coreference, or a changed affect state
/// are the deterministic surprise signal. No model is called to decide this.
pub async fn render_on_delta(
    ctx: &DurableStepContext<'_>,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    mut request: LlmRequest,
    delta: &InputDelta,
) -> DurableStepResult<GatedRender> {
    delta.after.validate(&delta.text)?;
    if !delta.threshold.is_finite() || !(0.0..=1.0).contains(&delta.threshold) {
        return Err(Error::InvalidConfig("invalid surprise threshold".into()).into());
    }
    if delta
        .before
        .affect
        .iter()
        .any(|n| !n.is_finite() || !(-1.0..=1.0).contains(n))
    {
        return Err(Error::InvalidConfig("invalid previous affect state".into()).into());
    }
    let before = delta.before.read_refs();
    let reads = delta.after.read_refs();
    let identity_change = before != reads || delta.before.coreference != delta.after.coreference;
    let affect_change = delta
        .before
        .affect
        .iter()
        .zip(delta.after.affect)
        .map(|(a, b)| (a - b).abs() / 2.0)
        .fold(0.0_f32, f32::max);
    let surprise = if identity_change { 1.0 } else { affect_change };
    let admitted = surprise > 0.0 && surprise >= delta.threshold;
    let input_hash = blake3::hash(&serde_json::to_vec(delta)?)
        .to_hex()
        .to_string();
    let receipt = RenderReceipt {
        turn: delta.turn,
        read_refs: reads,
        input_hash,
        surprise,
        admitted,
    };
    let step = if admitted {
        // Bind the exact deterministic inputs and receipt into the request hash.
        // A different delta cannot reuse a prior render merely because the host
        // reused its generic request template.
        request.messages.push(super::LlmMessage {
            role: super::LlmMessageRole::User,
            content: vec![super::ContentPart::Text {
                text: serde_json::to_string(&serde_json::json!({
                    "input_delta": delta,
                    "render_receipt": &receipt,
                }))?,
            }],
        });
        Some(super::call_as_step(ctx, backend, guard, request).await?)
    } else {
        None
    };
    Ok(GatedRender { receipt, step })
}

#[cfg(test)]
mod tests;
