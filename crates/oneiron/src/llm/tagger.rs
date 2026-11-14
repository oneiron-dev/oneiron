//! Host-injected retrieval tags, a write-free shadow comparison, and the
//! deterministic surprise gate between the two model families. Tags never
//! author claims, and the tagger is never a render: a generative call reads a
//! tag delta only when the gate admits it (ARCH-0036, ARCH-0035 "tagging is
//! never a render").
use super::{
    BudgetGuard, DurableStepContext, DurableStepResult, LlmBackend, LlmRequest, ModelId,
    StepOutcome,
};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
};
#[doc(hidden)]
pub use oneiron_records::llm::tagger::{
    CoreferenceTag, InputDelta, MentionTag, PprSeed, RenderReceipt, RetrievalTags, ShadowTagReport,
};
use serde::{Deserialize, Serialize};

pub trait OneironerTagger: Send + Sync {
    fn model(&self) -> ModelId;
    fn tag(&self, text: &str) -> Result<RetrievalTags>;
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
#[derive(Debug, Clone, PartialEq)]
pub struct GatedRender {
    pub receipt: RenderReceipt,
    pub step: Option<StepOutcome>,
}
/// The deterministic surprise of a tag delta, in `[0, 1]`: 1 when the
/// retrieval identities or the coreference changed, else the largest move of
/// one affect coordinate over half its span. No model is called to decide
/// this; the saved-tag path and [`render_on_delta`] read the same gate.
#[must_use]
pub fn delta_surprise(identity_changed: bool, before: [f32; 3], after: [f32; 3]) -> f32 {
    if identity_changed {
        return 1.0;
    }
    before
        .iter()
        .zip(after)
        .map(|(a, b)| (a - b).abs() / 2.0)
        .fold(0.0_f32, f32::max)
        .min(1.0)
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
    delta.before.validate(&delta.text)?;
    delta.after.validate(&delta.text)?;
    if !delta.threshold.is_finite() || !(0.0..=1.0).contains(&delta.threshold) {
        return Err(Error::InvalidConfig("invalid surprise threshold".into()).into());
    }
    let before = delta.before.read_refs();
    let reads = delta.after.read_refs();
    let identity_change = before != reads || delta.before.coreference != delta.after.coreference;
    let surprise = delta_surprise(identity_change, delta.before.affect, delta.after.affect);
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
                signature: None,
            }],
        });
        Some(super::call_as_step(ctx, backend, guard, request).await?)
    } else {
        None
    };
    Ok(GatedRender { receipt, step })
}
