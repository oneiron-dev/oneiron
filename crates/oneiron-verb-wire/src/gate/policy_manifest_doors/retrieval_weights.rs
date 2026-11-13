//! Moved from `crates/oneiron/src/gate/policy_manifest_doors/retrieval_weights.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

/// Independent, default-off read-side priors. None changes claim truth or authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalWeights {
    /// Emotion congruence, in 0..=0.4.
    pub affect: f32,
    /// Arousal half-life stretch, in 0..=4.
    pub arousal: f32,
    /// Nonnegative community beta; the existing community safety caps still apply.
    pub community: f32,
    /// Stored semantic-edge VAD salience for PPR, in 0..=0.4.
    pub vad: f32,
}

impl RetrievalWeights {
    fn from_config(config: &oneiron_store::config::VaultConfig) -> Self {
        Self {
            affect: config.affect_retrieval.emotion_weight,
            arousal: config.affect_retrieval.arousal_stretch,
            community: config.ppr_community.beta,
            vad: config.ppr_vad_alpha,
        }
    }

    pub fn validate(&self) -> Result<()> {
        oneiron_store::config::retrieval_affect::AffectRetrievalPolicy {
            emotion_weight: self.affect,
            arousal_stretch: self.arousal,
            ..Default::default()
        }
        .validate()?;
        oneiron_store::config::validate_ppr_vad_alpha(self.vad)?;
        oneiron_store::config::validate_ppr_community(
            &oneiron_store::config::community_graph::PprCommunityConfig {
                beta: self.community,
                ..Default::default()
            },
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalWeightsConfigureRequest {
    pub expected_body_hash: String,
    pub weights: RetrievalWeights,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalWeightsView {
    pub manifest_ref: String,
    pub body_hash: String,
    pub weights: RetrievalWeights,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalWeightsReceipt {
    pub configuration: RetrievalWeightsView,
    pub receipt_ref: String,
}
