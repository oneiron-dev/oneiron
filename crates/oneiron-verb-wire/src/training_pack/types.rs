//! Moved from `crates/oneiron/src/training_pack/types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::skill_optimize::training_choice::SwapChoice;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A particular version in the vault's existing blob custody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactPin {
    pub artifact: EntityId,
    pub version: u64,
    pub blake3: [u8; 32],
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointFileKind {
    Weights,
    Tokenizer,
    Config,
    Template,
    AdapterConfig,
}

/// The owner a run, an authorization or a swap receipt names: an actor, or
/// no one once that actor was erased (FIX 3520). It reads and writes as the
/// actor's hex id, or as [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrainingOwner {
    Actor(EntityId),
    Erased,
}

impl TrainingOwner {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }

    /// Makes this no one when it is `actor`; whether it was.
    pub fn forget(&mut self, actor: EntityId) -> bool {
        let named = self.is(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

impl Serialize for TrainingOwner {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Actor(id) => serializer.serialize_str(&id.to_hex()),
            Self::Erased => serializer.serialize_str(ERASED_CALL_IDENTITY),
        }
    }
}

impl<'de> Deserialize<'de> for TrainingOwner {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == ERASED_CALL_IDENTITY {
            return Ok(Self::Erased);
        }
        EntityId::from_hex(&value)
            .map(Self::Actor)
            .map_err(serde::de::Error::custom)
    }
}

/// Its schema is its wire form: the actor's hex id, or [`ERASED_CALL_IDENTITY`].
impl schemars::JsonSchema for TrainingOwner {
    fn schema_name() -> String {
        "TrainingOwner".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExportCheck {
    pub hash_mismatches: Vec<String>,
    pub probe_coverage_matches: bool,
    pub probe_checkpoints_match: bool,
    pub settings_match: bool,
    pub harness_matches: bool,
    pub argmax_flips: u64,
    pub max_logit_difference: f64,
    pub tolerance: f64,
    /// A question head's own producer check; a role run has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub question_check: Option<QuestionExportCheck>,
    /// The host's Candle-side reproduction of a question head's probe
    /// evidence (FIX 7568); a role run has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candle_parity: Option<CandleParityCheck>,
}

/// What the host reproduced of a trained classifier's receipt on the stack
/// that would serve it (FIX 7568), before it may serve: a check of our own
/// artifact against the trainer's word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CandleParityCheck {
    /// Every probe's token ids, rendered and tokenized here with the
    /// export's own pinned tokenizer and cut into its windows, hash to the
    /// trainer's.
    pub tokens_match: bool,
    /// The probes whose ids did not reproduce, by id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub token_mismatches: Vec<String>,
    /// Whether the export's logits reproduced in Candle: `None` while no
    /// Candle classifier loader is built here, so none was run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logits_match: Option<bool>,
}

impl CandleParityCheck {
    /// No half that ran failed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.tokens_match && self.logits_match != Some(false)
    }
}

/// What a question head's trainer also measured on its fixed probes: every
/// logit finite, the export's tokens the training's, and its own verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QuestionExportCheck {
    pub finite: bool,
    pub tokens_match: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalibrationResult {
    pub temperature: f64,
    pub brier_score: f64,
    pub calibration_error: f64,
}
