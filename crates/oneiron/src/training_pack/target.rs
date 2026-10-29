//! What a training run trains (FIX 7263): a model for one manifest role, or
//! one two-logit head for one exact detector question. A role run swaps into
//! the manifest through the owner's separate choice; a question head binds no
//! role, and its own approval is a later slice.
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;
use crate::llm::ModelId;
use crate::llm::manifest::{ModelBinding, ModelRole};

use super::{hash_json, invalid};

/// The labels a question head trains on: one yes or no per target.
pub const QUESTION_LABEL_SCHEMA: &str = "oneiron.per-target-binary/1";
/// How a question head's input is written as text.
pub const QUESTION_RENDERER: &str = "oneiron.detector-target-text/1";

/// The plan's target. A role plan writes `role` and `output_binding` as the
/// plan's own keys, as before; a question plan writes one `question` key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TrainingTarget {
    Role {
        role: ModelRole,
        output_binding: ModelBinding,
    },
    Question {
        question: QuestionTarget,
    },
}

/// The one exact question a head answers, and the new model id its
/// checkpoints carry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuestionTarget {
    pub question_id: String,
    pub question_version: u32,
    /// The exact question and its policy, as JSON.
    pub definition: Value,
    /// BLAKE3 of the definition's canonical JSON.
    pub definition_blake3: [u8; 32],
    pub family: String,
    pub corpus_revision: String,
    pub feature_schema: String,
    pub label_schema: String,
    pub renderer: String,
    pub output_model: ModelId,
}

impl TrainingTarget {
    /// The model id the returned checkpoints carry.
    #[must_use]
    pub fn output_model(&self) -> &ModelId {
        match self {
            Self::Role { output_binding, .. } => &output_binding.model,
            Self::Question { question } => &question.output_model,
        }
    }

    /// The role and the binding a role run swaps in; `None` for a question.
    #[must_use]
    pub fn role_binding(&self) -> Option<(ModelRole, &ModelBinding)> {
        match self {
            Self::Role {
                role,
                output_binding,
            } => Some((*role, output_binding)),
            Self::Question { .. } => None,
        }
    }

    /// The question a question run's head answers; `None` for a role.
    #[must_use]
    pub fn question(&self) -> Option<&QuestionTarget> {
        match self {
            Self::Role { .. } => None,
            Self::Question { question } => Some(question),
        }
    }
}

impl QuestionTarget {
    /// The exact question, its digest, its pins and a new model, checked
    /// against the plan's starting model `base`.
    pub(super) fn validate(&self, base: &ModelId) -> Result<()> {
        if self.definition.is_null()
            || self.definition_blake3 != hash_json(&self.definition)?
            || self.question_version == 0
            || [
                &self.question_id,
                &self.family,
                &self.corpus_revision,
                &self.feature_schema,
            ]
            .iter()
            .any(|text| text.trim().is_empty())
            || self.label_schema != QUESTION_LABEL_SCHEMA
            || self.renderer != QUESTION_RENDERER
            || self.output_model == *base
        {
            return Err(invalid(
                "a question head needs its exact definition and digest, a version, its pins, \
                 the per-target labels and renderer, and a new model",
            ));
        }
        Ok(())
    }

    /// The text [`QUESTION_RENDERER`] writes for one probe or row `input`,
    /// as the trainer writes it (FIX 7568): canonical-JSON lines for the
    /// question, the input's `target` and each item of its `context`.
    /// Labels, reviewers, consent and ids never reach the model.
    pub fn render_target_text(&self, input: &Value) -> Result<String> {
        let line = |label: &str, value: &Value| -> Result<String> {
            let bytes = crate::llm::canonical_json_bytes(value)
                .map_err(|_| invalid("a detector target does not encode"))?;
            let text = String::from_utf8(bytes)
                .map_err(|_| invalid("a detector target does not encode"))?;
            Ok(format!("{label}: {text}"))
        };
        let (Some(target), Some(context)) = (
            input.get("target"),
            input.get("context").and_then(Value::as_array),
        ) else {
            return Err(invalid("a detector input needs a target and a context list"));
        };
        let mut lines = vec![line("question", &self.definition)?, line("target", target)?];
        for item in context {
            lines.push(line("context", item)?);
        }
        Ok(lines.join("\n"))
    }
}
