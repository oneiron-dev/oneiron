//! The frozen binary question head exported by training_pack/worker.py.
//! This CPU loader is independent of the extraction slot and never binds a role.

use candle_core::{DType, Device, Module, Tensor};
use candle_nn::{Linear, VarBuilder, linear};
use oneiron::training_pack::{CheckpointFileKind, CheckpointUpload, QuestionTarget};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokenizers::Tokenizer;

use super::backbone::{Backbone, Config};
use crate::config::oneironer::OneironerBackbone;

const CLASSIFIER_FORMAT: &str = "oneiron.question-classifier/1";
const RECIPE: &str = "oneiron.frozen-encoder-binary-head/1";
const POOLING: &str = "window-mean-of-position-means/1";

fn file<'a>(
    export: &'a CheckpointUpload,
    name: &str,
    kind: CheckpointFileKind,
) -> anyhow::Result<&'a [u8]> {
    let mut matches = export.files.iter().filter(|file| file.name == name);
    let file = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing question-head file"))?;
    anyhow::ensure!(
        matches.next().is_none()
            && file.kind == kind
            && blake3::hash(&file.bytes).as_bytes() == &file.blake3,
        "invalid question-head file pin"
    );
    Ok(&file.bytes)
}

/// The exact renderer's tokenizer and window length, usable without weights.
pub(crate) struct QuestionTokenizer {
    tokenizer: Tokenizer,
    positions: usize,
}

impl QuestionTokenizer {
    pub(crate) fn load(export: &CheckpointUpload) -> anyhow::Result<Self> {
        let mut tokenizer = Tokenizer::from_bytes(file(
            export,
            "tokenizer.json",
            CheckpointFileKind::Tokenizer,
        )?)
        .map_err(|_| anyhow::anyhow!("invalid question-head tokenizer"))?;
        tokenizer.with_padding(None);
        tokenizer
            .with_truncation(None)
            .map_err(|_| anyhow::anyhow!("invalid question-head tokenizer truncation"))?;
        let config: Config =
            serde_json::from_slice(file(export, "config.json", CheckpointFileKind::Config)?)?;
        config.validate(OneironerBackbone::Auto)?;
        Ok(Self {
            tokenizer,
            positions: config.max_position_embeddings,
        })
    }

    /// Consecutive content windows, each wrapped in the tokenizer's specials.
    /// Nothing is padded, truncated or cut out of the target.
    pub(crate) fn windows(&self, text: &str) -> anyhow::Result<Vec<Vec<u32>>> {
        let full = self
            .tokenizer
            .encode(text, true)
            .map_err(|_| anyhow::anyhow!("question-head tokenization failed"))?
            .get_ids()
            .to_vec();
        let content = self
            .tokenizer
            .encode(text, false)
            .map_err(|_| anyhow::anyhow!("question-head tokenization failed"))?
            .get_ids()
            .to_vec();
        let room_for_content = full
            .len()
            .checked_sub(content.len())
            .ok_or_else(|| anyhow::anyhow!("question-head tokenizer changes content"))?;
        let start = (0..=room_for_content)
            .find(|&start| full[start..start + content.len()] == content[..])
            .ok_or_else(|| anyhow::anyhow!("question-head tokenizer changes content"))?;
        let (prefix, suffix) = (&full[..start], &full[start + content.len()..]);
        let room = self
            .positions
            .checked_sub(prefix.len() + suffix.len())
            .filter(|room| *room > 0)
            .ok_or_else(|| anyhow::anyhow!("question-head specials fill every position"))?;
        let runs: Vec<&[u32]> = if content.is_empty() {
            vec![&content[..]]
        } else {
            content.chunks(room).collect()
        };
        Ok(runs
            .into_iter()
            .map(|run| [prefix, run, suffix].concat())
            .collect())
    }

    pub(crate) fn tokens_blake3(
        &self,
        question: &QuestionTarget,
        input: &Value,
    ) -> anyhow::Result<[u8; 32]> {
        let windows = self.windows(&question.render_target_text(input)?)?;
        let bytes = oneiron::llm::canonical_json_bytes(&windows)?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

#[derive(Deserialize)]
struct Manifest {
    format: String,
    model: String,
    recipe: String,
    renderer: String,
    pooling: String,
    label_order: Vec<String>,
    dtype: String,
    output: String,
    max_positions: usize,
    target: Value,
    files: Vec<FilePin>,
}

#[derive(Deserialize)]
struct FilePin {
    name: String,
    sha256: String,
    bytes: u64,
}

/// Raw [no, yes] logits from the exported frozen encoder and trained head.
pub(crate) struct QuestionHead {
    question: QuestionTarget,
    tokenizer: QuestionTokenizer,
    backbone: Backbone,
    head: Linear,
}

impl QuestionHead {
    /// Loads the returned load set for this batch of actual inputs. Rotary
    /// tables cover only its longest window, not an untrusted config length.
    /// No model path, download, fallback or policy token limit is added.
    pub(crate) fn load(
        question: &QuestionTarget,
        export: &CheckpointUpload,
        inputs: &[&Value],
    ) -> anyhow::Result<Self> {
        let manifest: Manifest =
            serde_json::from_slice(file(export, "classifier.json", CheckpointFileKind::Config)?)?;
        let target = serde_json::json!({
            "kind": "question",
            "question_id": question.question_id,
            "question_version": question.question_version,
            "definition_blake3": blake3::Hash::from(question.definition_blake3).to_hex().to_string(),
            "family": question.family,
            "corpus_revision": question.corpus_revision,
            "feature_schema": question.feature_schema,
            "label_schema": question.label_schema,
            "renderer": question.renderer,
            "output_model": question.output_model,
        });
        let definition = oneiron::llm::canonical_json_bytes(&question.definition)?;
        anyhow::ensure!(
            export.model == question.output_model
                && manifest.model == question.output_model.as_str()
                && manifest.target == target
                && blake3::hash(&definition).as_bytes() == &question.definition_blake3
                && manifest.format == CLASSIFIER_FORMAT
                && manifest.recipe == RECIPE
                && manifest.renderer == oneiron::training_pack::QUESTION_RENDERER
                && manifest.pooling == POOLING
                && manifest.label_order == ["no", "yes"]
                && manifest.dtype == "float32"
                && manifest.output == "raw_logits",
            "question-head manifest does not match its target or recipe"
        );
        let required = [
            ("config.json", CheckpointFileKind::Config),
            ("tokenizer.json", CheckpointFileKind::Tokenizer),
            ("trunk.safetensors", CheckpointFileKind::Weights),
            ("head.safetensors", CheckpointFileKind::Weights),
        ];
        anyhow::ensure!(
            export.files.len() == required.len() + 1 && manifest.files.len() == required.len(),
            "question-head load set is incomplete or ambiguous"
        );
        for (name, kind) in required {
            let bytes = file(export, name, kind)?;
            let mut pins = manifest.files.iter().filter(|pin| pin.name == name);
            let pin = pins
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing question-head manifest pin"))?;
            anyhow::ensure!(
                pins.next().is_none()
                    && pin.bytes == bytes.len() as u64
                    && pin.sha256 == format!("{:x}", Sha256::digest(bytes)),
                "question-head manifest file pin differs"
            );
        }
        let config: Config =
            serde_json::from_slice(file(export, "config.json", CheckpointFileKind::Config)?)?;
        let gte = config.validate(OneironerBackbone::Auto)?;
        anyhow::ensure!(
            manifest.max_positions == config.max_position_embeddings,
            "question-head positions differ"
        );
        let tokenizer = QuestionTokenizer::load(export)?;
        let cap = inputs
            .iter()
            .try_fold(0usize, |cap, input| -> anyhow::Result<usize> {
                let windows = tokenizer.windows(&question.render_target_text(input)?)?;
                Ok(cap.max(windows.iter().map(Vec::len).max().unwrap_or(0)))
            })?;
        anyhow::ensure!(cap > 0, "question-head load needs a nonempty input window");
        let device = Device::Cpu;
        let weights = VarBuilder::from_slice_safetensors(
            file(export, "trunk.safetensors", CheckpointFileKind::Weights)?,
            DType::F32,
            &device,
        )?;
        let backbone = Backbone::load(weights.pp("encoder"), &config, gte, cap)?;
        let weights = VarBuilder::from_slice_safetensors(
            file(export, "head.safetensors", CheckpointFileKind::Weights)?,
            DType::F32,
            &device,
        )?;
        let head = linear(config.hidden_size, 2, weights.pp("head"))?;
        Ok(Self {
            question: question.clone(),
            tokenizer,
            backbone,
            head,
        })
    }

    /// Position means include specials; windows have equal weight, as trained.
    pub(crate) fn logits(&self, input: &Value) -> anyhow::Result<[f64; 2]> {
        let text = self.question.render_target_text(input)?;
        let means = self
            .tokenizer
            .windows(&text)?
            .iter()
            .map(|ids| self.backbone.forward(ids)?.mean(0))
            .collect::<candle_core::Result<Vec<_>>>()?;
        let pooled = Tensor::stack(&means, 0)?.mean(0)?.unsqueeze(0)?;
        let logits = self.head.forward(&pooled)?.squeeze(0)?.to_vec1::<f32>()?;
        let [no, yes]: [f32; 2] = logits
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid question-head output shape"))?;
        anyhow::ensure!(
            no.is_finite() && yes.is_finite(),
            "non-finite question-head output"
        );
        Ok([f64::from(no), f64::from(yes)])
    }
}
