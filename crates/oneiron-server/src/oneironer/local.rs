//! Native extraction on candle, with no HTTP server or second runtime.
//!
//! A model directory contains `oneironer.json`: format_version 1, hashed
//! `trunk`, `config` and `tokenizer` artifacts, `ner_labels` in classifier
//! order, and optional `mentions`, `coref`, `vad` and `characters` heads.
//! Artifact rows have `file` and full `sha256` fields. Head rows name their
//! `trunk_sha16`. The SHA-256 prefix of this manifest is the served stack
//! identity, binding the tokenizer, backbone config, all weights, label
//! tables and decode knobs. Weights retain the model repository's state-dict
//! names in safetensors.
//!
//! `characters` names the checkpoint's own training config, which holds the
//! character vocabulary and width, and the decode revision; the head's
//! weights ride in the trunk as `char_head.*`. With it, names take the full
//! decode (BIO, the DATE snap, character refinement); without it, BIO alone.

mod backbone;
mod heads;
mod window;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Component, Path};
use std::sync::Mutex;

use candle_core::{DType, Device, Module};
use candle_nn::{Linear, VarBuilder, linear};
use oneiron::ModelId;
use oneiron::embed::EmbedderLocality;
use oneiron::memory::extraction::{EncoderInput, EncoderOutput, ExtractionEncoder, NerSpan};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokenizers::Tokenizer;

use super::endpoint::{CONTRACT_VERSION, ModelCard, Returns};
use crate::config::{EmbedderDevice, OneironerConfig};
use backbone::{Backbone, Config};
use heads::{Affect, CharacterBoundary, Coreference};
use window::{
    CharacterFeatures, Characters, DecodeLayers, Named, ONEIRONER_DECODE_REVISION, Window,
    conversation_tokenizer, decode, decode_ner,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    file: String,
    sha256: String,
}

impl Artifact {
    fn read(&self, dir: &Path) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            !self.file.is_empty()
                && Path::new(&self.file)
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "oneironer artifact file must be relative to its model directory"
        );
        let bytes = std::fs::read(dir.join(&self.file))?;
        anyhow::ensure!(
            format!("{:x}", Sha256::digest(&bytes)) == self.sha256,
            "oneironer artifact SHA-256 mismatch"
        );
        Ok(bytes)
    }

    fn weights(&self, dir: &Path, device: &Device) -> anyhow::Result<VarBuilder<'static>> {
        Ok(VarBuilder::from_buffered_safetensors(
            self.read(dir)?,
            DType::F32,
            device,
        )?)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MentionHead {
    weights: Artifact,
    trunk_sha16: String,
    labels: Vec<String>,
    o_bias: f32,
    /// Labels that are not overt mentions (for example predicate anchors).
    ignored_labels: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorefHead {
    weights: Artifact,
    trunk_sha16: String,
    repr_dim: usize,
    tau: f32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VadHead {
    weights: Artifact,
    trunk_sha16: String,
    hidden_size: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CharacterHead {
    /// The checkpoint's own training config.json, copied verbatim.
    config: Artifact,
    /// Must be this build's `ONEIRONER_DECODE_REVISION`, so a bundle never
    /// runs a decode other than the one it names.
    decode_revision: String,
}

/// The keys a checkpoint's training config holds for its character head.
/// The file's other keys are training settings and go unread.
#[derive(Deserialize)]
struct CharacterConfig {
    char_head: bool,
    char_dim: u32,
    char_vocab: BTreeMap<String, u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format_version: u32,
    trunk: Artifact,
    config: Artifact,
    tokenizer: Artifact,
    ner_labels: Vec<String>,
    mentions: Option<MentionHead>,
    coref: Option<CorefHead>,
    vad: Option<VadHead>,
    characters: Option<CharacterHead>,
}

struct Network {
    backbone: Backbone,
    ner: Linear,
    characters: Option<CharacterBoundary>,
    mentions: Option<Linear>,
    coref: Option<Coreference>,
    vad: Option<Affect>,
}

/// The window each call is tagged in.
enum WindowMode {
    /// The slot's causal window (`Window::new`): earlier text up to
    /// `live_window_tokens`, then the current turn, never cut. Only the
    /// current turn's spans return, `NerSpan.message` indexing
    /// `EncoderInput.messages`. Every production caller tags in it.
    Live,
    /// The whole conversation in one window (`Window::conversation`), as the
    /// model project's reference predictor tags it; `oneironer qualify`
    /// alone selects it. Every turn is returnable: `NerSpan.message` is the
    /// message's ordinal in the flattened conversation (each context turn's
    /// messages in order, then the current turn's), and `start`/`end` are
    /// UTF-8 byte offsets into that message. A conversation longer than
    /// `max_input_tokens` is cut at its end by this tokenizer, never refused;
    /// a turn the cut reaches keeps the spans inside its covered part.
    Conversation(Box<Tokenizer>),
}

pub(crate) struct LocalTagger {
    model: ModelId,
    card: ModelCard,
    manifest: Manifest,
    tokenizer: Tokenizer,
    /// The character head's vocabulary; empty when the bundle has none.
    char_vocab: HashMap<char, u32>,
    layers: DecodeLayers,
    window: WindowMode,
    network: Mutex<Network>,
    cap: usize,
    live: usize,
}

impl LocalTagger {
    pub(crate) fn load(config: &OneironerConfig) -> anyhow::Result<Self> {
        config.validate()?;
        let dir = config
            .model_dir
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("oneironer.model_dir is required"))?;
        let manifest_bytes = std::fs::read(dir.join("oneironer.json"))?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
        anyhow::ensure!(
            manifest.format_version == 1,
            "unsupported local oneironer manifest version"
        );
        validate_labels(&manifest.ner_labels)?;
        let checkpoint = config.checkpoint_sha16.as_deref().unwrap_or_default();
        anyhow::ensure!(
            manifest.trunk.sha256.len() == 64 && manifest.trunk.sha256.starts_with(checkpoint),
            "local oneironer checkpoint does not match checkpoint_sha16"
        );
        let stack = format!("{:x}", Sha256::digest(&manifest_bytes))[..16].to_owned();
        anyhow::ensure!(
            config
                .stack_sha16
                .as_deref()
                .is_none_or(|expected| expected == stack),
            "local oneironer stack does not match stack_sha16"
        );
        anyhow::ensure!(
            config.label_count == Some(manifest.ner_labels.len() as u32),
            "local oneironer label count does not match label_count"
        );
        let body: Config = serde_json::from_slice(&manifest.config.read(dir)?)?;
        let gte = body.validate(config.backbone)?;
        anyhow::ensure!(
            config.max_input_tokens <= body.max_position_embeddings,
            "oneironer.max_input_tokens exceeds backbone positions"
        );
        let device = match config.device {
            EmbedderDevice::Cpu => Device::Cpu,
            EmbedderDevice::Metal => Device::new_metal(0)?,
            EmbedderDevice::Cuda => Device::new_cuda(0)?,
            // The slot resolves `auto` to a measured engine before it loads
            // (`super::engines`); a direct load runs on the built-in CPU one.
            EmbedderDevice::Auto => Device::Cpu,
        };
        let mut tokenizer = Tokenizer::from_bytes(manifest.tokenizer.read(dir)?)
            .map_err(|_| anyhow::anyhow!("invalid local extraction tokenizer"))?;
        tokenizer.with_padding(None);
        tokenizer
            .with_truncation(None)
            .map_err(|_| anyhow::anyhow!("invalid local extraction tokenizer truncation"))?;
        let weights = manifest.trunk.weights(dir, &device)?;
        let backbone = Backbone::load(weights.pp("encoder"), &body, gte, config.max_input_tokens)?;
        let ner = linear(
            body.hidden_size,
            manifest.ner_labels.len(),
            weights.pp("classifier"),
        )?;
        let (characters, char_vocab) = match &manifest.characters {
            Some(head) => {
                anyhow::ensure!(
                    head.decode_revision == ONEIRONER_DECODE_REVISION,
                    "oneironer bundle names a decode revision this build does not run"
                );
                let options: CharacterConfig = serde_json::from_slice(&head.config.read(dir)?)?;
                anyhow::ensure!(
                    options.char_head,
                    "oneironer character config declares no character head"
                );
                let (vocab, rows) = character_vocab(options.char_vocab)?;
                let boundary = CharacterBoundary::load(
                    weights.pp("char_head"),
                    body.hidden_size,
                    options.char_dim as usize,
                    rows,
                )?;
                (Some(boundary), vocab)
            }
            None => (None, HashMap::new()),
        };
        let mentions = manifest
            .mentions
            .as_ref()
            .map(|head| -> anyhow::Result<Linear> {
                anyhow::ensure!(
                    head.trunk_sha16 == checkpoint,
                    "mention head belongs to another trunk"
                );
                anyhow::ensure!(head.o_bias.is_finite(), "invalid mention O bias");
                validate_labels(&head.labels)?;
                Ok(linear(
                    body.hidden_size,
                    head.labels.len(),
                    head.weights.weights(dir, &device)?.pp("classifier"),
                )?)
            })
            .transpose()?;
        let coref = manifest
            .coref
            .as_ref()
            .map(|head| -> anyhow::Result<Coreference> {
                anyhow::ensure!(
                    head.trunk_sha16 == checkpoint && head.repr_dim > 0 && head.tau.is_finite(),
                    "invalid coreference head or trunk binding"
                );
                anyhow::ensure!(
                    mentions.is_some(),
                    "coreference requires a mention proposer"
                );
                Ok(Coreference::load(
                    head.weights.weights(dir, &device)?,
                    body.hidden_size,
                    head.repr_dim,
                    head.tau,
                )?)
            })
            .transpose()?;
        let vad = manifest
            .vad
            .as_ref()
            .map(|head| -> anyhow::Result<Affect> {
                anyhow::ensure!(
                    head.trunk_sha16 == checkpoint && head.hidden_size > 0,
                    "invalid affect head or trunk binding"
                );
                Ok(Affect::load(
                    head.weights.weights(dir, &device)?,
                    body.hidden_size,
                    head.hidden_size,
                )?)
            })
            .transpose()?;
        let card = ModelCard {
            checkpoint_sha16: checkpoint.to_owned(),
            contract_version: CONTRACT_VERSION,
            label_count: manifest.ner_labels.len() as u32,
            returns: Returns {
                spans: true,
                links: coref.is_some(),
                mood: vad.is_some(),
            },
            stack_sha16: Some(stack),
        };
        let model = ModelId::new(format!("oneironer/local@{checkpoint}"))?;
        tracing::info!(
            runtime = config.runtime.as_str(),
            backbone = body.model_type.as_str(),
            device = match &device {
                Device::Cpu => "cpu",
                Device::Metal(_) => "metal",
                Device::Cuda(_) => "cuda",
            },
            "local oneironer loaded"
        );
        Ok(Self {
            model,
            card,
            manifest,
            tokenizer,
            char_vocab,
            layers: DecodeLayers::SERVED,
            window: WindowMode::Live,
            network: Mutex::new(Network {
                backbone,
                ner,
                characters,
                mentions,
                coref,
                vad,
            }),
            cap: config.max_input_tokens,
            live: config.live_window_tokens as usize,
        })
    }

    pub(crate) fn card(&self) -> ModelCard {
        self.card.clone()
    }

    /// Decodes as E4's frozen baseline from here on: the served layers but
    /// for the DATE snap after refinement. Only `oneironer qualify` asks.
    pub(crate) fn decode_as_e4(&mut self) {
        self.layers = DecodeLayers::E4;
    }

    /// Tags each call's whole conversation in one window from here on, as
    /// the model project's reference predictor does, cut at
    /// `max_input_tokens`; `WindowMode::Conversation` says what its spans
    /// address. Only `oneironer qualify` asks.
    pub(crate) fn window_as_conversation(&mut self) -> anyhow::Result<()> {
        let tokenizer = conversation_tokenizer(&self.tokenizer, self.cap)?;
        self.window = WindowMode::Conversation(Box::new(tokenizer));
        Ok(())
    }

    fn extract(&self, input: &EncoderInput) -> anyhow::Result<EncoderOutput> {
        let window = match &self.window {
            WindowMode::Live => Window::new(input, &self.tokenizer, self.cap, self.live)?,
            WindowMode::Conversation(tokenizer) => Window::conversation(input, tokenizer)?,
        };
        // The live window returns its current turn; the conversation window
        // returns every turn.
        let conversation = matches!(self.window, WindowMode::Conversation(_));
        let returned = |segment: usize| conversation || window.segments[segment].current;
        let network = self
            .network
            .lock()
            .map_err(|_| anyhow::anyhow!("local extraction lock poisoned"))?;
        let hidden = network.backbone.forward(window.encoding.get_ids())?;
        let ner = network.ner.forward(&hidden)?.to_vec2::<f32>()?;
        let named: Vec<Named> = match &network.characters {
            Some(head) => {
                let characters = Characters::new(&window);
                let features = CharacterFeatures::new(&characters, &self.char_vocab);
                let probabilities = head.probabilities(&hidden, &features)?;
                decode_ner(
                    &window,
                    &characters,
                    &ner,
                    &self.manifest.ner_labels,
                    &probabilities,
                    input.language.as_deref(),
                    self.layers,
                )?
            }
            None => {
                let spans = decode(&window, &ner, &self.manifest.ner_labels, 0.0)?;
                spans.into_iter().map(Named::from).collect()
            }
        };
        let mut mentioned = match (&network.mentions, &self.manifest.mentions) {
            (Some(classifier), Some(head)) => decode(
                &window,
                &classifier.forward(&hidden)?.to_vec2::<f32>()?,
                &head.labels,
                head.o_bias,
            )?,
            _ => Vec::new(),
        };
        if let Some(head) = &self.manifest.mentions {
            mentioned.retain(|span| !head.ignored_labels.contains(&span.label));
        }
        let mut spans = BTreeMap::new();
        for span in &mentioned {
            if returned(span.segment) {
                spans.insert((span.segment, span.start, span.end), span);
            }
        }
        // A typed NER label wins over a generic mention label at the same
        // coordinates; a pronoun retains its proposer label. A name the DATE
        // snap or refinement moved still wins the mention proposed where BIO
        // put it, and that mention's links resolve to the name.
        let mut names = BTreeSet::new();
        let mut moved = Vec::new();
        for name in &named {
            let span = &name.span;
            if returned(span.segment) {
                let key = (span.segment, span.start, span.end);
                let decoded = (span.segment, name.decoded.0, name.decoded.1);
                let left = decoded != key && !names.contains(&decoded);
                if left && spans.remove(&decoded).is_some() {
                    moved.push((decoded, key));
                }
                names.insert(key);
                spans.insert(key, span);
            }
        }
        let mut coordinates = BTreeMap::new();
        let mut output = EncoderOutput {
            spans: Vec::new(),
            links: Vec::new(),
            vad: None,
            context_links: Vec::new(),
            speaker_links: Vec::new(),
            stack_sha16: self.card.stack_sha16.clone(),
        };
        for (key, span) in spans {
            let segment = &window.segments[span.segment];
            // The conversation window keeps every message's segment in
            // order, so a segment's index is its flattened message ordinal.
            let message = if conversation {
                span.segment
            } else {
                segment.message_index
            };
            coordinates.insert(key, output.spans.len());
            output.spans.push(NerSpan {
                message,
                start: span.start - segment.base + segment.source_offset,
                end: span.end - segment.base + segment.source_offset,
                label: span.label.clone(),
                confidence: span.confidence,
            });
        }
        for (decoded, key) in moved {
            if let Some(&index) = coordinates.get(&key) {
                coordinates.entry(decoded).or_insert(index);
            }
        }
        if let Some(coref) = &network.coref {
            coref.infer(&hidden, &window, &mentioned, &coordinates, &mut output)?;
        }
        if let Some(vad) = &network.vad {
            output.vad = vad.infer(&hidden, &window)?;
        }
        Ok(output)
    }
}

/// The character vocabulary as the head reads it, and the embedding rows it
/// fills: ids run from 2 with no gap, 0 being padding and 1 an unknown
/// character, as the model project's loader requires.
fn character_vocab(vocab: BTreeMap<String, u32>) -> anyhow::Result<(HashMap<char, u32>, usize)> {
    let mut ids = BTreeSet::new();
    let mut table = HashMap::with_capacity(vocab.len());
    for (key, id) in vocab {
        let mut scalars = key.chars();
        let (Some(character), None) = (scalars.next(), scalars.next()) else {
            anyhow::bail!("oneironer character vocabulary keys must be single characters");
        };
        ids.insert(id);
        table.insert(character, id);
    }
    let rows = table.len() + 2;
    anyhow::ensure!(
        ids.len() == table.len()
            && ids.first() == Some(&2)
            && ids.last().map(|&last| last as usize + 1) == Some(rows),
        "oneironer character vocabulary ids must run from 2 with no gap"
    );
    Ok((table, rows))
}

fn validate_labels(labels: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(
        labels.first().map(String::as_str) == Some("O"),
        "local extraction BIO table must start with O"
    );
    let mut seen = BTreeSet::new();
    for label in labels {
        anyhow::ensure!(seen.insert(label), "duplicate extraction BIO label");
        if label == "O" {
            continue;
        }
        let Some((prefix, kind)) = label.split_once('-') else {
            anyhow::bail!("invalid extraction BIO label");
        };
        anyhow::ensure!(
            matches!(prefix, "B" | "I") && !kind.is_empty() && kind.len() <= 64,
            "invalid extraction BIO label"
        );
    }
    Ok(())
}

impl ExtractionEncoder for LocalTagger {
    fn model_id(&self) -> &ModelId {
        &self.model
    }
    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }
    fn infer(&self, input: &EncoderInput) -> oneiron::Result<EncoderOutput> {
        // Inference errors can contain token ids. Traces retain the failure
        // class, never a tensor dump or any part of a conversation.
        self.extract(input)
            .map_err(|_| oneiron::Error::UpstreamToolFailure {
                tool: "oneironer-local",
                code: "native extraction failed".to_owned(),
            })
    }
}
