//! Native extraction on candle, with no HTTP server or second runtime.
//!
//! A model directory is a format-2 bundle ([`super::bundle`]): its
//! `oneironer.json` names the hashed trunk, config and tokenizer, the label
//! table in classifier order and the optional heads, each head naming its
//! `trunk_sha16`, and its SHA-256 prefix is the served stack, binding every
//! file, table and decode knob. Candle reads the common rows only; the
//! platform rows are other runtimes'. Weights retain the model repository's
//! state-dict names in safetensors.
//!
//! `characters` names the checkpoint's own training config, which holds the
//! character vocabulary and width, and the decode revision; the head's
//! weights ride in the trunk as `char_head.*`. With it, names take the full
//! decode (BIO, the DATE snap, character refinement); without it, BIO alone.

mod backbone;
mod heads;
mod window;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

use candle_core::{Device, Module};
use candle_nn::{Linear, linear};
use oneiron::ModelId;
use oneiron::memory::extraction::{EncoderInput, EncoderOutput, NerSpan};
use tokenizers::Tokenizer;

use super::bundle::{CharacterConfig, Manifest, ReadManifest, character_vocab, read_manifest};
use super::endpoint::{CONTRACT_VERSION, ModelCard, Returns};
use crate::config::{EmbedderDevice, OneironerConfig};
use backbone::{Backbone, Config};
use heads::{Affect, CharacterBoundary, Coreference};
use window::{
    CharacterFeatures, Characters, DecodeLayers, Named, ONEIRONER_DECODE_REVISION, Window,
    conversation_tokenizer, decode, decode_ner,
};

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

/// A call's live window as every runtime of a slot builds it (FIX 6755):
/// `Window::new` over the bundle's tokenizer, `max_input_tokens` and
/// `live_window_tokens`, the window [`LocalTagger::infer`] tags in. The
/// dispatcher counts each call by it once, outside every lock, to know
/// which workers may run it; calibration holds a reference case to a row's
/// max window by it. No runtime builds a shorter window to fit.
#[derive(Clone)]
pub(crate) struct WindowCounter {
    tokenizer: Tokenizer,
    cap: usize,
    live: usize,
}

impl WindowCounter {
    /// The tokens of `input`'s live window, special tokens included: its
    /// context joined and cut to the live budget. A window that cannot be
    /// built fails as the call's infer would.
    pub(crate) fn count(&self, input: &EncoderInput) -> oneiron::Result<usize> {
        let window = Window::new(input, &self.tokenizer, self.cap, self.live)
            .map_err(|_| extraction_failed())?;
        Ok(window.tokens())
    }
}

/// The failure of a native call, by class alone: never a tensor dump or any
/// part of a conversation.
fn extraction_failed() -> oneiron::Error {
    oneiron::Error::UpstreamToolFailure {
        tool: "oneironer-local",
        code: "native extraction failed".to_owned(),
    }
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
        // The format, every closed row and every check no setting decides.
        let ReadManifest {
            manifest,
            stack_sha16: stack,
        } = read_manifest(dir)?;
        let checkpoint = config.checkpoint_sha16.as_deref().unwrap_or_default();
        anyhow::ensure!(
            manifest.trunk.sha256.starts_with(checkpoint),
            "local oneironer checkpoint does not match checkpoint_sha16"
        );
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

    /// `oneironer/local@<checkpoint>`: the model every worker of this bundle
    /// serves, whichever engine runs it.
    pub(crate) fn model_id(&self) -> &ModelId {
        &self.model
    }

    /// One input on this tagger's own engine, with no dispatcher: what its
    /// worker runs, and what calibration and `oneironer qualify` time, each
    /// pinned to the engine it names.
    pub(crate) fn infer(&self, input: &EncoderInput) -> oneiron::Result<EncoderOutput> {
        // Inference errors can contain token ids. Traces retain the failure
        // class, never a tensor dump or any part of a conversation.
        self.extract(input).map_err(|_| extraction_failed())
    }

    /// The counter of this tagger's live windows: its own tokenizer, cap
    /// and live budget, so a count is the window [`Self::infer`] tags in.
    pub(crate) fn window_counter(&self) -> WindowCounter {
        WindowCounter {
            tokenizer: self.tokenizer.clone(),
            cap: self.cap,
            live: self.live,
        }
    }

    /// The stack this tagger serves: the SHA-256 prefix of its manifest.
    pub(crate) fn stack_sha16(&self) -> &str {
        self.card.stack_sha16.as_deref().unwrap_or_default()
    }

    /// The configured `max_input_tokens`: the longest window it builds.
    pub(crate) const fn max_input_tokens(&self) -> usize {
        self.cap
    }

    /// The revision of this build's decoder: what a bundle's character head
    /// must declare. A bundle without one declares none.
    pub(crate) fn decode_revision(&self) -> &'static str {
        ONEIRONER_DECODE_REVISION
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
