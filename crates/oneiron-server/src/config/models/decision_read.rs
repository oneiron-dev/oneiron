//! `[models.decision_read]`: the house model's decision read on the
//! `local_reasoner` rung, and the recipe it reads with.
//!
//! The recipe is the host's: a TOML file in its prompt package (with the
//! template files it names) carrying the prompts, a label's row wording, the
//! single-token label verbalizers, the end-of-generation token and the owner
//! probe's paired, person and presence questions. No prompt text lives in the
//! server.
//! One read is a pack: each question renders over the same state with its
//! own text and label rows. A question read jointly with the paired question
//! (ARCH-0076 `#ask-a-person`: Q1 and Q2 stay joint) renders the joint
//! template, one single-token row per (option, paired answer), normalized
//! once over all of them; the person question renders the plain template,
//! its own yes and no.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::llm::manifest::ModelRole;
use serde::Deserialize;
use serde_json::Value as JsonValue;

use super::{ModelsConfig, ProviderKind};

/// The most one answer body may hold by default (a pack's first answer, or
/// one exact retry): llama.cpp's probabilities over a 262,144-token
/// vocabulary come to about 25 MiB for one question.
const DEFAULT_MAX_RESPONSE_BYTES: u64 = 64 << 20;
/// The PersonThreshold row's start value: high, so "ask a person?" stays
/// rare until the Coach tunes it from real overrides.
const DEFAULT_PERSON_THRESHOLD: f64 = 0.9;
const RECIPE_FORMAT: u32 = 3;

/// `[models.decision_read]` as written.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecisionReadFile {
    recipe: PathBuf,
    max_response_bytes: Option<u64>,
    person_threshold: Option<f64>,
}

// `[models]` compares whole; a threshold that is not a number fails to resolve.
impl Eq for DecisionReadFile {}

/// The resolved section.
#[derive(Clone, Debug, PartialEq)]
pub struct DecisionReadSettings {
    pub recipe: Arc<DecisionReadRecipe>,
    /// The bound on one answer body: a pack's first answer, or one retry.
    pub max_response_bytes: u64,
    /// The start value a host gives `DecisionBandPolicy::set_person_threshold`
    /// (the PersonThreshold row), in (0, 1].
    pub person_threshold: f64,
}

// The threshold is checked to lie in (0, 1], so it is never NaN.
impl Eq for DecisionReadSettings {}

impl DecisionReadFile {
    /// Loads the recipe (relative to the config file's directory) and checks
    /// that `local_reasoner` has the one native rung a read needs.
    pub(super) fn resolve(
        self,
        base: Option<&Path>,
        models: &ModelsConfig,
    ) -> anyhow::Result<DecisionReadSettings> {
        let ladder = models
            .roles
            .get(&ModelRole::LocalReasoner)
            .ok_or_else(|| anyhow::anyhow!("models.decision_read needs roles.local_reasoner"))?;
        let [rung] = ladder.as_slice() else {
            anyhow::bail!(
                "models.decision_read reads one model: roles.local_reasoner must have one rung"
            );
        };
        let provider = &models.providers[&rung.model.provider];
        if !matches!(
            provider.kind,
            ProviderKind::LocalOpenaiCompat | ProviderKind::OpenaiCompat
        ) || provider.key_secret.is_some()
        {
            anyhow::bail!(
                "models.decision_read: the local_reasoner provider must be a llama.cpp server (openai-compat or local-openai-compat, no key_secret)"
            );
        }
        let max_response_bytes = self
            .max_response_bytes
            .unwrap_or(DEFAULT_MAX_RESPONSE_BYTES);
        let person_threshold = self.person_threshold.unwrap_or(DEFAULT_PERSON_THRESHOLD);
        if max_response_bytes == 0 || !(person_threshold > 0.0 && person_threshold <= 1.0) {
            anyhow::bail!(
                "models.decision_read: max_response_bytes must be > 0 and person_threshold in (0, 1]"
            );
        }
        let path = match base {
            Some(base) if self.recipe.is_relative() => base.join(&self.recipe),
            _ => self.recipe,
        };
        let recipe = DecisionReadRecipe::load(&path)
            .map_err(|error| anyhow::anyhow!("models.decision_read.recipe: {error}"))?;
        Ok(DecisionReadSettings {
            recipe: Arc::new(recipe),
            max_response_bytes,
            person_threshold,
        })
    }
}

/// The recipe file as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeFile {
    format: u32,
    /// The plain prompt template, relative to the recipe file.
    template: PathBuf,
    /// The joint prompt template, relative to the recipe file: a question
    /// and the paired question over one table of joint labels.
    joint_template: PathBuf,
    /// One label's line.
    row: String,
    /// One joint label's line: the option and the paired answer (`{think}`).
    joint_row: String,
    yes: String,
    no: String,
    /// A yes/no question lists no before yes (test 6b's side questions did).
    #[serde(default)]
    no_first: bool,
    /// The label verbalizers, each one token, in row order: a question of
    /// `n` labels takes the first `n`, a joint one the first `2n`.
    tokens: Vec<String>,
    /// The end-of-generation token the read forces.
    eos: String,
    /// The probabilities the answer lists: its top `n_probs`. llama.cpp
    /// normalizes over the whole vocabulary before it cuts the list, so a
    /// label among them reads the same as over the vocabulary.
    n_probs: u64,
    /// The probabilities a question's one exact retry lists when the top
    /// `n_probs` miss one of its labels: the whole vocabulary. Without it,
    /// such a read is refused.
    n_probs_full: Option<u64>,
    probe: Option<ProbeFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeFile {
    paired: String,
    person: Option<String>,
    presence: Option<String>,
}

/// A host-authored read recipe, checked whole when it loads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionReadRecipe {
    template: Vec<Piece>,
    joint_template: Vec<Piece>,
    row: Vec<Piece>,
    joint_row: Vec<Piece>,
    yes: String,
    no: String,
    no_first: bool,
    tokens: Vec<String>,
    eos: String,
    n_probs: u64,
    n_probs_full: Option<u64>,
    probe: Option<ProbeQuestions>,
    fingerprint: String,
}

/// The owner probe's paired question and, when set, its person question and
/// its presence question (asked before a Box or Point question: is the target
/// the `locate` state field words in the image?).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeQuestions {
    pub paired: String,
    pub person: Option<String>,
    pub presence: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Piece {
    Text(String),
    Slot(Slot),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    Question,
    Paired,
    Labels,
    State,
    StateKey(String),
    Token,
    Label,
    Think,
}

/// Why a read's prompt cannot be rendered: the caller's request, not the
/// recipe, is at fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderRefusal {
    /// More labels than the recipe has tokens.
    TooManyLabels,
    /// A `{state.<key>}` the state does not hold as a string.
    MissingState,
}

/// What one question of a pack renders.
pub struct ReadPrompt<'a> {
    pub question: &'a str,
    /// The options in order; a yes/no question is `None`.
    pub options: Option<&'a [String]>,
    /// The paired question read jointly with this one, when it is.
    pub paired: Option<&'a str>,
    /// What a yes and a no mean, from the question's criteria: each yes/no
    /// label row reads its label with its description.
    pub descriptions: Option<[String; 2]>,
    pub state: &'a JsonValue,
}

impl DecisionReadRecipe {
    fn load(path: &Path) -> anyhow::Result<Self> {
        let recipe_bytes = std::fs::read(path)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
        let file: RecipeFile = toml::from_str(std::str::from_utf8(&recipe_bytes)?)?;
        if file.format != RECIPE_FORMAT {
            anyhow::bail!("format must be {RECIPE_FORMAT}");
        }
        let template_path = path
            .parent()
            .map_or_else(|| file.template.clone(), |dir| dir.join(&file.template));
        let template_text = std::fs::read_to_string(&template_path)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", template_path.display()))?;
        let joint_path = path.parent().map_or_else(
            || file.joint_template.clone(),
            |dir| dir.join(&file.joint_template),
        );
        let joint_text = std::fs::read_to_string(&joint_path)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", joint_path.display()))?;
        let template = parse(&template_text)?;
        let joint_template = parse(&joint_text)?;
        let row = parse(&file.row)?;
        let joint_row = parse(&file.joint_row)?;
        if !slots_fit(&template, &row, false) || !slots_fit(&joint_template, &joint_row, true) {
            anyhow::bail!(
                "the template needs {{question}} and {{labels}}, the joint template {{paired}} too, and each holds only those and state slots; row needs exactly {{token}} and {{label}}, joint_row {{think}} too"
            );
        }
        if !tokens_fit(&file) {
            anyhow::bail!(
                "tokens must be at least 4 distinct non-empty labels, eos one other token, n_probs at least the token count, n_probs_full above n_probs, and yes and no two different words"
            );
        }
        let probe = file.probe.map(ProbeFile::resolve).transpose()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(recipe_bytes.len() as u64).to_le_bytes());
        hasher.update(&recipe_bytes);
        hasher.update(&(template_text.len() as u64).to_le_bytes());
        hasher.update(template_text.as_bytes());
        hasher.update(joint_text.as_bytes());
        let fingerprint = hasher.finalize().to_hex().as_str()[..16].to_owned();
        Ok(Self {
            template,
            joint_template,
            row,
            joint_row,
            yes: file.yes,
            no: file.no,
            no_first: file.no_first,
            tokens: file.tokens,
            eos: file.eos,
            n_probs: file.n_probs,
            n_probs_full: file.n_probs_full,
            probe,
            fingerprint,
        })
    }

    /// The recipe's identity: a digest of the recipe and template bytes.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    #[must_use]
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }

    #[must_use]
    pub fn eos(&self) -> &str {
        &self.eos
    }

    #[must_use]
    pub fn n_probs(&self) -> u64 {
        self.n_probs
    }

    /// The exact retry's size, when the recipe retries a question that
    /// misses a label.
    #[must_use]
    pub fn n_probs_full(&self) -> Option<u64> {
        self.n_probs_full
    }

    #[must_use]
    pub fn probe(&self) -> Option<&ProbeQuestions> {
        self.probe.as_ref()
    }

    /// Whether a yes/no question lists no before yes; its readout still
    /// reports yes, then no.
    #[must_use]
    pub fn no_first(&self) -> bool {
        self.no_first
    }

    /// The prompt for one question of a pack: the template with the
    /// question, its label rows and the state. A joint question renders the
    /// joint template, its rows in readout order: row `2i` is option `i`
    /// with the paired answer no, row `2i + 1` with yes. Its yes/no options
    /// keep their declared order, yes first.
    pub fn render(&self, read: &ReadPrompt<'_>) -> Result<String, RenderRefusal> {
        let mut noul = [self.yes.clone(), self.no.clone()];
        if let (None, Some(descriptions)) = (read.options, &read.descriptions) {
            for (label, description) in noul.iter_mut().zip(descriptions) {
                *label = format!("{label}: {description}");
            }
        }
        if self.no_first && read.paired.is_none() {
            noul.reverse();
        }
        let options = read.options.unwrap_or(&noul);
        let thinks = match read.paired {
            Some(_) => vec![Some(self.no.as_str()), Some(self.yes.as_str())],
            None => vec![None],
        };
        if options.len() * thinks.len() > self.tokens.len() {
            return Err(RenderRefusal::TooManyLabels);
        }
        let (template, row) = match read.paired {
            Some(_) => (&self.joint_template, &self.joint_row),
            None => (&self.template, &self.row),
        };
        let mut table = String::new();
        let cells = options
            .iter()
            .flat_map(|label| thinks.iter().map(move |think| (label, *think)));
        for (r, (label, think)) in cells.enumerate() {
            if r > 0 {
                table.push('\n');
            }
            fill(row, &mut table, |slot, out| {
                out.push_str(match (slot, think) {
                    (Slot::Token, _) => self.tokens[r].as_str(),
                    (Slot::Label, _) => label.as_str(),
                    (Slot::Think, Some(think)) => think,
                    _ => return Err(RenderRefusal::MissingState),
                });
                Ok(())
            })?;
        }
        let state = read.state.to_string();
        let mut prompt = String::new();
        fill(template, &mut prompt, |slot, out| {
            out.push_str(match slot {
                Slot::Question => read.question,
                Slot::Paired => read.paired.ok_or(RenderRefusal::MissingState)?,
                Slot::Labels => &table,
                Slot::State => &state,
                Slot::StateKey(key) => read
                    .state
                    .get(key)
                    .and_then(JsonValue::as_str)
                    .ok_or(RenderRefusal::MissingState)?,
                _ => return Err(RenderRefusal::MissingState),
            });
            Ok(())
        })?;
        Ok(prompt)
    }
}

impl ProbeFile {
    fn resolve(self) -> anyhow::Result<ProbeQuestions> {
        let blank = |text: &str| text.trim().is_empty();
        if blank(&self.paired)
            || self.person.as_deref().is_some_and(blank)
            || self.presence.as_deref().is_some_and(blank)
        {
            anyhow::bail!(
                "probe.paired must be set, and probe.person and probe.presence, when set, not blank"
            );
        }
        Ok(ProbeQuestions {
            paired: self.paired,
            person: self.person,
            presence: self.presence,
        })
    }
}

fn slots(pieces: &[Piece]) -> BTreeSet<Slot> {
    pieces
        .iter()
        .filter_map(|piece| match piece {
            Piece::Slot(slot) => Some(slot.clone()),
            Piece::Text(_) => None,
        })
        .collect()
}

/// The template holds the question and its label rows (a joint one the
/// paired question too), and only prompt slots; the row holds exactly its
/// own slots, a joint row the paired answer too.
fn slots_fit(template: &[Piece], row: &[Piece], joint: bool) -> bool {
    let in_template = slots(template);
    let prompt_slots = in_template.iter().all(|slot| match slot {
        Slot::Question | Slot::Labels | Slot::State | Slot::StateKey(_) => true,
        Slot::Paired => joint,
        _ => false,
    });
    let mut row_slots: BTreeSet<Slot> = [Slot::Token, Slot::Label].into();
    if joint {
        row_slots.insert(Slot::Think);
    }
    prompt_slots
        && in_template.contains(&Slot::Question)
        && in_template.contains(&Slot::Labels)
        && (!joint || in_template.contains(&Slot::Paired))
        && slots(row) == row_slots
}

fn tokens_fit(file: &RecipeFile) -> bool {
    let distinct: BTreeSet<&String> = file.tokens.iter().collect();
    file.tokens.len() >= 4
        && distinct.len() == file.tokens.len()
        && !file.tokens.iter().any(String::is_empty)
        && !file.eos.is_empty()
        && !distinct.contains(&file.eos)
        && file.n_probs >= file.tokens.len() as u64
        && file.n_probs_full.is_none_or(|full| full > file.n_probs)
        && !file.yes.trim().is_empty()
        && !file.no.trim().is_empty()
        && file.yes != file.no
}

/// Appends `pieces` to `out`, each slot's value written by `value` once and
/// never scanned again, so a value that holds braces stays text.
fn fill(
    pieces: &[Piece],
    out: &mut String,
    mut value: impl FnMut(&Slot, &mut String) -> Result<(), RenderRefusal>,
) -> Result<(), RenderRefusal> {
    for piece in pieces {
        match piece {
            Piece::Text(text) => out.push_str(text),
            Piece::Slot(slot) => value(slot, out)?,
        }
    }
    Ok(())
}

/// Splits a template into text and `{slot}`s; `{{` and `}}` are braces.
fn parse(text: &str) -> anyhow::Result<Vec<Piece>> {
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(['{', '}']) {
        literal.push_str(&rest[..at]);
        let tail = &rest[at..];
        if let Some(after) = tail.strip_prefix("{{") {
            literal.push('{');
            rest = after;
        } else if let Some(after) = tail.strip_prefix("}}") {
            literal.push('}');
            rest = after;
        } else if let Some(open) = tail.strip_prefix('{') {
            let end = open
                .find('}')
                .ok_or_else(|| anyhow::anyhow!("an unclosed {{ in {text:?}"))?;
            let slot = match &open[..end] {
                "question" => Slot::Question,
                "paired" => Slot::Paired,
                "labels" => Slot::Labels,
                "state" => Slot::State,
                "token" => Slot::Token,
                "label" => Slot::Label,
                "think" => Slot::Think,
                name => match name.strip_prefix("state.") {
                    Some(key) if !key.is_empty() => Slot::StateKey(key.to_owned()),
                    _ => anyhow::bail!("unknown placeholder {{{name}}}"),
                },
            };
            if !literal.is_empty() {
                pieces.push(Piece::Text(std::mem::take(&mut literal)));
            }
            pieces.push(Piece::Slot(slot));
            rest = &open[end + 1..];
        } else {
            anyhow::bail!("a lone }} in {text:?}; write }}}} for a brace");
        }
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        pieces.push(Piece::Text(literal));
    }
    Ok(pieces)
}
