//! `[models.decision_read]`: the house model's decision read on the
//! `local_reasoner` rung, and the recipe it reads with.
//!
//! The recipe is the host's: a TOML file in its prompt package (with the
//! template file it names) carrying the prompt, the joint label table's row
//! wording, the single-token label verbalizers, the end-of-generation token
//! and the owner probe's paired and person questions. No prompt text lives in
//! the server. One read scores the joint labels at one position: option `i`,
//! "more thinking" `j` and, when the person question is asked, "ask a person"
//! `k` sit at row `4i + 2k + j` (`2i + j` without it), each row one token.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::llm::manifest::ModelRole;
use serde::Deserialize;
use serde_json::Value as JsonValue;

use super::{ModelsConfig, ProviderKind};

/// The most one read's answer may hold by default: llama.cpp's probabilities
/// over a 262,144-token vocabulary come to about 25 MiB.
const DEFAULT_MAX_RESPONSE_BYTES: u64 = 64 << 20;
/// The PersonThreshold row's start value: high, so "ask a person?" stays
/// rare until the Coach tunes it from real overrides.
const DEFAULT_PERSON_THRESHOLD: f64 = 0.9;
const RECIPE_FORMAT: u32 = 1;

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
    /// The bound on one read's answer body.
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
    /// The prompt template, relative to the recipe file.
    template: PathBuf,
    /// One joint label's line without the person question.
    row: String,
    /// One joint label's line with it; without one, reads never ask it.
    row_person: Option<String>,
    yes: String,
    no: String,
    /// The label verbalizers, each one token, in row order.
    tokens: Vec<String>,
    /// The end-of-generation token the read forces.
    eos: String,
    /// The probabilities the answer lists: enough that every label's is
    /// among them (the whole vocabulary, as measured).
    n_probs: u64,
    probe: Option<ProbeFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeFile {
    paired: String,
    person: Option<String>,
}

/// A host-authored read recipe, checked whole when it loads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionReadRecipe {
    template: Vec<Piece>,
    row: Vec<Piece>,
    row_person: Option<Vec<Piece>>,
    yes: String,
    no: String,
    tokens: Vec<String>,
    eos: String,
    n_probs: u64,
    probe: Option<ProbeQuestions>,
    fingerprint: String,
}

/// The owner probe's paired question and, when set, its person question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeQuestions {
    pub paired: String,
    pub person: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Piece {
    Text(String),
    Slot(Slot),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    Question,
    Labels,
    Paired,
    Person,
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
    /// More joint labels than the recipe has tokens, or a person question the
    /// recipe has no row for.
    TooManyLabels,
    /// A `{state.<key>}` the state does not hold as a string.
    MissingState,
}

/// What one read renders.
pub struct ReadPrompt<'a> {
    pub question: &'a str,
    /// The primary options in order; a yes/no question is `None`.
    pub options: Option<&'a [String]>,
    pub paired: &'a str,
    pub person: Option<&'a str>,
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
        let template = parse(&template_text)?;
        let row = parse(&file.row)?;
        let row_person = file.row_person.as_deref().map(parse).transpose()?;
        if !slots_fit(&template, &row, row_person.as_deref()) {
            anyhow::bail!(
                "the template needs {{question}}, {{labels}} and {{paired}} (and {{person}} with row_person); row needs {{token}}, {{label}} and {{think}}, and row_person {{person}} as well"
            );
        }
        if !tokens_fit(&file) {
            anyhow::bail!(
                "tokens must be at least 4 distinct non-empty labels, eos one other token, n_probs at least the token count, and yes and no two different words"
            );
        }
        let probe = file
            .probe
            .map(|probe| probe.resolve(row_person.is_some(), file.tokens.len()))
            .transpose()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(recipe_bytes.len() as u64).to_le_bytes());
        hasher.update(&recipe_bytes);
        hasher.update(template_text.as_bytes());
        let fingerprint = hasher.finalize().to_hex().as_str()[..16].to_owned();
        Ok(Self {
            template,
            row,
            row_person,
            yes: file.yes,
            no: file.no,
            tokens: file.tokens,
            eos: file.eos,
            n_probs: file.n_probs,
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

    #[must_use]
    pub fn probe(&self) -> Option<&ProbeQuestions> {
        self.probe.as_ref()
    }

    /// The joint labels a read of `options` options takes: two per option,
    /// four with the person question.
    pub fn rows(&self, options: usize, person: bool) -> Result<usize, RenderRefusal> {
        let rows = options.saturating_mul(if person { 4 } else { 2 });
        if rows > self.tokens.len() || (person && self.row_person.is_none()) {
            return Err(RenderRefusal::TooManyLabels);
        }
        Ok(rows)
    }

    /// The prompt for one read: the template with the caller's question, the
    /// joint label table, the paired and person questions and the state.
    pub fn render(&self, read: &ReadPrompt<'_>) -> Result<String, RenderRefusal> {
        let noul = [self.yes.clone(), self.no.clone()];
        let options = read.options.unwrap_or(&noul);
        let person = read.person.is_some();
        let rows = self.rows(options.len(), person)?;
        let row = match (person, &self.row_person) {
            (true, Some(row)) => row,
            _ => &self.row,
        };
        let word = |yes: bool| if yes { &self.yes } else { &self.no };
        let mut table = String::new();
        for r in 0..rows {
            let (i, k, j) = if person {
                (r / 4, (r / 2) % 2 == 1, r % 2 == 1)
            } else {
                (r / 2, false, r % 2 == 1)
            };
            if r > 0 {
                table.push('\n');
            }
            fill(row, &mut table, |slot, out| {
                out.push_str(match slot {
                    Slot::Token => &self.tokens[r],
                    Slot::Label => &options[i],
                    Slot::Think => word(j),
                    Slot::Person => word(k),
                    _ => return Err(RenderRefusal::MissingState),
                });
                Ok(())
            })?;
        }
        let state = read.state.to_string();
        let mut prompt = String::new();
        fill(&self.template, &mut prompt, |slot, out| {
            out.push_str(match slot {
                Slot::Question => read.question,
                Slot::Labels => &table,
                Slot::Paired => read.paired,
                Slot::Person => read.person.unwrap_or_default(),
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
    /// The probe always asks its questions, so its smallest read, a yes/no
    /// question, must fit `tokens` labels: four, or eight with the person
    /// question.
    fn resolve(self, row_person: bool, tokens: usize) -> anyhow::Result<ProbeQuestions> {
        let blank = |text: &str| text.trim().is_empty();
        if blank(&self.paired)
            || self.person.as_deref().is_some_and(blank)
            || (self.person.is_some() && (!row_person || tokens < 8))
        {
            anyhow::bail!(
                "probe.paired must be set, and probe.person needs row_person and at least 8 tokens"
            );
        }
        Ok(ProbeQuestions {
            paired: self.paired,
            person: self.person,
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

/// The template holds the caller's question, the label table and the paired
/// question (and the person question when there is a person row), and only
/// prompt slots; each row holds exactly its own slots.
fn slots_fit(template: &[Piece], row: &[Piece], row_person: Option<&[Piece]>) -> bool {
    let in_template = slots(template);
    let prompt_slots = in_template.iter().all(|slot| {
        matches!(
            slot,
            Slot::Question
                | Slot::Labels
                | Slot::Paired
                | Slot::Person
                | Slot::State
                | Slot::StateKey(_)
        )
    });
    let required = [Slot::Question, Slot::Labels, Slot::Paired]
        .iter()
        .all(|slot| in_template.contains(slot))
        && (row_person.is_none() || in_template.contains(&Slot::Person));
    let row_slots: BTreeSet<Slot> = [Slot::Token, Slot::Label, Slot::Think].into();
    let mut person_slots = row_slots.clone();
    person_slots.insert(Slot::Person);
    prompt_slots
        && required
        && slots(row) == row_slots
        && row_person.is_none_or(|pieces| slots(pieces) == person_slots)
}

fn tokens_fit(file: &RecipeFile) -> bool {
    let distinct: BTreeSet<&String> = file.tokens.iter().collect();
    file.tokens.len() >= 4
        && distinct.len() == file.tokens.len()
        && !file.tokens.iter().any(String::is_empty)
        && !file.eos.is_empty()
        && !distinct.contains(&file.eos)
        && file.n_probs >= file.tokens.len() as u64
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
                "labels" => Slot::Labels,
                "paired" => Slot::Paired,
                "person" => Slot::Person,
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
