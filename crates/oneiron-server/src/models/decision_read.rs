//! The house model's decision read over llama.cpp's native API: the
//! `LabelReadModel` the escalation rung is filled with (ARCH-0076
//! `#decide-required`).
//!
//! One read is a pack (idle-fold test 6b): one `/completion` call whose
//! prompt is an array, one prompt per typed question, each the recipe's
//! template over the same state with the question's own text and labels; a
//! question read jointly with the paired question renders the joint
//! template over its joint labels (ARCH-0076 `#ask-a-person`). Each answer
//! forces the end of generation at the position after its prompt and returns
//! the probabilities the model gave every token there, before any sampler. A
//! question's labels' share of them, normalized over its labels (or joint
//! labels) alone, is its readout. Each answer is checked: no text came back and
//! generation stopped at the forced end; a read that fails a check is refused
//! whole, never read as p = 0. This is the read idle-fold tests 4 to 6
//! measured (one row, `logit_bias` on the end token, `post_sampling_probs`
//! off). It lists the top `n_probs` tokens and, when one of a question's
//! labels falls below them, sends that question once more alone over the
//! whole vocabulary: test 6 read the same label numbers both ways, bit for bit.
//!
//! The prompt, the label wording and the verbalizer tokens are the host's
//! recipe (`[models.decision_read]`); nothing here is prompt text.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::llm::decision::questions::QuestionCriteria;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::{KeyCustody, LeaseUnit, OfferRoute, PaidConnector};
use oneiron::llm::{
    BudgetLease, FatalLlmError, LabelReadFailure, LabelReadModel, LabelReadRequest,
    LabelReadResponse, LabelReadout, LabelSet, LlmError, LlmInputUsage, LlmOutputUsage, LlmResult,
    LlmUsage, RetryableLlmError,
};
use serde_json::{Value as JsonValue, json};

use super::catalog::engine_model_id;
use super::http::{HttpFailure, KeyStyle, ProviderHttp};
use crate::config::models::{
    DecisionReadRecipe, DecisionReadSettings, ModelsConfig, ProbeQuestions, ProviderConfig,
    ReadPrompt, RenderRefusal,
};

const TOKENIZE_PATH: &str = "/tokenize";
const COMPLETION_PATH: &str = "/completion";
/// The fields each answer carries: as measured, and the prompt it answers.
const RESPONSE_FIELDS: [&str; 8] = [
    "index",
    "content",
    "completion_probabilities",
    "timings",
    "tokens_evaluated",
    "tokens_predicted",
    "stop_type",
    "stopped_eos",
];
/// The bias that forces the end token: generation stops at once, and the
/// probabilities read are the pre-sampler ones, which no bias touches.
const EOS_BIAS: f64 = 1e9;
/// The floor a probability is read at before its logarithm, as measured.
const PROBABILITY_FLOOR: f64 = 1e-38;

/// The house model's read, bound to the `local_reasoner` rung, its paid
/// connector, and the owner probe's questions when the recipe names them.
#[derive(Clone)]
pub struct DecisionReadDoor {
    reader: Arc<dyn LabelReadModel>,
    connector: PaidConnector,
    probe: Option<ProbeQuestions>,
    person_threshold: f64,
    /// The ThinkThreshold row's start value; none on a door a host builds.
    think_threshold: Option<f64>,
    /// The recipe the reader renders with, when it is this server's own.
    recipe: Option<Arc<DecisionReadRecipe>>,
}

impl DecisionReadDoor {
    /// A door over any reader: a host that brings its own, or a test.
    #[must_use]
    pub fn new(
        reader: Arc<dyn LabelReadModel>,
        connector: PaidConnector,
        probe: Option<ProbeQuestions>,
        person_threshold: f64,
    ) -> Self {
        Self {
            reader,
            connector,
            probe,
            person_threshold,
            think_threshold: None,
            recipe: None,
        }
    }

    /// What one read of `request` may reserve: each question's prompt as the
    /// recipe renders it (no tokenizer makes more tokens than bytes) and the
    /// one position read, twice when the recipe retries a question. A read the
    /// recipe cannot render is refused here, before anything is admitted. A
    /// host's own reader reserves what each question carries with the state.
    pub fn reserve(&self, request: &LabelReadRequest<'_>) -> LlmResult<u64> {
        let state = request.state.to_string();
        let mut total = 0_u64;
        for question in request.questions {
            let (bytes, calls) = match &self.recipe {
                Some(recipe) => (
                    recipe
                        .render(&prompt_of(request.state, question))
                        .map_err(refused)?
                        .len(),
                    1 + u64::from(recipe.n_probs_full().is_some()),
                ),
                None => {
                    let options = match question.labels {
                        LabelSet::Noul => 0,
                        LabelSet::Choice(options) => options.iter().map(String::len).sum(),
                    };
                    let paired = question.paired.map_or(0, str::len);
                    (question.text.len() + paired + options + state.len(), 1)
                }
            };
            total = total.saturating_add(
                u64::try_from(bytes)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1)
                    .saturating_mul(calls),
            );
        }
        Ok(total)
    }

    /// The reader a host fills `DecisionReadProvider` with. Its `read` blocks
    /// on the server's runtime: call it from a blocking thread.
    #[must_use]
    pub fn reader(&self) -> Arc<dyn LabelReadModel> {
        Arc::clone(&self.reader)
    }

    /// What each read is admitted as under a run.
    #[must_use]
    pub fn connector(&self) -> &PaidConnector {
        &self.connector
    }

    #[must_use]
    pub fn probe(&self) -> Option<&ProbeQuestions> {
        self.probe.as_ref()
    }

    /// The PersonThreshold row's configured start value, for the host's
    /// `DecisionBandPolicy::set_person_threshold`.
    #[must_use]
    pub fn person_threshold(&self) -> f64 {
        self.person_threshold
    }

    /// The ThinkThreshold row's configured start value, for the host's
    /// `DecisionBandPolicy::set_think_threshold`. A door a host builds itself
    /// has none: its paired readings stay on the receipt and route nothing.
    #[must_use]
    pub fn think_threshold(&self) -> Option<f64> {
        self.think_threshold
    }
}

/// The door `config` describes, its reads sent on `runtime`. `None` without
/// `[models.decision_read]`.
pub(super) fn bind(
    config: &ModelsConfig,
    runtime: tokio::runtime::Handle,
) -> anyhow::Result<Option<DecisionReadDoor>> {
    let Some(settings) = &config.decision_read else {
        return Ok(None);
    };
    // `[models.decision_read]` resolved only with one rung here.
    let rung = config
        .roles
        .get(&ModelRole::LocalReasoner)
        .and_then(|ladder| ladder.first())
        .ok_or_else(|| anyhow::anyhow!("decision read: no local_reasoner rung"))?;
    let provider = config
        .providers
        .get(&rung.model.provider)
        .ok_or_else(|| anyhow::anyhow!("decision read: no local_reasoner provider"))?;
    let model = engine_model_id(&rung.model, provider)?;
    let reader = DecisionReader::new(model.as_str(), provider, settings, runtime)?;
    let mut door = DecisionReadDoor::new(
        Arc::new(reader),
        connector(provider, model.as_str())?,
        settings.recipe.probe().cloned(),
        settings.person_threshold,
    );
    door.think_threshold = Some(settings.think_threshold);
    door.recipe = Some(Arc::clone(&settings.recipe));
    Ok(Some(door))
}

/// A read admitted as one paid call at the provider's origin, with the
/// payer and allocation-unit rates the host bound on that provider.
fn connector(provider: &ProviderConfig, model: &str) -> anyhow::Result<PaidConnector> {
    let origin = reqwest::Url::parse(&provider.base_url)?
        .origin()
        .ascii_serialization();
    let route = OfferRoute::new("llama-cpp-read", origin)
        .map_err(|error| anyhow::anyhow!("decision read route: {error}"))?;
    let keyed = provider.key_env.as_ref();
    Ok(PaidConnector {
        connector: format!("decision-read:{model}"),
        route,
        locality: provider.locality,
        payer: provider.payer,
        credential_binding: keyed.map(|env| format!("env:{env}")),
        catalog_revision: Some(provider.revision.clone()),
        custody: if keyed.is_some() {
            KeyCustody::T1
        } else {
            KeyCustody::Keyless
        },
        unit_cost: 1,
        cost_unit: LeaseUnit::tokens(),
        rates: provider.rates.clone(),
    })
}

/// The label and end tokens' ids on the served tokenizer.
struct TokenIds {
    labels: Vec<u64>,
    eos: u64,
}

struct DecisionReader {
    model: String,
    /// The provider's revision and the recipe's fingerprint: a new recipe is
    /// a new revision, so an escalation pin names the exact read.
    revision: String,
    recipe: Arc<DecisionReadRecipe>,
    http: ProviderHttp,
    max_response_bytes: usize,
    runtime: tokio::runtime::Handle,
    /// Looked up on the first read: one reader serves one recipe at one
    /// revision, so the ids hold for its life.
    ids: Mutex<Option<Arc<TokenIds>>>,
}

impl DecisionReader {
    fn new(
        model: &str,
        provider: &ProviderConfig,
        settings: &DecisionReadSettings,
        runtime: tokio::runtime::Handle,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            model: model.to_owned(),
            revision: format!(
                "{}+recipe.{}",
                provider.revision,
                settings.recipe.fingerprint()
            ),
            recipe: Arc::clone(&settings.recipe),
            http: ProviderHttp::new(provider, KeyStyle::Bearer)?.native(),
            max_response_bytes: usize::try_from(settings.max_response_bytes).unwrap_or(usize::MAX),
            runtime,
            ids: Mutex::new(None),
        })
    }

    async fn ids(&self) -> LlmResult<Arc<TokenIds>> {
        if let Some(ids) = self
            .ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Ok(ids);
        }
        let mut labels = Vec::with_capacity(self.recipe.tokens().len());
        for token in self.recipe.tokens() {
            labels.push(self.token_id(token, false).await?);
        }
        let eos = self.token_id(self.recipe.eos(), true).await?;
        let distinct: BTreeSet<u64> = labels.iter().copied().collect();
        // Two labels on one token, or a label on the end token, cannot be read apart.
        if distinct.len() != labels.len() || distinct.contains(&eos) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let ids = Arc::new(TokenIds { labels, eos });
        *self.ids.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&ids));
        Ok(ids)
    }

    /// The one token `text` is; a verbalizer of more tokens cannot be read at
    /// one position.
    async fn token_id(&self, text: &str, special: bool) -> LlmResult<u64> {
        let body = json!({"content": text, "add_special": false, "parse_special": special});
        let reply = self
            .http
            .post_json(TOKENIZE_PATH, &BTreeMap::new(), &body)
            .await
            .map_err(transport)?;
        status(reply.status)?;
        match reply
            .body
            .get("tokens")
            .and_then(JsonValue::as_array)
            .map(Vec::as_slice)
        {
            Some([token]) => token
                .as_u64()
                .or_else(|| token.get("id").and_then(JsonValue::as_u64))
                .ok_or_else(|| failed(LabelReadFailure::Malformed)),
            Some(_) => Err(FatalLlmError::InvalidRequest.into()),
            None => Err(failed(LabelReadFailure::Malformed)),
        }
    }

    /// One completion of `prompt` (one prompt, or an array of them) forced
    /// to end at once, listing the top `n_probs` tokens. Any free slot takes
    /// each prompt, and each slot's prompt cache keeps what it last read.
    async fn complete(&self, prompt: JsonValue, eos: u64, n_probs: u64) -> LlmResult<JsonValue> {
        let body = json!({
            "prompt": prompt,
            "n_predict": 1,
            "temperature": 0.0,
            "cache_prompt": true,
            "id_slot": -1,
            "stop": [],
            "response_fields": RESPONSE_FIELDS,
            "n_probs": n_probs,
            "post_sampling_probs": false,
            "logit_bias": [[eos, EOS_BIAS]],
        });
        let reply = self
            .http
            .post_json_within(
                COMPLETION_PATH,
                &BTreeMap::new(),
                &body,
                self.max_response_bytes,
            )
            .await
            .map_err(transport)?;
        status(reply.status)?;
        Ok(reply.body)
    }

    /// The pack's prompts in one completion, each answer read over its own
    /// question's labels; a question that misses a label below the top
    /// `n_probs` is sent once more alone over the whole vocabulary, its checks
    /// and its cost the read's own.
    async fn read_pack(
        &self,
        prompts: &[String],
        questions: &[LabelReadout<'_>],
    ) -> LlmResult<LabelReadResponse> {
        let ids = self.ids().await?;
        let prompt_array = JsonValue::from(prompts.to_vec());
        let first = self
            .complete(prompt_array, ids.eos, self.recipe.n_probs())
            .await?;
        let replies = answers(first, prompts.len())?;
        let mut readouts = Vec::with_capacity(prompts.len());
        let mut reads = Vec::with_capacity(prompts.len());
        for ((prompt, question), mut reply) in prompts.iter().zip(questions).zip(replies) {
            let count = question.width();
            let (labels, tokens) = (&ids.labels[..count], &self.recipe.tokens()[..count]);
            let mut logprobs = label_logprobs(&reply, labels, tokens);
            let mut spent = None;
            if let Some(full) = self.recipe.n_probs_full()
                && logprobs.as_ref().err() == Some(&failed(LabelReadFailure::MissingLabels))
            {
                spent = Some(usage(&reply)?);
                reply = self.complete(json!(prompt), ids.eos, full).await?;
                logprobs = label_logprobs(&reply, labels, tokens);
            }
            let mut readout = normalized(&logprobs?);
            // A plain readout reports yes, then no, whichever the prompt lists
            // first; a joint one lists yes first already.
            if question.labels == LabelSet::Noul
                && question.paired.is_none()
                && self.recipe.no_first()
            {
                readout.reverse();
            }
            readouts.push(readout);
            let usage = usage(&reply)?;
            reads.push(match spent {
                Some(first) => retried(first, usage),
                None => usage,
            });
        }
        Ok(LabelReadResponse {
            readouts,
            usage: pack_usage(reads),
        })
    }
}

impl LabelReadModel for DecisionReader {
    fn model(&self) -> &str {
        &self.model
    }

    fn revision(&self) -> &str {
        &self.revision
    }

    /// One label, or one joint label, per recipe token.
    fn max_labels(&self) -> usize {
        self.recipe.tokens().len()
    }

    /// Blocks on the server's runtime until the model answers, so it runs on
    /// a blocking thread, never on one of that runtime's workers. Its caller
    /// owns the lease and settles it.
    fn read(
        &self,
        request: &LabelReadRequest<'_>,
        _lease: &BudgetLease,
    ) -> LlmResult<LabelReadResponse> {
        if request.questions.is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let prompts = request
            .questions
            .iter()
            .map(|question| self.recipe.render(&prompt_of(request.state, question)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(refused)?;
        let read = self.read_pack(&prompts, request.questions);
        // One bound for the tokenizer and completion waits: the decision's work cutoff.
        match request.work_until {
            Some(until) => self.runtime.block_on(async {
                tokio::time::timeout_at(until.into(), read)
                    .await
                    .unwrap_or_else(|_| Err(RetryableLlmError::Timeout.into()))
            }),
            None => self.runtime.block_on(read),
        }
    }
}

/// What the recipe renders for one question of a pack over `state`. The
/// state's criteria triple describes the caller's yes/no question, the one
/// read jointly; the person question reads its own wording alone.
fn prompt_of<'a>(state: &'a JsonValue, question: &LabelReadout<'a>) -> ReadPrompt<'a> {
    let descriptions = match (question.labels, question.paired) {
        (LabelSet::Noul, Some(_)) => QuestionCriteria::from_state(state)
            .map(|criteria| [criteria.yes_means(), criteria.no_means()]),
        _ => None,
    };
    ReadPrompt {
        question: question.text,
        options: match question.labels {
            LabelSet::Noul => None,
            LabelSet::Choice(options) => Some(options),
        },
        paired: question.paired,
        descriptions,
        state,
    }
}

/// The pack's answers in prompt order. llama.cpp answers one prompt with an
/// object and several with an array; each answer names the prompt it answers.
fn answers(body: JsonValue, prompts: usize) -> LlmResult<Vec<JsonValue>> {
    let malformed = || failed(LabelReadFailure::Malformed);
    let replies = match body {
        JsonValue::Array(replies) => replies,
        reply @ JsonValue::Object(_) => vec![reply],
        _ => return Err(malformed()),
    };
    let mut ordered: Vec<Option<JsonValue>> = vec![None; prompts];
    for reply in replies {
        let slot = reply
            .get("index")
            .and_then(JsonValue::as_u64)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| ordered.get_mut(index))
            .ok_or_else(malformed)?;
        if slot.replace(reply).is_some() {
            return Err(malformed());
        }
    }
    ordered
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(malformed)
}

/// The label rows' log-probabilities, in row order, after the read's checks:
/// no text, a stop at the forced end, one probability row holding every label.
fn label_logprobs(body: &JsonValue, ids: &[u64], tokens: &[String]) -> LlmResult<Vec<f64>> {
    let malformed = || failed(LabelReadFailure::Malformed);
    let text = body
        .get("content")
        .and_then(JsonValue::as_str)
        .ok_or_else(malformed)?;
    if !text.trim().is_empty() {
        return Err(failed(LabelReadFailure::EmittedText));
    }
    let eos = body.get("stop_type").and_then(JsonValue::as_str) == Some("eos")
        || body.get("stopped_eos").and_then(JsonValue::as_bool) == Some(true);
    if !eos {
        return Err(failed(LabelReadFailure::NotEosStop));
    }
    let rows = body
        .get("completion_probabilities")
        .and_then(JsonValue::as_array)
        .ok_or_else(malformed)?;
    let [row] = rows.as_slice() else {
        return Err(malformed());
    };
    // The current schema, then the older one.
    let entries = row
        .get("top_logprobs")
        .or_else(|| row.get("probs"))
        .and_then(JsonValue::as_array)
        .ok_or_else(malformed)?;
    let mut found: Vec<Option<f64>> = vec![None; ids.len()];
    for entry in entries {
        // As test 6 reads it, a label is its id: another id spelled as a
        // label is not that label. An older answer without ids, by spelling.
        let index = match entry.get("id") {
            Some(id) => id
                .as_u64()
                .and_then(|id| ids.iter().position(|label| *label == id)),
            None => entry
                .get("token")
                .or_else(|| entry.get("tok_str"))
                .and_then(JsonValue::as_str)
                .and_then(|text| tokens.iter().position(|token| token == text)),
        };
        let Some(index) = index else {
            continue;
        };
        let logprob = match entry.get("logprob") {
            Some(logprob) => logprob.as_f64(),
            None => entry
                .get("prob")
                .and_then(JsonValue::as_f64)
                .map(|p| p.max(PROBABILITY_FLOOR).ln()),
        }
        .filter(|&logprob| logprob.is_finite())
        .ok_or_else(malformed)?;
        // As measured, a label's last entry is its value.
        found[index] = Some(logprob);
    }
    found
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| failed(LabelReadFailure::MissingLabels))
}

/// One question's labels normalized over its labels alone.
fn normalized(logprobs: &[f64]) -> Vec<f64> {
    let top = logprobs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let weights: Vec<f64> = logprobs.iter().map(|lp| (lp - top).exp()).collect();
    let total: f64 = weights.iter().sum();
    weights.iter().map(|weight| weight / total).collect()
}

/// Prompt tokens in, and at least the one position read out: a read that
/// generates no text still costs its forward pass. An answer without both
/// counts is refused, so its caller charges the read's reservation.
fn usage(body: &JsonValue) -> LlmResult<LlmUsage> {
    let count = |key: &str| {
        body.get(key)
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| failed(LabelReadFailure::Malformed))
    };
    Ok(LlmUsage {
        input: LlmInputUsage {
            total: count("tokens_evaluated")?,
            ..LlmInputUsage::default()
        },
        output: LlmOutputUsage {
            total: count("tokens_predicted")?.max(1),
            text: 0,
            reasoning: 0,
        },
        raw_provider: body
            .get("timings")
            .map_or(JsonValue::Null, |timings| json!({ "timings": timings })),
    })
}

/// A retried read's cost: both calls' tokens, and each call's timings.
fn retried(top_k: LlmUsage, full: LlmUsage) -> LlmUsage {
    LlmUsage {
        input: LlmInputUsage {
            total: top_k.input.total.saturating_add(full.input.total),
            ..LlmInputUsage::default()
        },
        output: LlmOutputUsage {
            total: top_k.output.total.saturating_add(full.output.total),
            text: 0,
            reasoning: 0,
        },
        raw_provider: json!({"top_k": top_k.raw_provider, "full": full.raw_provider}),
    }
}

/// A pack's cost: every question's tokens, retries included, and each
/// question's own timings. The answers ran side by side, so their times
/// overlap and are kept apart, not summed.
fn pack_usage(reads: Vec<LlmUsage>) -> LlmUsage {
    let (mut input, mut output) = (0_u64, 0_u64);
    let mut timings = Vec::with_capacity(reads.len());
    for read in reads {
        input = input.saturating_add(read.input.total);
        output = output.saturating_add(read.output.total);
        timings.push(read.raw_provider);
    }
    LlmUsage {
        input: LlmInputUsage {
            total: input,
            ..LlmInputUsage::default()
        },
        output: LlmOutputUsage {
            total: output,
            text: 0,
            reasoning: 0,
        },
        raw_provider: json!({ "questions": timings }),
    }
}

fn failed(failure: LabelReadFailure) -> LlmError {
    FatalLlmError::LabelRead(failure).into()
}

fn refused(_: RenderRefusal) -> LlmError {
    FatalLlmError::InvalidRequest.into()
}

fn status(code: u16) -> LlmResult<()> {
    match code {
        200..=299 => Ok(()),
        401 | 403 => Err(FatalLlmError::Auth.into()),
        429 => Err(RetryableLlmError::RateLimited {
            retry_after: None,
            resets_at: Vec::new(),
        }
        .into()),
        400..=499 => Err(FatalLlmError::InvalidRequest.into()),
        _ => Err(RetryableLlmError::ServerError.into()),
    }
}

fn transport(failure: HttpFailure) -> LlmError {
    match failure {
        HttpFailure::Timeout => RetryableLlmError::Timeout.into(),
        HttpFailure::Connection | HttpFailure::StreamCut => RetryableLlmError::ServerError.into(),
        HttpFailure::Malformed | HttpFailure::EventTooLarge | HttpFailure::BodyTooLarge => {
            failed(LabelReadFailure::Malformed)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
