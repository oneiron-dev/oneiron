//! The house model's decision read over llama.cpp's native API: the
//! `LabelReadModel` the escalation rung is filled with (ARCH-0076
//! `#decide-required`).
//!
//! One read is one `/completion` call that forces the end of generation at
//! the position after the prompt and returns the probabilities the model gave
//! every token there, before any sampler. The joint labels' share of them,
//! normalized over the labels alone, is the read: the question's options, "more
//! thinking?" and, when asked, "ask a person?", from one forward pass. Each
//! call checks that no text came back and that generation stopped at the
//! forced end; a read that fails a check is refused, never read as p = 0. This
//! is the read idle-fold tests 4 to 6 measured (one row, `logit_bias` on the
//! end token, `post_sampling_probs` off). It lists the top `n_probs` tokens and,
//! when a label falls below them, retries once over the whole vocabulary:
//! test 6 read the same label numbers both ways, bit for bit.
//!
//! The prompt, the label wording and the verbalizer tokens are the host's
//! recipe (`[models.decision_read]`); nothing here is prompt text.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::{KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer};
use oneiron::llm::{
    BudgetLease, FatalLlmError, LabelReadFailure, LabelReadModel, LabelReadRequest,
    LabelReadResponse, LabelSet, LlmError, LlmInputUsage, LlmOutputUsage, LlmResult, LlmUsage,
    RetryableLlmError,
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
/// The fields a read's answer carries, as measured.
const RESPONSE_FIELDS: [&str; 7] = [
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
            recipe: None,
        }
    }

    /// What one read of `request` may reserve: the prompt the recipe renders
    /// for it (no tokenizer makes more tokens than bytes) and the one position
    /// read, twice when the recipe retries a read. A read the recipe cannot
    /// render is refused here, before anything is admitted. A host's own
    /// reader reserves what the request carries, each option once per joint
    /// row.
    pub fn reserve(&self, request: &LabelReadRequest<'_>) -> LlmResult<u64> {
        let prompt = prompt_of(request);
        let (bytes, calls) = match &self.recipe {
            Some(recipe) => (
                recipe.render(&prompt).map_err(refused)?.len(),
                1 + u64::from(recipe.n_probs_full().is_some()),
            ),
            None => {
                let options = prompt
                    .options
                    .map_or(0, |options| options.iter().map(String::len).sum::<usize>());
                let bytes = prompt.question.len()
                    + options.saturating_mul(4)
                    + prompt.paired.len()
                    + prompt.person.map_or(0, str::len)
                    + prompt.state.to_string().len();
                (bytes, 1)
            }
        };
        Ok(u64::try_from(bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1)
            .saturating_mul(calls))
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
    door.recipe = Some(Arc::clone(&settings.recipe));
    Ok(Some(door))
}

/// A read admitted as one paid call at the provider's origin: the owner's own
/// server, or a keyed endpoint paid with the owner's key.
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
        payer: if keyed.is_some() {
            Payer::CustomerKey
        } else {
            Payer::Local
        },
        credential_binding: keyed.map(|env| format!("env:{env}")),
        catalog_revision: Some(provider.revision.clone()),
        custody: if keyed.is_some() {
            KeyCustody::T1
        } else {
            KeyCustody::Keyless
        },
        unit_cost: 1,
        cost_unit: LeaseUnit::tokens(),
        rates: Vec::new(),
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

    /// One completion of `prompt` forced to end at once, listing the top
    /// `n_probs` tokens.
    async fn complete(&self, prompt: &str, eos: u64, n_probs: u64) -> LlmResult<JsonValue> {
        let body = json!({
            "prompt": prompt,
            "n_predict": 1,
            "temperature": 0.0,
            "cache_prompt": true,
            "id_slot": 0,
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

    async fn read_prompt(
        &self,
        prompt: String,
        rows: usize,
        options: usize,
        person: bool,
    ) -> LlmResult<LabelReadResponse> {
        let ids = self.ids().await?;
        let (labels, tokens) = (&ids.labels[..rows], &self.recipe.tokens()[..rows]);
        let mut reply = self
            .complete(&prompt, ids.eos, self.recipe.n_probs())
            .await?;
        let mut logprobs = label_logprobs(&reply, labels, tokens);
        let mut spent = None;
        // A label below the top `n_probs`: the same prompt once more over the
        // whole vocabulary, its checks and its cost the read's own.
        if let Some(full) = self.recipe.n_probs_full()
            && logprobs.as_ref().err() == Some(&failed(LabelReadFailure::MissingLabels))
        {
            spent = Some(usage(&reply)?);
            reply = self.complete(&prompt, ids.eos, full).await?;
            logprobs = label_logprobs(&reply, labels, tokens);
        }
        let (primary, paired_yes, person_yes) = joint(&logprobs?, options, person);
        let usage = usage(&reply)?;
        Ok(LabelReadResponse {
            primary,
            paired_yes,
            person_yes,
            usage: match spent {
                Some(first) => retried(first, usage),
                None => usage,
            },
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

    /// Blocks on the server's runtime until the model answers, so it runs on
    /// a blocking thread, never on one of that runtime's workers. Its caller
    /// owns the lease and settles it.
    fn read(
        &self,
        request: &LabelReadRequest<'_>,
        _lease: &BudgetLease,
    ) -> LlmResult<LabelReadResponse> {
        let read = prompt_of(request);
        let count = read.options.map_or(2, <[String]>::len);
        let person = request.person.is_some();
        let rows = self.recipe.rows(count, person).map_err(refused)?;
        let prompt = self.recipe.render(&read).map_err(refused)?;
        let read = self.read_prompt(prompt, rows, count, person);
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

/// What the recipe renders for `request`.
fn prompt_of<'a>(request: &LabelReadRequest<'a>) -> ReadPrompt<'a> {
    ReadPrompt {
        question: request.primary.text,
        options: match request.primary.labels {
            LabelSet::Noul => None,
            LabelSet::Choice(options) => Some(options),
        },
        paired: request.paired,
        person: request.person,
        state: request.state,
    }
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

/// Normalizes the rows over the joint labels alone and reads the marginals:
/// each option's mass, P(more thinking) (rows with odd `j`) and, with the
/// person question, P(ask a person) (rows with odd `k`), at row `4i + 2k + j`
/// or `2i + j`.
fn joint(logprobs: &[f64], options: usize, person: bool) -> (Vec<f64>, f64, Option<f64>) {
    let top = logprobs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let weights: Vec<f64> = logprobs.iter().map(|lp| (lp - top).exp()).collect();
    let total: f64 = weights.iter().sum();
    let per_option = if person { 4 } else { 2 };
    let mut primary = vec![0.0; options];
    let (mut think, mut ask) = (0.0, 0.0);
    for (row, weight) in weights.iter().enumerate() {
        let q = weight / total;
        primary[row / per_option] += q;
        if row % 2 == 1 {
            think += q;
        }
        if (row / 2) % 2 == 1 {
            ask += q;
        }
    }
    (primary, think, person.then_some(ask))
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
