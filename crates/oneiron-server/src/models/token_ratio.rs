//! Each catalog model's tokens per o200k token (OF-577): its tokenizer's
//! count of one fixed passage over o200k's count of the same passage. A
//! training offer prices a candidate on the incumbent's counts scaled by the
//! two models' ratios, so no stored text is ever recounted.
//!
//! A model is counted through the host provider its id names: Anthropic's
//! `count_tokens`, Gemini's `countTokens`, or a llama.cpp server's
//! `/tokenize`. A model of the OpenAI family counts with o200k itself. A
//! model none of these reaches keeps no ratio: a key held by the credential
//! broker, a proxy with no count endpoint, or no provider on this host. Its
//! offer price is then an estimate.
use std::collections::BTreeMap;

use oneiron::Vault;
use oneiron::llm::registry::ModelRegistryRow;
use oneiron::tokenizer::DEFAULT_CONTEXT_PACK_TOKENIZER;
use serde_json::{Value as JsonValue, json};

use super::http::{JsonReply, KeyStyle, ProviderHttp};
use crate::config::models::{ModelsConfig, ProviderConfig, ProviderKind};

/// The calibration passage: plain public-domain prose (the Gettysburg
/// Address, 1863), never eval text.
const CALIBRATION_PASSAGE: &str = "Four score and seven years ago our fathers brought forth on \
    this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all \
    men are created equal.\n\nNow we are engaged in a great civil war, testing whether that \
    nation, or any nation so conceived and so dedicated, can long endure. We are met on a great \
    battle-field of that war. We have come to dedicate a portion of that field, as a final \
    resting place for those who here gave their lives that that nation might live. It is \
    altogether fitting and proper that we should do this.\n\nBut, in a larger sense, we can not \
    dedicate -- we can not consecrate -- we can not hallow -- this ground. The brave men, living \
    and dead, who struggled here, have consecrated it, far above our poor power to add or \
    detract. The world will little note, nor long remember what we say here, but it can never \
    forget what they did here. It is for us the living, rather, to be dedicated here to the \
    unfinished work which they who fought here have thus far so nobly advanced. It is rather for \
    us to be here dedicated to the great task remaining before us -- that from these honored \
    dead we take increased devotion to that cause for which they gave the last full measure of \
    devotion -- that we here highly resolve that these dead shall not have died in vain -- that \
    this nation, under God, shall have a new birth of freedom -- and that government of the \
    people, by the people, for the people, shall not perish from the earth.";
/// One word each count also takes alone: subtracting it drops what a count
/// endpoint adds around the text (a message's role and framing).
const CALIBRATION_PROBE: &str = "Four";
/// The family whose models count with o200k itself.
const O200K_FAMILY: &str = "openai";
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The host's token counters: its providers, and the runtime their requests
/// run on.
pub struct TokenRatios {
    providers: BTreeMap<String, ProviderConfig>,
    runtime: tokio::runtime::Handle,
}

impl TokenRatios {
    pub(super) fn new(config: &ModelsConfig, runtime: tokio::runtime::Handle) -> Self {
        Self {
            providers: config.providers.clone(),
            runtime,
        }
    }

    /// Measures each stored registry row that has no ratio yet and stores
    /// the ratio it counts; returns how many it stored. A row no counter
    /// reaches, or whose count fails, stays unmeasured until the next pass.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn measure_missing(&self, vault: &Vault) -> oneiron::Result<usize> {
        let Some(o200k) = o200k_count() else {
            return Ok(0);
        };
        let mut stored = 0;
        for row in vault.model_registry_rows()? {
            if row.tokens_per_o200k.is_some() {
                continue;
            }
            let Some(count) = self.count(&row).await else {
                continue;
            };
            let ratio = count as f64 / o200k as f64;
            if ratio.is_finite() && ratio > 0.0 && vault.set_model_token_ratio(&row, ratio)? {
                stored += 1;
            }
        }
        Ok(stored)
    }

    /// [`Self::measure_missing`] for a caller on a thread that may run its
    /// own runtime (a Dreamer pass): the requests run on the host's runtime,
    /// from a scoped thread.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn measure_missing_blocking(&self, vault: &Vault) -> oneiron::Result<usize> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.runtime.block_on(self.measure_missing(vault)))
                .join()
        })
        .unwrap_or_else(|_| {
            Err(oneiron::Error::InvalidConfig(
                "the token ratio pass stopped".into(),
            ))
        })
    }

    /// `row`'s model's count of the passage, less its count of the probe;
    /// `None` when no counter reaches the model or a count fails.
    async fn count(&self, row: &ModelRegistryRow) -> Option<u64> {
        if row
            .catalog
            .family()
            .is_some_and(|family| family.eq_ignore_ascii_case(O200K_FAMILY))
        {
            return o200k_count();
        }
        let model = &row.catalog.model;
        let provider = self.providers.get(model.provider())?;
        if provider.key_secret.is_some() {
            return None;
        }
        let wire = row
            .catalog
            .metadata
            .get("wire_model")
            .and_then(JsonValue::as_str)
            .unwrap_or_else(|| model.name());
        let counter = Counter::new(provider)?;
        let passage = counter.count(wire, CALIBRATION_PASSAGE).await?;
        let probe = counter.count(wire, CALIBRATION_PROBE).await?;
        passage.checked_sub(probe).filter(|count| *count > 0)
    }
}

/// o200k's count of the passage, less its count of the probe.
fn o200k_count() -> Option<u64> {
    let passage = DEFAULT_CONTEXT_PACK_TOKENIZER.count(CALIBRATION_PASSAGE);
    let probe = DEFAULT_CONTEXT_PACK_TOKENIZER.count(CALIBRATION_PROBE);
    u64::try_from(passage.checked_sub(probe)?)
        .ok()
        .filter(|count| *count > 0)
}

/// One provider's count endpoint.
enum Counter {
    Anthropic(ProviderHttp),
    Gemini(ProviderHttp),
    Tokenize(ProviderHttp),
}

impl Counter {
    /// The counter `provider`'s kind speaks; `None` for a kind with no count
    /// endpoint, or a key that does not read.
    fn new(provider: &ProviderConfig) -> Option<Self> {
        Some(match provider.kind {
            ProviderKind::AnthropicCompat => {
                Self::Anthropic(ProviderHttp::new(provider, KeyStyle::ApiKeyHeader).ok()?)
            }
            ProviderKind::Gemini => {
                // Its paths carry their own `/v1beta`, as the media rung's do.
                let mut provider = provider.clone();
                provider.base_url = provider
                    .base_url
                    .strip_suffix("/v1beta")
                    .unwrap_or(&provider.base_url)
                    .to_owned();
                Self::Gemini(ProviderHttp::new(&provider, KeyStyle::Named("x-goog-api-key")).ok()?)
            }
            ProviderKind::LocalOpenaiCompat => {
                Self::Tokenize(ProviderHttp::new(provider, KeyStyle::Bearer).ok()?.native())
            }
            _ => return None,
        })
    }

    /// The tokens `wire` counts in `text`.
    async fn count(&self, wire: &str, text: &str) -> Option<u64> {
        match self {
            Self::Anthropic(http) => {
                let headers = BTreeMap::from([(
                    "anthropic-version".to_owned(),
                    ANTHROPIC_VERSION.to_owned(),
                )]);
                let body = json!({
                    "model": wire,
                    "messages": [{"role": "user", "content": text}],
                });
                let reply = http
                    .post_json("/v1/messages/count_tokens", &headers, &body)
                    .await
                    .ok()?;
                answered(&reply)?.get("input_tokens")?.as_u64()
            }
            Self::Gemini(http) => {
                let body = json!({"contents": [{"parts": [{"text": text}]}]});
                let reply = http
                    .post_json(
                        &format!("/v1beta/models/{wire}:countTokens"),
                        &BTreeMap::new(),
                        &body,
                    )
                    .await
                    .ok()?;
                answered(&reply)?.get("totalTokens")?.as_u64()
            }
            Self::Tokenize(http) => {
                let body = json!({"content": text, "add_special": false});
                let reply = http
                    .post_json("/tokenize", &BTreeMap::new(), &body)
                    .await
                    .ok()?;
                let tokens = answered(&reply)?.get("tokens")?.as_array()?;
                u64::try_from(tokens.len()).ok()
            }
        }
    }
}

/// A 2xx reply's body.
fn answered(reply: &JsonReply) -> Option<&JsonValue> {
    (200..300).contains(&reply.status).then_some(&reply.body)
}
