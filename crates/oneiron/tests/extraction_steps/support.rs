//! Shared helpers for the bound extraction step test: vault setup, request builders and one capturing backend.

use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptBinding};
use oneiron::memory::MemoryResult;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::{
    AttemptId, BudgetLease, ContentPart, FatalLlmError, LlmBackend, LlmCapability, LlmError,
    LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId, UnsupportedCapability, Vault,
    VaultConfig,
};
use oneiron_testkit::{ScriptedBackend, Step};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// Returns a fixture or assertion error without hiding its source.
pub(crate) type ExtractionStepTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The bound submit verb under test.
pub(crate) const AI_STEPS_SUBMIT_VERB: &str = "ai.steps.submit";
/// The bound receipt verb under test.
pub(crate) const AI_STEPS_RECEIPT_VERB: &str = "ai.steps.receipt";
/// The inputs page an extraction attempt reads its turns and pins through.
pub(crate) const EXTRACTION_INPUTS_PAGE_VERB: &str = "vault.consolidation.extraction.inputs.page";
/// The queue clock every enqueue and admission here runs at, in seconds.
pub(crate) const QUEUE_NOW: u64 = 1_000;

/// Opens a vault the way the extraction verdict test does.
pub(crate) fn open_extraction_step_vault(
    dir: &tempfile::TempDir,
) -> ExtractionStepTestResult<Vault> {
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    Ok(vault)
}

/// Returns the attempt id as the page names it: its bytes as lowercase hex.
pub(crate) fn extraction_attempt_hex(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Reads the extraction inputs page for `attempt` through `binding`.
pub(crate) fn read_bound_extraction_page(
    binding: &DreamerAttemptBinding,
    attempt: &str,
) -> MemoryResult<Value> {
    binding
        .invoke(
            EXTRACTION_INPUTS_PAGE_VERB,
            json!({"attempt": attempt}),
            None,
        )
        .map(|answer| answer["value"].clone())
}

/// Submits one bound extraction step through `binding` with `request` as plain JSON.
pub(crate) fn invoke_bound_step(
    binding: &DreamerAttemptBinding,
    request: Value,
) -> MemoryResult<Value> {
    binding
        .invoke(AI_STEPS_SUBMIT_VERB, request, None)
        .map(|answer| answer["value"].clone())
}

/// Reads one bound extraction step receipt through `binding` for `step_ref`.
pub(crate) fn invoke_bound_step_receipt(
    binding: &DreamerAttemptBinding,
    step_ref: &str,
) -> MemoryResult<Value> {
    binding
        .invoke(AI_STEPS_RECEIPT_VERB, json!({"step_key": step_ref}), None)
        .map(|answer| answer["value"].clone())
}

/// Binds `admitted` in `vault` and returns the live extraction binding.
pub(crate) fn bind_extraction(
    vault: &Arc<Vault>,
    admitted: &DreamerAdmittedAttempt,
) -> ExtractionStepTestResult<DreamerAttemptBinding> {
    Ok(vault.bind_dreamer_attempt(admitted)?)
}

/// Builds one bound extraction step request over `evidence` entries.
pub(crate) fn extraction_step_request(evidence: Value) -> Value {
    json!({"evidence": evidence})
}

/// Builds one step evidence entry over `turn` at `version`, with an optional byte range.
pub(crate) fn extraction_step_evidence(turn: &str, version: Value, span: Option<Value>) -> Value {
    let mut entry = json!({"turn": turn, "version": version});
    if let Some(span) = span {
        entry["span"] = span;
    }
    entry
}

/// Reads the turn refs with their served versions from a bound inputs page.
pub(crate) fn page_turns_with_versions(page: &Value) -> Vec<(String, Value)> {
    page["turns"]
        .as_array()
        .unwrap_or_else(|| panic!("turns is an array"))
        .iter()
        .map(|served| {
            let turn = served["turn"]
                .as_str()
                .unwrap_or_else(|| panic!("the turn is a string"))
                .to_owned();
            (turn, served["version"].clone())
        })
        .collect()
}

/// Builds the fixed plain-text step reply the capturing backend answers.
pub(crate) fn step_plain_reply() -> String {
    "owen keeps tea warm".to_owned()
}

/// Answers every generation with the fixed reply and captures each request it serves.
pub(crate) struct CapturingStepBackend {
    /// Holds the fixed plain-text reply.
    reply: String,
    /// Declares the reply input tokens.
    input_tokens: u64,
    /// Declares the reply output tokens.
    output_tokens: u64,
    /// Captures every request served, in order.
    seen: Mutex<Vec<LlmRequest>>,
    /// Counts the generations served so far.
    calls: AtomicUsize,
}

impl CapturingStepBackend {
    /// Builds a backend answering every generation with `reply`, declaring the token counts.
    pub(crate) fn new(reply: String, input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            reply,
            input_tokens,
            output_tokens,
            seen: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
        }
    }

    /// Returns the generations served so far.
    pub(crate) fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Returns the joined text parts of every request served, in order.
    pub(crate) fn request_texts(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|request| {
                request
                    .messages
                    .iter()
                    .flat_map(|message| message.content.iter())
                    .filter_map(|part| match part {
                        ContentPart::Text { text, .. } => Some(text.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .collect()
    }
}

impl LlmBackend for CapturingStepBackend {
    /// The scripted backend answers every model, so this backend does too.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Captures the request, then answers it from a per-request scripted backend.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request.clone());
        let reply = self.reply.clone();
        let (input_tokens, output_tokens) = (self.input_tokens, self.output_tokens);
        Box::pin(async move {
            let digest = ScriptedBackend::digest_of(&request);
            let backend = ScriptedBackend::new(vec![
                Step::text("extraction-step", digest, reply)
                    .buffered()
                    .usage(input_tokens, output_tokens),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the step scripted backend did not build: {error}"),
                    code: None,
                })
            })?;
            let response = backend.generate(request, lease).await;
            let seen = backend.finish();
            self.calls.fetch_add(seen.len(), Ordering::SeqCst);
            response
        })
    }

    /// The step legs never stream; a streamed call fails loudly.
    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}
