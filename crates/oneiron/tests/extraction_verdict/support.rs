//! Shared helpers for the bound extraction verdict tests: vault setup, request builders, and one counting backend.
//!
//! `extraction_verdict`, `extraction_read_layout` and `extraction_observations_listing` include this file
//! instead of copying these helpers.
#![allow(dead_code)]

use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptBinding};
use oneiron::memory::MemoryResult;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{
    AttemptId, BudgetLease, EntityId, FatalLlmError, LlmBackend, LlmCapability, LlmError,
    LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId, UnsupportedCapability, Vault,
    VaultConfig,
};
use oneiron_testkit::{ScriptedBackend, Step};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Returns a fixture or assertion error without hiding its source.
pub(crate) type ExtractionVerdictTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The bound verdict verb under test, invoked by name with plain JSON, so this file
/// compiles without naming the handler and fails at runtime below its facet allow-list.
pub(crate) const AI_VERDICT_VERB: &str = "ai.verdict";

/// The inputs page an extraction attempt reads its turns and pins through.
pub(crate) const EXTRACTION_INPUTS_PAGE_VERB: &str = "vault.consolidation.extraction.inputs.page";

/// The queue clock every enqueue and admission here runs at, in seconds.
pub(crate) const QUEUE_NOW: u64 = 1_000;

/// Opens a vault the way the extraction inputs page test does: the Dreamer fixture
/// vault, reopened owned, with engine machines provisioned and the embedded owner ensured.
pub(crate) fn open_extraction_verdict_vault(
    dir: &tempfile::TempDir,
) -> ExtractionVerdictTestResult<Vault> {
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

/// Asks one bound verdict through `binding` with `request` as plain JSON.
pub(crate) fn invoke_bound_verdict(
    binding: &DreamerAttemptBinding,
    request: Value,
) -> MemoryResult<Value> {
    binding.invoke(AI_VERDICT_VERB, request, None)
}

/// Binds `admitted` in `vault` and returns the live extraction binding.
pub(crate) fn bind_extraction(
    vault: &Arc<Vault>,
    admitted: &DreamerAdmittedAttempt,
) -> ExtractionVerdictTestResult<DreamerAttemptBinding> {
    Ok(vault.bind_dreamer_attempt(admitted)?)
}

/// Builds one bound Extraction verdict request with `question`, a Choice contract over
/// `options`, empty evidence and `pack` as its state.
pub(crate) fn extraction_verdict_request(question: &str, options: Value, pack: Value) -> Value {
    json!({
        "question": question,
        "contract": {"kind": "choice", "options": options},
        "evidence": [],
        "state": pack,
        "ceiling": "big",
        "reversibility": "reversible_read",
        "routine": false,
        "misses": 0,
    })
}

/// Builds one candidate operand over `subject` and `predicate` with `value`, citing one
/// turn with its pin and quoting its whole words.
pub(crate) fn extraction_candidate(
    subject: &str,
    predicate: &str,
    value: Value,
    turn: &str,
    version: Value,
) -> Value {
    json!({
        "subject": subject,
        "predicate": predicate,
        "value": value,
        "evidence": [{"turn": turn, "version": version}],
    })
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

/// Opens the extraction verdict vault with the Dreamer's Steward grant
/// standing and a selection that holds no candidate back, seeds the person
/// `name` at a fresh subject, witnesses each of `words` as one TURN, and
/// enqueues and admits one Meso extraction attempt over them: the vault, the
/// attempt, the served turns with their versions, and the subject.
pub(crate) fn extraction_attempt_with_turns(
    dir: &tempfile::TempDir,
    name: &str,
    words: &[&str],
) -> ExtractionVerdictTestResult<(Arc<Vault>, AttemptId, Vec<(String, Value)>, EntityId)> {
    let vault = Arc::new(open_extraction_verdict_vault(dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, name, vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, words)?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let attempt = extraction_attempt_hex(attempt_id);
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &attempt)?;
    Ok((vault, attempt_id, page_turns_with_versions(&page), subject))
}

/// The native resolution options in native order, as the conflict pack builds them.
pub(crate) fn native_resolution_options() -> Value {
    json!(["merge", "supersede", "accumulate", "escalate"])
}

/// Answers the one pack generation from a per-request scripted backend and counts the
/// generations it serves.
pub(crate) struct ParityReasoner {
    /// Holds the fixed both-question reply text.
    reply: String,
    /// Declares the reply's input tokens.
    input_tokens: u64,
    /// Declares the reply's output tokens.
    output_tokens: u64,
    /// Counts the generations served so far.
    calls: AtomicUsize,
}

impl ParityReasoner {
    /// Builds a reasoner answering every generation with `reply`, declaring the token counts.
    pub(crate) fn new(reply: String, input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            reply,
            input_tokens,
            output_tokens,
            calls: AtomicUsize::new(0),
        }
    }

    /// Returns the generations served so far.
    pub(crate) fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl LlmBackend for ParityReasoner {
    /// The scripted backend answers every model, so this reasoner does too.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Answers the generation from a scripted backend matching this request's digest.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let reply = self.reply.clone();
        let (input_tokens, output_tokens) = (self.input_tokens, self.output_tokens);
        Box::pin(async move {
            let digest = ScriptedBackend::digest_of(&request);
            let backend = ScriptedBackend::new(vec![
                Step::text("parity-pack", digest, reply)
                    .buffered()
                    .usage(input_tokens, output_tokens),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the parity scripted backend did not build: {error}"),
                    code: None,
                })
            })?;
            let response = backend.generate(request, lease).await;
            let seen = backend.finish();
            self.calls.fetch_add(seen.len(), Ordering::SeqCst);
            response
        })
    }

    /// The parity legs never stream; a streamed call fails loudly.
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
