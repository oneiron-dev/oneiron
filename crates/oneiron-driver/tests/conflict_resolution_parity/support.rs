//! Dual-lent fixtures for conflict resolution parity tests.
//!
//! One admitted attempt with a verdict lender for `run` and a merged-value
//! step lender for `plan`, over vaults copied from the decision tests.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use oneiron::BudgetLease;
use oneiron::EntityId;
use oneiron::FatalLlmError;
use oneiron::LlmBackend;
use oneiron::LlmCapability;
use oneiron::LlmError;
use oneiron::LlmGenerateFuture;
use oneiron::LlmRequest;
use oneiron::LlmStreamResult;
use oneiron::ModelId;
use oneiron::UnsupportedCapability;
use oneiron::Vault;
use oneiron::claim::ClaimSource;
use oneiron::test_doors::extraction_inputs::enqueue_admitted_extraction_attempt;
use oneiron::test_doors::extraction_steps::ExtractionStepFixture;
use oneiron::test_doors::extraction_steps::attach_extraction_step_lender;
use oneiron::test_doors::extraction_verdict::ExtractionVerdictFixture;
use oneiron::test_doors::extraction_verdict::attach_extraction_verdict_lender;
use oneiron_dreamer::extraction_decisions::Input;
use oneiron_dreamer::extraction_decisions::Outcome;
use oneiron_dreamer::extraction_decisions::run;
use oneiron_dreamer::extraction_reply::BoundExtractionReply;
use oneiron_dreamer::extraction_selection::ExtractionSelectionConfig;
use oneiron_remote::OneironClient;
use oneiron_testkit::ScriptedBackend;
use oneiron_testkit::Step;
use serde_json::Value;
use serde_json::json;

use crate::support as base;

/// Carries fixture failures without hiding their source.
pub(crate) type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Answers merged-value generations with scripted replies in order.
pub(crate) struct ValueBackend {
    /// Holds replies in generation order, repeating the final reply when exhausted.
    replies: Vec<String>,
    /// Declares the reply input tokens.
    input_tokens: u64,
    /// Declares the reply output tokens.
    output_tokens: u64,
    /// Counts the generations served so far.
    calls: AtomicUsize,
}

impl ValueBackend {
    /// Builds a backend answering each generation from `replies` in order.
    pub(crate) fn scripted(replies: Vec<String>) -> Self {
        Self {
            replies,
            input_tokens: 100,
            output_tokens: 50,
            calls: AtomicUsize::new(0),
        }
    }

    /// Returns the generations served so far.
    pub(crate) fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl LlmBackend for ValueBackend {
    /// Answers every model the fixture names.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Answers the request from a per-request scripted backend.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let reply = self
            .replies
            .get(self.call_count())
            .or_else(|| self.replies.last())
            .cloned()
            .unwrap_or_default();
        let (input_tokens, output_tokens) = (self.input_tokens, self.output_tokens);
        Box::pin(async move {
            let digest = ScriptedBackend::digest_of(&request);
            let backend = ScriptedBackend::new(vec![
                Step::text("merged-value", digest, reply)
                    .buffered()
                    .usage(input_tokens, output_tokens),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the value scripted backend did not build: {error}"),
                    code: None,
                })
            })?;
            let response = backend.generate(request, lease).await;
            let seen = backend.finish();
            self.calls.fetch_add(seen.len(), Ordering::SeqCst);
            response
        })
    }

    /// Refuses streaming because every merged value reads buffered.
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

/// Holds one dual-lent run with its outcome and step backend.
pub(crate) struct DualRun {
    /// Holds the person the fixture seeds.
    pub(crate) subject: EntityId,
    /// Holds the verdict client's decisions.
    pub(crate) outcome: Outcome,
    /// Holds the decoded bound reply the decisions judged.
    pub(crate) reply: BoundExtractionReply,
    /// Holds the step client's handle for `plan`.
    pub(crate) step_client: OneironClient,
    /// Holds the admitted attempt id for commits and native doors.
    pub(crate) attempt_id: oneiron::AttemptId,
    /// Holds the attempt id as the pages name it.
    pub(crate) attempt: String,
    /// Holds the attempt clock the reads used.
    pub(crate) now_ms: u64,
    /// Holds the vault the attempt was admitted in.
    pub(crate) vault: Arc<Vault>,
    /// Holds the merged-value backend for call counts.
    pub(crate) step_backend: Arc<ValueBackend>,
    /// Counts lent verdict generations by family.
    pub(crate) counts: Arc<base::Counts>,
    /// Keeps the vault directory alive.
    _dir: tempfile::TempDir,
}

/// Answers merge and the first shown candidate.
pub(crate) fn merge_script() -> base::Script {
    Arc::new(|call: &base::ParsedCall| {
        let mut out = HashMap::new();
        for asked in &call.questions {
            let pick = if asked.labels.iter().any(|label| label == "merge") {
                "merge".to_owned()
            } else {
                asked.labels.get(1).cloned().unwrap_or_default()
            };
            out.insert(asked.id.clone(), pick);
        }
        out
    })
}

/// Answers none for corrections and merge plus the first candidate otherwise.
pub(crate) fn none_script() -> base::Script {
    Arc::new(|call: &base::ParsedCall| {
        let mut out = HashMap::new();
        let correction = call.state.get("listed").is_some();
        for asked in &call.questions {
            let pick = if correction {
                asked.labels.first().cloned().unwrap_or_default()
            } else if asked.labels.iter().any(|label| label == "merge") {
                "merge".to_owned()
            } else {
                asked.labels.get(1).cloned().unwrap_or_default()
            };
            out.insert(asked.id.clone(), pick);
        }
        out
    })
}

/// Answers accumulate and the first shown candidate.
pub(crate) fn accumulate_script() -> base::Script {
    Arc::new(|call: &base::ParsedCall| {
        let mut out = HashMap::new();
        for asked in &call.questions {
            let pick = if asked.labels.iter().any(|label| label == "accumulate") {
                "accumulate".to_owned()
            } else {
                asked.labels.get(1).cloned().unwrap_or_default()
            };
            out.insert(asked.id.clone(), pick);
        }
        out
    })
}

/// Answers escalate and the first shown candidate.
pub(crate) fn escalate_script() -> base::Script {
    Arc::new(|call: &base::ParsedCall| {
        let mut out = HashMap::new();
        for asked in &call.questions {
            let pick = if asked.labels.iter().any(|label| label == "escalate") {
                "escalate".to_owned()
            } else {
                asked.labels.get(1).cloned().unwrap_or_default()
            };
            out.insert(asked.id.clone(), pick);
        }
        out
    })
}

/// Holds counted scripted answers.
fn keyed(script: base::Script) -> (Arc<base::Counts>, Arc<base::KeyedReasoner>) {
    let counts = Arc::new(base::Counts::new());
    let reasoner = Arc::new(base::KeyedReasoner::new(
        script,
        Arc::clone(&counts),
        Arc::new(Mutex::new(Vec::new())),
    ));
    (counts, reasoner)
}

/// Runs one Owen reply with Generated heads through verdict then holds the step client.
///
/// Copies `extraction_decisions.rs` `run_case` without varying it, except the
/// attempt also lends the step backend under a second client for `plan`.
pub(crate) fn run_case_two(
    heads: &[(&str, &str)],
    words: &[&str],
    candidates: &[(&str, Value)],
    verdict_script: base::Script,
    single_valued: &[&str],
    step_replies: Vec<String>,
) -> TestResult<DualRun> {
    let (dir, vault) = base::open_vault()?;
    if !single_valued.is_empty() {
        base::seed_single_valued(&vault, single_valued)?;
    }
    let subject = base::seed_person(&vault, "owen")?;
    for &(predicate, value) in heads {
        base::land_head(&vault, subject, predicate, value, ClaimSource::Generated)?;
    }
    let turns = base::witness_turns(&vault, words)?;
    let (counts, reasoner) = keyed(verdict_script);
    let step_backend = Arc::new(ValueBackend::scripted(step_replies));
    let (verdict_client, step_client, attempt_id, attempt, now_ms, page, config, policy_pin) =
        bind_two(&vault, &turns, reasoner, Arc::clone(&step_backend))?;
    let served = base::page_turns(&page)?;
    let subject_hex = subject.to_hex();
    let mut built = Vec::with_capacity(candidates.len());
    for (n, (predicate, value)) in candidates.iter().enumerate() {
        let row = &served[n % served.len()];
        let evidence = [(row.0.clone(), row.1.clone(), 0, 4)];
        built.push(base::listed_candidate(
            n,
            &subject_hex,
            predicate,
            value.clone(),
            &evidence,
        ));
    }
    let reply = base::decode_reply(base::reply_json(built, Vec::new()))?;
    let outcome = run(Input {
        client: &verdict_client,
        attempt: &attempt,
        now_ms,
        reply: &reply,
        config: &config,
        policy_pin: &policy_pin,
    })?;
    Ok(DualRun {
        subject,
        outcome,
        reply,
        step_client,
        attempt_id,
        attempt,
        now_ms,
        vault,
        step_backend,
        counts,
        _dir: dir,
    })
}

/// Binds one admitted attempt twice: a verdict lender and a step lender.
///
/// Enqueues once, mints one binding per lender from the same admission, and
/// reads the inputs page for the selection config.
fn bind_two(
    vault: &Arc<Vault>,
    turns: &[EntityId],
    reasoner: Arc<base::KeyedReasoner>,
    step_backend: Arc<ValueBackend>,
) -> TestResult<(
    OneironClient,
    OneironClient,
    oneiron::AttemptId,
    String,
    u64,
    Value,
    ExtractionSelectionConfig,
    String,
)> {
    let (id, admitted) = enqueue_admitted_extraction_attempt(vault, turns, 1_000)?;
    let attempt: String = id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let lent = ExtractionVerdictFixture::new(reasoner)?;
    let steps = ExtractionStepFixture::new(step_backend)?;
    let verdict_binding =
        attach_extraction_verdict_lender(vault.bind_dreamer_attempt(&admitted)?, &lent);
    let step_binding =
        attach_extraction_step_lender(vault.bind_dreamer_attempt(&admitted)?, &steps);
    let verdict_client = OneironClient::for_dreamer_attempt(verdict_binding);
    let step_client = OneironClient::for_dreamer_attempt(step_binding);
    let now_ms = vault
        .now_recorded_at()
        .saturating_add(1)
        .saturating_mul(1_000);
    let inputs = verdict_client.agent_verb(
        "vault.consolidation.extraction.inputs.page",
        json!({"attempt": attempt}),
    )?;
    let page = inputs["value"].clone();
    let policy_pin = page["policy_pin"]
        .as_str()
        .ok_or("missing policy pin")?
        .to_owned();
    let config = ExtractionSelectionConfig::from_selection(
        page["policy"]["selection"].clone(),
        &policy_pin,
    )?;
    Ok((
        verdict_client,
        step_client,
        id,
        attempt,
        now_ms,
        page,
        config,
        policy_pin,
    ))
}
