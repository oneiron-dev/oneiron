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
use oneiron::ContentPart;
use oneiron::EntityId;
use oneiron::FatalLlmError;
use oneiron::LlmBackend;
use oneiron::LlmCapability;
use oneiron::LlmError;
use oneiron::LlmGenerateFuture;
use oneiron::LlmMessageRole;
use oneiron::LlmRequest;
use oneiron::LlmStreamResult;
use oneiron::ModelId;
use oneiron::UnsupportedCapability;
use oneiron::Vault;
use oneiron::claim::ClaimSource;
use oneiron::llm::BudgetDenied;
use oneiron::test_doors::extraction_inputs::enqueue_admitted_extraction_attempt;
use oneiron::test_doors::extraction_steps::ExtractionStepFixture;
use oneiron::test_doors::extraction_steps::attach_extraction_step_lender;
use oneiron::test_doors::extraction_verdict::ExtractionVerdictFixture;
use oneiron::test_doors::extraction_verdict::attach_extraction_verdict_lender;
use oneiron_dreamer::extraction_decisions::Input;
use oneiron_dreamer::extraction_decisions::Outcome;
use oneiron_dreamer::extraction_decisions::run;
use oneiron_dreamer::extraction_observations::read_observations;
use oneiron_dreamer::extraction_reply::BoundExtractionReply;
use oneiron_dreamer::extraction_reply::decision_operands;
use oneiron_dreamer::extraction_selection::ExtractionSelectionConfig;
use oneiron_remote::OneironClient;
use oneiron_testkit::ScriptedBackend;
use oneiron_testkit::Step;
use serde_json::Value;
use serde_json::json;

use crate::support as base;

/// Carries fixture failures without hiding their source.
pub(crate) type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Selects how the merged-value backend answers a generation.
enum ValueAnswers {
    /// Holds replies in generation order, repeating the final reply when exhausted.
    Scripted(Vec<String>),
    /// Selects a distinct merged value by the rendered request's predicate.
    ByPredicate(HashMap<String, Value>),
    /// Refuses the call without invoking native's fatal-error fallback.
    Refused,
    /// Parks the step on a host budget check without a transport retry.
    BudgetDenied,
}

/// Answers merged-value generations and records their rendered requests.
pub(crate) struct ValueBackend {
    /// Selects the reply or refusal for each request.
    answers: ValueAnswers,
    /// Declares the reply input tokens.
    input_tokens: u64,
    /// Declares the reply output tokens.
    output_tokens: u64,
    /// Counts every generation, including a refused one.
    calls: AtomicUsize,
    /// Holds the user text native rendered for every generation.
    requests: Mutex<Vec<String>>,
}

impl ValueBackend {
    /// Builds a backend answering each generation from `replies` in order.
    pub(crate) fn scripted(replies: Vec<String>) -> Self {
        Self {
            answers: ValueAnswers::Scripted(replies),
            input_tokens: 100,
            output_tokens: 50,
            calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Answers each request with the value registered for its rendered predicate.
    pub(crate) fn by_predicate(values: &[(&str, Value)]) -> Self {
        Self {
            answers: ValueAnswers::ByPredicate(
                values
                    .iter()
                    .map(|(predicate, value)| ((*predicate).to_owned(), value.clone()))
                    .collect(),
            ),
            ..Self::scripted(Vec::new())
        }
    }

    /// Returns a terminal erased-response refusal, which never falls back.
    pub(crate) fn refusing() -> Self {
        Self {
            answers: ValueAnswers::Refused,
            ..Self::scripted(Vec::new())
        }
    }

    /// Returns a host-check refusal, which answers with a budget-denied step receipt.
    pub(crate) fn budget_denied() -> Self {
        Self {
            answers: ValueAnswers::BudgetDenied,
            ..Self::scripted(Vec::new())
        }
    }

    /// Returns the generations served so far.
    pub(crate) fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Returns the rendered user requests in generation order.
    pub(crate) fn requests(&self) -> TestResult<Vec<String>> {
        Ok(self
            .requests
            .lock()
            .map_err(|_| "the request lock")?
            .clone())
    }
}

impl LlmBackend for ValueBackend {
    /// Answers every model the fixture names.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Records and answers one native-rendered merged-value request.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let text: String = request
                .messages
                .iter()
                .filter(|message| message.role == LlmMessageRole::User)
                .flat_map(|message| &message.content)
                .filter_map(|part| match part {
                    ContentPart::Text { text, .. } => Some(text.as_str()),
                    _ => None,
                })
                .collect();
            self.requests
                .lock()
                .map_err(|_| LlmError::Fatal(FatalLlmError::InvalidRequest))?
                .push(text.clone());
            let reply = match &self.answers {
                ValueAnswers::Scripted(replies) => replies
                    .get(call)
                    .or_else(|| replies.last())
                    .cloned()
                    .unwrap_or_default(),
                ValueAnswers::ByPredicate(values) => {
                    let predicate = text
                        .lines()
                        .find_map(|line| line.strip_prefix("predicate "));
                    let value = predicate
                        .and_then(|predicate| values.get(predicate))
                        .ok_or_else(|| {
                            LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                                message: format!("no merged value for the request: {text}"),
                                code: None,
                            })
                        })?;
                    json!({"value": value}).to_string()
                }
                ValueAnswers::Refused => {
                    return Err(LlmError::Fatal(FatalLlmError::ResponseErased));
                }
                ValueAnswers::BudgetDenied => return Err(BudgetDenied::HostCheck.into()),
            };
            let digest = ScriptedBackend::digest_of(&request);
            let backend = ScriptedBackend::new(vec![
                Step::text("merged-value", digest, reply)
                    .buffered()
                    .usage(self.input_tokens, self.output_tokens),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the value scripted backend did not build: {error}"),
                    code: None,
                })
            })?;
            let response = backend.generate(request, lease).await;
            assert_eq!(backend.finish().len(), 1);
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

/// Answers merge and the second shown member of a same-predicate component.
pub(crate) fn merge_second_script() -> base::Script {
    Arc::new(|call: &base::ParsedCall| {
        let mut out = HashMap::new();
        for asked in &call.questions {
            let pick = if asked.labels.iter().any(|label| label == "merge") {
                "merge".to_owned()
            } else {
                // Same-predicate identity options are none, first, second.
                asked.labels.get(2).cloned().unwrap_or_default()
            };
            out.insert(asked.id.clone(), pick);
        }
        out
    })
}

/// Answers no correction, then supersede with the first shown candidate.
pub(crate) fn supersede_script() -> base::Script {
    Arc::new(|call: &base::ParsedCall| {
        let mut out = HashMap::new();
        let correction = call.state.get("listed").is_some();
        for asked in &call.questions {
            let pick = if correction {
                asked.labels.first().cloned().unwrap_or_default()
            } else if asked.labels.iter().any(|label| label == "supersede") {
                "supersede".to_owned()
            } else {
                asked.labels.get(1).cloned().unwrap_or_default()
            };
            out.insert(asked.id.clone(), pick);
        }
        out
    })
}

/// Answers merge without keeping a member; paged identity groups offer none.
pub(crate) fn unnamed_merge_script() -> base::Script {
    Arc::new(|call: &base::ParsedCall| {
        let mut out = HashMap::new();
        for asked in &call.questions {
            let pick = if asked.labels.iter().any(|label| label == "merge") {
                "merge".to_owned()
            } else {
                asked.labels.first().cloned().unwrap_or_default()
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

/// Answers no correction, then escalate and the first shown candidate.
pub(crate) fn escalate_script() -> base::Script {
    Arc::new(|call: &base::ParsedCall| {
        let mut out = HashMap::new();
        let correction = call.state.get("listed").is_some();
        for asked in &call.questions {
            let pick = if correction {
                asked.labels.first().cloned().unwrap_or_default()
            } else if asked.labels.iter().any(|label| label == "escalate") {
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

/// Selects reply-member facts and optional host-materialized candidate vectors.
#[derive(Default)]
pub(crate) struct ReplyOptions {
    /// Holds confidence and prospective queries in reply order, or no overrides.
    pub(crate) facts: Vec<(f64, Vec<String>)>,
    /// Seeds identical vectors under the reply's engine-derived candidate ids.
    pub(crate) shared_vectors: bool,
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
    run_case_with(
        heads,
        words,
        candidates,
        verdict_script,
        single_valued,
        ValueBackend::scripted(step_replies),
        ReplyOptions::default(),
    )
}

/// Runs a dual-lent fixture with a chosen step backend and per-reply-member facts.
///
/// Facts, when supplied, follow reply order; routing still selects its own order.
pub(crate) fn run_case_with(
    heads: &[(&str, &str)],
    words: &[&str],
    candidates: &[(&str, Value)],
    verdict_script: base::Script,
    single_valued: &[&str],
    step_backend: ValueBackend,
    options: ReplyOptions,
) -> TestResult<DualRun> {
    if !options.facts.is_empty() && options.facts.len() != candidates.len() {
        return Err("member facts must cover every reply candidate".into());
    }
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
    let step_backend = Arc::new(step_backend);
    let (verdict_client, step_client, attempt_id, attempt, now_ms, page, config, policy_pin) =
        bind_two(&vault, &turns, reasoner, Arc::clone(&step_backend))?;
    let served = base::page_turns(&page)?;
    let subject_hex = subject.to_hex();
    let mut built = Vec::with_capacity(candidates.len());
    for (n, (predicate, value)) in candidates.iter().enumerate() {
        let row = &served[n % served.len()];
        let evidence = [(row.0.clone(), row.1.clone(), 0, 4)];
        let mut candidate =
            base::listed_candidate(n, &subject_hex, predicate, value.clone(), &evidence);
        if let Some((confidence, hints)) = options.facts.get(n) {
            candidate["confidence"] = json!(confidence);
            candidate["prospective_queries"] = json!(hints);
        }
        built.push(candidate);
    }
    let reply = base::decode_reply(base::reply_json(built, Vec::new()))?;
    if options.shared_vectors {
        let operands = decision_operands(&reply)?;
        let observations =
            read_observations(&verdict_client, &attempt, now_ms, &operands.operands)?;
        let vector = vec![1.0_f32; oneiron::VaultConfig::device().dimensions];
        for candidate in observations.candidates {
            vault.put_vector(&EntityId::from_hex(&candidate.claim)?, &vector)?;
        }
    }
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
