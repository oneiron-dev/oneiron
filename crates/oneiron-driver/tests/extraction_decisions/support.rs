//! Lent scripted verdict fixtures for bound extraction decision tests.
//!
//! Builds real vaults with admitted attempts, lends a key-based scripted ladder
//! through the extraction verdict fixture, and counts each generation by family.
//! Vault, selection and head shapes follow the observed support; big values follow
//! the packs support; the lender follows the extraction verdict parity fixture.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use oneiron::BudgetLease;
use oneiron::ContentPart;
use oneiron::EntityId;
use oneiron::FatalLlmError;
use oneiron::FinishReason;
use oneiron::LlmBackend;
use oneiron::LlmCapability;
use oneiron::LlmError;
use oneiron::LlmGenerateFuture;
use oneiron::LlmInputUsage;
use oneiron::LlmMessage;
use oneiron::LlmMessageRole;
use oneiron::LlmOutputUsage;
use oneiron::LlmRequest;
use oneiron::LlmResponse;
use oneiron::LlmStreamResult;
use oneiron::LlmUsage;
use oneiron::ModelId;
use oneiron::TimeRange;
use oneiron::UnsupportedCapability;
use oneiron::Vault;
use oneiron::VaultConfig;
use oneiron::claim::ClaimApprovalStatus;
use oneiron::claim::ClaimBody;
use oneiron::claim::ClaimLifecycleStatus;
use oneiron::claim::ClaimSource;
use oneiron::claim::ClaimSubject;
use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::enqueue_admitted_extraction_attempt;
use oneiron::test_doors::extraction_inputs::witness_extraction_turns;
use oneiron::test_doors::extraction_verdict::ExtractionVerdictFixture;
use oneiron::test_doors::extraction_verdict::attach_extraction_verdict_lender;
use oneiron::test_doors::steward::STEWARD_VERBS;
use oneiron::test_doors::steward::dreamer;
use oneiron::test_doors::steward::stand_steward_grant;
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron_dreamer::extraction_reply::BoundExtractionReply;
use oneiron_dreamer::extraction_selection::ExtractionSelectionConfig;
use oneiron_remote::OneironClient;
use rmpv::Value as RmpValue;
use serde_json::Value;
use serde_json::json;

/// Carries fixture failures without hiding their source.
pub(crate) type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Counts lent generations by read family.
pub(crate) struct Counts {
    correction: AtomicUsize,
    resolution: AtomicUsize,
}

impl Counts {
    /// Holds zeroed counters.
    pub(crate) fn new() -> Self {
        Self {
            correction: AtomicUsize::new(0),
            resolution: AtomicUsize::new(0),
        }
    }

    /// Counts correction-family generations by their listed state.
    pub(crate) fn correction(&self) -> usize {
        self.correction.load(Ordering::SeqCst)
    }

    /// Counts resolution-family generations by their conflict state.
    pub(crate) fn resolution(&self) -> usize {
        self.resolution.load(Ordering::SeqCst)
    }
}

/// Holds one parsed decision question with its shown labels.
pub(crate) struct ParsedQuestion {
    /// Holds the call-local question label.
    pub id: String,
    /// Holds the shown labels in request order.
    pub labels: Vec<String>,
}

/// Holds one parsed generation call with its state.
pub(crate) struct ParsedCall {
    /// Holds the asked questions in request order.
    pub questions: Vec<ParsedQuestion>,
    /// Holds the native state the questions read over.
    pub state: Value,
}

/// Answers each question id with its chosen shown label.
pub(crate) type Script = Arc<dyn Fn(&ParsedCall) -> HashMap<String, String> + Send + Sync>;

/// Records one served generation state for exact-array checks.
pub(crate) struct RecordedCall {
    /// Holds the native state the generation read over.
    pub state: Value,
}

/// Serves scripted answers keyed by question id and state.
pub(crate) struct KeyedReasoner {
    script: Script,
    counts: Arc<Counts>,
    recorded: Arc<Mutex<Vec<RecordedCall>>>,
}

impl KeyedReasoner {
    /// Serves `script` while counting into `counts` and recording into `recorded`.
    pub(crate) fn new(
        script: Script,
        counts: Arc<Counts>,
        recorded: Arc<Mutex<Vec<RecordedCall>>>,
    ) -> Self {
        Self {
            script,
            counts,
            recorded,
        }
    }
}

/// Reads the last user turn carrying decision questions and state.
fn parse_call(request: &LlmRequest) -> Result<ParsedCall, String> {
    for message in request.messages.iter().rev() {
        if message.role != LlmMessageRole::User {
            continue;
        }
        for part in &message.content {
            let ContentPart::Text { text, .. } = part else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<Value>(text) else {
                continue;
            };
            let (Some(questions), Some(state)) = (value.get("questions"), value.get("state"))
            else {
                continue;
            };
            let questions = questions
                .as_array()
                .ok_or_else(|| "questions is not an array".to_owned())?;
            let mut parsed = Vec::with_capacity(questions.len());
            for asked in questions {
                let id = asked
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "a question has no id".to_owned())?
                    .to_owned();
                let labels = asked
                    .get("labels")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "a question has no labels".to_owned())?;
                let mut shown = Vec::with_capacity(labels.len());
                for label in labels {
                    shown.push(
                        label
                            .as_str()
                            .ok_or_else(|| "a label is not text".to_owned())?
                            .to_owned(),
                    );
                }
                parsed.push(ParsedQuestion { id, labels: shown });
            }
            return Ok(ParsedCall {
                questions: parsed,
                state: state.clone(),
            });
        }
    }
    Err("no decision turn".to_owned())
}

fn fatal(message: String) -> LlmError {
    LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
        message,
        code: None,
    })
}

impl LlmBackend for KeyedReasoner {
    /// Answers every model the fixture names.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Answers one generation from the keyed script with terminal usage.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let parsed = parse_call(&request).map_err(fatal)?;
            if parsed.state.get("listed").is_some() {
                self.counts.correction.fetch_add(1, Ordering::SeqCst);
            } else {
                self.counts.resolution.fetch_add(1, Ordering::SeqCst);
            }
            let chosen = (self.script)(&parsed);
            let mut reply = serde_json::Map::new();
            for asked in &parsed.questions {
                let pick = chosen
                    .get(&asked.id)
                    .cloned()
                    .unwrap_or_else(|| asked.labels.first().cloned().unwrap_or_default());
                let mut weights = serde_json::Map::new();
                let count = asked.labels.len();
                for label in &asked.labels {
                    let weight = if label == &pick {
                        0.85
                    } else if count > 1 {
                        0.15 / ((count - 1) as f64)
                    } else {
                        1.0
                    };
                    weights.insert(label.clone(), json!(weight));
                }
                reply.insert(asked.id.clone(), Value::Object(weights));
            }
            let text = Value::Object(reply).to_string();
            if text.is_empty() {
                return Err(LlmError::Fatal(FatalLlmError::EmptyResponse));
            }
            self.recorded.lock().expect("record").push(RecordedCall {
                state: parsed.state.clone(),
            });
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text,
                        signature: None,
                    }],
                },
                usage: LlmUsage {
                    input: LlmInputUsage {
                        total: 100,
                        cache_read: 0,
                        cache_write: 0,
                    },
                    output: LlmOutputUsage {
                        total: 50,
                        text: 50,
                        reasoning: 0,
                    },
                    raw_provider: Value::Null,
                    call_metadata: None,
                },
                finish_reason: FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }

    /// Refuses streaming because every verdict reads buffered.
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

/// Opens a vault with steward grant and ready selection.
pub(crate) fn open_vault() -> TestResult<(tempfile::TempDir, Arc<Vault>)> {
    let directory = tempfile::tempdir()?;
    drop(open_dreamer_vault(directory.path(), "owen")?);
    let vault = Vault::open_owned(directory.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    Ok((directory, vault))
}

/// Seeds one named person and returns its id.
pub(crate) fn seed_person(vault: &Vault, name: &str) -> TestResult<EntityId> {
    let person = EntityId::now();
    seed_named_person(vault, &person, name, vault.now_recorded_at())?;
    Ok(person)
}

/// Lands one active auto head with the given predicate and value.
pub(crate) fn land_head(
    vault: &Vault,
    subject: EntityId,
    predicate: &str,
    value: &str,
    source: ClaimSource,
) -> TestResult<EntityId> {
    let head = EntityId::now();
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        RmpValue::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(source);
    body.scope_facet = vault.default_facet()?;
    let now = vault.now_recorded_at();
    vault.put_claim(
        &head,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(head)
}

/// Witnesses each word as its own turn and returns the turns in order.
pub(crate) fn witness_turns(vault: &Vault, words: &[&str]) -> TestResult<Vec<EntityId>> {
    Ok(witness_extraction_turns(vault, words)?.turns)
}

/// Seeds the single-valued predicates the fast-path checks read.
pub(crate) fn seed_single_valued(vault: &Vault, predicates: &[&str]) -> TestResult<()> {
    Ok(
        oneiron::test_doors::extraction_single_valued::seed_extraction_single_valued_predicates(
            vault, predicates,
        )?,
    )
}

/// Binds one admitted attempt with the lent scripted ladder and reads its inputs page.
pub(crate) fn bind_lent(
    vault: &Arc<Vault>,
    turns: &[EntityId],
    reasoner: Arc<KeyedReasoner>,
) -> TestResult<(
    OneironClient,
    String,
    u64,
    Value,
    ExtractionSelectionConfig,
    String,
    Arc<ExtractionVerdictFixture>,
)> {
    let (id, admitted) = enqueue_admitted_extraction_attempt(vault, turns, 1_000)?;
    let attempt: String = id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let lent = ExtractionVerdictFixture::new(reasoner)?;
    let binding = attach_extraction_verdict_lender(vault.bind_dreamer_attempt(&admitted)?, &lent);
    let client = OneironClient::for_dreamer_attempt(binding);
    let now_ms = vault
        .now_recorded_at()
        .saturating_add(1)
        .saturating_mul(1_000);
    let inputs = client.agent_verb(
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
    Ok((client, attempt, now_ms, page, config, policy_pin, lent))
}

/// Reads served turn refs with versions from a bound inputs page.
pub(crate) fn page_turns(page: &Value) -> TestResult<Vec<(String, Value)>> {
    let served = page["turns"].as_array().ok_or("missing turns")?;
    let mut turns = Vec::with_capacity(served.len());
    for row in served {
        turns.push((
            row["turn"].as_str().ok_or("missing turn")?.to_owned(),
            row["version"].clone(),
        ));
    }
    if turns.is_empty() {
        return Err("the bound inputs page served no TURN".into());
    }
    Ok(turns)
}

/// Builds an exactly 50,000-character value over `prefix`.
pub(crate) fn big_value(prefix: &str) -> Value {
    json!(prefix.chars().cycle().take(50_000).collect::<String>())
}

/// Builds one listed candidate reply entry with the given evidence pins and spans.
pub(crate) fn listed_candidate(
    index: usize,
    subject: &str,
    predicate: &str,
    value: Value,
    evidence: &[(String, Value, u64, u64)],
) -> Value {
    let evidence: Vec<Value> = evidence
        .iter()
        .map(|(turn, version, start, end)| {
            json!({"turn": turn, "version": version, "span": {"start": start, "end": end}})
        })
        .collect();
    json!({
        "index": index,
        "subject": {"listed": subject},
        "predicate": predicate,
        "value": value,
        "confidence": 0.9,
        "prospective_queries": [],
        "evidence": evidence,
    })
}

/// Builds one declared candidate reply entry with the given evidence pins and spans.
pub(crate) fn declared_candidate(
    index: usize,
    declared: usize,
    predicate: &str,
    value: Value,
    evidence: &[(String, Value, u64, u64)],
) -> Value {
    let evidence: Vec<Value> = evidence
        .iter()
        .map(|(turn, version, start, end)| {
            json!({"turn": turn, "version": version, "span": {"start": start, "end": end}})
        })
        .collect();
    json!({
        "index": index,
        "subject": {"declared": declared},
        "predicate": predicate,
        "value": value,
        "confidence": 0.9,
        "prospective_queries": [],
        "evidence": evidence,
    })
}

/// Builds one bound reply with the given candidates and declared persons.
pub(crate) fn reply_json(candidates: Vec<Value>, persons: Vec<Value>) -> Value {
    json!({"candidates": candidates, "persons": persons, "skipped": []})
}

/// Decodes one bound reply value.
pub(crate) fn decode_reply(value: Value) -> TestResult<BoundExtractionReply> {
    Ok(serde_json::from_value(value)?)
}
