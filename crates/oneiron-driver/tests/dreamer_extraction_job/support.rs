//! Production lender fixtures for extraction job driver tests.
//!
//! Lends scripted verdict packs and merged values on the verdict role, and
//! turn-aware scripted extraction steps through JobStepBackend,
//! both lent by ExtractionAttemptLender via ConsolidationExecutorFactory.
//! Vault, selection, head shapes and the job clock follow
//! `extraction_decisions/support.rs`; the lender wiring follows
//! `dreamer_extraction_steps.rs`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use oneiron::AttemptId;
use oneiron::BudgetLease;
use oneiron::ContentPart;
use oneiron::DreamerAdmittedAttempt;
use oneiron::DreamerClaimAuthoringStrategy;
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
use oneiron::WakeAttemptContext;
use oneiron::claim::ClaimApprovalStatus;
use oneiron::claim::ClaimBody;
use oneiron::claim::ClaimLifecycleStatus;
use oneiron::claim::ClaimSource;
use oneiron::claim::ClaimSubject;
use oneiron::dreamer_consolidation::DREAMER_EXTRACTION_ROLE;
use oneiron::dreamer_consolidation::DREAMER_VERDICT_ROLE;
use oneiron::dreamer_consolidation::RoleBackend;
use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::dreamer_promotion::AttemptPromotionSink;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::enqueue_admitted_extraction_attempt;
use oneiron::test_doors::extraction_inputs::witness_extraction_turns;
use oneiron::test_doors::extraction_verdict::ExtractionVerdictFixture;
use oneiron::test_doors::steward::STEWARD_VERBS;
use oneiron::test_doors::steward::dreamer;
use oneiron::test_doors::steward::stand_steward_grant;
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron_driver::ConsolidationExecutorFactory;
use oneiron_driver::ExtractionAttemptLender;
use oneiron_driver::ExtractionDecisionGate;
use oneiron_driver::PassExecutorFactory;
use oneiron_remote::OneironClient;
use oneiron_testkit::ScriptedBackend;
use oneiron_testkit::Step;
use rmpv::Value as RmpValue;
use serde_json::Value;
use serde_json::json;

/// Carries fixture failures without hiding their source.
pub(crate) type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Counts lent generations by read family.
pub(crate) struct Counts {
    pub(crate) correction: AtomicUsize,
    pub(crate) resolution: AtomicUsize,
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
    pub(crate) id: String,
    /// Holds the shown labels in request order.
    pub(crate) labels: Vec<String>,
}

/// Holds one parsed generation call with its state.
pub(crate) struct ParsedCall {
    /// Holds the asked questions in request order.
    pub(crate) questions: Vec<ParsedQuestion>,
    /// Holds the native state the questions read over.
    pub(crate) state: Value,
}

/// Answers each question id with its chosen shown label.
pub(crate) type Script = Arc<dyn Fn(&ParsedCall) -> HashMap<String, String> + Send + Sync>;

/// Records one served generation state for exact-array checks.
pub(crate) struct RecordedCall {
    /// Holds the native state the generation read over.
    pub(crate) state: Value,
}

/// Serves scripted answers keyed by question id and state.
pub(crate) struct KeyedReasoner {
    /// Refuses actual verdict generations while the retry fixture is faulted.
    pub(crate) refusing: AtomicBool,
    /// Counts actual backend refusals independently of answered verdicts.
    pub(crate) refused_calls: AtomicUsize,
    pub(crate) script: Script,
    pub(crate) counts: Arc<Counts>,
    pub(crate) recorded: Arc<Mutex<Vec<RecordedCall>>>,
}

impl KeyedReasoner {
    /// Serves `script` while counting into `counts` and recording into `recorded`.
    pub(crate) fn new(
        script: Script,
        counts: Arc<Counts>,
        recorded: Arc<Mutex<Vec<RecordedCall>>>,
    ) -> Self {
        Self {
            refusing: AtomicBool::new(false),
            refused_calls: AtomicUsize::new(0),
            script,
            counts,
            recorded,
        }
    }
}

/// Reads the last user turn carrying decision questions and state.
pub(crate) fn parse_call(request: &LlmRequest) -> Result<ParsedCall, String> {
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

pub(crate) fn fatal(message: String) -> LlmError {
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
            if self.refusing.load(Ordering::SeqCst) {
                self.refused_calls.fetch_add(1, Ordering::SeqCst);
                return Err(fatal(
                    "the owen verdict backend refuses this try".to_owned(),
                ));
            }
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

/// Answers none for corrections, accumulate for resolution and the first candidate otherwise.
pub(crate) fn accumulate_script() -> Script {
    Arc::new(|call: &ParsedCall| {
        let mut out = HashMap::new();
        for asked in &call.questions {
            let pick = if call.state.get("listed").is_some() {
                asked.labels.first().cloned().unwrap_or_default()
            } else if asked.labels.iter().any(|label| label == "accumulate") {
                "accumulate".to_owned()
            } else {
                asked.labels.get(1).cloned().unwrap_or_default()
            };
            out.insert(asked.id.clone(), pick);
        }
        out
    })
}

/// Answers merge when offered, else the second shown label.
pub(crate) fn merge_script() -> Script {
    Arc::new(|call: &ParsedCall| {
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

/// Holds counted scripted answers without retaining recorded states.
pub(crate) fn keyed(script: Script) -> (Arc<Counts>, Arc<KeyedReasoner>) {
    let counts = Arc::new(Counts::new());
    let recorded: Arc<Mutex<Vec<RecordedCall>>> = Arc::new(Mutex::new(Vec::new()));
    let reasoner = Arc::new(KeyedReasoner::new(script, Arc::clone(&counts), recorded));
    (counts, reasoner)
}

/// Serves verdict packs through a keyed script and merged-value steps through scripted replies.
///
/// Merged-value steps arrive on the verdict role (production lender
/// `lend_merged_value_step` resolves `DREAMER_VERDICT_ROLE` after checking
/// both `admits` and `admits_step`), so one verdict backend must answer both
/// families. A request whose last user turn parses as questions/state takes
/// the KeyedReasoner path with terminal usage; any other request takes the
/// parity ValueBackend path with the next scripted `{"value": ..}` reply.
pub(crate) struct JobVerdictBackend {
    /// Answers verdict packs through the shared keyed reasoner.
    pub(crate) reasoner: Arc<KeyedReasoner>,
    /// Holds merged-value replies in generation order.
    pub(crate) value_replies: Vec<String>,
    /// Counts actual merged-value generations.
    pub(crate) value_calls: AtomicUsize,
    /// Fails every merged-value generation with a fatal model error while set.
    pub(crate) value_refusing: AtomicBool,
    /// Counts the merged-value generations failed that way.
    pub(crate) value_refused_calls: AtomicUsize,
}

impl JobVerdictBackend {
    /// Borrows the existing reasoner and scripts merged-value generations.
    pub(crate) fn new(reasoner: Arc<KeyedReasoner>, value_replies: Vec<String>) -> Self {
        Self {
            reasoner,
            value_replies,
            value_calls: AtomicUsize::new(0),
            value_refusing: AtomicBool::new(false),
            value_refused_calls: AtomicUsize::new(0),
        }
    }

    /// Counts the merged-value generations served so far.
    pub(crate) fn value_calls(&self) -> usize {
        self.value_calls.load(Ordering::SeqCst)
    }
}

impl LlmBackend for JobVerdictBackend {
    /// Answers every model the fixture names.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Answers verdict packs from the script and merged values from scripted replies.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        if parse_call(&request).is_ok() {
            return self.reasoner.generate(request, lease);
        }
        if self.value_refusing.load(Ordering::SeqCst) {
            self.value_refused_calls.fetch_add(1, Ordering::SeqCst);
            return Box::pin(async move {
                Err(fatal(
                    "the owen merged-value backend fails this generation".to_owned(),
                ))
            });
        }
        let reply = self
            .value_replies
            .get(self.value_calls())
            .or_else(|| self.value_replies.last())
            .cloned()
            .unwrap_or_default();
        Box::pin(async move {
            let backend = ScriptedBackend::new(vec![
                Step::text("merged-value", ScriptedBackend::digest_of(&request), reply)
                    .buffered()
                    .usage(100, 50),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the merged-value scripted backend did not build: {error}"),
                    code: None,
                })
            })?;
            let response = backend.generate(request, lease).await;
            let seen = backend.finish();
            self.value_calls.fetch_add(seen.len(), Ordering::SeqCst);
            response
        })
    }

    /// Refuses streaming because verdicts and merged values read buffered.
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

/// Lets the test withdraw verdict or step permission while retaining the binding.
pub(crate) struct JobGate {
    /// Records whether the host currently admits a verdict loan.
    pub(crate) verdict_open: AtomicBool,
    /// Records whether the host currently admits a step loan.
    pub(crate) step_open: AtomicBool,
    /// Counts every live verdict permission check, including a refused loan.
    pub(crate) verdict_calls: AtomicUsize,
    /// Counts every live step permission check, including a refused loan.
    pub(crate) step_calls: AtomicUsize,
    /// Admits only the first `step_budget` step checks while open; `usize::MAX` admits all.
    pub(crate) step_budget: AtomicUsize,
}

impl JobGate {
    /// Holds the given permissions with zeroed counts and an unlimited step budget.
    pub(crate) fn new(verdict_open: bool, step_open: bool) -> Self {
        Self {
            verdict_open: AtomicBool::new(verdict_open),
            step_open: AtomicBool::new(step_open),
            verdict_calls: AtomicUsize::new(0),
            step_calls: AtomicUsize::new(0),
            step_budget: AtomicUsize::new(usize::MAX),
        }
    }
}

impl ExtractionDecisionGate for JobGate {
    /// Reads the test host's verdict permission at each verdict loan.
    fn admits(&self) -> oneiron::Result<bool> {
        self.verdict_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.verdict_open.load(Ordering::SeqCst))
    }

    /// Reads the test host's step permission and budget at each step loan.
    fn admits_step(&self) -> oneiron::Result<bool> {
        let call = self.step_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.step_open.load(Ordering::SeqCst) && call < self.step_budget.load(Ordering::SeqCst))
    }
}

/// Answers extraction steps from the final user transcript with terminal usage.
pub(crate) struct JobStepBackend {
    /// Counts the actual generations observed by the scripted backend.
    pub(crate) calls: AtomicUsize,
    /// Builds one wire reply JSON from the final user transcript.
    pub(crate) handler: Arc<dyn Fn(&str) -> String + Send + Sync>,
}

impl JobStepBackend {
    /// Answers every step through `handler` while counting generations.
    pub(crate) fn new(handler: Arc<dyn Fn(&str) -> String + Send + Sync>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            handler,
        }
    }

    /// Counts the step generations served so far.
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl LlmBackend for JobStepBackend {
    /// Admits every capability the fixture's fixed model asks about.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Answers the step from its final user transcript with terminal usage.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let transcript = request
            .messages
            .iter()
            .rfind(|message| message.role == LlmMessageRole::User)
            .map(|message| {
                message
                    .content
                    .iter()
                    .filter_map(|part| match part {
                        ContentPart::Text { text, .. } => Some(text.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let reply = (self.handler)(&transcript);
        Box::pin(async move {
            let backend = ScriptedBackend::new(vec![
                Step::text(
                    "extraction-step",
                    ScriptedBackend::digest_of(&request),
                    reply,
                )
                .buffered()
                .usage(100, 50),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the job step scripted backend did not build: {error}"),
                    code: None,
                })
            })?;
            let response = backend.generate(request, lease).await;
            let seen = backend.finish();
            self.calls.fetch_add(seen.len(), Ordering::SeqCst);
            response
        })
    }

    /// Refuses streaming because this fixture only generates buffered steps.
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

/// Finds the listed label naming `name` in one step transcript.
pub(crate) fn find_person_label(transcript: &str, name: &str) -> Option<String> {
    let wanted = format!("\"{name}\"");
    for line in transcript.lines() {
        if let Some(listed) = line.strip_prefix("entity ")
            && let Some((label, _)) = listed.split_once(' ')
            && label.starts_with('P')
            && line.contains(&wanted)
        {
            return Some(label.to_owned());
        }
    }
    None
}

/// Builds one listed-subject wire reply with one quoted candidate.
pub(crate) fn listed_step_reply(
    subject_label: &str,
    predicate: &str,
    value: &str,
    source_label: &str,
    quote: &str,
) -> String {
    json!({
        "persons": [],
        "candidates": [{
            "subject": subject_label,
            "predicate": predicate,
            "value": value,
            "confidence": 0.9,
            "evidence_refs": [{"source": source_label, "quote": quote}],
        }],
    })
    .to_string()
}

/// Builds one listed-subject wire reply with two quoted candidates.
pub(crate) fn listed_two_candidate_reply(
    subject_label: &str,
    predicate: &str,
    candidates: &[(&str, &str, &str)],
) -> String {
    let built: Vec<Value> = candidates
        .iter()
        .map(|(value, source, quote)| {
            json!({
                "subject": subject_label,
                "predicate": predicate,
                "value": value,
                "confidence": 0.9,
                "evidence_refs": [{"source": source, "quote": quote}],
            })
        })
        .collect();
    json!({"persons": [], "candidates": built}).to_string()
}

/// Answers only the merge-fixture TURNs actually present in this slice transcript.
pub(crate) fn merge_step_reply(transcript: &str) -> String {
    let label = find_person_label(transcript, "owen").expect("owen lists");
    let green = transcript.contains("owen chooses green tea");
    let black = transcript.contains("owen chooses black coffee");
    match (green, black) {
        (true, true) => listed_two_candidate_reply(
            &label,
            "preference.food",
            &[
                ("green tea", "T1", "owen chooses green tea"),
                ("black coffee", "T2", "owen chooses black coffee"),
            ],
        ),
        (true, false) => listed_step_reply(
            &label,
            "preference.food",
            "green tea",
            "T1",
            "owen chooses green tea",
        ),
        (false, true) => listed_step_reply(
            &label,
            "preference.food",
            "black coffee",
            "T1",
            "owen chooses black coffee",
        ),
        (false, false) => panic!("the owen merge slice shows neither fixture TURN"),
    }
}

/// Builds one declared-person wire reply with one quoted candidate.
pub(crate) fn declared_step_reply(
    name: &str,
    predicate: &str,
    value: &str,
    turn_label: &str,
    quote: &str,
) -> String {
    json!({
        "persons": [{"id": "new:P1", "name": name, "evidence_turn_refs": [turn_label]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": predicate,
            "value": value,
            "confidence": 0.9,
            "evidence_refs": [{"source": turn_label, "quote": quote}],
        }],
    })
    .to_string()
}

/// Holds one production-lent extraction attempt with its retained resources.
pub(crate) struct JobFixture {
    /// Owns the temporary directory for the vault lifetime.
    pub(crate) dir: tempfile::TempDir,
    /// Holds the vault the job reads and commits through its client.
    pub(crate) vault: Arc<Vault>,
    /// Holds the admitted attempt id.
    pub(crate) attempt: AttemptId,
    /// Holds the admission for same-attempt rebinds.
    pub(crate) admitted: DreamerAdmittedAttempt,
    /// Names the attempt as 32 lowercase hex digits for job inputs.
    pub(crate) attempt_hex: String,
    /// Holds the attempt clock the job's reads use: one second past the
    /// vault's recorded clock, as the decision fixtures take it.
    pub(crate) now_ms: u64,
    /// Holds the bound job client lending the production lender.
    pub(crate) client: OneironClient,
    /// Holds the switchable production gate for permission flips.
    pub(crate) gate: Arc<JobGate>,
    /// Holds the turn-aware step backend for generation counts.
    pub(crate) step_backend: Arc<JobStepBackend>,
    /// Holds the verdict counts by read family.
    pub(crate) counts: Arc<Counts>,
    /// Retains the actual verdict backend for the retry fault switch.
    pub(crate) reasoner: Arc<KeyedReasoner>,
    /// Retains the production lender across verdict and step loans.
    pub(crate) lender: Arc<ExtractionAttemptLender>,
    /// Retains the verdict fixture owning the lent runtime.
    pub(crate) fixture: Arc<ExtractionVerdictFixture>,
    /// Holds the witnessed turns in order for native slice checks.
    pub(crate) turn_ids: Vec<EntityId>,
    /// Holds the seeded person ids in seeds order.
    pub(crate) seeded: Vec<EntityId>,
    /// Holds the multiplexed verdict backend for merged-value counts, when the attempt mints one.
    pub(crate) value_backend: Option<Arc<JobVerdictBackend>>,
}

/// Builds one production-lent attempt over `words` with `seeds` named and `heads` landed before witnessing.
///
/// Each head names a seeded index with its predicate and value; heads land as active auto
/// `Generated` claims before any TURN is witnessed, per the existing decision fixture order.
pub(crate) fn job_fixture(
    words: &[&str],
    seeds: &[&str],
    heads: &[(usize, &str, &str)],
    selection_override: Option<(u64, usize)>,
    step_handler: Arc<dyn Fn(&str) -> String + Send + Sync>,
    verdict_open: bool,
    step_open: bool,
) -> TestResult<JobFixture> {
    let (directory, vault) = open_vault()?;
    if let Some((soak_ms, evidence_minimum)) = selection_override {
        vault.set_consolidation_selection(&SelectionConfig {
            soak_ms,
            evidence_minimum,
            ..vault.consolidation_selection()?
        })?;
    }
    let mut seeded = Vec::with_capacity(seeds.len());
    for name in seeds {
        seeded.push(seed_person(&vault, name)?);
    }
    for (index, predicate, value) in heads {
        let subject = *seeded
            .get(*index)
            .ok_or("a seeded head names a seeded person")?;
        land_head(&vault, subject, predicate, value, ClaimSource::Generated)?;
    }
    let witnessed = witness_extraction_turns(&vault, words)?;
    let (attempt, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, 1_000)?;
    let binding = vault.bind_dreamer_attempt(&admitted)?;
    let attempt_hex: String = attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let page = binding.invoke(
        "vault.consolidation.extraction.inputs.page",
        json!({"attempt": attempt_hex}),
        None,
    )?;
    let turns = page["value"]["turns"]
        .as_array()
        .ok_or("the extraction inputs page serves its turns")?;
    assert_eq!(turns.len(), words.len());
    let (counts, reasoner) = keyed(accumulate_script());
    let step_backend = Arc::new(JobStepBackend::new(step_handler));
    let verdict_backend: Arc<dyn LlmBackend> = reasoner.clone();
    let fixture = ExtractionVerdictFixture::new(verdict_backend)?;
    let pass = fixture.pass_resources();
    let verdict = pass
        .roles
        .get(DREAMER_VERDICT_ROLE)
        .ok_or("the fixture routes its verdict role")?;
    let (_, extraction_model, extraction_binding) = fixture.extraction_route();
    let step_route: Arc<dyn LlmBackend> = step_backend.clone();
    let roles = pass.roles.clone().with(
        DREAMER_EXTRACTION_ROLE,
        RoleBackend {
            backend: step_route,
            model: extraction_model,
            binding: extraction_binding,
            sourced: None,
        },
    );
    let gate = Arc::new(JobGate::new(verdict_open, step_open));
    let mut factory = ConsolidationExecutorFactory::new(
        Arc::clone(&verdict.backend),
        DreamerClaimAuthoringStrategy::SinglePass,
        binding.actor(),
        verdict.model.clone(),
        verdict.binding.clone(),
        Some(Arc::new(|_: &LlmRequest| true)),
        Box::new(AttemptPromotionSink::new(Arc::clone(&vault))),
    )
    .with_role_backends(roles)
    .with_decisions(pass.decisions.clone())
    .with_dreamer_job_vault(Arc::clone(&vault))
    .with_extraction_decisions(gate.clone(), pass.runtime.clone());
    let executor = factory.executor(&pass.guard)?;
    let context = WakeAttemptContext {
        vault: &vault,
        deadline: &pass.deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "extraction-inputs",
        now_ms: pass.now_ms,
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    let lender = executor
        .extraction_lender(&context)
        .ok_or("the production factory prepares an extraction lender")?;
    let binding = binding.lend_decisions(lender.clone());
    let client = OneironClient::for_dreamer_attempt(binding);
    let now_ms = vault
        .now_recorded_at()
        .saturating_add(1)
        .saturating_mul(1_000);
    Ok(JobFixture {
        dir: directory,
        vault,
        attempt,
        admitted,
        attempt_hex,
        now_ms,
        client,
        gate,
        step_backend,
        counts,
        reasoner,
        lender,
        fixture,
        turn_ids: witnessed.turns,
        seeded,
        value_backend: None,
    })
}

/// Builds one production-lent attempt whose verdict backend also answers merged values.
///
/// Uses the merge script with `value_replies` in order (e.g. one
/// `{"value":"oolong tea"}` reply for the two-member merge), through the same
/// production lender shape as [`job_fixture`]: the same factory, roles, gate,
/// runtime and lender retention, with the verdict role multiplexed.
pub(crate) fn job_merge_fixture(
    words: &[&str],
    seeds: &[&str],
    selection_override: Option<(u64, usize)>,
    step_handler: Arc<dyn Fn(&str) -> String + Send + Sync>,
    value_replies: Vec<String>,
    verdict_open: bool,
    step_open: bool,
) -> TestResult<JobFixture> {
    let (directory, vault) = open_vault()?;
    if let Some((soak_ms, evidence_minimum)) = selection_override {
        vault.set_consolidation_selection(&SelectionConfig {
            soak_ms,
            evidence_minimum,
            ..vault.consolidation_selection()?
        })?;
    }
    let mut seeded = Vec::with_capacity(seeds.len());
    for name in seeds {
        seeded.push(seed_person(&vault, name)?);
    }
    let witnessed = witness_extraction_turns(&vault, words)?;
    let (attempt, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, 1_000)?;
    let binding = vault.bind_dreamer_attempt(&admitted)?;
    let attempt_hex: String = attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let page = binding.invoke(
        "vault.consolidation.extraction.inputs.page",
        json!({"attempt": attempt_hex}),
        None,
    )?;
    let turns = page["value"]["turns"]
        .as_array()
        .ok_or("the extraction inputs page serves its turns")?;
    assert_eq!(turns.len(), words.len());
    let (counts, reasoner) = keyed(merge_script());
    let multiplexer = Arc::new(JobVerdictBackend::new(reasoner.clone(), value_replies));
    let step_backend = Arc::new(JobStepBackend::new(step_handler));
    let verdict_backend: Arc<dyn LlmBackend> = multiplexer.clone();
    let fixture = ExtractionVerdictFixture::new(verdict_backend)?;
    let pass = fixture.pass_resources();
    let verdict = pass
        .roles
        .get(DREAMER_VERDICT_ROLE)
        .ok_or("the fixture routes its verdict role")?;
    let (_, extraction_model, extraction_binding) = fixture.extraction_route();
    let step_route: Arc<dyn LlmBackend> = step_backend.clone();
    let roles = pass.roles.clone().with(
        DREAMER_EXTRACTION_ROLE,
        RoleBackend {
            backend: step_route,
            model: extraction_model,
            binding: extraction_binding,
            sourced: None,
        },
    );
    let gate = Arc::new(JobGate::new(verdict_open, step_open));
    let mut factory = ConsolidationExecutorFactory::new(
        Arc::clone(&verdict.backend),
        DreamerClaimAuthoringStrategy::SinglePass,
        binding.actor(),
        verdict.model.clone(),
        verdict.binding.clone(),
        Some(Arc::new(|_: &LlmRequest| true)),
        Box::new(AttemptPromotionSink::new(Arc::clone(&vault))),
    )
    .with_role_backends(roles)
    .with_decisions(pass.decisions.clone())
    .with_dreamer_job_vault(Arc::clone(&vault))
    .with_extraction_decisions(gate.clone(), pass.runtime.clone());
    let executor = factory.executor(&pass.guard)?;
    let context = WakeAttemptContext {
        vault: &vault,
        deadline: &pass.deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "extraction-inputs",
        now_ms: pass.now_ms,
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    let lender = executor
        .extraction_lender(&context)
        .ok_or("the production factory prepares an extraction lender")?;
    let binding = binding.lend_decisions(lender.clone());
    let client = OneironClient::for_dreamer_attempt(binding);
    let now_ms = vault
        .now_recorded_at()
        .saturating_add(1)
        .saturating_mul(1_000);
    Ok(JobFixture {
        dir: directory,
        vault,
        attempt,
        admitted,
        attempt_hex,
        now_ms,
        client,
        gate,
        step_backend,
        counts,
        reasoner,
        lender,
        fixture,
        turn_ids: witnessed.turns,
        seeded,
        value_backend: Some(multiplexer),
    })
}

/// Binds the same admitted attempt again with the same production lender.
pub(crate) fn rebind_same_attempt(fixture: &JobFixture) -> TestResult<OneironClient> {
    let binding = fixture.vault.bind_dreamer_attempt(&fixture.admitted)?;
    let binding = binding.lend_decisions(fixture.lender.clone());
    Ok(OneironClient::for_dreamer_attempt(binding))
}
