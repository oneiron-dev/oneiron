//! A decisions run over a real lent extraction step names its recorded candidates.
//!
//! One bound attempt runs a real lent generation step with three listed candidates about
//! owen, then the shipped decisions run over that step's decoded reply with the step named.
//! Two candidates propose the same predicate and value with different quotes, so they fold
//! into one group whose union names both members, and the engine takes it. A reply the step
//! did not produce is refused.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test extraction_decisions_step_record` (the driver's dev dependency turns on the engine's `test-support` feature).
#![cfg(oneiron_test_support)]

#[path = "extraction_decisions/support.rs"]
mod support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use oneiron::dreamer_consolidation::{DREAMER_EXTRACTION_ROLE, DREAMER_VERDICT_ROLE, RoleBackend};
use oneiron::dreamer_promotion::AttemptPromotionSink;
use oneiron::test_doors::extraction_inputs::enqueue_admitted_extraction_attempt;
use oneiron::test_doors::extraction_verdict::ExtractionVerdictFixture;
use oneiron::{
    BudgetLease, ContentPart, DreamerClaimAuthoringStrategy, FatalLlmError, LlmBackend,
    LlmCapability, LlmError, LlmGenerateFuture, LlmMessageRole, LlmRequest, LlmStreamResult,
    ModelId, UnsupportedCapability, Vault, WakeAttemptContext,
};
use oneiron_dreamer::extraction_decisions::{self, Input, run};
use oneiron_dreamer::extraction_observations;
use oneiron_dreamer::extraction_reply::BoundExtractionReply;
use oneiron_dreamer::extraction_selection::ExtractionSelectionConfig;
use oneiron_driver::{
    ConsolidationExecutorFactory, ExtractionAttemptLender, ExtractionDecisionGate,
    PassExecutorFactory,
};
use oneiron_remote::OneironClient;
use oneiron_testkit::{ScriptedBackend, Step};
use serde_json::{Value, json};

/// Answers merge and the first shown candidate.
fn merge_script() -> support::Script {
    Arc::new(|call: &support::ParsedCall| {
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

/// Holds counted scripted answers and their recorded states.
fn keyed(
    script: support::Script,
) -> (
    Arc<support::Counts>,
    Arc<Mutex<Vec<support::RecordedCall>>>,
    Arc<support::KeyedReasoner>,
) {
    let counts = Arc::new(support::Counts::new());
    let recorded: Arc<Mutex<Vec<support::RecordedCall>>> = Arc::new(Mutex::new(Vec::new()));
    let reasoner = Arc::new(support::KeyedReasoner::new(
        script,
        Arc::clone(&counts),
        Arc::clone(&recorded),
    ));
    (counts, recorded, reasoner)
}

/// Answers one bound extraction step with three listed candidates about owen.
struct StepReplyBackend {
    /// Counts the generations that reached this backend.
    calls: AtomicUsize,
}

impl StepReplyBackend {
    /// Counts the generations served so far.
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// Reads the final user message of a step request, which carries its transcript.
fn final_user_text(request: &LlmRequest) -> String {
    request
        .messages
        .iter()
        .rev()
        .find(|message| message.role == LlmMessageRole::User)
        .map(|message| {
            message
                .content
                .iter()
                .filter_map(|part| match part {
                    ContentPart::Text { text, .. } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Builds the three-candidate extraction reply the transcript's labels allow.
///
/// The reply names the listed entity the transcript calls owen. Its first two
/// candidates propose the same predicate and value and quote the first and the
/// second cited turn in full, so they fold into one group with different quotes.
/// Its third candidate proposes another value of another predicate.
fn step_reply_for(transcript: &str) -> Result<String, String> {
    let mut owen = None;
    let mut turns = Vec::new();
    for line in transcript.lines() {
        if let Some(rest) = line.strip_prefix("entity ") {
            let label = rest.split_whitespace().next().unwrap_or_default();
            if rest.contains("\"owen\"") && owen.is_none() {
                owen = Some(label.to_owned());
            }
        } else if let Some(rest) = line.strip_prefix("[") {
            if let Some((label, text)) = rest.split_once("] ") {
                let label = label.split_whitespace().next().unwrap_or_default();
                if label.starts_with('T') && !label.is_empty() {
                    turns.push((label.to_owned(), text.to_owned()));
                }
            }
        }
    }
    let owen = owen.ok_or_else(|| "the step transcript lists no entity named owen".to_owned())?;
    if turns.len() < 2 {
        return Err("the step transcript shows fewer than two turns".to_owned());
    }
    let (first_turn, first_quote) = &turns[0];
    let (second_turn, second_quote) = &turns[1];
    Ok(json!({
        "persons": [],
        "candidates": [
            {
                "subject": owen,
                "predicate": "preference.food",
                "value": "green tea",
                "confidence": 0.9,
                "evidence_refs": [{"source": first_turn, "quote": first_quote}],
            },
            {
                "subject": owen,
                "predicate": "preference.food",
                "value": "green tea",
                "confidence": 0.9,
                "evidence_refs": [{"source": second_turn, "quote": second_quote}],
            },
            {
                "subject": owen,
                "predicate": "preference.drink",
                "value": "water",
                "confidence": 0.9,
                "evidence_refs": [{"source": second_turn, "quote": second_quote}],
            },
        ],
    })
    .to_string())
}

impl LlmBackend for StepReplyBackend {
    /// Admits every capability the fixture's fixed model asks about.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Answers the step with the three-candidate reply and declares its terminal usage.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let transcript = final_user_text(&request);
            let reply = step_reply_for(&transcript).map_err(|message| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message,
                    code: None,
                })
            })?;
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

    /// Refuses streaming because this fixture only generates a buffered step.
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

/// Admits every lent extraction verdict and generation step.
struct AlwaysAdmitGate;

impl ExtractionDecisionGate for AlwaysAdmitGate {
    /// Admits every verdict loan.
    fn admits(&self) -> oneiron::Result<bool> {
        Ok(true)
    }

    /// Admits every generation step loan.
    fn admits_step(&self) -> oneiron::Result<bool> {
        Ok(true)
    }
}

/// Holds one bound attempt with its finished step and the decoded reply it carried.
struct BoundStepRun {
    /// Holds the client bound to the admitted attempt.
    client: OneironClient,
    /// Names the attempt as 32 lowercase hex digits.
    attempt: String,
    /// Holds the clock for observations and assembly.
    now_ms: u64,
    /// Holds the selection policy the inputs page served.
    config: ExtractionSelectionConfig,
    /// Names the policy pin the inputs page served.
    policy_pin: String,
    /// Names the finished step as its receipt's step reference.
    step_ref: String,
    /// Holds the step receipt's decoded reply.
    reply: BoundExtractionReply,
    /// Counts the lent verdict generations by family.
    counts: Arc<support::Counts>,
    /// Holds the backend that answered the bound step.
    step_backend: Arc<StepReplyBackend>,
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _dir: tempfile::TempDir,
    /// Holds the vault the attempt was admitted in.
    _vault: Arc<Vault>,
    /// Holds the verdict fixture the production lender borrows.
    _verdict: Arc<ExtractionVerdictFixture>,
    /// Holds the production lender that lent the step and the verdicts.
    _lender: Arc<ExtractionAttemptLender>,
}

/// Binds one admitted attempt with a step lender and a verdict lender on one binding.
///
/// The production lender routes the extraction role to the three-candidate step backend
/// and the verdict role to the keyed reasoner. The step cites both served turns, which
/// mention owen, in one native slice. The submit runs through the bound client.
fn bound_step() -> support::TestResult<BoundStepRun> {
    let (_dir, vault) = support::open_vault()?;
    support::seed_person(&vault, "owen")?;
    let turns = support::witness_turns(
        &vault,
        &[
            "owen chooses green tea",
            "owen drinks water after green tea",
        ],
    )?;
    let (attempt_id, admitted) = enqueue_admitted_extraction_attempt(&vault, &turns, 1_000)?;
    let binding = vault.bind_dreamer_attempt(&admitted)?;
    let attempt: String = attempt_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let (counts, _recorded, reasoner) = keyed(merge_script());
    let step_backend = Arc::new(StepReplyBackend {
        calls: AtomicUsize::new(0),
    });
    let verdict_fixture = ExtractionVerdictFixture::new(reasoner)?;
    let pass = verdict_fixture.pass_resources();
    let verdict = pass
        .roles
        .get(DREAMER_VERDICT_ROLE)
        .ok_or("the fixture routes its verdict role")?;
    let (_, extraction_model, extraction_binding) = verdict_fixture.extraction_route();
    let step_route: Arc<dyn LlmBackend> = Arc::clone(&step_backend);
    let roles = pass.roles.clone().with(
        DREAMER_EXTRACTION_ROLE,
        RoleBackend {
            backend: step_route,
            model: extraction_model,
            binding: extraction_binding,
            sourced: None,
        },
    );
    let gate = Arc::new(AlwaysAdmitGate);
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
    .with_extraction_decisions(gate, pass.runtime.clone());
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
    let served = support::page_turns(&page)?;
    let evidence: Vec<Value> = served
        .iter()
        .map(|(turn, version)| json!({"turn": turn, "version": version}))
        .collect();
    let submit = client.agent_verb("ai.steps.submit", json!({"evidence": evidence}))?;
    assert_eq!(
        submit["result"]["status"],
        json!("finished"),
        "The bound step finishes on its lent loan."
    );
    let step_ref = submit["step_ref"]
        .as_str()
        .ok_or("the submit answers its step reference")?
        .to_owned();
    let reply: BoundExtractionReply = serde_json::from_value(submit["result"]["json"].clone())?;
    Ok(BoundStepRun {
        client,
        attempt,
        now_ms,
        config,
        policy_pin,
        step_ref,
        reply,
        counts,
        step_backend,
        _dir,
        _vault: vault,
        _verdict: verdict_fixture,
        _lender: lender,
    })
}

/// A decisions run over the step's reply names each operand's recorded candidate.
///
/// The two candidates with the same predicate and value fold into one group of two
/// members. The run reads the group's union through the observations page, so a run
/// that returns Ok proves the engine took a union that names both members.
#[test]
fn a_decisions_run_names_its_recorded_candidates_and_the_engine_takes_them()
-> support::TestResult<()> {
    let fixture = bound_step()?;
    assert_eq!(
        fixture.reply.candidates.len(),
        3,
        "The step keeps three listed candidates."
    );
    let outcome = run(Input {
        client: &fixture.client,
        attempt: &fixture.attempt,
        now_ms: fixture.now_ms,
        reply: &fixture.reply,
        step: Some(&fixture.step_ref),
        config: &fixture.config,
        policy_pin: &fixture.policy_pin,
    })?;
    assert_eq!(
        outcome.operands.len(),
        3,
        "The run keeps one operand per listed candidate."
    );
    assert_eq!(
        outcome.candidate_indexes,
        vec![0, 1, 2],
        "The operands keep reply order."
    );
    for (position, operand) in outcome.operands.iter().enumerate() {
        let expected = json!([{
            "step": fixture.step_ref.clone(),
            "index": outcome.candidate_indexes[position],
        }]);
        assert_eq!(
            operand["from_steps"], expected,
            "The operand names its recorded candidate."
        );
    }
    assert!(
        outcome
            .selection
            .groups
            .iter()
            .any(|group| group.member_indexes == vec![0, 1]),
        "The selection holds one group with two members."
    );
    assert_eq!(
        fixture.step_backend.calls(),
        1,
        "The bound step generates once."
    );
    assert_eq!(
        (fixture.counts.correction(), fixture.counts.resolution()),
        (0, 0),
        "No verdict read is needed without priors or conflicts."
    );
    Ok(())
}

/// A reply the step did not produce is refused against the step's own record.
///
/// The first candidate's value is changed after the step finished. The decisions run
/// names the recorded candidate it no longer matches, so the engine refuses the operand
/// before any verdict is asked.
#[test]
fn a_reply_the_step_did_not_produce_is_refused() -> support::TestResult<()> {
    let fixture = bound_step()?;
    assert_eq!(
        fixture.reply.candidates.len(),
        3,
        "The step keeps three listed candidates."
    );
    let mut reply = fixture.reply.clone();
    reply.candidates[0].value = json!("black coffee");
    let error = run(Input {
        client: &fixture.client,
        attempt: &fixture.attempt,
        now_ms: fixture.now_ms,
        reply: &reply,
        step: Some(&fixture.step_ref),
        config: &fixture.config,
        policy_pin: &fixture.policy_pin,
    })
    .expect_err("A reply the step did not produce is refused.");
    match &error {
        extraction_decisions::Error::Observations(extraction_observations::Error::Client {
            message,
            ..
        }) => {
            assert!(
                message.contains("differs from the recorded candidates it names"),
                "The refusal names the recorded candidates it differs from: {message}."
            );
        }
        other => panic!("The refusal carries the engine's observations message: {other:?}."),
    }
    Ok(())
}
