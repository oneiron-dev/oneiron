#![cfg(oneiron_test_support)]
//! DECIDE-BYPASS-1: the claim re-check judges each live claim drawn from a
//! mail message deleted at the provider and kept as the registered question
//! `dreamer.claim_source.support` on the host's decision ladder. The judge's
//! generated read is the ladder's one rung, Big to Big; the typed decision
//! lands in the claim's finding under `recheck.judge.decision`, and its
//! answer is the verdict.
//!
//! Red on origin/main: the runner's judge request asks no question (it reads
//! a bare verdict outside decide()), so the first assertion, that the request
//! asks the registered question, fails. (The backend answers such a request
//! `{}`, which main's required-verdict schema also rejects.) On the head the
//! read asks the registered question and persists its typed answer.
//! The head door re-exports the registered question family; the main-variant
//! door supplies the same descriptor so this file compiles on both trees.

use std::future::Future;
use std::sync::{Arc, Mutex};

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::llm::decision::HeldLadder;
use oneiron::model_decision::{AnswerContract, DecisionAnswer, DecisionBandPolicy};
use oneiron::test_doors::claim_source_recheck as doors;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, ContentPart, DreamerAttemptExecution,
    FatalLlmError, FinishReason, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture,
    LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse,
    LlmStreamResult, LlmUsage, ModelId, UnsupportedCapability, Vault, VaultConfig,
    WakeAttemptContext, WakePassDeadline,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The host's rubric and the support question's wording under test: prompt
/// data beside the host, never engine prose.
const RUBRIC: &str = "the test rubric the judge reads the claim against its supports by";
const WORDING: &str = "Do the claim's supports, as they stand now, still carry the claim?";

/// The judge's backend: it records every request, and answers each asked
/// question `weakened` at 0.9. A request that asks no question gets `{}`.
struct WeighingBackend {
    requests: Mutex<Vec<LlmRequest>>,
}

impl WeighingBackend {
    fn new() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<LlmRequest> {
        self.requests.lock().expect("requests mutex").clone()
    }
}

/// The ids the request's last user turn asks about, in order; none when the
/// turn carries no `questions` array.
fn asked_ids(request: &LlmRequest) -> Vec<String> {
    let Some(turn) = request
        .messages
        .iter()
        .rev()
        .find(|message| message.role == LlmMessageRole::User)
    else {
        return Vec::new();
    };
    let text: String = turn
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let Ok(turn) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    turn.get("questions")
        .and_then(serde_json::Value::as_array)
        .map(|questions| {
            questions
                .iter()
                .filter_map(|entry| entry.get("id")?.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The backend's reply: `weakened` at 0.9 under each asked id, or `{}` when
/// the request asks no question. Usage is nonzero either way.
fn weighed(ids: &[String]) -> LlmResponse {
    let mut reply = serde_json::Map::new();
    for id in ids {
        reply.insert(
            id.clone(),
            serde_json::json!({
                "supported": 0.05,
                "weakened": 0.9,
                "unsupported": 0.05,
            }),
        );
    }
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: serde_json::Value::Object(reply).to_string(),
                signature: None,
            }],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 10,
                cache_read: 0,
                cache_write: 0,
            },
            output: LlmOutputUsage {
                total: 5,
                text: 5,
                reasoning: 0,
            },
            raw_provider: serde_json::Value::Null,
            call_metadata: None,
        },
        finish_reason: FinishReason::Stop,
        reply_assertions: Default::default(),
        token_scores: None,
    }
}

impl LlmBackend for WeighingBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let reply = weighed(&asked_ids(&request));
        self.requests.lock().expect("requests mutex").push(request);
        Box::pin(async move { Ok(reply) })
    }

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

/// Drives the door's async run on a current-thread runtime. This crate's
/// tokio carries no `macros` feature, so `#[tokio::test]` is unavailable.
fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

/// DECIDE-BYPASS-1: the re-check's verdict is the registered support
/// question decided on the ladder: one generated read asks it, the finding's
/// verdict is `weakened`, and the finding carries the typed decision behind
/// it.
#[test]
fn claim_recheck_verdict_is_decided_on_the_ladder() -> TestResult {
    let directory = tempfile::tempdir()?;
    // The seed installs the mail pack and syncs the source as the embedded
    // owner, whose proof needs the vault's writer lease: open it owned.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let _owner = vault.ensure_embedded_owner_actor()?;
    // The host's start, as a self-hosted server's: the process keystore,
    // the vault rooted under the host, this install profiled, and the
    // engine's MACHINE writers (the Dreamer among them) enrolled with
    // host-held keys, so the re-check's finding lands signed.
    let issuer = HostSlipIssuer::from_secret(b"claim source recheck test host")?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    vault.provision_engine_machine_identities(&issuer)?;
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    let seeded = doors::seed(&vault, now_ms)?;
    let backend = WeighingBackend::new();
    let guard = BudgetGuard::with_reserve_units(
        "claim-source-recheck-decide",
        100_000,
        500,
        BudgetExhaustionPolicy::Suspend,
    );
    let model = ModelId::new("test/judge@r1")?;
    let deadline = WakePassDeadline::new(60_000);
    let ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "test",
        now_ms,
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    // The judge's generated read is the ladder's one rung; no slot is
    // consulted and no person is asked.
    let held = HeldLadder::unstaffed();
    let execution = block_on(doors::run(
        &ctx,
        &seeded.attempt,
        &backend,
        &guard,
        &model,
        RUBRIC,
        held.ladder(),
        DecisionBandPolicy::default(),
        WORDING,
    ))?;

    // The decide path first: the judge's first request asks the registered
    // question, keyed by the rubric's digest, with the same wording and
    // choice options, and the verdict is that one generated read.
    let requests = backend.requests();
    let digest = blake3::hash(RUBRIC.as_bytes());
    let expected = doors::CLAIM_SOURCE_SUPPORT.question(
        &[digest.as_bytes().as_slice()],
        WORDING.to_owned(),
        AnswerContract::Choice {
            options: ["supported", "weakened", "unsupported"]
                .map(str::to_owned)
                .to_vec(),
        },
    )?;
    // wire::question_key(id, None) is the canonical hexadecimal id.
    assert_eq!(
        requests.first().map(asked_ids).unwrap_or_default(),
        vec![expected.id.to_hex()],
        "the read asks the registered support question"
    );
    assert_eq!(requests.len(), 1, "the verdict is one generated read");

    let DreamerAttemptExecution::Completed {
        completed_units,
        step_bindings,
    } = &execution
    else {
        panic!("the re-check completes, got {execution:?}");
    };
    assert_eq!(
        step_bindings.len(),
        1,
        "one judge generation books one step binding"
    );
    assert!(
        *completed_units > 0,
        "the judge generation spends nonzero units"
    );

    // A completed re-check persists its verdict and the typed answer behind it.
    let finding = doors::finding(&vault, seeded.claim)?;
    let recheck = finding
        .get("recheck")
        .expect("the finding carries the recheck object");
    assert_eq!(
        recheck.get("verdict").and_then(serde_json::Value::as_str),
        Some("weakened"),
        "the verdict is decided on the ladder"
    );
    let decision = recheck
        .pointer("/judge/decision")
        .expect("the finding carries the typed decision");
    assert!(decision.is_object(), "the typed decision is an object");
    let answer: DecisionAnswer = serde_json::from_value(
        decision
            .get("answer")
            .cloned()
            .expect("the decision carries its answer"),
    )?;
    assert_eq!(
        answer,
        DecisionAnswer::Choice("weakened".to_owned()),
        "the typed answer is weakened"
    );

    Ok(())
}
