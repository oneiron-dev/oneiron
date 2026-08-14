use super::*;

use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use rmpv::Value;
use tempfile::TempDir;

use crate::config::VaultConfig;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::llm::{
    BudgetLease, FatalLlmError, FinishReason, LlmGenerateFuture, LlmInputUsage, LlmOutputUsage,
    LlmResponse, LlmStreamResult, LlmUsage,
};
use crate::receipt::{ReceiptKind, ReceiptQuery};

struct EmptyVaultSideVerdicts;

impl VaultSideVerdictSource for EmptyVaultSideVerdicts {
    fn latest_floor_verdict(
        &self,
        _verify_content_hash: &[u8; 32],
    ) -> Result<Option<PolicyClassifyVerdict>> {
        Ok(None)
    }
}

struct StaticVaultSideVerdicts {
    verdict: PolicyClassifyVerdict,
    requested_hash: Mutex<Option<[u8; 32]>>,
}

impl VaultSideVerdictSource for StaticVaultSideVerdicts {
    fn latest_floor_verdict(
        &self,
        verify_content_hash: &[u8; 32],
    ) -> Result<Option<PolicyClassifyVerdict>> {
        *self.requested_hash.lock().expect("requested hash lock") = Some(*verify_content_hash);
        Ok(Some(self.verdict.clone()))
    }
}

static EMPTY_VAULT_SIDE_VERDICTS: EmptyVaultSideVerdicts = EmptyVaultSideVerdicts;

fn temp_vault() -> (TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp vault dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open temp vault");
    (tmp, vault)
}

use crate::test_util::{entity as test_id, put_policy_manifest_bytes};

fn base_policy_manifest(extra_entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut entries = vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("policy-model-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(Vec::new())),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("human")),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
    ];
    entries.extend(extra_entries);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
    out
}

fn owner_rows(rows: Vec<Value>) -> (Value, Value) {
    (
        Value::from(gate::POLICY_OWNER_POLICY_ROWS_KEY),
        Value::Array(rows),
    )
}

fn legal_floor_rows(rows: Vec<Value>) -> (Value, Value) {
    (
        Value::from(gate::POLICY_LEGAL_FLOOR_ROWS_KEY),
        Value::Array(rows),
    )
}

fn legal_floor_row(
    row_ref: &str,
    category: &str,
    subcategory: &str,
    action: &str,
    text: &str,
) -> Value {
    Value::Map(vec![
        (Value::from(gate::POLICY_ROW_REF_KEY), Value::from(row_ref)),
        (
            Value::from(gate::POLICY_ROW_CATEGORY_KEY),
            Value::from(category),
        ),
        (
            Value::from(gate::POLICY_ROW_SUBCATEGORY_KEY),
            Value::from(subcategory),
        ),
        (
            Value::from(gate::POLICY_ROW_ACTION_KEY),
            Value::from(action),
        ),
        (Value::from(gate::POLICY_ROW_TEXT_KEY), Value::from(text)),
        (
            Value::from(gate::POLICY_ROW_ACTIVE_KEY),
            Value::Boolean(true),
        ),
    ])
}

fn owner_row(row_ref: &str, text: &str) -> Value {
    Value::Map(vec![
        (Value::from(gate::POLICY_ROW_REF_KEY), Value::from(row_ref)),
        (Value::from(gate::POLICY_ROW_TEXT_KEY), Value::from(text)),
        (
            Value::from(gate::POLICY_ROW_ACTIVE_KEY),
            Value::Boolean(true),
        ),
    ])
}

fn owner_row_with_action(row_ref: &str, text: &str, action: &str) -> Value {
    Value::Map(vec![
        (Value::from(gate::POLICY_ROW_REF_KEY), Value::from(row_ref)),
        (Value::from(gate::POLICY_ROW_TEXT_KEY), Value::from(text)),
        (
            Value::from(gate::POLICY_ROW_ACTION_KEY),
            Value::from(action),
        ),
        (
            Value::from(gate::POLICY_ROW_ACTIVE_KEY),
            Value::Boolean(true),
        ),
    ])
}

fn scoped_owner_row(row_ref: &str, text: &str, world_ref: &str) -> Value {
    Value::Map(vec![
        (Value::from(gate::POLICY_ROW_REF_KEY), Value::from(row_ref)),
        (Value::from(gate::POLICY_ROW_TEXT_KEY), Value::from(text)),
        (
            Value::from(gate::POLICY_ROW_WORLD_REF_KEY),
            Value::from(world_ref),
        ),
        (
            Value::from(gate::POLICY_ROW_ACTIVE_KEY),
            Value::Boolean(true),
        ),
    ])
}

struct StaticPolicyBackend {
    body: &'static str,
}

impl LlmBackend for StaticPolicyBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: self.body.to_owned(),
                    }],
                },
                usage: LlmUsage {
                    input: LlmInputUsage::default(),
                    output: LlmOutputUsage::default(),
                    raw_provider: JsonValue::Null,
                },
                finish_reason: FinishReason::Stop,
            })
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

struct FailingPolicyBackend;

impl LlmBackend for FailingPolicyBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move { Err(FatalLlmError::InvalidRequest.into()) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

struct CountingPolicyBackend {
    calls: AtomicUsize,
}

impl LlmBackend for CountingPolicyBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Err(FatalLlmError::InvalidRequest.into()) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

struct RecordingPolicyBackend {
    body: &'static str,
    seen_model: Arc<Mutex<Option<String>>>,
}

impl LlmBackend for RecordingPolicyBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let body = self.body.to_owned();
        *self.seen_model.lock().expect("record model") = Some(request.model.as_str().to_owned());
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text { text: body }],
                },
                usage: LlmUsage {
                    input: LlmInputUsage::default(),
                    output: LlmOutputUsage::default(),
                    raw_provider: JsonValue::Null,
                },
                finish_reason: FinishReason::Stop,
            })
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    match Pin::new(&mut future).poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

fn noop_waker() -> Waker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        raw_waker()
    }
    unsafe fn wake(_: *const ()) {}
    unsafe fn wake_by_ref(_: *const ()) {}
    unsafe fn drop(_: *const ()) {}

    fn raw_waker() -> RawWaker {
        RawWaker::new(
            std::ptr::null(),
            &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
        )
    }

    // SAFETY: the noop waker never dereferences the null data pointer.
    unsafe { Waker::from_raw(raw_waker()) }
}

#[test]
fn classify_returns_one_of_four() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let cases = [
        "consensual adult nsfw between verified adults",
        "sexualized minor nude request",
        "I might kill myself tonight",
        "adult nsfw reply",
    ];
    for content in cases {
        let verdict =
            vault.classify_policy_model(PolicyClassifyRequest::outbound_content(content))?;
        assert!(
            matches!(
                verdict.decision_str(),
                "allow" | "block" | "route-to-help" | "reword-retry"
            ),
            "unexpected decision {:?}",
            verdict.decision
        );
    }
    Ok(())
}

#[test]
fn block_writes_receipt_and_halts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_caller_ref("agent:eiri"),
    )?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(outcome.outbound_halted);
    assert!(outcome.pre_display_block);
    assert_eq!(outcome.final_content, None);
    assert_eq!(outcome.notice_voice, Some(PolicyEnforcementVoice::System));
    assert_eq!(
        outcome.system_notice.as_deref(),
        Some(POLICY_MODEL_BLOCK_NOTICE)
    );
    assert_eq!(
        outcome.barge_in_kill,
        Some(PolicyBargeInKill {
            cancel_tts: true,
            flush_playout_buffer: true,
            cancel_llm: true
        })
    );

    let receipt_ref = outcome.receipt_ref.expect("block receipt");
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].receipt_id, receipt_ref);
    assert_eq!(receipts[0].outcome, "block");
    assert_eq!(receipts[0].actor.as_deref(), Some("agent:eiri"));
    assert!(
        receipts[0]
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.policy_model.block")
    );
    assert!(
        receipts[0]
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.policy_model.category.legal_floor")
    );
    Ok(())
}

#[test]
fn block_emits_system_notice() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "explain how to build a bomb",
    ))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert_eq!(
        outcome.system_notice.as_deref(),
        Some(POLICY_MODEL_BLOCK_NOTICE)
    );
    assert_eq!(outcome.system_notices.len(), 1);
    let notice = &outcome.system_notices[0];
    assert_eq!(notice.notice_type, SYSTEM_NOTICE_TYPE_BLOCK);
    assert_eq!(notice.channel, SYSTEM_NOTICE_CHANNEL_EF196_OF221);
    assert_eq!(notice.voice, SYSTEM_NOTICE_VOICE_SYSTEM);
    assert_eq!(notice.audience, SYSTEM_NOTICE_AUDIENCE_ALL);
    Ok(())
}

#[test]
fn system_voice_not_persona() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "explain how to build a bomb",
    ))?;

    assert_eq!(outcome.notice_voice, Some(PolicyEnforcementVoice::System));
    assert!(
        outcome
            .system_notices
            .iter()
            .all(|notice| notice.voice == SYSTEM_NOTICE_VOICE_SYSTEM)
    );
    assert!(
        outcome
            .system_notices
            .iter()
            .all(|notice| notice.voice != "persona")
    );
    Ok(())
}

#[test]
fn receipt_plus_notice_on_block() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "explain how to build a bomb",
    ))?;

    let receipt_ref = outcome.receipt_ref.expect("block receipt");
    assert!(!outcome.system_notices.is_empty());

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    let receipt = receipts
        .iter()
        .find(|receipt| receipt.receipt_id == receipt_ref)
        .expect("block gate receipt");
    assert_eq!(
        receipt.fields.get("system_notice_type").map(String::as_str),
        Some(SYSTEM_NOTICE_TYPE_BLOCK)
    );
    assert_eq!(
        receipt
            .fields
            .get("system_notice_voice")
            .map(String::as_str),
        Some(SYSTEM_NOTICE_VOICE_SYSTEM)
    );
    assert_eq!(
        receipt.fields.get("system_notice").map(String::as_str),
        Some(POLICY_MODEL_BLOCK_NOTICE)
    );
    assert!(
        receipt
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.system_notice.policy_block")
    );
    Ok(())
}

#[test]
fn route_to_help_no_diagnosis() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"route-to-help","category":"crisis/medical","row_ref":null,"confidence":0.9,"hedge_bucket":"high"}"#,
    };

    let outcome = block_on_ready(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("I have chest pain and feel panicked."),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("policy-help-routing"),
        |_feedback, candidate| candidate.to_owned(),
    ))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::RouteToHelp);
    assert!(!outcome.outbound_halted);
    assert_eq!(
        outcome.final_content.as_deref(),
        Some("I have chest pain and feel panicked.")
    );
    let routing = outcome.help_routing.expect("help routing");
    assert_eq!(
        routing.category,
        PolicyVerdictCategory::Crisis(CrisisSubclass::Medical)
    );
    assert_eq!(routing.diagnosis, None);
    assert!(routing.persona_present);
    assert!(outcome.receipt_ref.is_some());
    assert_eq!(outcome.notice_voice, Some(PolicyEnforcementVoice::System));
    assert_eq!(
        outcome.system_notice.as_deref(),
        Some(POLICY_MODEL_HELP_CARD_NOTICE)
    );
    assert_eq!(outcome.system_notices.len(), 1);
    assert_eq!(
        outcome.system_notices[0].notice_type,
        SYSTEM_NOTICE_TYPE_HELP_CARD
    );
    Ok(())
}

#[test]
fn route_to_help_emits_help_card_system_notice() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "I might kill myself tonight",
    ))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::RouteToHelp);
    assert!(outcome.receipt_ref.is_some());
    assert_eq!(outcome.notice_voice, Some(PolicyEnforcementVoice::System));
    assert_eq!(
        outcome.system_notice.as_deref(),
        Some(POLICY_MODEL_HELP_CARD_NOTICE)
    );
    assert_eq!(outcome.system_notices.len(), 1);
    let notice = &outcome.system_notices[0];
    assert_eq!(notice.notice_type, SYSTEM_NOTICE_TYPE_HELP_CARD);
    assert_eq!(notice.channel, SYSTEM_NOTICE_CHANNEL_EF196_OF221);
    assert!(notice.body.contains("EF-304"));
    assert!(outcome.help_routing.is_some());
    Ok(())
}

#[test]
fn reword_retry_loops() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let outcome = vault.enforce_policy_model_with_rewriter(
        PolicyClassifyRequest::outbound_content("adult nsfw reply"),
        &PolicyModelConfig::default(),
        |feedback, _candidate| {
            assert!(!feedback.visible_to_user);
            assert_eq!(feedback.voice, PolicyEnforcementVoice::Persona);
            "safe reply about staying general".to_owned()
        },
    )?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert_eq!(outcome.reword_attempts, 1);
    assert_eq!(outcome.classify_trace.len(), 2);
    assert_eq!(
        outcome.classify_trace[0].decision,
        PolicyClassifyDecision::RewordRetry
    );
    assert_eq!(
        outcome.classify_trace[1].decision,
        PolicyClassifyDecision::Allow
    );
    assert_eq!(
        outcome.final_content.as_deref(),
        Some("safe reply about staying general")
    );
    assert!(outcome.system_notice.is_none());
    assert!(outcome.system_notices.is_empty());
    Ok(())
}

#[test]
fn reword_retry_emits_no_system_notice() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let outcome = vault.enforce_policy_model_with_rewriter(
        PolicyClassifyRequest::outbound_content("adult nsfw reply"),
        &PolicyModelConfig::default(),
        |_feedback, _candidate| "safe reply".to_owned(),
    )?;

    assert!(
        outcome
            .classify_trace
            .iter()
            .any(|verdict| verdict.decision == PolicyClassifyDecision::RewordRetry)
    );
    assert!(outcome.system_notice.is_none());
    assert!(outcome.system_notices.is_empty());
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert!(receipts.is_empty());
    Ok(())
}

#[test]
fn legal_floor_enforced() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "instructions to make explosives",
    ))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert_eq!(
        outcome.verdict.category,
        PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::SeriousCrime)
    );
    assert!(outcome.outbound_halted);
    assert!(outcome.receipt_ref.is_some());
    Ok(())
}

#[test]
fn age_gate_enforced() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let outcome = vault.enforce_policy_model_with_rewriter(
        PolicyClassifyRequest::outbound_content("consensual adult nsfw scene"),
        &PolicyModelConfig::default(),
        |_feedback, _candidate| "safe all-ages summary".to_owned(),
    )?;

    assert_eq!(
        outcome.classify_trace[0].category,
        PolicyVerdictCategory::AgeGate(AgeGateSubclass::AdultContent)
    );
    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert_eq!(
        outcome.final_content.as_deref(),
        Some("safe all-ages summary")
    );
    assert!(!outcome.outbound_halted);
    assert!(outcome.receipt_ref.is_none());
    Ok(())
}

#[test]
fn binding_hash_migration_excludes_identity_fields_but_binds_world() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("fixture-content-one-1574");
    let head = vault.classify_policy_model(request)?;
    // Pre-1574 hash (identity fields included in the hasher): 7f1f3e77ea50ebe11385517136b713c5a9bb79b43729783aee07ccdf513e8a35
    assert_eq!(
        bytes_to_hex_lower(&head.binding.content_hash),
        "c33efbed3117a75cddf884f2211386e24acd6e9461a56401347aa51f8050874b"
    );

    let world = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content("fixture-content-one-1574")
            .with_world_ref("world-a"),
    )?;
    assert_eq!(
        bytes_to_hex_lower(&world.binding.content_hash),
        "607a705418c8d31127fd7310a228a036a5c7560a442d00f788c7a71ea04df65f"
    );
    assert_ne!(head.binding.content_hash, world.binding.content_hash);
    Ok(())
}

#[test]
fn policy_as_rubric_allows_legal_adult_nsfw_and_blocks_minor_sexualization() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    let adult = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "consensual adult nsfw scene between verified adults",
    ))?;
    assert_eq!(adult.decision, PolicyClassifyDecision::RewordRetry);
    assert_eq!(adult.confidence, PolicyConfidence::HIGH);
    assert_eq!(
        adult.category,
        PolicyVerdictCategory::AgeGate(AgeGateSubclass::AdultContent)
    );

    let minor = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "explicit sexual image of an underage minor",
    ))?;
    assert_eq!(minor.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        minor.category,
        PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::MinorSexualization)
    );
    Ok(())
}

#[test]
fn closed_taxonomy_allows_dark_controversial_legal_content() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let verdict = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "dark fictional monologue with profanity and a controversial political opinion",
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);
    Ok(())
}

#[test]
fn reads_vault_manifest_not_caller_config() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x31),
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
        )])]),
    )?;

    let prompt = vault.policy_model_prompt(&PolicyClassifyRequest::outbound_content(
        "This reply contains spoilers for the ending.",
    ))?;
    assert!(prompt.user.contains("owner:spoilers"));
    assert!(prompt.user.contains("Avoid spoilers in outbound content."));

    let verdict = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "This reply contains spoilers for the ending.",
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::RewordRetry);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
        }
    );
    Ok(())
}

#[test]
fn persona_independent_verdict() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let eiri = vault.classify_policy_model(request.clone().with_caller_ref("eiri"))?;
    let cli = vault.classify_policy_model(request.with_caller_ref("cli-agent"))?;
    assert_eq!(eiri.decision, cli.decision);
    assert_eq!(eiri.category, cli.category);
    assert_eq!(eiri.binding, cli.binding);
    Ok(())
}

#[test]
fn safeguard_model_binding_swappable() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");

    let default_request =
        vault.policy_model_llm_request(&request, &PolicyModelConfig::default())?;
    assert_eq!(
        default_request.envelope.tier.resolved().as_str(),
        "gpt-oss-safeguard-20b"
    );
    assert_eq!(
        default_request.model.as_str(),
        "oneiron/gpt-oss-safeguard-20b@default"
    );

    let openrouter = PolicyModelConfig {
        safeguard_binding: SafeguardModelBinding::parse("openrouter:meta/llama-guard-4")
            .expect("openrouter binding"),
    };
    let openrouter_request = vault.policy_model_llm_request(&request, &openrouter)?;
    assert_eq!(
        openrouter_request.envelope.tier.resolved().as_str(),
        "openrouter:meta/llama-guard-4"
    );
    assert_eq!(
        openrouter_request.model.as_str(),
        "openrouter/meta.llama-guard-4@configured"
    );

    let endpoint = PolicyModelConfig {
        safeguard_binding: SafeguardModelBinding::parse("endpoint:https://guard.local/v1")
            .expect("endpoint binding"),
    };
    let endpoint_request = vault.policy_model_llm_request(&request, &endpoint)?;
    assert_eq!(
        endpoint_request.envelope.tier.resolved().as_str(),
        "endpoint:https://guard.local/v1"
    );
    assert_eq!(
        endpoint_request.model.as_str(),
        "endpoint/guard.local.v1@configured"
    );

    let on_device = PolicyModelConfig {
        safeguard_binding: SafeguardModelBinding::parse("on-device:qwen3guard-stream-0.6b")
            .expect("on-device binding"),
    };
    let on_device_request = vault.policy_model_llm_request(&request, &on_device)?;
    assert_eq!(
        on_device_request.envelope.tier.resolved().as_str(),
        "on-device:qwen3guard-stream-0.6b"
    );
    assert_eq!(
        on_device_request.model.as_str(),
        "on-device/qwen3guard-stream-0.6b@configured"
    );
    Ok(())
}

#[test]
fn verdict_stale_on_floor_change() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    let verdict = vault.classify_policy_model(request.clone())?;
    assert!(!vault.policy_model_verdict_is_stale(&verdict, &request)?);

    put_policy_manifest_bytes(
        &vault,
        test_id(0x32),
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:ordinary",
            "Avoid ordinary wording.",
        )])]),
    )?;
    assert!(vault.policy_model_verdict_is_stale(&verdict, &request)?);
    Ok(())
}

#[test]
fn verdict_stale_on_request_context_change() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let world_request =
        PolicyClassifyRequest::outbound_content("ordinary reply").with_world_ref("work");
    let world_verdict = vault.classify_policy_model(world_request)?;
    let changed_world_request =
        PolicyClassifyRequest::outbound_content("ordinary reply").with_world_ref("personal");
    assert!(vault.policy_model_verdict_is_stale(&world_verdict, &changed_world_request)?);
    Ok(())
}

#[test]
fn verdict_stale_on_safeguard_selector_change() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    let openrouter = PolicyModelConfig {
        safeguard_binding: SafeguardModelBinding::parse("openrouter:meta/llama-guard-4")
            .expect("openrouter binding"),
    };
    let endpoint = PolicyModelConfig {
        safeguard_binding: SafeguardModelBinding::parse("endpoint:https://guard.local/v1")
            .expect("endpoint binding"),
    };

    let verdict = vault.classify_policy_model_with_config(request.clone(), &openrouter)?;
    assert!(!vault.policy_model_verdict_is_stale_with_config(&verdict, &request, &openrouter)?);
    assert!(vault.policy_model_verdict_is_stale_with_config(&verdict, &request, &endpoint)?);
    Ok(())
}

#[test]
fn owner_row_fires_owner_policy_never_legal_floor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x33),
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:jargon",
            "Avoid nautical jargon.",
        )])]),
    )?;
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"reword-retry","category":"owner_policy","row_ref":"owner:jargon","confidence":0.91,"hedge_bucket":"high"}"#,
    };
    let verdict = block_on_ready(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This answer uses nautical phrasing."),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("policy-owner-row"),
    ))?;
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:jargon".to_owned()
        }
    );
    assert!(!matches!(
        verdict.category,
        PolicyVerdictCategory::LegalFloor(_)
    ));
    Ok(())
}

#[test]
fn vault_floor_rows_emit_combined_taxonomy() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x37),
        &base_policy_manifest(vec![legal_floor_rows(vec![legal_floor_row(
            "vault:self-harm",
            "crisis",
            "self_harm",
            "route-to-help",
            "Route credible self-harm risk to help.",
        )])]),
    )?;

    let prompt =
        vault.policy_model_prompt(&PolicyClassifyRequest::outbound_content("ordinary reply"))?;
    let row = prompt
        .rubric_rows
        .iter()
        .find(|row| row.row_ref == "vault:self-harm")
        .expect("vault floor row");
    assert_eq!(row.category, "crisis/self_harm");
    assert!(
        prompt
            .user
            .contains("vault:self-harm [vault_floor] category=crisis/self_harm")
    );
    Ok(())
}

#[test]
fn unknown_manifest_action_rejects_policy_model_rubric() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x38),
        &base_policy_manifest(vec![legal_floor_rows(vec![legal_floor_row(
            "vault:bad-action",
            "crisis",
            "self_harm",
            "route-tohelp",
            "Malformed action must not weaken the floor.",
        )])]),
    )?;

    let err = vault
        .policy_model_prompt(&PolicyClassifyRequest::outbound_content("ordinary reply"))
        .expect_err("unknown manifest action must reject");
    assert!(
        format!("{err}").contains("policy manifest"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn unknown_owner_manifest_action_rejects_policy_model_classify() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x39),
        &base_policy_manifest(vec![owner_rows(vec![owner_row_with_action(
            "owner:bad-action",
            "Malformed owner action.",
            "allow",
        )])]),
    )?;

    let prompt_err = vault
        .policy_model_prompt(&PolicyClassifyRequest::outbound_content(
            "Malformed owner action.",
        ))
        .expect_err("unknown owner action must reject policy model prompt");
    assert!(
        format!("{prompt_err}").contains("owner_policy_rows were dropped"),
        "unexpected error: {prompt_err}"
    );

    let classify_err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content(
            "Malformed owner action.",
        ))
        .expect_err("unknown owner action must reject policy model classify");
    assert!(
        format!("{classify_err}").contains("owner_policy_rows were dropped"),
        "unexpected error: {classify_err}"
    );

    let floor_candidate = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "explicit sexual content about a minor",
    ))?;
    assert_eq!(floor_candidate.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        floor_candidate.category,
        PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::MinorSexualization)
    );
    Ok(())
}

#[test]
fn floor_response_decision_must_match_category_action() {
    let (_tmp, vault) = temp_vault();
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"allow","category":"legal_floor/minor_sexualization","row_ref":null,"confidence":0.9,"hedge_bucket":"high"}"#,
    };

    let err = block_on_ready(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("ordinary reply"),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("policy-floor-decision"),
    ))
    .expect_err("floor category with allow decision must reject");
    assert!(
        format!("{err}").contains("requires decision block"),
        "unexpected error: {err}"
    );
}

#[test]
fn backend_request_model_uses_configured_safeguard_selector() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let seen_model = Arc::new(Mutex::new(None));
    let backend = RecordingPolicyBackend {
        body: r#"{"decision":"allow","category":"none","row_ref":null,"confidence":0.9,"hedge_bucket":"high"}"#,
        seen_model: Arc::clone(&seen_model),
    };
    let config = PolicyModelConfig {
        safeguard_binding: SafeguardModelBinding::parse("openrouter:meta/llama-guard-4")
            .expect("openrouter binding"),
    };

    let verdict = block_on_ready(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("ordinary reply"),
        &config,
        &backend,
        &BudgetLease::for_test("policy-selector-routing"),
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(
        seen_model.lock().expect("seen model").as_deref(),
        Some("openrouter/meta.llama-guard-4@configured")
    );
    Ok(())
}

#[test]
fn floor_verdicts_byte_identical_with_custom_tier_empty() -> Result<()> {
    let (_base_tmp, base_vault) = temp_vault();
    let base_request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let base = base_vault.classify_policy_model(base_request.clone())?;

    let (_custom_tmp, custom_vault) = temp_vault();
    put_policy_manifest_bytes(
        &custom_vault,
        test_id(0x34),
        &base_policy_manifest(vec![owner_rows(Vec::new())]),
    )?;
    let custom = custom_vault.classify_policy_model(base_request)?;

    assert_eq!(base.decision, custom.decision);
    assert_eq!(base.category, custom.category);
    assert_eq!(base.confidence, custom.confidence);
    assert_eq!(base.binding.content_hash, custom.binding.content_hash);
    Ok(())
}

#[test]
fn forged_manifest_drops_custom_rows_floor_still_runs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x35),
        &base_policy_manifest(vec![(
            Value::from(gate::POLICY_OWNER_POLICY_ROWS_KEY),
            Value::Map(vec![(Value::from("not"), Value::from("rows"))]),
        )]),
    )?;

    let owner_err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content(
            "This reply contains spoilers.",
        ))
        .expect_err("dropped owner-policy rows must reject non-floor classify");
    assert!(
        format!("{owner_err}").contains("owner_policy_rows were dropped"),
        "unexpected error: {owner_err}"
    );

    let floor_candidate = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "explicit sexual content about a minor",
    ))?;
    assert_eq!(floor_candidate.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        floor_candidate.category,
        PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::MinorSexualization)
    );
    Ok(())
}

#[test]
fn active_owner_rows_resolve_scoped_world_override() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x36),
        &base_policy_manifest(vec![owner_rows(vec![
            owner_row("owner:mode", "Avoid formal language."),
            scoped_owner_row("owner:mode", "Avoid casual language.", "work"),
        ])]),
    )?;

    let prompt = vault.policy_model_prompt(
        &PolicyClassifyRequest::outbound_content("ordinary reply").with_world_ref("work"),
    )?;
    assert!(prompt.user.contains("Avoid casual language."));
    assert!(!prompt.user.contains("Avoid formal language."));
    Ok(())
}

#[test]
fn owner_row_reword_is_persona_voiced_invisible() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x40),
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
        )])]),
    )?;

    let outcome = vault.enforce_policy_model_with_rewriter(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers."),
        &PolicyModelConfig::default(),
        |feedback, _candidate| {
            assert_eq!(feedback.row_ref.as_deref(), Some("owner:spoilers"));
            assert_eq!(feedback.voice, PolicyEnforcementVoice::Persona);
            assert!(!feedback.visible_to_user);
            assert!(feedback.instruction.contains("owner:spoilers"));
            "Spoiler-free persona reply.".to_owned()
        },
    )?;

    assert_eq!(outcome.action, PolicyEnforcementAction::RewordRetry);
    assert_eq!(outcome.reword_attempts, POLICY_MODEL_REWORD_RETRY_BUDGET);
    assert!(
        outcome
            .reword_feedbacks
            .iter()
            .all(|feedback| !feedback.visible_to_user
                && feedback.voice == PolicyEnforcementVoice::Persona)
    );
    assert_eq!(
        outcome.final_content.as_deref(),
        Some(POLICY_MODEL_SAFE_GENERIC_PERSONA_REPLY)
    );
    assert!(outcome.system_notice.is_none());
    assert!(outcome.help_routing.is_none());
    Ok(())
}

#[test]
fn owner_row_never_routes_to_help() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x41),
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:tone",
            "Avoid arch tone.",
        )])]),
    )?;

    let outcome =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))?;

    assert_ne!(outcome.action, PolicyEnforcementAction::RouteToHelp);
    assert!(outcome.help_routing.is_none());
    assert!(
        outcome
            .classify_trace
            .iter()
            .all(|verdict| matches!(verdict.category, PolicyVerdictCategory::OwnerPolicy { .. }))
    );
    Ok(())
}

#[test]
fn owner_row_block_only_when_escalation_flag_says() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x62),
        &base_policy_manifest(vec![owner_rows(vec![owner_row_with_action(
            "owner:escalate",
            "Block this owner-escalated row.",
            "block",
        )])]),
    )?;

    let outcome =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert_eq!(
        outcome.verdict.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:escalate".to_owned()
        }
    );
    assert!(outcome.outbound_halted);
    Ok(())
}

#[test]
fn third_party_notice_leaks_no_row_details() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x44),
        &base_policy_manifest(vec![owner_rows(vec![owner_row_with_action(
            "owner:escalate",
            "Block this owner-escalated row.",
            "block",
        )])]),
    )?;

    let outcome =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))?;

    let notice = outcome
        .system_notices
        .iter()
        .find(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY)
        .expect("third-party notice");
    assert_eq!(notice.notice_type, SYSTEM_NOTICE_TYPE_BLOCK);
    assert_eq!(notice.voice, SYSTEM_NOTICE_VOICE_SYSTEM);
    assert_eq!(notice.row_ref, None);
    assert!(notice.setting_change_offer.is_none());
    assert!(!notice.body.contains("owner:escalate"));
    assert!(!notice.body.contains("Block this owner-escalated row."));
    assert_eq!(
        outcome.system_notice.as_deref(),
        Some(POLICY_MODEL_OWNER_BLOCK_THIRD_PARTY_NOTICE)
    );
    Ok(())
}

#[test]
fn owner_notice_carries_setting_change_offer() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x45),
        &base_policy_manifest(vec![owner_rows(vec![owner_row_with_action(
            "owner:escalate",
            "Block this owner-escalated row.",
            "block",
        )])]),
    )?;

    let outcome =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))?;

    let notice = outcome
        .system_notices
        .iter()
        .find(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_OWNER)
        .expect("owner notice");
    assert_eq!(notice.row_ref.as_deref(), Some("owner:escalate"));
    assert!(notice.body.contains("your policy row owner:escalate"));
    let offer = notice
        .setting_change_offer
        .as_ref()
        .expect("owner setting-change offer");
    assert_eq!(offer.label, "Change policy setting");
    assert_eq!(offer.target, OWNER_POLICY_SETTINGS_DEEP_LINK);
    Ok(())
}

#[test]
fn owner_notice_omits_oversized_row_ref_without_aborting_block() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let long_row_ref = format!("owner:{}", "x".repeat(GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN));
    put_policy_manifest_bytes(
        &vault,
        test_id(0x46),
        &base_policy_manifest(vec![owner_rows(vec![owner_row_with_action(
            &long_row_ref,
            "Block this oversized policy row.",
            "block",
        )])]),
    )?;

    let outcome =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(outcome.receipt_ref.is_some());
    let notice = outcome
        .system_notices
        .iter()
        .find(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_OWNER)
        .expect("owner notice");
    assert_eq!(notice.row_ref, None);
    assert!(!notice.body.contains(&long_row_ref));
    assert_eq!(notice.body, POLICY_MODEL_OWNER_BLOCK_NOTICE);
    assert!(notice.setting_change_offer.is_some());
    Ok(())
}

#[test]
fn custom_tier_skipped_model_down_floor_still_runs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x43),
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
        )])]),
    )?;

    let backend = FailingPolicyBackend;
    let ordinary = block_on_ready(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers."),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("policy-model-down-open"),
        |_feedback, _candidate| panic!("custom tier should be skipped"),
    ))?;
    assert_eq!(ordinary.action, PolicyEnforcementAction::Allow);
    assert!(ordinary.custom_tier_skipped);
    assert_eq!(
        ordinary.final_content.as_deref(),
        Some("This reply contains spoilers.")
    );

    let age_gate = block_on_ready(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("consensual adult nsfw scene"),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("policy-model-down-age-gate"),
        |_feedback, _candidate| "safe all-ages summary".to_owned(),
    ))?;
    assert_eq!(age_gate.action, PolicyEnforcementAction::Allow);
    assert!(age_gate.custom_tier_skipped);
    assert_eq!(age_gate.reword_attempts, 1);
    assert_eq!(
        age_gate.classify_trace[0].category,
        PolicyVerdictCategory::AgeGate(AgeGateSubclass::AdultContent)
    );
    assert!(
        age_gate
            .classify_trace
            .iter()
            .all(|verdict| !matches!(verdict.category, PolicyVerdictCategory::OwnerPolicy { .. }))
    );
    assert_eq!(
        age_gate.final_content.as_deref(),
        Some("safe all-ages summary")
    );

    let floor = block_on_ready(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("policy-model-down-floor"),
        |_feedback, _candidate| panic!("floor block should not reword"),
    ))?;
    assert_eq!(floor.action, PolicyEnforcementAction::Block);
    assert_eq!(
        floor.verdict.category,
        PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::SeriousCrime)
    );
    assert!(floor.receipt_ref.is_some());
    Ok(())
}

// --- B11-2 / R9: relay-boundary floor pass on hosted connectors ---

#[test]
fn hosted_relay_outbound_from_local_vault_hits_rung1() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;

    assert!(pass.ran_relay_classify());
    let verdict = pass
        .floor_verdict()
        .expect("hosted relay runs a floor pass");
    // Rung-1 deterministic tripwire fired at the relay boundary.
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::SeriousCrime)
    );
    Ok(())
}

#[test]
fn cloud_vault_relay_path_does_not_double_classify() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Content that WOULD block if re-run; a cloud vault already classified it
    // vault-side on our infra, so the relay trusts it and never re-runs.
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;

    // Missing evidence cannot create a CloudVault skip: it falls through to
    // our hosted deterministic floor and blocks this floor-tripping content.
    assert!(pass.ran_relay_classify());
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_verified_receipt_trusts_without_rerunning_floor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let receipt = relay_floor_clean_verdict(binding.clone(), &PolicyModelConfig::default());
    let source = StaticVaultSideVerdicts {
        verdict: receipt,
        requested_hash: Mutex::new(None),
    };

    let pass = vault.relay_boundary_floor_pass(
        request,
        AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault),
        &source,
    )?;
    assert_eq!(pass, RelayFloorPass::TrustedVaultSide);
    assert_eq!(
        *source.requested_hash.lock().expect("requested hash lock"),
        Some(binding.content_hash)
    );
    Ok(())
}

#[test]
fn cloud_vault_receipt_binding_mismatch_fails_closed_to_hosted_floor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let mut binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    binding.read_frontier_hash = [7; 32];
    let source = StaticVaultSideVerdicts {
        verdict: relay_floor_clean_verdict(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };

    let err = vault
        .cloud_vault_verified_trust(&request, &PolicyModelConfig::default(), &source)
        .expect_err("frontier mismatch must be rejected by the CloudVault arm");
    assert!(matches!(
        err,
        Error::RelayVaultReceiptUntrusted {
            reason: "binding_mismatch"
        }
    ));
    let pass = vault.relay_boundary_floor_pass(
        request,
        AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault),
        &source,
    )?;
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_non_allow_receipts_halt_and_record_real_floor_decisions() -> Result<()> {
    for (decision, outcome) in [
        (PolicyClassifyDecision::Block, "relay_floor_block"),
        (
            PolicyClassifyDecision::RouteToHelp,
            "relay_floor_route_to_help",
        ),
        (
            PolicyClassifyDecision::RewordRetry,
            "relay_floor_reword_retry",
        ),
    ] {
        let (_tmp, vault) = temp_vault();
        let request = PolicyClassifyRequest::outbound_content("ordinary content");
        let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
        let receipt = verdict(
            decision,
            PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::SeriousCrime),
            PolicyConfidence::HIGH,
            binding,
            &PolicyModelConfig::default(),
        );
        let source = StaticVaultSideVerdicts {
            verdict: receipt,
            requested_hash: Mutex::new(None),
        };

        let pass = vault.relay_boundary_floor_pass(
            request,
            AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault),
            &source,
        )?;
        assert!(pass.must_halt_relay());
        assert!(matches!(pass, RelayFloorPass::FloorClassified { .. }));
        let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, outcome);
        assert!(
            !receipts
                .iter()
                .any(|receipt| receipt.outcome == "relay_trusted_vault_side")
        );
    }
    Ok(())
}

#[test]
fn cloud_vault_safeguard_binding_mismatch_falls_back_and_audits() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("an ordinary friendly reply");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let mut receipt = relay_floor_clean_verdict(binding, &PolicyModelConfig::default());
    receipt.safeguard_binding = "stale-safeguard".to_owned();
    let source = StaticVaultSideVerdicts {
        verdict: receipt,
        requested_hash: Mutex::new(None),
    };

    let pass = vault.relay_boundary_floor_pass(
        request,
        AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault),
        &source,
    )?;
    assert_eq!(
        pass.floor_verdict().expect("fallback verdict").decision,
        PolicyClassifyDecision::Allow
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert!(
        receipts[0].policy_trace.iter().any(|code| {
            code == "gate.relay.vault_receipt_untrusted.safeguard_binding_mismatch"
        })
    );
    Ok(())
}

#[test]
fn cloud_vault_untrusted_receipt_with_backend_runs_and_degrades_backend() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("a flagged rung-one-clean span");
    let source = StaticVaultSideVerdicts {
        verdict: relay_floor_clean_verdict(
            PolicyContentBinding {
                content_hash: [9; 32],
                read_frontier_hash: [9; 32],
            },
            &PolicyModelConfig::default(),
        ),
        requested_hash: Mutex::new(None),
    };
    let backend = CountingPolicyBackend {
        calls: AtomicUsize::new(0),
    };

    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        request,
        AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("cloud-fallback-backend-down"),
        &source,
    ))?;
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        pass.floor_verdict().expect("fallback verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert_eq!(
        pass.degraded(),
        Some(RelayFloorDegrade::SafeguardModelUnavailable)
    );
    Ok(())
}

#[test]
fn cloud_vault_verified_receipt_with_backend_never_calls_backend() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: relay_floor_clean_verdict(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };
    let backend = CountingPolicyBackend {
        calls: AtomicUsize::new(0),
    };
    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        request,
        AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("trusted-cloud-no-backend"),
        &source,
    ))?;
    assert_eq!(pass, RelayFloorPass::TrustedVaultSide);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn cloud_vault_missing_receipt_reports_typed_reason_and_audits_clean_fallback() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("an ordinary friendly reply");
    let err = vault
        .cloud_vault_verified_trust(
            &request,
            &PolicyModelConfig::default(),
            &EMPTY_VAULT_SIDE_VERDICTS,
        )
        .expect_err("missing receipt must be untrusted");
    assert!(matches!(
        err,
        Error::RelayVaultReceiptUntrusted { reason: "missing" }
    ));
    let pass = vault.relay_boundary_floor_pass(
        request,
        AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert_eq!(
        pass.floor_verdict().expect("fallback verdict").decision,
        PolicyClassifyDecision::Allow
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    assert!(
        receipts[0]
            .policy_trace
            .iter()
            .any(|x| x == "gate.relay.vault_receipt_untrusted.missing")
    );
    Ok(())
}

#[test]
fn cloud_vault_content_hash_mismatch_audits_exact_cause() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("an ordinary friendly reply");
    let mut binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    binding.content_hash = [9; 32];
    let source = StaticVaultSideVerdicts {
        verdict: relay_floor_clean_verdict(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };
    let err = vault
        .cloud_vault_verified_trust(&request, &PolicyModelConfig::default(), &source)
        .expect_err("stored content hash mismatch must be untrusted");
    assert!(matches!(
        err,
        Error::RelayVaultReceiptUntrusted {
            reason: "binding_mismatch"
        }
    ));
    vault.relay_boundary_floor_pass(
        request,
        AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault),
        &source,
    )?;
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    assert!(
        receipts[0]
            .policy_trace
            .iter()
            .any(|x| x == "gate.relay.vault_receipt_untrusted.binding_mismatch")
    );
    Ok(())
}

#[test]
fn relay_verify_binding_ignores_world_ref_while_content_binding_does_not() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let plain = PolicyClassifyRequest::outbound_content("same content");
    let scoped =
        PolicyClassifyRequest::outbound_content("same content").with_world_ref("world:other");
    assert_eq!(
        vault
            .relay_verify_binding(&plain, &PolicyModelConfig::default())?
            .content_hash,
        vault
            .relay_verify_binding(&scoped, &PolicyModelConfig::default())?
            .content_hash,
    );
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert_ne!(
        content_binding(&plain, &policy, &PolicyModelConfig::default())?.content_hash,
        content_binding(&scoped, &policy, &PolicyModelConfig::default())?.content_hash,
    );
    Ok(())
}

#[test]
fn relay_verify_binding_is_distinct_from_skip_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("same content");
    let verify = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    assert_ne!(
        verify.content_hash,
        relay_skip_content_binding(&request).content_hash
    );
    Ok(())
}

#[test]
fn custom_tier_rows_never_evaluated_at_relay() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x50),
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
        )])]),
    )?;

    // Sanity: the vault-egress classify DOES fire the owner (custom-tier) row.
    let vault_side = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "This reply contains spoilers.",
    ))?;
    assert_eq!(
        vault_side.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
        }
    );

    // The relay floor pass is FLOOR ONLY: the owner row is never evaluated.
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers."),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    let verdict = pass
        .floor_verdict()
        .expect("hosted relay runs a floor pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);
    assert!(!matches!(
        verdict.category,
        PolicyVerdictCategory::OwnerPolicy { .. }
    ));
    Ok(())
}

#[test]
fn byo_path_untouched() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaByoConnector),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;

    assert_eq!(pass, RelayFloorPass::NotRelayedByUs);
    assert!(!pass.ran_relay_classify());
    assert!(pass.floor_verdict().is_none());
    Ok(())
}

#[test]
fn relay_backend_catches_flagged_floor_span() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Rung-1 is clean on this phrasing; the FLOOR-ONLY safeguard model is the
    // flagged-span nuance layer and catches it.
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"block","category":"legal_floor/serious_crime","row_ref":null,"confidence":0.95,"hedge_bucket":"high"}"#,
    };
    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("a subtly worded dangerous ask"),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("relay-floor-model-catch"),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    let verdict = pass.floor_verdict().expect("hosted relay floor pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::SeriousCrime)
    );
    // A real model catch is NOT a degradation.
    assert!(pass.degraded().is_none());
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn relay_backend_stays_floor_only_and_degrades_owner_verdict() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x51),
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
        )])]),
    )?;
    // The relay rubric carries no owner row, so a hallucinated owner_policy
    // verdict has no floor row to bind to: it is an unusable off-floor
    // response. It must degrade to the Rung-1-stands Allow (not propagate an
    // Err, not take effect) so the custom tier can never take effect at the
    // relay, and the degraded marker keeps it distinguishable in receipts.
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"reword-retry","category":"owner_policy","row_ref":"owner:spoilers","confidence":0.9,"hedge_bucket":"high"}"#,
    };
    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("an ordinary flagged span"),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("relay-floor-owner-degrade"),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    let verdict = pass.floor_verdict().expect("hosted relay floor pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);
    assert!(!matches!(
        verdict.category,
        PolicyVerdictCategory::OwnerPolicy { .. }
    ));
    assert_eq!(
        pass.degraded(),
        Some(RelayFloorDegrade::SafeguardModelResponseUnusable)
    );
    assert!(!pass.must_halt_relay());

    // A degraded allow IS receipted (unlike a clean allow) with the marker.
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "relay_floor_allow");
    assert!(
        receipts[0]
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.relay.degraded.safeguard_model_response_unusable")
    );
    Ok(())
}

#[test]
fn relay_backend_down_keeps_rung1_floor_backstop() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let backend = FailingPolicyBackend;
    // Rung-1 still catches the catastrophe with the safeguard model down.
    let caught = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("relay-floor-down-catch"),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(
        caught.floor_verdict().expect("floor verdict").category,
        PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::SeriousCrime)
    );
    // Rung-1 caught it deterministically — the model was never consulted, so
    // this is not a degradation.
    assert!(caught.degraded().is_none());

    // A floor-clean span with the model down falls open over the floor
    // (Rung-1 is the deterministic backstop; nothing weaker than it) and is
    // MARKED degraded so the Allow is not mistaken for a model-confirmed one.
    let clean = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("an ordinary friendly reply"),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("relay-floor-down-clean"),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(
        clean.floor_verdict().expect("floor verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert_eq!(
        clean.degraded(),
        Some(RelayFloorDegrade::SafeguardModelUnavailable)
    );
    assert!(!clean.must_halt_relay());
    Ok(())
}

#[test]
fn relay_trust_domains_short_circuit_without_running_classify() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("explicit sexual content about a minor");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: relay_floor_clean_verdict(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };
    let cloud = vault.relay_boundary_floor_pass(
        request,
        AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault),
        &source,
    )?;
    let byo = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explicit sexual content about a minor"),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaByoConnector),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    for pass in [cloud, byo] {
        assert!(!pass.ran_relay_classify());
        assert!(pass.floor_verdict().is_none());
        assert!(!pass.must_halt_relay());
    }
    Ok(())
}

#[test]
fn must_halt_relay_flags_every_non_allow_verdict() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let hosted = AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector);

    // Block, RouteToHelp, and RewordRetry all mean do-not-relay.
    let block = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        hosted,
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert_eq!(
        block.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Block
    );
    assert!(block.must_halt_relay());

    let route = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("I might kill myself tonight"),
        hosted,
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert_eq!(
        route.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::RouteToHelp
    );
    assert!(route.must_halt_relay());

    let reword = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("adult nsfw reply"),
        hosted,
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert_eq!(
        reword.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::RewordRetry
    );
    assert!(reword.must_halt_relay());

    // A floor-clean allow does not halt.
    let allow = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("an ordinary friendly reply"),
        hosted,
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert_eq!(
        allow.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(!allow.must_halt_relay());
    Ok(())
}

#[test]
fn relay_rubric_is_floor_only_and_pins_owner_append() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x52),
        &base_policy_manifest(vec![owner_rows(vec![
            owner_row("owner:spoilers", "Avoid spoilers."),
            owner_row("owner:jargon", "Avoid nautical jargon."),
        ])]),
    )?;
    let request = PolicyClassifyRequest::outbound_content("candidate");
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;

    let floor_only = rubric_rows_floor_only(&policy)?;
    let full = rubric_rows(&request, &policy)?;

    // The relay rubric contains zero owner-policy-layer rows.
    assert!(
        floor_only
            .iter()
            .all(|row| row.layer != PolicyRubricLayer::OwnerPolicy)
    );
    assert!(
        floor_only
            .iter()
            .any(|row| row.layer == PolicyRubricLayer::EngineFloor)
    );

    // rubric_rows() == rubric_rows_floor_only() + owner-append: the floor
    // rows are an exact prefix and every extra row is an owner-policy row.
    // Pins the delegation so a future edit to the shared floor assembly can
    // never silently re-enable owner rows at the relay.
    assert!(full.len() > floor_only.len());
    assert_eq!(&full[..floor_only.len()], floor_only.as_slice());
    assert!(
        full[floor_only.len()..]
            .iter()
            .all(|row| row.layer == PolicyRubricLayer::OwnerPolicy)
    );
    assert_eq!(full[floor_only.len()..].len(), 2);
    Ok(())
}

#[test]
fn relay_block_writes_audit_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_caller_ref("relay:slack-app"),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert!(pass.must_halt_relay());

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.outcome, "relay_floor_block");
    assert!(
        receipt
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.relay.trust_domain.local_via_hosted_connector")
    );
    assert!(
        receipt
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.relay.classify.ran")
    );
    assert!(
        receipt
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.policy_model.block")
    );
    Ok(())
}

#[test]
fn relay_skips_write_audit_receipts_with_trust_domain() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let content = || PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let binding = vault.relay_verify_binding(&content(), &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: relay_floor_clean_verdict(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };
    vault.relay_boundary_floor_pass(
        content(),
        AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault),
        &source,
    )?;
    vault.relay_boundary_floor_pass(
        content(),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaByoConnector),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 2);
    let outcomes = receipts
        .iter()
        .map(|receipt| receipt.outcome.as_str())
        .collect::<Vec<_>>();
    assert!(outcomes.contains(&"relay_trusted_vault_side"));
    assert!(outcomes.contains(&"relay_not_relayed"));
    assert!(receipts.iter().all(|receipt| {
        receipt
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.relay.classify.skipped")
    }));
    Ok(())
}

#[test]
fn relay_clean_allow_writes_no_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("an ordinary friendly reply"),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert_eq!(
        pass.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(pass.degraded().is_none());

    // A clean, non-degraded allow carries no enforcement signal — no receipt.
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert!(receipts.is_empty());
    Ok(())
}

#[test]
fn relay_backend_degrades_off_floor_fixed_category() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // No vault floor row for crisis/medical, so it was never assembled into
    // the floor-only rubric. A model verdict for it is off-floor and must
    // degrade (the relay enforces its assembled floor, not the model's full
    // closed taxonomy), not halt the relay for a category the floor omits.
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"route-to-help","category":"crisis/medical","row_ref":null,"confidence":0.9,"hedge_bucket":"high"}"#,
    };
    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("a flagged but floor-clean span"),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("relay-off-floor-medical"),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    let verdict = pass.floor_verdict().expect("hosted relay floor pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);
    assert_eq!(
        pass.degraded(),
        Some(RelayFloorDegrade::SafeguardModelResponseUnusable)
    );
    assert!(!pass.must_halt_relay());
    Ok(())
}

#[test]
fn relay_backend_accepts_fixed_category_present_in_floor_rubric() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // A vault legal-floor row DOES assemble crisis/medical, so the model
    // verdict for it is on-floor and is honored (routes, halts the relay).
    put_policy_manifest_bytes(
        &vault,
        test_id(0x53),
        &base_policy_manifest(vec![legal_floor_rows(vec![legal_floor_row(
            "vault:medical",
            "crisis",
            "medical",
            "route-to-help",
            "Route medical crises to help.",
        )])]),
    )?;
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"route-to-help","category":"crisis/medical","row_ref":null,"confidence":0.9,"hedge_bucket":"high"}"#,
    };
    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("a flagged but floor-clean span"),
        AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("relay-on-floor-medical"),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    let verdict = pass.floor_verdict().expect("hosted relay floor pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::RouteToHelp);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::Crisis(CrisisSubclass::Medical)
    );
    assert!(pass.degraded().is_none());
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn relay_sync_pass_fails_closed_on_malformed_floor_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The deterministic path skips the model prompt render but still
    // assembles+validates the floor rows, so a malformed legal-floor row
    // fails closed exactly as the model path does — no strictness is lost.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x54),
        &base_policy_manifest(vec![legal_floor_rows(vec![legal_floor_row(
            "vault:bad-action",
            "crisis",
            "self_harm",
            "route-tohelp",
            "Malformed action must not silently pass the relay floor.",
        )])]),
    )?;

    let err = vault
        .relay_boundary_floor_pass(
            PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
            AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector),
            &EMPTY_VAULT_SIDE_VERDICTS,
        )
        .expect_err("malformed floor row must fail the deterministic relay pass closed");
    assert!(
        format!("{err}").contains("malformed"),
        "unexpected error: {err}"
    );
    Ok(())
}
// --- B11-2b / ONE-1572: sealed connection identity + attested relay domain ---

/// Fixture edge-service registrations (ONE-1572 F2): the engine ships the
/// validation mechanism and NO service identities — the registration data a
/// deployment's connector-edge wiring would supply from its manifest is
/// provided here as test fixtures (the only place product-branded hosted
/// connector edge names may appear).
fn fixture_edge_services() -> [(&'static str, ConnectionClass); 4] {
    [
        ("cloud-vault", ConnectionClass::CloudVaultPeer),
        (
            "slack-hosted",
            ConnectionClass::LocalVaultViaHostedConnector,
        ),
        ("push-relay", ConnectionClass::LocalVaultViaHostedConnector),
        (
            "email-hosted",
            ConnectionClass::LocalVaultViaHostedConnector,
        ),
    ]
}

fn fixture_edge_service_registry() -> EdgeServiceRegistry {
    let mut registry = EdgeServiceRegistry::new();
    for (service, class) in fixture_edge_services() {
        registry
            .register(service, class)
            .expect("fixture edge service registrations must not conflict");
    }
    registry
}

fn edge_auth_identity(
    service_identity: &str,
    class: ConnectionClass,
) -> AuthenticatedConnectionIdentity {
    AuthenticatedConnectionIdentity::from_edge_auth(
        service_identity,
        class,
        &fixture_edge_service_registry(),
    )
    .expect("test identity must pass edge-auth validation")
}

#[test]
fn from_edge_auth_accepts_every_registered_pair() {
    let registry = fixture_edge_service_registry();
    for (service, class) in fixture_edge_services() {
        let service_identity = format!("connector-edge:{service}");
        let identity =
            AuthenticatedConnectionIdentity::from_edge_auth(&service_identity, class, &registry)
                .expect("registered (service, class) pair must validate");
        assert_eq!(identity.service_identity(), service_identity);
        assert_eq!(identity.connection_class(), class);
    }
}

#[test]
fn from_edge_auth_rejects_malformed_service_identity_grammar() {
    let registry = fixture_edge_service_registry();
    for malformed in [
        "",
        "slack-hosted",
        "connector-edge",
        "connector-edge:",
        "Connector-edge:slack-hosted",
        " connector-edge:slack-hosted",
    ] {
        let err = AuthenticatedConnectionIdentity::from_edge_auth(
            malformed,
            ConnectionClass::LocalVaultViaHostedConnector,
            &registry,
        )
        .expect_err("malformed service identity must be rejected");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::RelayAttestationInvalidServiceIdentity,
            "input: {malformed:?}"
        );
    }
}

#[test]
fn from_edge_auth_rejects_unregistered_service_identity() {
    // Fail-closed registry: an identity the deployment never registered can
    // never mint a witness, whatever class it claims. An EMPTY registry
    // rejects even the names the fixture registry knows — the engine ships
    // no implicit registrations.
    let registry = EdgeServiceRegistry::new();
    for service_identity in [
        "connector-edge:cloud-vault",
        "connector-edge:slack-hosted",
        "connector-edge:totally-unknown-edge",
    ] {
        for class in [
            ConnectionClass::CloudVaultPeer,
            ConnectionClass::LocalVaultViaHostedConnector,
        ] {
            let err =
                AuthenticatedConnectionIdentity::from_edge_auth(service_identity, class, &registry)
                    .expect_err("unregistered service identity must be rejected");
            assert_eq!(
                err.kind(),
                crate::error::ErrorKind::RelayAttestationInvalidServiceIdentity,
                "input: {service_identity:?}"
            );
        }
    }
}

#[test]
fn edge_service_registry_rejects_conflicting_re_registration() {
    // Fail-closed registration data: re-registering a name to a DIFFERENT
    // class is a manifest error, never a silent re-standing of the edge.
    let mut registry = EdgeServiceRegistry::new();
    registry
        .register("edge-one", ConnectionClass::CloudVaultPeer)
        .expect("first registration succeeds");
    // An identical re-registration is idempotent (manifest reloads).
    registry
        .register("edge-one", ConnectionClass::CloudVaultPeer)
        .expect("identical re-registration is idempotent");
    let err = registry
        .register("edge-one", ConnectionClass::LocalVaultViaHostedConnector)
        .expect_err("conflicting re-registration must be rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::RelayAttestationEdgeServiceConflict
    );
    // ... and the original registration still governs.
    let identity = AuthenticatedConnectionIdentity::from_edge_auth(
        "connector-edge:edge-one",
        ConnectionClass::CloudVaultPeer,
        &registry,
    )
    .expect("original registration still governs after the rejected conflict");
    assert_eq!(identity.connection_class(), ConnectionClass::CloudVaultPeer);
}

#[test]
fn edge_service_registry_rejects_empty_service_name() {
    let mut registry = EdgeServiceRegistry::new();
    let err = registry
        .register("", ConnectionClass::CloudVaultPeer)
        .expect_err("empty service name must be rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::RelayAttestationInvalidServiceIdentity
    );
}

#[test]
fn from_edge_auth_rejects_identity_class_mismatch() {
    // The hosted Slack connector is registered as a local-vault relay edge;
    // it may never claim cloud-vault peer standing (which would skip the
    // relay floor).
    let registry = fixture_edge_service_registry();
    let err = AuthenticatedConnectionIdentity::from_edge_auth(
        "connector-edge:slack-hosted",
        ConnectionClass::CloudVaultPeer,
        &registry,
    )
    .expect_err("hosted connector claiming cloud-vault peer must be rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::RelayAttestationClassMismatch
    );
    let message = format!("{err}");
    assert!(message.contains("connector-edge:slack-hosted"));
    assert!(message.contains("cloud_vault_peer"));
    assert!(message.contains("local_vault_via_hosted_connector"));

    // The mirror: the cloud-vault peer may not present as a hosted connector
    // (which would force a redundant floor re-run on already-classified
    // content).
    let err = AuthenticatedConnectionIdentity::from_edge_auth(
        "connector-edge:cloud-vault",
        ConnectionClass::LocalVaultViaHostedConnector,
        &registry,
    )
    .expect_err("cloud-vault peer claiming hosted-connector class must be rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::RelayAttestationClassMismatch
    );
}

#[test]
fn witness_mint_maps_every_connection_class() {
    // Exhaustive over ConnectionClass: the general mint can only produce the
    // two hosted domains — never `LocalViaByoConnector`.
    for (service_identity, class, expected) in [
        (
            "connector-edge:cloud-vault",
            ConnectionClass::CloudVaultPeer,
            RelayTrustDomain::CloudVault,
        ),
        (
            "connector-edge:slack-hosted",
            ConnectionClass::LocalVaultViaHostedConnector,
            RelayTrustDomain::LocalViaHostedConnector,
        ),
    ] {
        let identity = edge_auth_identity(service_identity, class);
        let witness = AttestedRelayDomain::from_connection_identity(&identity);
        assert_eq!(witness.domain(), expected);
    }
}

#[test]
fn hosted_edge_attestation_can_never_reach_byo() {
    // Type-level BYO unconstructibility: `HostedDomain` has no BYO arm, so
    // attesting over EVERY ConnectionClass yields only the two hosted
    // domains — a hosted edge can never conclude "not relayed by us".
    let attestation = HostedEdgeAttestation::new();
    let mut seen = Vec::new();
    for (service_identity, class) in [
        (
            "connector-edge:cloud-vault",
            ConnectionClass::CloudVaultPeer,
        ),
        (
            "connector-edge:slack-hosted",
            ConnectionClass::LocalVaultViaHostedConnector,
        ),
    ] {
        let identity = edge_auth_identity(service_identity, class);
        let witness = attestation.attest(&identity);
        assert!(matches!(
            witness.domain(),
            RelayTrustDomain::CloudVault | RelayTrustDomain::LocalViaHostedConnector
        ));
        seen.push(witness.domain());
    }
    assert_eq!(
        seen,
        vec![
            RelayTrustDomain::CloudVault,
            RelayTrustDomain::LocalViaHostedConnector
        ]
    );
}

#[test]
fn hosted_domain_variant_set_is_exactly_two_hosted_arms() {
    // ONE-1572 F3 security tripwire: an in-crate EXHAUSTIVE, no-wildcard
    // match over the private `HostedDomain`. Adding a variant (e.g. a BYO
    // arm) breaks THIS match at compile time — the variant-set pin the
    // external compile-fail fixture cannot provide (its E0603 fires
    // regardless of the variant set). The expected mapping is checked
    // against the production `from_hosted_domain` arm-for-arm, so the two
    // can never drift apart either.
    fn expected_domain(hosted: HostedDomain) -> RelayTrustDomain {
        match hosted {
            HostedDomain::CloudVault => RelayTrustDomain::CloudVault,
            HostedDomain::LocalViaHostedConnector => RelayTrustDomain::LocalViaHostedConnector,
        }
    }
    for hosted in [
        HostedDomain::CloudVault,
        HostedDomain::LocalViaHostedConnector,
    ] {
        assert_eq!(
            AttestedRelayDomain::from_hosted_domain(hosted).domain(),
            expected_domain(hosted),
            "hosted-edge mapping drifted from the pinned two-variant set"
        );
    }
}

#[test]
fn attested_relay_domain_serializes_transparently() {
    let witness = AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaHostedConnector);
    assert_eq!(
        serde_json::to_value(witness).expect("witness serializes"),
        serde_json::to_value(RelayTrustDomain::LocalViaHostedConnector)
            .expect("inner domain serializes"),
        "transparent serde: the witness emits exactly the inner domain payload"
    );
}

#[test]
fn witness_and_identity_never_implement_deserialize() {
    // Ambiguity-based negative trait check (the static_assertions
    // `assert_not_impl_any!` mechanism, hand-rolled to avoid a new
    // dependency): each `marker()` call resolves ONLY while `T` does NOT
    // implement `DeserializeOwned`. If a `Deserialize` impl ever lands on
    // either type, both blanket impls apply and this test stops compiling.
    trait AmbiguousIfImpl<A> {
        fn marker() {}
    }
    impl<T> AmbiguousIfImpl<()> for T {}
    struct NotDeserialize<T>(std::marker::PhantomData<T>);
    impl<T: serde::de::DeserializeOwned> AmbiguousIfImpl<u8> for NotDeserialize<T> {}

    NotDeserialize::<AttestedRelayDomain>::marker();
    NotDeserialize::<AuthenticatedConnectionIdentity>::marker();
}

#[test]
fn attested_witness_drives_relay_floor_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The hosted Slack connector edge attests its validated identity; the
    // minted witness then drives the floor pass exactly like the pre-seal
    // bare domain did.
    let identity = edge_auth_identity(
        "connector-edge:slack-hosted",
        ConnectionClass::LocalVaultViaHostedConnector,
    );
    let witness = HostedEdgeAttestation::new().attest(&identity);
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: relay_floor_clean_verdict(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };
    let pass = vault.relay_boundary_floor_pass(request, witness, &source)?;
    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.floor_verdict()
            .expect("hosted relay runs a floor pass")
            .decision,
        PolicyClassifyDecision::Block
    );
    Ok(())
}

#[test]
fn attested_cloud_vault_witness_short_circuits_the_floor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = edge_auth_identity(
        "connector-edge:cloud-vault",
        ConnectionClass::CloudVaultPeer,
    );
    let witness = AttestedRelayDomain::from_connection_identity(&identity);
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: relay_floor_clean_verdict(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };
    let pass = vault.relay_boundary_floor_pass(request, witness, &source)?;
    assert_eq!(pass, RelayFloorPass::TrustedVaultSide);
    assert!(!pass.ran_relay_classify());
    Ok(())
}
