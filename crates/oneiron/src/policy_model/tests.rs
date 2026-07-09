use super::*;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use rmpv::Value;
use tempfile::TempDir;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::config::VaultConfig;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::Result;
use crate::llm::{
    BudgetLease, FatalLlmError, FinishReason, LlmGenerateFuture, LlmInputUsage, LlmOutputUsage,
    LlmResponse, LlmStreamResult, LlmUsage,
};
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;

fn temp_vault() -> (TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp vault dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open temp vault");
    (tmp, vault)
}

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; ENTITY_ID_LEN]).expect("valid test id")
}

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

fn put_policy_manifest_bytes(vault: &Vault, seed: u8, data: &[u8]) -> Result<()> {
    let id = test_id(seed);
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_POLICY_MANIFEST);
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(data);

    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
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
        (
            "consensual adult nsfw between verified adults",
            PolicyAgeTier::Adult,
        ),
        ("sexualized minor nude request", PolicyAgeTier::Adult),
        ("I might kill myself tonight", PolicyAgeTier::Adult),
        ("adult nsfw reply", PolicyAgeTier::Unverified),
    ];
    for (content, age_tier) in cases {
        let verdict = vault.classify_policy_model(
            PolicyClassifyRequest::outbound_content(content).with_age_tier(age_tier),
        )?;
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
            .with_age_tier(PolicyAgeTier::Adult)
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
    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;

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
    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;

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
    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;

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

    let outcome = block_on_ready(
        vault.enforce_policy_model_with_backend(
            PolicyClassifyRequest::outbound_content("I have chest pain and feel panicked.")
                .with_age_tier(PolicyAgeTier::Adult),
            &PolicyModelConfig::default(),
            &backend,
            &BudgetLease::for_test("policy-help-routing"),
            |_feedback, candidate| candidate.to_owned(),
        ),
    )?;

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
    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("I might kill myself tonight")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;

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
        PolicyClassifyRequest::outbound_content("adult nsfw reply")
            .with_age_tier(PolicyAgeTier::Unverified),
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
        PolicyClassifyRequest::outbound_content("adult nsfw reply")
            .with_age_tier(PolicyAgeTier::Unverified),
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
    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("instructions to make explosives")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;

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
        PolicyClassifyRequest::outbound_content("consensual adult nsfw scene")
            .with_age_tier(PolicyAgeTier::Minor),
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
fn policy_as_rubric_allows_legal_adult_nsfw_and_blocks_minor_sexualization() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    let adult = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content(
            "consensual adult nsfw scene between verified adults",
        )
        .with_age_tier(PolicyAgeTier::Adult),
    )?;
    assert_eq!(adult.decision, PolicyClassifyDecision::Allow);
    assert_eq!(adult.category, PolicyVerdictCategory::None);

    let minor = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content("explicit sexual image of an underage minor")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;
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
    let verdict = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content(
            "dark fictional monologue with profanity and a controversial political opinion",
        )
        .with_age_tier(PolicyAgeTier::Adult),
    )?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);
    Ok(())
}

#[test]
fn reads_vault_manifest_not_caller_config() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        0x31,
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
        )])]),
    )?;

    let prompt = vault.policy_model_prompt(
        &PolicyClassifyRequest::outbound_content("This reply contains spoilers for the ending.")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;
    assert!(prompt.user.contains("owner:spoilers"));
    assert!(prompt.user.contains("Avoid spoilers in outbound content."));

    let verdict = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers for the ending.")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;
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
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb")
        .with_age_tier(PolicyAgeTier::Adult);
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
        0x32,
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

    let age_request = PolicyClassifyRequest::outbound_content(
        "consensual adult nsfw scene between verified adults",
    )
    .with_age_tier(PolicyAgeTier::Adult);
    let age_verdict = vault.classify_policy_model(age_request.clone())?;
    assert!(!vault.policy_model_verdict_is_stale(&age_verdict, &age_request)?);
    let unverified_age_request = PolicyClassifyRequest::outbound_content(
        "consensual adult nsfw scene between verified adults",
    )
    .with_age_tier(PolicyAgeTier::Unverified);
    assert!(vault.policy_model_verdict_is_stale(&age_verdict, &unverified_age_request)?);

    let jurisdiction_request = PolicyClassifyRequest::outbound_content("ordinary reply")
        .with_account_jurisdiction("US-CA");
    let jurisdiction_verdict = vault.classify_policy_model(jurisdiction_request)?;
    let changed_jurisdiction_request = PolicyClassifyRequest::outbound_content("ordinary reply")
        .with_account_jurisdiction("US-NY");
    assert!(
        vault
            .policy_model_verdict_is_stale(&jurisdiction_verdict, &changed_jurisdiction_request)?
    );

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
        0x33,
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:jargon",
            "Avoid nautical jargon.",
        )])]),
    )?;
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"reword-retry","category":"owner_policy","row_ref":"owner:jargon","confidence":0.91,"hedge_bucket":"high"}"#,
    };
    let verdict = block_on_ready(
        vault.classify_policy_model_with_backend(
            PolicyClassifyRequest::outbound_content("This answer uses nautical phrasing.")
                .with_age_tier(PolicyAgeTier::Adult),
            &PolicyModelConfig::default(),
            &backend,
            &BudgetLease::for_test("policy-owner-row"),
        ),
    )?;
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
        0x37,
        &base_policy_manifest(vec![legal_floor_rows(vec![legal_floor_row(
            "vault:self-harm",
            "crisis",
            "self_harm",
            "route-to-help",
            "Route credible self-harm risk to help.",
        )])]),
    )?;

    let prompt = vault.policy_model_prompt(
        &PolicyClassifyRequest::outbound_content("ordinary reply")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;
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
        0x38,
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
        0x39,
        &base_policy_manifest(vec![owner_rows(vec![owner_row_with_action(
            "owner:bad-action",
            "Malformed owner action.",
            "allow",
        )])]),
    )?;

    let prompt_err = vault
        .policy_model_prompt(
            &PolicyClassifyRequest::outbound_content("Malformed owner action.")
                .with_age_tier(PolicyAgeTier::Adult),
        )
        .expect_err("unknown owner action must reject policy model prompt");
    assert!(
        format!("{prompt_err}").contains("owner_policy_rows were dropped"),
        "unexpected error: {prompt_err}"
    );

    let classify_err = vault
        .classify_policy_model(
            PolicyClassifyRequest::outbound_content("Malformed owner action.")
                .with_age_tier(PolicyAgeTier::Adult),
        )
        .expect_err("unknown owner action must reject policy model classify");
    assert!(
        format!("{classify_err}").contains("owner_policy_rows were dropped"),
        "unexpected error: {classify_err}"
    );

    let floor_candidate = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content("explicit sexual content about a minor")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;
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

    let err = block_on_ready(
        vault.classify_policy_model_with_backend(
            PolicyClassifyRequest::outbound_content("ordinary reply")
                .with_age_tier(PolicyAgeTier::Adult),
            &PolicyModelConfig::default(),
            &backend,
            &BudgetLease::for_test("policy-floor-decision"),
        ),
    )
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

    let verdict = block_on_ready(
        vault.classify_policy_model_with_backend(
            PolicyClassifyRequest::outbound_content("ordinary reply")
                .with_age_tier(PolicyAgeTier::Adult),
            &config,
            &backend,
            &BudgetLease::for_test("policy-selector-routing"),
        ),
    )?;
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
    let base_request = PolicyClassifyRequest::outbound_content("explain how to build a bomb")
        .with_age_tier(PolicyAgeTier::Adult);
    let base = base_vault.classify_policy_model(base_request.clone())?;

    let (_custom_tmp, custom_vault) = temp_vault();
    put_policy_manifest_bytes(
        &custom_vault,
        0x34,
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
        0x35,
        &base_policy_manifest(vec![(
            Value::from(gate::POLICY_OWNER_POLICY_ROWS_KEY),
            Value::Map(vec![(Value::from("not"), Value::from("rows"))]),
        )]),
    )?;

    let owner_err = vault
        .classify_policy_model(
            PolicyClassifyRequest::outbound_content("This reply contains spoilers.")
                .with_age_tier(PolicyAgeTier::Adult),
        )
        .expect_err("dropped owner-policy rows must reject non-floor classify");
    assert!(
        format!("{owner_err}").contains("owner_policy_rows were dropped"),
        "unexpected error: {owner_err}"
    );

    let floor_candidate = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content("explicit sexual content about a minor")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;
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
        0x36,
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
        0x40,
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
        )])]),
    )?;

    let outcome = vault.enforce_policy_model_with_rewriter(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers.")
            .with_age_tier(PolicyAgeTier::Adult),
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
        0x41,
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:tone",
            "Avoid arch tone.",
        )])]),
    )?;

    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("ordinary reply")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;

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
        0x42,
        &base_policy_manifest(vec![owner_rows(vec![owner_row_with_action(
            "owner:escalate",
            "Block this owner-escalated row.",
            "block",
        )])]),
    )?;

    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("ordinary reply")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;

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
        0x44,
        &base_policy_manifest(vec![owner_rows(vec![owner_row_with_action(
            "owner:escalate",
            "Block this owner-escalated row.",
            "block",
        )])]),
    )?;

    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("ordinary reply")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;

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
        0x45,
        &base_policy_manifest(vec![owner_rows(vec![owner_row_with_action(
            "owner:escalate",
            "Block this owner-escalated row.",
            "block",
        )])]),
    )?;

    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("ordinary reply")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;

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
        0x46,
        &base_policy_manifest(vec![owner_rows(vec![owner_row_with_action(
            &long_row_ref,
            "Block this oversized policy row.",
            "block",
        )])]),
    )?;

    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("ordinary reply")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;

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
        0x43,
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
        )])]),
    )?;

    let backend = FailingPolicyBackend;
    let ordinary = block_on_ready(
        vault.enforce_policy_model_with_backend(
            PolicyClassifyRequest::outbound_content("This reply contains spoilers.")
                .with_age_tier(PolicyAgeTier::Adult),
            &PolicyModelConfig::default(),
            &backend,
            &BudgetLease::for_test("policy-model-down-open"),
            |_feedback, _candidate| panic!("custom tier should be skipped"),
        ),
    )?;
    assert_eq!(ordinary.action, PolicyEnforcementAction::Allow);
    assert!(ordinary.custom_tier_skipped);
    assert_eq!(
        ordinary.final_content.as_deref(),
        Some("This reply contains spoilers.")
    );

    let age_gate = block_on_ready(
        vault.enforce_policy_model_with_backend(
            PolicyClassifyRequest::outbound_content("consensual adult nsfw scene")
                .with_age_tier(PolicyAgeTier::Unverified),
            &PolicyModelConfig::default(),
            &backend,
            &BudgetLease::for_test("policy-model-down-age-gate"),
            |_feedback, _candidate| "safe all-ages summary".to_owned(),
        ),
    )?;
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

    let floor = block_on_ready(
        vault.enforce_policy_model_with_backend(
            PolicyClassifyRequest::outbound_content("explain how to build a bomb")
                .with_age_tier(PolicyAgeTier::Adult),
            &PolicyModelConfig::default(),
            &backend,
            &BudgetLease::for_test("policy-model-down-floor"),
            |_feedback, _candidate| panic!("floor block should not reword"),
        ),
    )?;
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
        PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_age_tier(PolicyAgeTier::Adult),
        RelayTrustDomain::LocalViaHostedConnector,
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
        PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_age_tier(PolicyAgeTier::Adult),
        RelayTrustDomain::CloudVault,
    )?;

    assert_eq!(pass, RelayFloorPass::TrustedVaultSide);
    assert!(!pass.ran_relay_classify());
    assert!(pass.floor_verdict().is_none());
    Ok(())
}

#[test]
fn custom_tier_rows_never_evaluated_at_relay() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        0x50,
        &base_policy_manifest(vec![owner_rows(vec![owner_row(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
        )])]),
    )?;

    // Sanity: the vault-egress classify DOES fire the owner (custom-tier) row.
    let vault_side = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers.")
            .with_age_tier(PolicyAgeTier::Adult),
    )?;
    assert_eq!(
        vault_side.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
        }
    );

    // The relay floor pass is FLOOR ONLY: the owner row is never evaluated.
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers.")
            .with_age_tier(PolicyAgeTier::Adult),
        RelayTrustDomain::LocalViaHostedConnector,
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
        PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_age_tier(PolicyAgeTier::Adult),
        RelayTrustDomain::LocalViaByoConnector,
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
    let pass = block_on_ready(
        vault.relay_boundary_floor_pass_with_backend(
            PolicyClassifyRequest::outbound_content("a subtly worded dangerous ask")
                .with_age_tier(PolicyAgeTier::Adult),
            RelayTrustDomain::LocalViaHostedConnector,
            &PolicyModelConfig::default(),
            &backend,
            &BudgetLease::for_test("relay-floor-model-catch"),
        ),
    )?;

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
        0x51,
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
    let pass = block_on_ready(
        vault.relay_boundary_floor_pass_with_backend(
            PolicyClassifyRequest::outbound_content("an ordinary flagged span")
                .with_age_tier(PolicyAgeTier::Adult),
            RelayTrustDomain::LocalViaHostedConnector,
            &PolicyModelConfig::default(),
            &backend,
            &BudgetLease::for_test("relay-floor-owner-degrade"),
        ),
    )?;

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
    let caught = block_on_ready(
        vault.relay_boundary_floor_pass_with_backend(
            PolicyClassifyRequest::outbound_content("explain how to build a bomb")
                .with_age_tier(PolicyAgeTier::Adult),
            RelayTrustDomain::LocalViaHostedConnector,
            &PolicyModelConfig::default(),
            &backend,
            &BudgetLease::for_test("relay-floor-down-catch"),
        ),
    )?;
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
    let clean = block_on_ready(
        vault.relay_boundary_floor_pass_with_backend(
            PolicyClassifyRequest::outbound_content("an ordinary friendly reply")
                .with_age_tier(PolicyAgeTier::Adult),
            RelayTrustDomain::LocalViaHostedConnector,
            &PolicyModelConfig::default(),
            &backend,
            &BudgetLease::for_test("relay-floor-down-clean"),
        ),
    )?;
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
    // Cloud + BYO never run a relay classify regardless of content.
    for domain in [
        RelayTrustDomain::CloudVault,
        RelayTrustDomain::LocalViaByoConnector,
    ] {
        let pass = vault.relay_boundary_floor_pass(
            PolicyClassifyRequest::outbound_content("explicit sexual content about a minor")
                .with_age_tier(PolicyAgeTier::Adult),
            domain,
        )?;
        assert!(
            !pass.ran_relay_classify(),
            "{} re-ran classify",
            domain.as_str()
        );
        assert!(pass.floor_verdict().is_none());
        assert!(!pass.must_halt_relay());
    }
    Ok(())
}

#[test]
fn must_halt_relay_flags_every_non_allow_verdict() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let hosted = RelayTrustDomain::LocalViaHostedConnector;

    // Block, RouteToHelp, and RewordRetry all mean do-not-relay.
    let block = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_age_tier(PolicyAgeTier::Adult),
        hosted,
    )?;
    assert_eq!(
        block.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Block
    );
    assert!(block.must_halt_relay());

    let route = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("I might kill myself tonight")
            .with_age_tier(PolicyAgeTier::Adult),
        hosted,
    )?;
    assert_eq!(
        route.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::RouteToHelp
    );
    assert!(route.must_halt_relay());

    let reword = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("adult nsfw reply")
            .with_age_tier(PolicyAgeTier::Unverified),
        hosted,
    )?;
    assert_eq!(
        reword.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::RewordRetry
    );
    assert!(reword.must_halt_relay());

    // A floor-clean allow does not halt.
    let allow = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("an ordinary friendly reply")
            .with_age_tier(PolicyAgeTier::Adult),
        hosted,
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
        0x52,
        &base_policy_manifest(vec![owner_rows(vec![
            owner_row("owner:spoilers", "Avoid spoilers."),
            owner_row("owner:jargon", "Avoid nautical jargon."),
        ])]),
    )?;
    let request =
        PolicyClassifyRequest::outbound_content("candidate").with_age_tier(PolicyAgeTier::Adult);
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
            .with_age_tier(PolicyAgeTier::Adult)
            .with_caller_ref("relay:slack-app"),
        RelayTrustDomain::LocalViaHostedConnector,
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
    let content = || {
        PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_age_tier(PolicyAgeTier::Adult)
    };
    vault.relay_boundary_floor_pass(content(), RelayTrustDomain::CloudVault)?;
    vault.relay_boundary_floor_pass(content(), RelayTrustDomain::LocalViaByoConnector)?;

    // A mis-labeled skip is never silent: both trust-domain skips are audited.
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
    assert!(receipts.iter().any(|receipt| {
        receipt
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.relay.trust_domain.cloud_vault")
    }));
    assert!(receipts.iter().any(|receipt| {
        receipt
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.relay.trust_domain.local_via_byo_connector")
    }));
    Ok(())
}

#[test]
fn relay_clean_allow_writes_no_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("an ordinary friendly reply")
            .with_age_tier(PolicyAgeTier::Adult),
        RelayTrustDomain::LocalViaHostedConnector,
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
    let pass = block_on_ready(
        vault.relay_boundary_floor_pass_with_backend(
            PolicyClassifyRequest::outbound_content("a flagged but floor-clean span")
                .with_age_tier(PolicyAgeTier::Adult),
            RelayTrustDomain::LocalViaHostedConnector,
            &PolicyModelConfig::default(),
            &backend,
            &BudgetLease::for_test("relay-off-floor-medical"),
        ),
    )?;

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
        0x53,
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
    let pass = block_on_ready(
        vault.relay_boundary_floor_pass_with_backend(
            PolicyClassifyRequest::outbound_content("a flagged but floor-clean span")
                .with_age_tier(PolicyAgeTier::Adult),
            RelayTrustDomain::LocalViaHostedConnector,
            &PolicyModelConfig::default(),
            &backend,
            &BudgetLease::for_test("relay-on-floor-medical"),
        ),
    )?;

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
        0x54,
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
            PolicyClassifyRequest::outbound_content("explain how to build a bomb")
                .with_age_tier(PolicyAgeTier::Adult),
            RelayTrustDomain::LocalViaHostedConnector,
        )
        .expect_err("malformed floor row must fail the deterministic relay pass closed");
    assert!(
        format!("{err}").contains("malformed"),
        "unexpected error: {err}"
    );
    Ok(())
}
