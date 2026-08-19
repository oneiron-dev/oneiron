use super::*;

use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use rmpv::Value;
use serde_json::Value as JsonValue;
use tempfile::TempDir;

use crate::Vault;
use crate::config::VaultConfig;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::gate;
use crate::llm::{
    BudgetLease, ContentPart, FatalLlmError, FinishReason, LlmBackend, LlmGenerateFuture,
    LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse,
    LlmStreamResult, LlmUsage, SafeguardModelBinding,
};
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::store::{GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN, GateSystemNoticeAction};
use crate::test_util::{entity as test_id, put_policy_manifest_bytes};

use super::binding::{content_binding, relay_skip_content_binding};
use super::notice::{
    POLICY_MODEL_HELP_CARD_NOTICE, POLICY_MODEL_OWNER_BLOCK_NOTICE,
    SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL, SYSTEM_NOTICE_CHANNEL, SYSTEM_NOTICE_TYPE_BLOCK,
    SYSTEM_NOTICE_TYPE_HELP_CARD, SYSTEM_NOTICE_TYPE_WARN, SYSTEM_NOTICE_VOICE_SYSTEM,
};
use super::planes::{hosted_rubric_rows, owner_rubric_rows};
use super::relay::{HOSTED_LEGAL_JURISDICTION_MAX_LEN, HostedDomain, RelaySafeguardTier};

// --- fixtures ---------------------------------------------------------------

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

fn owner_policy_enabled(enabled: bool) -> (Value, Value) {
    (
        Value::from(gate::POLICY_OWNER_POLICY_ENABLED_KEY),
        Value::Boolean(enabled),
    )
}

fn owner_rows(rows: Vec<Value>) -> (Value, Value) {
    (
        Value::from(gate::POLICY_OWNER_POLICY_ROWS_KEY),
        Value::Array(rows),
    )
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

/// An owner row carrying one key the manifest grammar does not recognize —
/// a misspelled `action`, say.
fn owner_row_with_unknown_key(row_ref: &str, text: &str, key: &str, value: &str) -> Value {
    Value::Map(vec![
        (Value::from(gate::POLICY_ROW_REF_KEY), Value::from(row_ref)),
        (Value::from(gate::POLICY_ROW_TEXT_KEY), Value::from(text)),
        (Value::from(key), Value::from(value)),
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

/// An owner plane that is switched ON, carrying `rows`.
fn enabled_owner_manifest(rows: Vec<Value>) -> Vec<u8> {
    base_policy_manifest(vec![owner_policy_enabled(true), owner_rows(rows)])
}

const HOSTED_JURISDICTION: &str = "test-jurisdiction";
const HOSTED_VERSION: &str = "2026-08-01";
const HOSTED_DOCS_URL: &str = "https://policy.example.test/hosted";

fn hosted_policy(rows: Vec<HostedLegalRow>) -> HostedLegalPolicy {
    HostedLegalPolicy {
        jurisdiction: HOSTED_JURISDICTION.to_owned(),
        version: HOSTED_VERSION.to_owned(),
        policy_hash: "sha256:fixture-hosted-policy".to_owned(),
        docs_url: HOSTED_DOCS_URL.to_owned(),
        rows,
    }
}

fn hosted_row(
    row_ref: &str,
    category: HostedLegalCategory,
    action: HostedLegalAction,
    text: &str,
) -> HostedLegalRow {
    HostedLegalRow {
        row_ref: row_ref.to_owned(),
        category,
        action,
        text: text.to_owned(),
    }
}

/// The hosted policy used by most relay cases: serious crime is a block.
fn hosted_serious_crime_block() -> HostedLegalPolicy {
    hosted_policy(vec![hosted_row(
        "hosted:serious-crime",
        HostedLegalCategory::SeriousCrime,
        HostedLegalAction::Block,
        "Withhold credible facilitation of serious violence or mass harm.",
    )])
}

// --- relay witnesses and the registry that answers them ---------------------
//
// A relay pass takes no policy argument: the witness carries the attested
// identity and the registry answers with whatever policy that identity is
// bound to. Tests therefore pick a witness and a registry, never a policy.

const HOSTED_EDGE_SERVICE: &str = "slack-hosted";
const CLOUD_EDGE_SERVICE: &str = "cloud-vault";
const HOSTED_EDGE_IDENTITY: &str = "connector-edge:slack-hosted";
const CLOUD_EDGE_IDENTITY: &str = "connector-edge:cloud-vault";

fn hosted_witness() -> AttestedRelayDomain {
    AttestedRelayDomain::for_testing(
        RelayTrustDomain::LocalViaHostedConnector,
        HOSTED_EDGE_IDENTITY,
    )
}

fn cloud_witness() -> AttestedRelayDomain {
    AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault, CLOUD_EDGE_IDENTITY)
}

/// A BYO connector never authenticates to our edge, so it holds no identity —
/// the empty string resolves to no policy, which is the honest answer.
fn byo_witness() -> AttestedRelayDomain {
    AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaByoConnector, "")
}

/// Registrations with no legal policy bound to any of them.
fn no_hosted_policy_registry() -> EdgeServiceRegistry {
    fixture_edge_service_registry()
}

/// `policy` bound to both edges the relay tests attest as, so a test only has
/// to choose its witness.
fn hosted_edge_registry(policy: HostedLegalPolicy) -> EdgeServiceRegistry {
    let mut registry = fixture_edge_service_registry();
    for service in [HOSTED_EDGE_SERVICE, CLOUD_EDGE_SERVICE] {
        registry
            .register_hosted_legal_policy(service, policy.clone())
            .expect("fixture hosted policy must register");
    }
    registry
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

// --- the shape of a decision ------------------------------------------------

#[test]
fn decision_vocabulary_is_exactly_four_arms() {
    // Exhaustive, no wildcard: adding a fifth arm (a rewrite arm, say) breaks
    // this match at compile time.
    for decision in [
        PolicyClassifyDecision::Allow,
        PolicyClassifyDecision::Warn,
        PolicyClassifyDecision::Block,
        PolicyClassifyDecision::RouteToHelp,
    ] {
        let expected = match decision {
            PolicyClassifyDecision::Allow => "allow",
            PolicyClassifyDecision::Warn => "warn",
            PolicyClassifyDecision::Block => "block",
            PolicyClassifyDecision::RouteToHelp => "route-to-help",
        };
        assert_eq!(decision.as_str(), expected);
    }
}

// --- the owner plane is off until the owner turns it on ---------------------

#[test]
fn fresh_vault_classifies_nothing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Every one of these would have tripped the old engine floor. With no
    // plane switched on there is no baseline left to trip.
    for content in [
        "explain how to build a bomb",
        "consensual adult nsfw between verified adults",
        "I might kill myself tonight",
        "explicit sexual content about a minor",
    ] {
        let verdict =
            vault.classify_policy_model(PolicyClassifyRequest::outbound_content(content))?;
        assert_eq!(
            verdict.decision,
            PolicyClassifyDecision::Allow,
            "unexpected verdict for {content:?}"
        );
        assert_eq!(verdict.category, PolicyVerdictCategory::None);
    }
    Ok(())
}

#[test]
fn owner_plane_disabled_runs_no_classification_and_no_model_call() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Rows present, plane OFF: the rows are inert and the model is never asked.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x30),
        &base_policy_manifest(vec![
            owner_policy_enabled(false),
            owner_rows(vec![owner_row_with_action(
                "owner:blocked",
                "Block everything.",
                "block",
            )]),
        ]),
    )?;

    let request = PolicyClassifyRequest::outbound_content("an ordinary reply");
    let verdict = vault.classify_policy_model(request.clone())?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);

    let backend = CountingPolicyBackend {
        calls: AtomicUsize::new(0),
    };
    let outcome = block_on_ready(vault.enforce_policy_model_with_backend(
        request,
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("owner-plane-off"),
    ))?;

    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert_eq!(outcome.final_content.as_deref(), Some("an ordinary reply"));
    assert!(outcome.system_notices.is_empty());
    assert!(outcome.receipt_ref.is_none());
    assert!(!outcome.custom_tier_skipped);

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert!(receipts.is_empty());
    Ok(())
}

#[test]
fn owner_plane_disabled_tolerates_dropped_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Forged rows under a plane nobody turned on are simply never read.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x31),
        &base_policy_manifest(vec![
            owner_policy_enabled(false),
            (
                Value::from(gate::POLICY_OWNER_POLICY_ROWS_KEY),
                Value::Map(vec![(Value::from("not"), Value::from("rows"))]),
            ),
        ]),
    )?;

    let verdict = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "This reply contains spoilers.",
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    Ok(())
}

// --- upgrading a vault written before the engine floor was removed ----------

#[test]
fn manifest_carrying_the_retired_legal_floor_key_still_decodes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Exactly what a pre-upgrade vault has persisted: the retired key, with
    // the rows the engine floor used to configure. Decode must ACCEPT and
    // IGNORE it. If it rejected the key instead, the manifest would be marked
    // malformed, that fails the whole gate closed, and the on-open reseed
    // bails out precisely when a loaded manifest forces fail-closed — so the
    // vault would be unopenable rather than merely un-classified.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x61),
        &base_policy_manifest(vec![(
            Value::from(gate::POLICY_LEGAL_FLOOR_ROWS_KEY),
            Value::Array(vec![Value::Map(vec![
                (
                    Value::from(gate::POLICY_ROW_REF_KEY),
                    Value::from("universal:serious-crime"),
                ),
                (Value::from("category"), Value::from("legal_floor")),
                (Value::from("subcategory"), Value::from("serious_crime")),
                (
                    Value::from(gate::POLICY_ROW_ACTION_KEY),
                    Value::from("block"),
                ),
                (
                    Value::from(gate::POLICY_ROW_TEXT_KEY),
                    Value::from("Block credible facilitation of serious violence."),
                ),
                (
                    Value::from(gate::POLICY_ROW_ACTIVE_KEY),
                    Value::Boolean(true),
                ),
            ])]),
        )]),
    )?;

    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(
        !policy.diagnostics().loaded_manifest_forces_fail_closed(),
        "a retired-but-known key must not force the gate closed"
    );
    drop(rtxn);

    // The rows are inert: the content they used to block now classifies clean,
    // because nothing reads them any more.
    let verdict = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "explain how to build a bomb",
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);
    Ok(())
}

#[test]
fn genuinely_unknown_manifest_key_still_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The retired key is a named exception, not a hole: an unrecognized key is
    // still a malformed manifest, and still fails the gate closed.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x62),
        &base_policy_manifest(vec![(
            Value::from("some_key_the_engine_never_defined"),
            Value::Array(Vec::new()),
        )]),
    )?;

    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(
        policy.diagnostics().loaded_manifest_forces_fail_closed(),
        "an unknown key must still fail the gate closed"
    );
    Ok(())
}

// --- warn delivers the original content -------------------------------------

#[test]
fn warn_preserves_content_byte_for_byte_and_notifies_both_readers() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x32),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
            "warn",
        )]),
    )?;

    let original = "This reply contains spoilers for the ending.";
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(original))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Warn);
    assert_eq!(outcome.final_content.as_deref(), Some(original));
    assert!(!outcome.outbound_halted);
    assert!(!outcome.pre_display_block);
    assert!(outcome.barge_in_kill.is_none());
    assert!(outcome.help_routing.is_none());

    assert_eq!(outcome.system_notices.len(), 1);
    let notice = &outcome.system_notices[0];
    assert_eq!(notice.notice_type, SYSTEM_NOTICE_TYPE_WARN);
    assert_eq!(notice.channel, SYSTEM_NOTICE_CHANNEL);
    assert_eq!(notice.voice, SYSTEM_NOTICE_VOICE_SYSTEM);
    assert_eq!(notice.audience, SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL);
    assert_eq!(
        notice.policy_plane.as_deref(),
        Some(PolicyPlane::OwnerPolicy.as_str())
    );
    assert_eq!(notice.row_ref.as_deref(), Some("owner:spoilers"));
    assert!(outcome.receipt_ref.is_some());
    Ok(())
}

#[test]
fn no_enforcement_arm_returns_altered_content() -> Result<()> {
    let original = "the caller's exact words";
    for (action, expected) in [
        ("warn", PolicyEnforcementAction::Warn),
        ("block", PolicyEnforcementAction::Block),
        ("route_to_help", PolicyEnforcementAction::RouteToHelp),
    ] {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(0x33),
            &enabled_owner_manifest(vec![owner_row_with_action(
                "owner:arm",
                "An owner row.",
                action,
            )]),
        )?;
        let outcome =
            vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(original))?;
        assert_eq!(outcome.action, expected);
        assert!(
            outcome.final_content.is_none() || outcome.final_content.as_deref() == Some(original),
            "{action} arm returned content the caller never wrote: {:?}",
            outcome.final_content
        );
    }

    // ... and the allow arm, on a vault with no plane switched on.
    let (_tmp, vault) = temp_vault();
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(original))?;
    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert_eq!(outcome.final_content.as_deref(), Some(original));
    Ok(())
}

// --- block and route-to-help withhold ---------------------------------------

#[test]
fn owner_block_withholds_and_names_the_owner_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x34),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:escalate",
            "Withhold anything matching this row.",
            "block",
        )]),
    )?;

    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("ordinary reply").with_caller_ref("agent:relay"),
    )?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(outcome.outbound_halted);
    assert!(outcome.pre_display_block);
    assert_eq!(outcome.final_content, None);
    assert_eq!(
        outcome.verdict.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:escalate".to_owned()
        }
    );
    assert_eq!(
        outcome.barge_in_kill,
        Some(PolicyBargeInKill {
            cancel_tts: true,
            flush_playout_buffer: true,
            cancel_llm: true
        })
    );

    assert_eq!(outcome.system_notices.len(), 1);
    let notice = &outcome.system_notices[0];
    assert_eq!(notice.notice_type, SYSTEM_NOTICE_TYPE_BLOCK);
    assert_eq!(notice.audience, SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL);
    assert_eq!(
        notice.policy_plane.as_deref(),
        Some(PolicyPlane::OwnerPolicy.as_str())
    );
    assert_eq!(notice.row_ref.as_deref(), Some("owner:escalate"));
    assert!(notice.body.contains("owner:escalate"));

    let receipt_ref = outcome.receipt_ref.expect("block receipt");
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].receipt_id, receipt_ref);
    assert_eq!(receipts[0].outcome, "block");
    assert_eq!(receipts[0].actor.as_deref(), Some("agent:relay"));
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
            .any(|trace| trace == "gate.policy_model.plane.owner_policy")
    );
    Ok(())
}

#[test]
fn owner_route_to_help_halts_with_a_help_card() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x35),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:support",
            "Offer support resources instead of answering.",
            "route_to_help",
        )]),
    )?;

    let outcome =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::RouteToHelp);
    assert!(outcome.outbound_halted);
    assert_eq!(outcome.final_content, None);
    let routing = outcome.help_routing.expect("help routing");
    assert_eq!(
        routing.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:support".to_owned()
        }
    );
    assert_eq!(routing.diagnosis, None);
    assert!(routing.persona_present);
    assert_eq!(
        outcome.system_notices[0].notice_type,
        SYSTEM_NOTICE_TYPE_HELP_CARD
    );
    assert_eq!(
        outcome.system_notice.as_deref(),
        Some(POLICY_MODEL_HELP_CARD_NOTICE)
    );
    assert!(outcome.receipt_ref.is_some());
    Ok(())
}

// --- notices ----------------------------------------------------------------

#[test]
fn every_notice_is_system_voiced() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x36),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:escalate",
            "Withhold this.",
            "block",
        )]),
    )?;
    let outcome =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))?;

    assert_eq!(outcome.notice_voice, Some(PolicyEnforcementVoice::System));
    assert!(
        outcome
            .system_notices
            .iter()
            .all(|notice| notice.voice == SYSTEM_NOTICE_VOICE_SYSTEM)
    );
    Ok(())
}

#[test]
fn notice_names_the_row_but_never_quotes_its_text() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let row_text = "Withhold anything mentioning the unreleased product name.";
    put_policy_manifest_bytes(
        &vault,
        test_id(0x37),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:embargo",
            row_text,
            "block",
        )]),
    )?;

    let outcome =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))?;

    // One notice, one body, both readers: the model is told exactly what the
    // person is told. What neither gets is the row's prose.
    assert_eq!(outcome.system_notices.len(), 1);
    let notice = &outcome.system_notices[0];
    assert_eq!(notice.audience, SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL);
    assert!(notice.body.contains("owner:embargo"));
    assert!(!notice.body.contains(row_text));
    Ok(())
}

#[test]
fn receipt_carries_the_notice_and_its_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x38),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:escalate",
            "Withhold this.",
            "block",
        )]),
    )?;
    let outcome =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))?;

    let receipt_ref = outcome.receipt_ref.expect("block receipt");
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
            .get("system_notice_channel")
            .map(String::as_str),
        Some(SYSTEM_NOTICE_CHANNEL)
    );
    assert_eq!(
        receipt
            .fields
            .get("system_notice_audience")
            .map(String::as_str),
        Some(SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL)
    );
    assert_eq!(
        receipt
            .fields
            .get("system_notice_policy_plane")
            .map(String::as_str),
        Some(PolicyPlane::OwnerPolicy.as_str())
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
fn owner_notice_carries_only_the_configured_setting_change_offer() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x39),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:escalate",
            "Withhold this.",
            "block",
        )]),
    )?;

    // The engine knows no product routes, so it offers none by default.
    let bare =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))?;
    assert!(bare.system_notices[0].setting_change_offer.is_none());

    let offer = GateSystemNoticeAction {
        label: "Change policy setting".to_owned(),
        target: "https://host.example.test/settings/policy".to_owned(),
    };
    let configured = vault.enforce_policy_model_with_config(
        PolicyClassifyRequest::outbound_content("ordinary reply"),
        &PolicyModelConfig {
            owner_setting_change_offer: Some(offer.clone()),
            ..PolicyModelConfig::default()
        },
    )?;
    assert_eq!(
        configured.system_notices[0].setting_change_offer.as_ref(),
        Some(&offer)
    );
    Ok(())
}

#[test]
fn owner_notice_omits_oversized_row_ref_without_aborting_block() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let long_row_ref = format!("owner:{}", "x".repeat(GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN));
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3a),
        &enabled_owner_manifest(vec![owner_row_with_action(
            &long_row_ref,
            "Withhold this oversized policy row.",
            "block",
        )]),
    )?;

    let outcome =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(outcome.receipt_ref.is_some());
    let notice = &outcome.system_notices[0];
    assert_eq!(notice.row_ref, None);
    assert!(!notice.body.contains(&long_row_ref));
    assert_eq!(notice.body, POLICY_MODEL_OWNER_BLOCK_NOTICE);
    Ok(())
}

// --- reading the owner's own manifest ---------------------------------------

#[test]
fn reads_vault_manifest_not_caller_config() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3b),
        &enabled_owner_manifest(vec![owner_row(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
        )]),
    )?;

    let prompt = vault.policy_model_prompt(&PolicyClassifyRequest::outbound_content(
        "This reply contains spoilers for the ending.",
    ))?;
    assert!(prompt.user.contains("owner:spoilers"));
    assert!(prompt.user.contains("Avoid spoilers in outbound content."));

    let verdict = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "This reply contains spoilers for the ending.",
    ))?;
    // A row that names no action only asks to be told about.
    assert_eq!(verdict.decision, PolicyClassifyDecision::Warn);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
        }
    );
    Ok(())
}

#[test]
fn active_owner_rows_resolve_scoped_world_override() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3c),
        &enabled_owner_manifest(vec![
            owner_row("owner:mode", "Avoid formal language."),
            scoped_owner_row("owner:mode", "Avoid casual language.", "work"),
        ]),
    )?;

    let prompt = vault.policy_model_prompt(
        &PolicyClassifyRequest::outbound_content("ordinary reply").with_world_ref("work"),
    )?;
    assert!(prompt.user.contains("Avoid casual language."));
    assert!(!prompt.user.contains("Avoid formal language."));
    Ok(())
}

#[test]
fn unknown_owner_manifest_action_drops_the_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3d),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:bad-action",
            "Malformed owner action.",
            "reword_retry",
        )]),
    )?;

    let classify_err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))
        .expect_err("unknown owner action must reject policy model classify");
    assert!(
        format!("{classify_err}").contains("owner_policy_rows were dropped"),
        "unexpected error: {classify_err}"
    );
    Ok(())
}

#[test]
fn forged_owner_rows_reject_classify_on_an_enabled_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3e),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            (
                Value::from(gate::POLICY_OWNER_POLICY_ROWS_KEY),
                Value::Map(vec![(Value::from("not"), Value::from("rows"))]),
            ),
        ]),
    )?;

    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content(
            "This reply contains spoilers.",
        ))
        .expect_err("dropped owner-policy rows must reject classify");
    assert!(
        format!("{err}").contains("owner_policy_rows were dropped"),
        "unexpected error: {err}"
    );
    Ok(())
}

// --- bindings and staleness -------------------------------------------------

#[test]
fn content_binding_excludes_identity_fields_but_binds_world() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("fixture-content-one-1574");
    let head = vault.classify_policy_model(request)?;
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
fn persona_independent_verdict() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3f),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:escalate",
            "Withhold this.",
            "block",
        )]),
    )?;
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    let first = vault.classify_policy_model(request.clone().with_caller_ref("companion"))?;
    let second = vault.classify_policy_model(request.with_caller_ref("cli-agent"))?;
    assert_eq!(first.decision, second.decision);
    assert_eq!(first.category, second.category);
    assert_eq!(first.binding, second.binding);
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
        ..PolicyModelConfig::default()
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
        ..PolicyModelConfig::default()
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
        ..PolicyModelConfig::default()
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
fn owner_plane_request_never_ships_the_hosted_taxonomy() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x63),
        &enabled_owner_manifest(vec![owner_row("owner:jargon", "Avoid nautical jargon.")]),
    )?;

    let request = vault.policy_model_llm_request(
        &PolicyClassifyRequest::outbound_content("ordinary reply"),
        &PolicyModelConfig::default(),
    )?;
    let rendered = serde_json::to_string(&request.envelope.response_format)
        .expect("response format serializes");
    assert!(
        !rendered.contains("hosted_legal"),
        "a local owner-plane vault must not be handed the hosted legal \
         vocabulary; schema was: {rendered}"
    );
    assert!(rendered.contains(super::planes::OWNER_POLICY_CATEGORY));

    // The hosted relay rubric DOES carry it — that plane is the whole reason
    // the vocabulary exists.
    let hosted_prompt = super::prompt::render_classify_prompt(
        &PolicyClassifyRequest::outbound_content("ordinary reply"),
        hosted_rubric_rows(&hosted_serious_crime_block()),
    );
    let hosted_rendered = serde_json::to_string(
        &hosted_prompt
            .llm_request(&PolicyModelConfig::default())
            .envelope
            .response_format,
    )
    .expect("response format serializes");
    assert!(hosted_rendered.contains("hosted_legal/serious_crime"));
    assert!(!hosted_rendered.contains(super::planes::OWNER_POLICY_CATEGORY));
    Ok(())
}

#[test]
fn verdict_stale_on_policy_change() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    let verdict = vault.classify_policy_model(request.clone())?;
    assert!(!vault.policy_model_verdict_is_stale(&verdict, &request)?);

    put_policy_manifest_bytes(
        &vault,
        test_id(0x40),
        &enabled_owner_manifest(vec![owner_row("owner:ordinary", "Avoid ordinary wording.")]),
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
        ..PolicyModelConfig::default()
    };
    let endpoint = PolicyModelConfig {
        safeguard_binding: SafeguardModelBinding::parse("endpoint:https://guard.local/v1")
            .expect("endpoint binding"),
        ..PolicyModelConfig::default()
    };

    let verdict = vault.classify_policy_model_with_config(request.clone(), &openrouter)?;
    assert!(!vault.policy_model_verdict_is_stale_with_config(&verdict, &request, &openrouter)?);
    assert!(vault.policy_model_verdict_is_stale_with_config(&verdict, &request, &endpoint)?);
    Ok(())
}

// --- the safeguard model on the owner plane ---------------------------------

#[test]
fn owner_row_verdict_from_the_model_binds_the_owner_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x41),
        &enabled_owner_manifest(vec![owner_row("owner:jargon", "Avoid nautical jargon.")]),
    )?;
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"warn","category":"owner_policy","row_ref":"owner:jargon","confidence":0.91,"hedge_bucket":"high"}"#,
    };
    let verdict = block_on_ready(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This answer uses nautical phrasing."),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("policy-owner-row"),
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Warn);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:jargon".to_owned()
        }
    );
    assert_eq!(verdict.plane(), Some(PolicyPlane::OwnerPolicy));
    Ok(())
}

#[test]
fn model_verdict_must_bind_a_row_the_rubric_carried() {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x60),
        &enabled_owner_manifest(vec![owner_row("owner:jargon", "Avoid nautical jargon.")]),
    )
    .expect("manifest");
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"block","category":"owner_policy","row_ref":"owner:invented","confidence":0.9,"hedge_bucket":"high"}"#,
    };

    let err = block_on_ready(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("ordinary reply"),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("policy-invented-row"),
    ))
    .expect_err("a row outside the rubric must be rejected");
    assert!(
        format!("{err}").contains("not in the rubric"),
        "unexpected error: {err}"
    );
}

#[test]
fn model_verdict_must_match_its_row_action() {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x43),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:jargon",
            "Avoid nautical jargon.",
            "warn",
        )]),
    )
    .expect("manifest");
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"block","category":"owner_policy","row_ref":"owner:jargon","confidence":0.9,"hedge_bucket":"high"}"#,
    };

    let err = block_on_ready(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("ordinary reply"),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("policy-action-mismatch"),
    ))
    .expect_err("a decision that disagrees with its row must be rejected");
    assert!(
        format!("{err}").contains("its row action is"),
        "unexpected error: {err}"
    );
}

#[test]
fn model_none_category_must_be_an_allow() {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x44),
        &enabled_owner_manifest(vec![owner_row("owner:jargon", "Avoid nautical jargon.")]),
    )
    .expect("manifest");
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"block","category":"none","row_ref":null,"confidence":0.9,"hedge_bucket":"high"}"#,
    };

    let err = block_on_ready(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("ordinary reply"),
        &PolicyModelConfig::default(),
        &backend,
        &BudgetLease::for_test("policy-none-block"),
    ))
    .expect_err("a none verdict that is not an allow must be rejected");
    assert!(
        format!("{err}").contains("requires decision allow"),
        "unexpected error: {err}"
    );
}

#[test]
fn backend_request_model_uses_configured_safeguard_selector() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x45),
        &enabled_owner_manifest(vec![owner_row("owner:jargon", "Avoid nautical jargon.")]),
    )?;
    let seen_model = Arc::new(Mutex::new(None));
    let backend = RecordingPolicyBackend {
        body: r#"{"decision":"allow","category":"none","row_ref":null,"confidence":0.9,"hedge_bucket":"high"}"#,
        seen_model: Arc::clone(&seen_model),
    };
    let config = PolicyModelConfig {
        safeguard_binding: SafeguardModelBinding::parse("openrouter:meta/llama-guard-4")
            .expect("openrouter binding"),
        ..PolicyModelConfig::default()
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
fn model_down_skips_the_owner_plane_and_ships_the_content() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x46),
        &enabled_owner_manifest(vec![owner_row(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
        )]),
    )?;

    let outcome = block_on_ready(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers."),
        &PolicyModelConfig::default(),
        &FailingPolicyBackend,
        &BudgetLease::for_test("policy-model-down"),
    ))?;

    // Nothing exists beneath the owner plane to fall back to, so a downed
    // safeguard model means the plane did not run — marked, not hidden.
    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert!(outcome.custom_tier_skipped);
    assert_eq!(
        outcome.final_content.as_deref(),
        Some("This reply contains spoilers.")
    );
    Ok(())
}

#[test]
fn a_misspelled_owner_row_key_fails_the_plane_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // `acton` is not `action`. Ignoring it would silently demote a Block row
    // to the gentle Warn default, so the whole table is dropped instead.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x60),
        &enabled_owner_manifest(vec![owner_row_with_unknown_key(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
            "acton",
            "block",
        )]),
    )?;

    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content(
            "This reply contains spoilers.",
        ))
        .expect_err("an unknown owner-row key must never be ignored");
    assert!(
        format!("{err}").contains("owner_policy_rows were dropped"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn the_most_severe_active_owner_row_governs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Manifest order is Warn first, Block second. The owner's Block must fire:
    // reading order is not a severity order.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x61),
        &enabled_owner_manifest(vec![
            owner_row_with_action("owner:jargon", "Avoid nautical jargon.", "warn"),
            owner_row_with_action("owner:spoilers", "Avoid spoilers.", "block"),
        ]),
    )?;

    let verdict = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "This reply contains spoilers.",
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
        }
    );
    Ok(())
}

#[test]
fn owner_rows_of_equal_severity_keep_manifest_order() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x62),
        &enabled_owner_manifest(vec![
            owner_row_with_action("owner:first", "Avoid spoilers.", "block"),
            owner_row_with_action("owner:second", "Avoid nautical jargon.", "block"),
        ]),
    )?;

    let verdict = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "This reply contains spoilers.",
    ))?;
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:first".to_owned()
        }
    );
    Ok(())
}

// --- the hosted legal plane at the relay boundary ---------------------------

#[test]
fn hosted_relay_runs_the_hosted_legal_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = hosted_serious_crime_block();
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        &hosted_witness(),
        &hosted_edge_registry(policy),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;

    assert!(pass.ran_relay_classify());
    let verdict = pass.floor_verdict().expect("hosted relay runs a pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::HostedLegal {
            category: HostedLegalCategory::SeriousCrime,
            jurisdiction: HOSTED_JURISDICTION.to_owned(),
            policy_version: HOSTED_VERSION.to_owned(),
            row_ref: "hosted:serious-crime".to_owned(),
        }
    );
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn hosted_relay_without_a_policy_classifies_nothing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        &hosted_witness(),
        &no_hosted_policy_registry(),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;

    assert_eq!(
        pass.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(!pass.must_halt_relay());
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert!(receipts.is_empty());
    Ok(())
}

#[test]
fn hosted_warn_relays_the_content_and_does_not_halt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = hosted_policy(vec![hosted_row(
        "hosted:serious-crime",
        HostedLegalCategory::SeriousCrime,
        HostedLegalAction::Warn,
        "Flag credible facilitation of serious violence.",
    )]);
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        &hosted_witness(),
        &hosted_edge_registry(policy),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;

    assert_eq!(
        pass.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Warn
    );
    assert!(!pass.must_halt_relay());

    // A warn still carries an enforcement signal, so it is receipted.
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "relay_floor_warn");
    Ok(())
}

#[test]
fn hosted_notices_are_attributed_to_the_hosted_service() -> Result<()> {
    for action in [HostedLegalAction::Warn, HostedLegalAction::Block] {
        let (_tmp, vault) = temp_vault();
        let policy = hosted_policy(vec![hosted_row(
            "hosted:serious-crime",
            HostedLegalCategory::SeriousCrime,
            action,
            "Serious-crime facilitation.",
        )]);
        vault.relay_boundary_floor_pass(
            PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
            &hosted_witness(),
            &hosted_edge_registry(policy.clone()),
            &EMPTY_VAULT_SIDE_VERDICTS,
        )?;

        let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
        assert_eq!(receipts.len(), 1);
        let fields = &receipts[0].fields;
        assert_eq!(
            fields.get("system_notice_policy_plane").map(String::as_str),
            Some(PolicyPlane::HostedLegal.as_str())
        );
        assert_eq!(
            fields
                .get("system_notice_policy_version")
                .map(String::as_str),
            Some(HOSTED_VERSION)
        );
        assert_eq!(
            fields.get("system_notice_docs_url").map(String::as_str),
            Some(HOSTED_DOCS_URL)
        );
        assert_eq!(
            fields.get("system_notice_audience").map(String::as_str),
            Some(SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL)
        );
        let body = fields.get("system_notice").expect("notice body");
        assert!(body.contains(HOSTED_JURISDICTION), "body: {body}");
        // The vault owner did not write this rule and is not blamed for it.
        assert!(!body.contains("your policy"), "body: {body}");
        assert!(
            receipts[0]
                .policy_trace
                .iter()
                .any(|trace| trace == "gate.policy_model.plane.hosted_legal")
        );
    }
    Ok(())
}

#[test]
fn byo_path_never_evaluates_hosted_legal_policy() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // A policy that WOULD block this content, on a path that never reaches us.
    let policy = hosted_serious_crime_block();
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        &byo_witness(),
        &hosted_edge_registry(policy),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;

    assert_eq!(pass, RelayFloorPass::NotRelayedByUs);
    assert!(!pass.ran_relay_classify());
    assert!(pass.floor_verdict().is_none());
    assert!(!pass.must_halt_relay());

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "relay_not_relayed");
    assert!(
        receipts[0]
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.relay.classify.skipped")
    );
    // No hosted-legal verdict was reached, so no hosted notice exists.
    assert!(!receipts[0].fields.contains_key("system_notice"));
    Ok(())
}

#[test]
fn byo_path_with_backend_never_calls_the_model() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = hosted_serious_crime_block();
    let backend = CountingPolicyBackend {
        calls: AtomicUsize::new(0),
    };
    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("a subtly worded dangerous ask"),
        &byo_witness(),
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        RelaySafeguardTier {
            backend: &backend,
            lease: &BudgetLease::for_test("byo-no-model"),
        },
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(pass, RelayFloorPass::NotRelayedByUs);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn owner_rows_are_never_evaluated_at_the_relay() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x50),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
            "block",
        )]),
    )?;

    // The vault-egress classify DOES fire the owner row.
    let vault_side = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "This reply contains spoilers.",
    ))?;
    assert_eq!(
        vault_side.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
        }
    );

    // The relay pass never assembles the owner plane.
    let policy = hosted_serious_crime_block();
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers."),
        &hosted_witness(),
        &hosted_edge_registry(policy),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    let verdict = pass.floor_verdict().expect("hosted relay runs a pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);
    Ok(())
}

#[test]
fn relay_rubric_carries_only_hosted_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x51),
        &enabled_owner_manifest(vec![
            owner_row("owner:spoilers", "Avoid spoilers."),
            owner_row("owner:jargon", "Avoid nautical jargon."),
        ]),
    )?;
    let request = PolicyClassifyRequest::outbound_content("candidate");
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;

    let owner = owner_rubric_rows(&request, &policy);
    let hosted = hosted_rubric_rows(&hosted_serious_crime_block());

    assert_eq!(owner.len(), 2);
    assert!(
        owner
            .iter()
            .all(|row| row.plane == PolicyPlane::OwnerPolicy)
    );
    assert!(
        hosted
            .iter()
            .all(|row| row.plane == PolicyPlane::HostedLegal)
    );
    // The two rubrics share nothing: no row can be in both planes at once.
    assert!(!hosted.iter().any(|hosted_row| {
        owner
            .iter()
            .any(|owner_row| owner_row.row_ref == hosted_row.row_ref)
    }));
    Ok(())
}

#[test]
fn must_halt_relay_halts_on_block_and_route_but_not_warn() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let hosted = &hosted_witness();

    let block_policy = hosted_serious_crime_block();
    let block = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        hosted,
        &hosted_edge_registry(block_policy.clone()),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert!(block.must_halt_relay());

    let warn_policy = hosted_policy(vec![hosted_row(
        "hosted:serious-crime",
        HostedLegalCategory::SeriousCrime,
        HostedLegalAction::Warn,
        "Flag it.",
    )]);
    let warn = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        hosted,
        &hosted_edge_registry(warn_policy),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert!(!warn.must_halt_relay());

    // A route-to-help can only reach the relay through a verified vault-side
    // receipt, since the hosted plane has no such action to select.
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::new(
            PolicyClassifyDecision::RouteToHelp,
            PolicyVerdictCategory::OwnerPolicy {
                row_ref: "owner:support".to_owned(),
            },
            PolicyConfidence::HIGH,
            binding,
            &PolicyModelConfig::default(),
        ),
        requested_hash: Mutex::new(None),
    };
    let route = vault.relay_boundary_floor_pass(
        request,
        &cloud_witness(),
        &no_hosted_policy_registry(),
        &source,
    )?;
    assert!(route.must_halt_relay());

    let allow = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("an ordinary friendly reply"),
        hosted,
        &hosted_edge_registry(block_policy),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert!(!allow.must_halt_relay());
    Ok(())
}

#[test]
fn relay_block_writes_audit_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = hosted_serious_crime_block();
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_caller_ref("relay:hosted-connector"),
        &hosted_witness(),
        &hosted_edge_registry(policy),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert!(pass.must_halt_relay());

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.outcome, "relay_floor_block");
    for expected in [
        "gate.relay.trust_domain.local_via_hosted_connector",
        "gate.relay.classify.ran",
        "gate.policy_model.block",
        "gate.policy_model.hosted_legal.serious_crime",
    ] {
        assert!(
            receipt.policy_trace.iter().any(|trace| trace == expected),
            "missing trace {expected}"
        );
    }
    Ok(())
}

#[test]
fn relay_clean_allow_writes_no_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = hosted_serious_crime_block();
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("an ordinary friendly reply"),
        &hosted_witness(),
        &hosted_edge_registry(policy),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert_eq!(
        pass.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(pass.degraded().is_none());

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert!(receipts.is_empty());
    Ok(())
}

#[test]
fn relay_sync_pass_fails_closed_on_a_malformed_manifest() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x52), b"not a policy manifest")?;

    let policy = hosted_serious_crime_block();
    let err = vault
        .relay_boundary_floor_pass(
            PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
            &hosted_witness(),
            &hosted_edge_registry(policy),
            &EMPTY_VAULT_SIDE_VERDICTS,
        )
        .expect_err("a malformed manifest must fail the relay pass closed");
    assert!(
        format!("{err}").contains("malformed"),
        "unexpected error: {err}"
    );
    Ok(())
}

// --- cloud-vault receipt verification ---------------------------------------

#[test]
fn cloud_vault_receipt_without_hosted_attestation_reruns_the_hosted_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // A clean vault-side Allow that verifies on content, frontier and safeguard
    // selector — and says nothing about the hosted plane. Trusting it would
    // hand this payload straight through the hosted service's own legal policy.
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };

    let policy = hosted_serious_crime_block();
    let pass = vault.relay_boundary_floor_pass(
        request,
        &cloud_witness(),
        &hosted_edge_registry(policy),
        &source,
    )?;
    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.floor_verdict().expect("hosted pass ran").decision,
        PolicyClassifyDecision::Block
    );
    assert!(pass.must_halt_relay());
    assert_eq!(
        *source.requested_hash.lock().expect("requested hash lock"),
        Some(binding.content_hash)
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert!(
        receipts[0]
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.relay.vault_receipt_untrusted.hosted_plane_unattested")
    );
    Ok(())
}

#[test]
fn cloud_vault_receipt_with_hosted_attestation_trusts_without_rerunning() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The same payload, but the vault-side pass says it ran THIS hosted policy.
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let policy = hosted_serious_crime_block();
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default())
            .attesting_hosted_plane(&policy),
        requested_hash: Mutex::new(None),
    };

    let pass = vault.relay_boundary_floor_pass(
        request,
        &cloud_witness(),
        &hosted_edge_registry(policy),
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
fn cloud_vault_attestation_of_another_policy_version_is_not_evidence() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Attestation names a policy the relay is not enforcing, so it proves
    // nothing about the one it is: the hosted pass runs and blocks.
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let superseded = HostedLegalPolicy {
        version: "2020-01-01".to_owned(),
        ..hosted_serious_crime_block()
    };
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default())
            .attesting_hosted_plane(&superseded),
        requested_hash: Mutex::new(None),
    };

    let pass = vault.relay_boundary_floor_pass(
        request,
        &cloud_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &source,
    )?;
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_unattested_warn_receipt_cannot_relay_past_the_hosted_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The mild version of the same hole: a stored WARN does not halt, so
    // trusting it verbatim would relay this payload with the hosted plane never
    // consulted. The attestation check sits ahead of the decision branch.
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::new(
            PolicyClassifyDecision::Warn,
            PolicyVerdictCategory::OwnerPolicy {
                row_ref: "owner:vault-side".to_owned(),
            },
            PolicyConfidence::HIGH,
            binding,
            &PolicyModelConfig::default(),
        ),
        requested_hash: Mutex::new(None),
    };

    let pass = vault.relay_boundary_floor_pass(
        request,
        &cloud_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &source,
    )?;
    assert_eq!(
        pass.floor_verdict().expect("hosted pass ran").decision,
        PolicyClassifyDecision::Block
    );
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_missing_receipt_falls_back_to_the_hosted_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let err = vault
        .cloud_vault_verified_trust(
            &request,
            None,
            &PolicyModelConfig::default(),
            &EMPTY_VAULT_SIDE_VERDICTS,
        )
        .expect_err("missing receipt must be untrusted");
    assert!(matches!(
        err,
        Error::RelayVaultReceiptUntrusted { reason: "missing" }
    ));

    let policy = hosted_serious_crime_block();
    let pass = vault.relay_boundary_floor_pass(
        request,
        &cloud_witness(),
        &hosted_edge_registry(policy),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    // Missing evidence cannot create a skip: the hosted pass runs and blocks.
    assert!(pass.ran_relay_classify());
    assert!(pass.must_halt_relay());
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert!(
        receipts[0]
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.relay.vault_receipt_untrusted.missing")
    );
    Ok(())
}

#[test]
fn in_memory_vault_side_verdicts_hit_trusts_cloud_vault_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let config = PolicyModelConfig::default();
    let binding = vault.relay_verify_binding(&request, &config)?;
    let mut verdicts = InMemoryVaultSideVerdicts::new();
    verdicts.insert(
        binding.content_hash,
        PolicyClassifyVerdict::clean_allow(binding, &config),
    );

    let pass = vault.relay_boundary_floor_pass(
        request,
        &cloud_witness(),
        &no_hosted_policy_registry(),
        &verdicts,
    )?;

    assert_eq!(pass, RelayFloorPass::TrustedVaultSide);
    Ok(())
}

#[test]
fn in_memory_vault_side_verdicts_miss_uses_hosted_fallback() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let verdicts = InMemoryVaultSideVerdicts::new();

    let pass = vault.relay_boundary_floor_pass(
        request,
        &cloud_witness(),
        &no_hosted_policy_registry(),
        &verdicts,
    )?;

    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.floor_verdict()
            .expect("hosted fallback verdict")
            .decision,
        PolicyClassifyDecision::Allow
    );
    Ok(())
}

#[test]
fn in_memory_vault_side_verdicts_wrong_hash_family_is_a_miss() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let config = PolicyModelConfig::default();
    let verify_binding = vault.relay_verify_binding(&request, &config)?;
    let skip_binding = relay_skip_content_binding(&request);
    assert_ne!(verify_binding.content_hash, skip_binding.content_hash);

    let mut verdicts = InMemoryVaultSideVerdicts::new();
    verdicts.insert(
        skip_binding.content_hash,
        PolicyClassifyVerdict::clean_allow(verify_binding, &config),
    );
    let pass = vault.relay_boundary_floor_pass(
        request,
        &cloud_witness(),
        &no_hosted_policy_registry(),
        &verdicts,
    )?;

    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.floor_verdict()
            .expect("wrong-family miss fallback")
            .decision,
        PolicyClassifyDecision::Allow
    );
    Ok(())
}

#[test]
fn cloud_vault_receipt_binding_mismatch_fails_closed_to_the_hosted_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let mut binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    binding.read_frontier_hash = [7; 32];
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };

    let err = vault
        .cloud_vault_verified_trust(&request, None, &PolicyModelConfig::default(), &source)
        .expect_err("frontier mismatch must be rejected by the CloudVault arm");
    assert!(matches!(
        err,
        Error::RelayVaultReceiptUntrusted {
            reason: "binding_mismatch"
        }
    ));
    let policy = hosted_serious_crime_block();
    let pass = vault.relay_boundary_floor_pass(
        request,
        &cloud_witness(),
        &hosted_edge_registry(policy),
        &source,
    )?;
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_content_hash_mismatch_audits_exact_cause() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("an ordinary friendly reply");
    let mut binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    binding.content_hash = [9; 32];
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };
    let err = vault
        .cloud_vault_verified_trust(&request, None, &PolicyModelConfig::default(), &source)
        .expect_err("stored content hash mismatch must be untrusted");
    assert!(matches!(
        err,
        Error::RelayVaultReceiptUntrusted {
            reason: "binding_mismatch"
        }
    ));
    vault.relay_boundary_floor_pass(
        request,
        &cloud_witness(),
        &no_hosted_policy_registry(),
        &source,
    )?;
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    assert!(
        receipts[0]
            .policy_trace
            .iter()
            .any(|trace| trace == "gate.relay.vault_receipt_untrusted.binding_mismatch")
    );
    Ok(())
}

#[test]
fn cloud_vault_safeguard_binding_mismatch_falls_back_and_audits() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("an ordinary friendly reply");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let mut receipt = PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default());
    receipt.safeguard_binding = "stale-safeguard".to_owned();
    let source = StaticVaultSideVerdicts {
        verdict: receipt,
        requested_hash: Mutex::new(None),
    };

    let pass = vault.relay_boundary_floor_pass(
        request,
        &cloud_witness(),
        &no_hosted_policy_registry(),
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
fn cloud_vault_non_allow_receipts_halt_and_record_real_decisions() -> Result<()> {
    for (decision, outcome) in [
        (PolicyClassifyDecision::Block, "relay_floor_block"),
        (
            PolicyClassifyDecision::RouteToHelp,
            "relay_floor_route_to_help",
        ),
        (PolicyClassifyDecision::Warn, "relay_floor_warn"),
    ] {
        let (_tmp, vault) = temp_vault();
        let request = PolicyClassifyRequest::outbound_content("ordinary content");
        let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
        let source = StaticVaultSideVerdicts {
            verdict: PolicyClassifyVerdict::new(
                decision,
                PolicyVerdictCategory::OwnerPolicy {
                    row_ref: "owner:vault-side".to_owned(),
                },
                PolicyConfidence::HIGH,
                binding,
                &PolicyModelConfig::default(),
            ),
            requested_hash: Mutex::new(None),
        };

        let pass = vault.relay_boundary_floor_pass(
            request,
            &cloud_witness(),
            &no_hosted_policy_registry(),
            &source,
        )?;
        assert!(matches!(pass, RelayFloorPass::FloorClassified { .. }));
        assert_eq!(
            pass.must_halt_relay(),
            decision != PolicyClassifyDecision::Warn
        );
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
fn relay_skips_write_audit_receipts_with_trust_domain() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let content = || PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let binding = vault.relay_verify_binding(&content(), &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };
    vault.relay_boundary_floor_pass(
        content(),
        &cloud_witness(),
        &no_hosted_policy_registry(),
        &source,
    )?;
    vault.relay_boundary_floor_pass(
        content(),
        &byo_witness(),
        &no_hosted_policy_registry(),
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

// --- the safeguard model at the relay boundary ------------------------------

#[test]
fn relay_backend_catches_a_flagged_hosted_span() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = hosted_serious_crime_block();
    // The deterministic tier is clean on this phrasing; the hosted-only model
    // is the flagged-span nuance layer and catches it.
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"block","category":"hosted_legal/serious_crime","row_ref":"hosted:serious-crime","confidence":0.95,"hedge_bucket":"high"}"#,
    };
    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("a subtly worded dangerous ask"),
        &hosted_witness(),
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        RelaySafeguardTier {
            backend: &backend,
            lease: &BudgetLease::for_test("relay-model-catch"),
        },
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    let verdict = pass.floor_verdict().expect("hosted relay pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(verdict.plane(), Some(PolicyPlane::HostedLegal));
    // A real model catch is NOT a degradation.
    assert!(pass.degraded().is_none());
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn relay_backend_degrades_an_owner_plane_verdict() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x53),
        &enabled_owner_manifest(vec![owner_row(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
        )]),
    )?;
    // The relay rubric carries no owner row, so a hallucinated owner verdict
    // has nothing to bind to. It degrades to the deterministic result rather
    // than propagating an error or taking effect.
    let policy = hosted_serious_crime_block();
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"warn","category":"owner_policy","row_ref":"owner:spoilers","confidence":0.9,"hedge_bucket":"high"}"#,
    };
    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("an ordinary flagged span"),
        &hosted_witness(),
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        RelaySafeguardTier {
            backend: &backend,
            lease: &BudgetLease::for_test("relay-owner-degrade"),
        },
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    let verdict = pass.floor_verdict().expect("hosted relay pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);
    assert_eq!(
        pass.degraded(),
        Some(RelayFloorDegrade::SafeguardModelResponseUnusable)
    );
    // A hosted policy was in play and its coverage degraded, so the relay
    // halts rather than answering the outage with an unexamined allow.
    assert!(pass.must_halt_relay());

    // A degraded allow IS receipted (unlike a clean allow), with the marker.
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
fn relay_backend_degrades_a_category_the_hosted_policy_omits() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The hosted policy carries no NCII row, so a model verdict for it was
    // never on this service's rubric and must not take effect.
    let policy = hosted_serious_crime_block();
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"block","category":"hosted_legal/ncii","row_ref":"hosted:ncii","confidence":0.9,"hedge_bucket":"high"}"#,
    };
    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("a flagged but clean span"),
        &hosted_witness(),
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        RelaySafeguardTier {
            backend: &backend,
            lease: &BudgetLease::for_test("relay-off-plane-ncii"),
        },
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    let verdict = pass.floor_verdict().expect("hosted relay pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(
        pass.degraded(),
        Some(RelayFloorDegrade::SafeguardModelResponseUnusable)
    );
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn relay_backend_accepts_a_category_the_hosted_policy_carries() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = hosted_policy(vec![hosted_row(
        "hosted:jurisdiction-rule",
        HostedLegalCategory::JurisdictionRule,
        HostedLegalAction::Block,
        "Withhold content this jurisdiction forbids.",
    )]);
    let backend = StaticPolicyBackend {
        body: r#"{"decision":"block","category":"hosted_legal/jurisdiction_rule","row_ref":"hosted:jurisdiction-rule","confidence":0.9,"hedge_bucket":"high"}"#,
    };
    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("a flagged but clean span"),
        &hosted_witness(),
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        RelaySafeguardTier {
            backend: &backend,
            lease: &BudgetLease::for_test("relay-on-plane-jurisdiction"),
        },
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    let verdict = pass.floor_verdict().expect("hosted relay pass");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::HostedLegal {
            category: HostedLegalCategory::JurisdictionRule,
            jurisdiction: HOSTED_JURISDICTION.to_owned(),
            policy_version: HOSTED_VERSION.to_owned(),
            row_ref: "hosted:jurisdiction-rule".to_owned(),
        }
    );
    assert!(pass.degraded().is_none());
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn relay_backend_down_keeps_the_deterministic_backstop() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = hosted_serious_crime_block();
    let backend = FailingPolicyBackend;
    // The deterministic tier still catches the catastrophe with the model down.
    let caught = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        &hosted_witness(),
        &hosted_edge_registry(policy.clone()),
        &PolicyModelConfig::default(),
        RelaySafeguardTier {
            backend: &backend,
            lease: &BudgetLease::for_test("relay-down-catch"),
        },
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(
        caught.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Block
    );
    // The deterministic tier resolved it, so the model was never consulted.
    assert!(caught.degraded().is_none());

    // A clean span with the model down falls back to the deterministic tier and
    // is MARKED, so the allow is not mistaken for a model-confirmed one — and
    // because a hosted policy is in play, the marked pass halts the relay.
    let clean = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("an ordinary friendly reply"),
        &hosted_witness(),
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        RelaySafeguardTier {
            backend: &backend,
            lease: &BudgetLease::for_test("relay-down-clean"),
        },
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(
        clean.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert_eq!(
        clean.degraded(),
        Some(RelayFloorDegrade::SafeguardModelUnavailable)
    );
    assert!(clean.must_halt_relay());
    Ok(())
}

#[test]
fn a_degraded_pass_halts_only_where_a_hosted_policy_was_in_play() {
    // The contract stated directly, both sides of the line. A hosted policy in
    // play means the fail-closed plane lost coverage, so the relay stops; with
    // no hosted policy there was never anything for the outage to uncover, and
    // the owner plane is sovereign — it never gains a halt it did not ask for.
    let binding = relay_skip_content_binding(&PolicyClassifyRequest::outbound_content("candidate"));
    let verdict = PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default());
    for degrade in [
        RelayFloorDegrade::SafeguardModelUnavailable,
        RelayFloorDegrade::SafeguardModelResponseUnusable,
    ] {
        assert!(
            !RelayFloorPass::FloorClassified {
                verdict: verdict.clone(),
                degraded: Some(degrade),
                hosted_policy_in_play: false,
            }
            .must_halt_relay(),
            "owner-plane-only degrade must not halt: {degrade:?}"
        );
        assert!(
            RelayFloorPass::FloorClassified {
                verdict: verdict.clone(),
                degraded: Some(degrade),
                hosted_policy_in_play: true,
            }
            .must_halt_relay(),
            "hosted-plane degrade must halt: {degrade:?}"
        );
    }
    // Undegraded, a clean allow still relays whichever plane was in play.
    for hosted_policy_in_play in [false, true] {
        assert!(
            !RelayFloorPass::FloorClassified {
                verdict: verdict.clone(),
                degraded: None,
                hosted_policy_in_play,
            }
            .must_halt_relay()
        );
    }
}

#[test]
fn a_relay_with_no_hosted_policy_bound_never_degrades_at_all() -> Result<()> {
    // The path-level companion to the unit pin above: with nothing bound to the
    // attested identity the safeguard model is never called, so a downed model
    // cannot even produce a degrade, let alone a halt.
    let (_tmp, vault) = temp_vault();
    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        &hosted_witness(),
        &no_hosted_policy_registry(),
        &PolicyModelConfig::default(),
        RelaySafeguardTier {
            backend: &FailingPolicyBackend,
            lease: &BudgetLease::for_test("relay-unbound-no-degrade"),
        },
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert!(pass.degraded().is_none());
    assert!(!pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_untrusted_receipt_with_backend_runs_and_degrades() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = hosted_serious_crime_block();
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(
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
        PolicyClassifyRequest::outbound_content("a clean flagged span"),
        &cloud_witness(),
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        RelaySafeguardTier {
            backend: &backend,
            lease: &BudgetLease::for_test("cloud-fallback-backend-down"),
        },
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
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };
    let backend = CountingPolicyBackend {
        calls: AtomicUsize::new(0),
    };
    let pass = block_on_ready(vault.relay_boundary_floor_pass_with_backend(
        request,
        &cloud_witness(),
        &no_hosted_policy_registry(),
        &PolicyModelConfig::default(),
        RelaySafeguardTier {
            backend: &backend,
            lease: &BudgetLease::for_test("trusted-cloud-no-backend"),
        },
        &source,
    ))?;
    assert_eq!(pass, RelayFloorPass::TrustedVaultSide);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

// --- sealed connection identity and the attested relay domain ---------------

/// Fixture edge-service registrations: the engine ships the validation
/// mechanism and NO service identities, so the registration data a
/// deployment's connector-edge wiring would supply from its manifest is
/// provided here as test fixtures.
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
    // rejects even the names the fixture registry knows — the engine ships no
    // implicit registrations.
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
fn hosted_legal_policy_binds_to_a_registered_service_identity() {
    let mut registry = fixture_edge_service_registry();
    registry
        .register_hosted_legal_policy("slack-hosted", hosted_serious_crime_block())
        .expect("registering a policy on a known service succeeds");

    let bound = registry
        .hosted_legal_policy("connector-edge:slack-hosted")
        .expect("the registered policy is reachable by identity");
    assert_eq!(bound.jurisdiction, HOSTED_JURISDICTION);
    assert_eq!(bound.version, HOSTED_VERSION);

    // A service with no policy has none, and an unregistered name can never
    // carry one — jurisdiction authority does not float free of an identity.
    assert!(
        registry
            .hosted_legal_policy("connector-edge:push-relay")
            .is_none()
    );
    let err = registry
        .register_hosted_legal_policy("totally-unknown-edge", hosted_serious_crime_block())
        .expect_err("a policy needs a registered service behind it");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::RelayAttestationInvalidServiceIdentity
    );
}

#[test]
fn the_relay_takes_its_hosted_policy_from_the_attested_identity() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The policy is bound to `push-relay`. The pass runs under `slack-hosted`,
    // so nothing applies to it — the caller has no way to reach for another
    // service's jurisdiction, because it never names one.
    let mut registry = fixture_edge_service_registry();
    registry.register_hosted_legal_policy("push-relay", hosted_serious_crime_block())?;

    let request = || PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let unbound = vault.relay_boundary_floor_pass(
        request(),
        &hosted_witness(),
        &registry,
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert_eq!(
        unbound.floor_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(!unbound.must_halt_relay());

    // The same content under the identity the policy IS bound to blocks.
    let bound_witness = AttestedRelayDomain::for_testing(
        RelayTrustDomain::LocalViaHostedConnector,
        "connector-edge:push-relay",
    );
    let bound = vault.relay_boundary_floor_pass(
        request(),
        &bound_witness,
        &registry,
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert!(bound.must_halt_relay());
    Ok(())
}

#[test]
fn hosted_legal_policy_registration_rejects_unreceiptable_attribution() {
    // Every one of these registers fine without the guard and then makes EVERY
    // hosted warn/block fail at receipt-append, which is an enforcement outage
    // wearing a storage error's coat.
    for (field, policy) in [
        (
            "docs_url",
            HostedLegalPolicy {
                docs_url: String::new(),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "docs_url",
            HostedLegalPolicy {
                docs_url: "   ".to_owned(),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "version",
            HostedLegalPolicy {
                version: "v".repeat(65),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "version",
            HostedLegalPolicy {
                version: String::new(),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "jurisdiction",
            HostedLegalPolicy {
                jurisdiction: "j".repeat(1024),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "policy_hash",
            HostedLegalPolicy {
                policy_hash: String::new(),
                ..hosted_serious_crime_block()
            },
        ),
    ] {
        let mut registry = fixture_edge_service_registry();
        let err = registry
            .register_hosted_legal_policy("slack-hosted", policy)
            .expect_err("an unreceiptable hosted policy must be rejected at registration");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::RelayHostedLegalPolicyInvalid,
            "field: {field}"
        );
        assert!(format!("{err}").contains(field), "field: {field}");
        // The rejection is total: nothing partial was bound to the service.
        assert!(
            registry
                .hosted_legal_policy("connector-edge:slack-hosted")
                .is_none()
        );
    }
}

#[test]
fn a_max_length_jurisdiction_still_produces_a_receiptable_notice() -> Result<()> {
    // The jurisdiction bound is derived from the ledger's notice-body bound, so
    // the longest ACCEPTED jurisdiction must still receipt end to end.
    let (_tmp, vault) = temp_vault();
    let longest = "j".repeat(HOSTED_LEGAL_JURISDICTION_MAX_LEN);
    let policy = HostedLegalPolicy {
        jurisdiction: longest.clone(),
        ..hosted_serious_crime_block()
    };
    let registry = hosted_edge_registry(policy);

    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        &hosted_witness(),
        &registry,
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert!(pass.must_halt_relay());

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    assert!(
        receipts[0]
            .fields
            .get("system_notice")
            .expect("notice body")
            .contains(&longest)
    );
    Ok(())
}

#[test]
fn from_edge_auth_rejects_identity_class_mismatch() {
    // The hosted connector is registered as a local-vault relay edge; it may
    // never claim cloud-vault peer standing (which would skip the hosted pass).
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
    // (which would force a redundant re-run on already-classified content).
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
    // Security tripwire: an in-crate EXHAUSTIVE, no-wildcard match over the
    // module-private `HostedDomain`. Adding a variant (a BYO arm, say) breaks
    // THIS match at compile time — the variant-set pin the external
    // compile-fail fixture cannot provide (its E0603 fires regardless of the
    // variant set). The expected mapping is checked against the production
    // `from_hosted_domain` arm-for-arm, so the two cannot drift apart either.
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
            AttestedRelayDomain::from_hosted_domain(hosted, HOSTED_EDGE_IDENTITY.to_owned())
                .domain(),
            expected_domain(hosted),
            "hosted-edge mapping drifted from the pinned two-variant set"
        );
    }
}

#[test]
fn attested_relay_domain_serializes_domain_and_identity() {
    // The witness emits BOTH halves of its evidence: which trust domain, and
    // which attested service identity that domain was established for. A
    // receipt naming only the domain could not be traced back to the edge that
    // presented it.
    let witness = &hosted_witness();
    assert_eq!(
        serde_json::to_value(witness).expect("witness serializes"),
        serde_json::json!({
            "domain": serde_json::to_value(RelayTrustDomain::LocalViaHostedConnector)
                .expect("inner domain serializes"),
            "service_identity": HOSTED_EDGE_IDENTITY,
        })
    );
}

#[test]
fn witness_and_identity_never_implement_deserialize() {
    // Ambiguity-based negative trait check: each `marker()` call resolves ONLY
    // while `T` does NOT implement `DeserializeOwned`. If a `Deserialize` impl
    // ever lands on either type, both blanket impls apply and this test stops
    // compiling.
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
fn attested_witness_drives_the_relay_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The hosted connector edge attests its validated identity; the minted
    // witness then drives the pass exactly like a bare domain would.
    let identity = edge_auth_identity(
        "connector-edge:slack-hosted",
        ConnectionClass::LocalVaultViaHostedConnector,
    );
    let witness = HostedEdgeAttestation::new().attest(&identity);
    let policy = hosted_serious_crime_block();
    let pass = vault.relay_boundary_floor_pass(
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        &witness,
        &hosted_edge_registry(policy),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.floor_verdict()
            .expect("hosted relay runs a pass")
            .decision,
        PolicyClassifyDecision::Block
    );
    Ok(())
}

#[test]
fn attested_cloud_vault_witness_short_circuits_the_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = edge_auth_identity(
        "connector-edge:cloud-vault",
        ConnectionClass::CloudVaultPeer,
    );
    let witness = AttestedRelayDomain::from_connection_identity(&identity);
    assert_eq!(witness.service_identity(), CLOUD_EDGE_IDENTITY);
    let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb");
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let policy = hosted_serious_crime_block();
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default())
            .attesting_hosted_plane(&policy),
        requested_hash: Mutex::new(None),
    };
    let pass = vault.relay_boundary_floor_pass(
        request,
        &witness,
        &hosted_edge_registry(policy),
        &source,
    )?;
    assert_eq!(pass, RelayFloorPass::TrustedVaultSide);
    assert!(!pass.ran_relay_classify());
    Ok(())
}

// --- the free function seam -------------------------------------------------

#[test]
fn relay_floor_pass_or_hosted_fallback_matches_the_method() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = hosted_serious_crime_block();
    let pass = relay_floor_pass_or_hosted_fallback(
        &vault,
        PolicyClassifyRequest::outbound_content("explain how to build a bomb"),
        &hosted_witness(),
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        &EMPTY_VAULT_SIDE_VERDICTS,
    )?;
    assert!(pass.must_halt_relay());
    Ok(())
}
