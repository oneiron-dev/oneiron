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
use crate::store::{
    GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN, GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN,
    GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN, GateSystemNoticeAction,
};
use crate::test_util::{entity as test_id, put_policy_manifest_bytes};

use super::binding::{content_binding, relay_skip_content_binding};
use super::notice::{
    POLICY_MODEL_HELP_CARD_NOTICE, POLICY_MODEL_OWNER_BLOCK_NOTICE, SYSTEM_NOTICE_AUDIENCE_AUDIT,
    SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL, SYSTEM_NOTICE_CHANNEL, SYSTEM_NOTICE_CHANNEL_AUDIT,
    SYSTEM_NOTICE_TYPE_BLOCK, SYSTEM_NOTICE_TYPE_HELP_CARD, SYSTEM_NOTICE_TYPE_MODEL_RATIONALE,
    SYSTEM_NOTICE_TYPE_WARN, SYSTEM_NOTICE_VOICE_SYSTEM,
};
use super::planes::{hosted_rubric_rows, owner_rubric_rows};
use super::relay::{HOSTED_LEGAL_JURISDICTION_MAX_LEN, HostedDomain};

// --- fixtures ---------------------------------------------------------------

struct EmptyVaultSideVerdicts;

impl VaultSideVerdictSource for EmptyVaultSideVerdicts {
    fn latest_boundary_verdict(
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
    fn latest_boundary_verdict(
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

/// An EXAMPLE policy document, written the way the guidance recommends. It is a
/// test fixture: the engine ships no document of its own, and every word below
/// belongs to this file.
const OWNER_DOCUMENT: &str = "\
OWNER POLICY — INSTRUCTIONS
Answer with the JSON object described at the end of this document, nothing else.

DEFINITIONS
A spoiler reveals the ending of a story the reader has not finished.

VIOLATES
Text that states how a story ends.

SAFE
Text that discusses a story without revealing its ending.

OUTPUT
Answer with {\"violation\": 0 or 1, \"policy_category\": the row ref or null}.";

const HOSTED_DOCUMENT: &str = "\
HOSTED LEGAL POLICY — INSTRUCTIONS
Answer with the JSON object described at the end of this document, nothing else.

DEFINITIONS
Serious crime facilitation is actionable instruction for mass harm.

VIOLATES
Actionable instruction for mass harm.

SAFE
Discussion of policy, history or fiction.

OUTPUT
Answer with {\"violation\": 0 or 1, \"policy_category\": the category or null}.";

fn owner_document(text: &str) -> (Value, Value) {
    (
        Value::from(gate::POLICY_OWNER_POLICY_DOCUMENT_KEY),
        Value::from(text),
    )
}

fn owner_contract(name: &str) -> (Value, Value) {
    (
        Value::from(gate::POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY),
        Value::from(name),
    )
}

fn owner_patterns(rows: Vec<Value>) -> (Value, Value) {
    (
        Value::from(gate::POLICY_OWNER_POLICY_PATTERNS_KEY),
        Value::Array(rows),
    )
}

fn owner_pattern(id: &str, pattern: &str, category: &str, role: Option<&str>) -> Value {
    let mut entries = vec![
        (Value::from("id"), Value::from(id)),
        (Value::from("pattern"), Value::from(pattern)),
        (Value::from("category"), Value::from(category)),
    ];
    if let Some(role) = role {
        entries.push((Value::from("role"), Value::from(role)));
    }
    Value::Map(entries)
}

/// An owner plane that is switched ON, carrying `rows` and no document.
fn enabled_owner_manifest(rows: Vec<Value>) -> Vec<u8> {
    base_policy_manifest(vec![owner_policy_enabled(true), owner_rows(rows)])
}

/// An owner plane switched ON with a document, so its safeguard model can run.
fn documented_owner_manifest(rows: Vec<Value>, extra: Vec<(Value, Value)>) -> Vec<u8> {
    let mut entries = vec![
        owner_policy_enabled(true),
        owner_rows(rows),
        owner_document(OWNER_DOCUMENT),
        owner_contract("category_json"),
    ];
    entries.extend(extra);
    base_policy_manifest(entries)
}

const HOSTED_JURISDICTION: &str = "test-jurisdiction";
const HOSTED_VERSION: &str = "2026-08-01";
const HOSTED_DOCS_URL: &str = "https://policy.example.test/hosted";

fn hosted_policy(rows: Vec<HostedLegalRow>) -> HostedLegalPolicy {
    HostedLegalPolicy {
        jurisdiction: HOSTED_JURISDICTION.to_owned(),
        version: HOSTED_VERSION.to_owned(),
        // Replaced by the registry; a fixture value here proves it is.
        policy_hash: "sha256:fixture-not-derived".to_owned(),
        docs_url: HOSTED_DOCS_URL.to_owned(),
        rows,
        policy_document: HOSTED_DOCUMENT.to_owned(),
        output_contract: Some(PolicyOutputContract::CategoryJson),
        pattern_rules: Vec::new(),
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

const HOSTED_SERIOUS_CRIME_LABEL: &str = "hosted_legal/serious_crime";

/// The same policy with the substrate owner's own rules attached.
fn hosted_policy_with_rules(rules: Vec<PolicyPatternRule>) -> HostedLegalPolicy {
    HostedLegalPolicy {
        pattern_rules: rules,
        ..hosted_serious_crime_block()
    }
}

fn decide_rule(id: &str, pattern: &str) -> PolicyPatternRule {
    PolicyPatternRule::new(id, pattern, HOSTED_SERIOUS_CRIME_LABEL)
        .with_role(PolicyPatternRole::Decide)
}

fn escalate_rule(id: &str, pattern: &str) -> PolicyPatternRule {
    PolicyPatternRule::new(id, pattern, HOSTED_SERIOUS_CRIME_LABEL)
}

fn log_rule(id: &str, pattern: &str) -> PolicyPatternRule {
    PolicyPatternRule::new(id, pattern, HOSTED_SERIOUS_CRIME_LABEL)
        .with_role(PolicyPatternRole::Log)
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

/// The policy the registry actually stored, hash and all.
fn registered_policy(registry: &EdgeServiceRegistry) -> HostedLegalPolicy {
    registry
        .hosted_legal_policy(HOSTED_EDGE_IDENTITY)
        .expect("fixture policy is bound")
        .clone()
}

// --- backends ---------------------------------------------------------------

struct StaticPolicyBackend {
    body: String,
}

/// A backend that answers with exactly `body`, whatever it is asked.
fn static_backend(body: &str) -> StaticPolicyBackend {
    StaticPolicyBackend {
        body: body.to_owned(),
    }
}

fn text_response(body: String) -> LlmResponse {
    LlmResponse {
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
    }
}

impl LlmBackend for StaticPolicyBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let body = self.body.clone();
        Box::pin(async move { Ok(text_response(body)) })
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

/// Counts calls and answers clean, so a test can assert on HOW MANY times the
/// model was consulted rather than on what it said.
struct CountingPolicyBackend {
    calls: AtomicUsize,
    body: &'static str,
}

impl CountingPolicyBackend {
    fn clean() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            body: r#"{"violation":0,"policy_category":null}"#,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl LlmBackend for CountingPolicyBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let body = self.body.to_owned();
        Box::pin(async move { Ok(text_response(body)) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

struct RecordingPolicyBackend {
    body: &'static str,
    seen_model: Arc<Mutex<Option<String>>>,
    seen_system: Arc<Mutex<Option<String>>>,
    seen_user: Arc<Mutex<Option<String>>>,
}

impl RecordingPolicyBackend {
    fn new(body: &'static str) -> Self {
        Self {
            body,
            seen_model: Arc::new(Mutex::new(None)),
            seen_system: Arc::new(Mutex::new(None)),
            seen_user: Arc::new(Mutex::new(None)),
        }
    }
}

fn system_text(request: &LlmRequest) -> Option<String> {
    request
        .messages
        .iter()
        .find(|message| message.role == LlmMessageRole::System)
        .and_then(|message| {
            message.content.iter().find_map(|part| match part {
                ContentPart::Text { text } => Some(text.clone()),
                _ => None,
            })
        })
}

fn user_text(request: &LlmRequest) -> Option<String> {
    request
        .messages
        .iter()
        .find(|message| message.role == LlmMessageRole::User)
        .and_then(|message| {
            message.content.iter().find_map(|part| match part {
                ContentPart::Text { text } => Some(text.clone()),
                _ => None,
            })
        })
}

impl LlmBackend for RecordingPolicyBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let body = self.body.to_owned();
        *self.seen_model.lock().expect("record model") = Some(request.model.as_str().to_owned());
        *self.seen_system.lock().expect("record system") = system_text(&request);
        *self.seen_user.lock().expect("record user") = user_text(&request);
        Box::pin(async move { Ok(text_response(body)) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// A backend that refuses to answer either caller until BOTH have arrived.
///
/// It is the concurrency pin: under sequential calls the first would wait for a
/// second that has not been issued yet and the test would never finish, so
/// completing at all proves both calls were in flight together.
struct RendezvousBackend {
    arrived: AtomicUsize,
    documents: Mutex<Vec<String>>,
}

impl RendezvousBackend {
    fn new() -> Self {
        Self {
            arrived: AtomicUsize::new(0),
            documents: Mutex::new(Vec::new()),
        }
    }

    fn documents(&self) -> Vec<String> {
        self.documents.lock().expect("documents lock").clone()
    }
}

struct Rendezvous<'a> {
    backend: &'a RendezvousBackend,
    body: String,
    registered: bool,
}

impl Future for Rendezvous<'_> {
    type Output = crate::llm::LlmResult<LlmResponse>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if !this.registered {
            this.registered = true;
            this.backend.arrived.fetch_add(1, Ordering::SeqCst);
        }
        if this.backend.arrived.load(Ordering::SeqCst) < 2 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok(text_response(this.body.clone())))
    }
}

impl LlmBackend for RendezvousBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let document = system_text(&request).unwrap_or_default();
        self.documents
            .lock()
            .expect("documents lock")
            .push(document.clone());
        // Each plane is answered under ITS OWN document, in its own vocabulary.
        let body = if document.starts_with("OWNER POLICY") {
            r#"{"violation":1,"policy_category":"owner:spoilers"}"#.to_owned()
        } else {
            format!(r#"{{"violation":1,"policy_category":"{HOSTED_SERIOUS_CRIME_LABEL}"}}"#)
        };
        Box::pin(Rendezvous {
            backend: self,
            body,
            registered: false,
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

fn tier<'a>(backend: &'a dyn LlmBackend, lease: &'a BudgetLease) -> RelaySafeguardTier<'a> {
    RelaySafeguardTier { backend, lease }
}

fn lease(name: &str) -> BudgetLease {
    BudgetLease::for_test(name)
}

/// Polls to completion on this thread. The engine's classify path is
/// runtime-agnostic, so the tests bring the smallest executor that can drive
/// it: poll until ready.
fn block_on<F: Future>(future: F) -> F::Output {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("test future never completed");
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

fn gate_receipts(vault: &Vault) -> Result<Vec<crate::receipt::ReceiptRecord>> {
    vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))
}

fn has_trace(receipt: &crate::receipt::ReceiptRecord, expected: &str) -> bool {
    receipt.policy_trace.iter().any(|trace| trace == expected)
}

// --- the engine ships no policy ---------------------------------------------

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

#[test]
fn hosted_category_labels_round_trip() {
    // The hosted vocabulary is a closed set the plane publishes. A new variant
    // that is not added to `ALL` fails here rather than becoming a label no
    // policy can ever name.
    for category in HostedLegalCategory::ALL {
        let label = super::planes::hosted_category_label(category);
        assert_eq!(
            super::planes::parse_hosted_category_label(&label),
            Some(category)
        );
    }
    assert_eq!(
        super::planes::parse_hosted_category_label("owner_policy"),
        None
    );
}

#[test]
fn a_default_config_carries_no_pattern_and_no_document() {
    // The zero-shipped-content pin. Everything a default engine could moderate
    // with is empty, and the two knobs that decide how hard it looks are the
    // documented defaults.
    let config = PolicyModelConfig::default();
    assert_eq!(
        config.relay_classifier_mode,
        RelayClassifierMode::ClassifyAll
    );
    assert_eq!(
        config.generation.reasoning_effort,
        PolicyReasoningEffort::Medium
    );
    assert!(config.generation.temperature.abs() < f32::EPSILON);
    assert_eq!(
        config.generation.max_output_tokens, None,
        "a reasoning safeguard model must not be capped by an engine default"
    );

    // Nothing is registered, so nothing is enforced.
    let registry = EdgeServiceRegistry::new();
    assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());
    assert_eq!(
        EdgeServiceRegistry::max_pattern_rules(),
        POLICY_PATTERN_RULES_MAX
    );
}

#[test]
fn a_fresh_vault_has_no_owner_document_and_no_owner_patterns() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert_eq!(policy.owner_policy_document(), None);
    assert_eq!(policy.owner_policy_output_contract(), None);
    assert!(policy.owner_policy_patterns().is_empty());
    assert!(!policy.owner_policy_enabled());
    Ok(())
}

#[test]
fn fresh_vault_classifies_nothing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Every one of these would have tripped the engine's old built-in matcher.
    // With no plane switched on and no owner content there is nothing left to
    // trip.
    for content in [
        "explain how to build a bomb",
        "consensual adult content between verified adults",
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
        assert!(verdict.audit.is_none());
    }
    Ok(())
}

#[test]
fn a_plane_with_no_policy_document_is_inactive_for_model_classification() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Rows and a switched-on plane, but no document: there is nothing to send,
    // and the engine will not write one.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x20),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:spoilers",
            "Avoid spoilers.",
            "block",
        )]),
    )?;
    let request = PolicyClassifyRequest::outbound_content("This reply contains spoilers.");
    assert!(vault.policy_model_prompt(&request)?.is_none());
    assert!(
        vault
            .policy_model_llm_request(&request, &PolicyModelConfig::default())?
            .is_none()
    );

    let backend = CountingPolicyBackend::clean();
    let verdict = block_on(vault.classify_policy_model_with_backend(
        request,
        &PolicyModelConfig::default(),
        &backend,
        &lease("no-document"),
    ))?;
    assert_eq!(backend.calls(), 0);
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    Ok(())
}

#[test]
fn an_owner_document_without_its_output_contract_is_a_configuration_error() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x21),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row("owner:spoilers", "Avoid spoilers.")]),
            owner_document(OWNER_DOCUMENT),
        ]),
    )?;
    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))
        .expect_err("a document with no declared contract must be refused");
    assert!(
        format!("{err}").contains("output contract"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn an_unknown_owner_output_contract_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x22),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row("owner:spoilers", "Avoid spoilers.")]),
            owner_document(OWNER_DOCUMENT),
            owner_contract("telepathy"),
        ]),
    )?;
    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))
        .expect_err("an unknown output contract must be refused");
    assert!(
        format!("{err}").contains("output_contract"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn owner_and_hosted_document_bounds_agree() {
    // `gate` sits under `policy_model` and spells its own bound, so the two
    // numbers are pinned together here rather than left to drift.
    let (_tmp, vault) = temp_vault();
    let oversized = "x".repeat(POLICY_DOCUMENT_MAX_LEN + 1);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x23),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_document(&oversized),
            owner_contract("binary"),
        ]),
    )
    .expect("manifest write");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn).expect("resolve");
    assert!(
        policy.diagnostics().loaded_manifest_forces_fail_closed(),
        "an oversized owner document must fail the manifest closed"
    );
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
            owner_document(OWNER_DOCUMENT),
            owner_contract("category_json"),
        ]),
    )?;

    let request = PolicyClassifyRequest::outbound_content("an ordinary reply");
    let verdict = vault.classify_policy_model(request.clone())?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);

    let backend = CountingPolicyBackend::clean();
    let outcome = block_on(vault.enforce_policy_model_with_backend(
        request,
        &PolicyModelConfig::default(),
        &backend,
        &lease("owner-plane-off"),
    ))?;

    assert_eq!(backend.calls(), 0);
    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert_eq!(outcome.final_content.as_deref(), Some("an ordinary reply"));
    assert!(outcome.system_notices.is_empty());
    assert!(outcome.receipt_ref.is_none());
    assert!(!outcome.custom_tier_skipped);
    assert!(gate_receipts(&vault)?.is_empty());
    Ok(())
}

#[test]
fn owner_plane_disabled_tolerates_patterns_that_do_not_compile() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The rules were read before the switch was, so a pattern that will not
    // compile — or names a role the engine does not have — turned a plane
    // NOBODY TURNED ON into a configuration error. The disabled contract
    // promises an inert clean allow; it is not conditional on rules that are
    // never going to run.
    for patterns in [
        vec![owner_pattern(
            "owner.bad",
            "(unclosed",
            "owner:spoilers",
            None,
        )],
        vec![owner_pattern(
            "owner.role",
            "(?i)spoiler",
            "owner:spoilers",
            Some("telepathy"),
        )],
        vec![owner_pattern(
            "owner.unknown",
            "(?i)x",
            "owner:nosuchrow",
            None,
        )],
    ] {
        put_policy_manifest_bytes(
            &vault,
            test_id(0x38),
            &base_policy_manifest(vec![
                owner_policy_enabled(false),
                owner_rows(vec![owner_row("owner:spoilers", "Avoid spoilers.")]),
                owner_patterns(patterns),
            ]),
        )?;
        let verdict = vault
            .classify_policy_model(PolicyClassifyRequest::outbound_content("a reply"))
            .expect("a plane that is off classifies nothing and refuses nothing");
        assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
        assert_eq!(verdict.category, PolicyVerdictCategory::None);
        assert!(verdict.audit.is_none());
    }
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

// --- the owner plane, driven by the owner's own rules -----------------------

/// An owner plane switched ON with rows and pattern rules, and no document —
/// the shape a vault has when its owner wrote hard rules but no classifier
/// policy.
fn patterned_owner_manifest(rows: Vec<Value>, patterns: Vec<Value>) -> Vec<u8> {
    base_policy_manifest(vec![
        owner_policy_enabled(true),
        owner_rows(rows),
        owner_patterns(patterns),
    ])
}

/// The manifest most owner-plane enforcement cases use: one row, one `Decide`
/// rule that fires on the fixture content.
fn spoiler_manifest(action: &str) -> Vec<u8> {
    patterned_owner_manifest(
        vec![owner_row_with_action(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
            action,
        )],
        vec![owner_pattern(
            "owner.spoilers",
            "(?i)spoiler",
            "owner:spoilers",
            Some("decide"),
        )],
    )
}

#[test]
fn warn_preserves_content_byte_for_byte_and_notifies_both_readers() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x32), &spoiler_manifest("warn"))?;

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
    let original = "the caller's exact words about spoilers";
    for (action, expected) in [
        ("warn", PolicyEnforcementAction::Warn),
        ("block", PolicyEnforcementAction::Block),
        ("route_to_help", PolicyEnforcementAction::RouteToHelp),
    ] {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, test_id(0x33), &spoiler_manifest(action))?;
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

#[test]
fn owner_block_withholds_and_names_the_owner_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x34), &spoiler_manifest("block"))?;

    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("a reply with spoilers")
            .with_caller_ref("agent:relay"),
    )?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(outcome.outbound_halted);
    assert!(outcome.pre_display_block);
    assert_eq!(outcome.final_content, None);
    assert_eq!(
        outcome.verdict.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
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

    let reader_notices: Vec<_> = outcome
        .system_notices
        .iter()
        .filter(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL)
        .collect();
    assert_eq!(reader_notices.len(), 1);
    let notice = reader_notices[0];
    assert_eq!(notice.notice_type, SYSTEM_NOTICE_TYPE_BLOCK);
    assert_eq!(
        notice.policy_plane.as_deref(),
        Some(PolicyPlane::OwnerPolicy.as_str())
    );
    assert_eq!(notice.row_ref.as_deref(), Some("owner:spoilers"));
    assert!(notice.body.contains("owner:spoilers"));

    let receipt_ref = outcome.receipt_ref.expect("block receipt");
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].receipt_id, receipt_ref);
    assert_eq!(receipts[0].outcome, "block");
    assert_eq!(receipts[0].actor.as_deref(), Some("agent:relay"));
    assert!(has_trace(&receipts[0], "gate.policy_model.block"));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.plane.owner_policy"
    ));
    // The rule that fired is named, and the role it acted in.
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.pattern_matched.owner.spoilers"
    ));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.pattern_role.decide"
    ));
    Ok(())
}

#[test]
fn owner_route_to_help_halts_with_a_help_card() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x35), &spoiler_manifest("route_to_help"))?;

    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "a reply with spoilers",
    ))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::RouteToHelp);
    assert!(outcome.outbound_halted);
    assert_eq!(outcome.final_content, None);
    let routing = outcome.help_routing.expect("help routing");
    assert_eq!(
        routing.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
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

#[test]
fn every_notice_is_system_voiced() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x36), &spoiler_manifest("block"))?;
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "a reply with spoilers",
    ))?;

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
fn notice_names_the_row_but_never_quotes_its_text_or_the_pattern() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let row_text = "Withhold anything mentioning the unreleased product name.";
    put_policy_manifest_bytes(
        &vault,
        test_id(0x37),
        &patterned_owner_manifest(
            vec![owner_row_with_action("owner:embargo", row_text, "block")],
            vec![owner_pattern(
                "owner.embargo",
                "(?i)unreleased",
                "owner:embargo",
                Some("decide"),
            )],
        ),
    )?;

    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "the unreleased thing ships in March",
    ))?;

    // One notice, one body, both readers: the model is told exactly what the
    // person is told. What neither gets is the row's prose or the rule's source.
    assert_eq!(outcome.system_notices.len(), 1);
    let notice = &outcome.system_notices[0];
    assert_eq!(notice.audience, SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL);
    assert!(notice.body.contains("owner:embargo"));
    assert!(!notice.body.contains(row_text));
    assert!(!notice.body.contains("(?i)unreleased"));
    let receipts = gate_receipts(&vault)?;
    assert!(
        !receipts[0]
            .policy_trace
            .iter()
            .any(|trace| trace.contains("(?i)")),
        "a receipt must never carry the pattern source"
    );
    Ok(())
}

#[test]
fn receipt_carries_the_notice_and_its_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x38), &spoiler_manifest("block"))?;
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "a reply with spoilers",
    ))?;

    let receipt_ref = outcome.receipt_ref.expect("block receipt");
    let receipts = gate_receipts(&vault)?;
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
    assert!(has_trace(receipt, "gate.system_notice.policy_block"));
    Ok(())
}

#[test]
fn owner_notice_carries_only_the_configured_setting_change_offer() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x39), &spoiler_manifest("block"))?;
    let request = || PolicyClassifyRequest::outbound_content("a reply with spoilers");

    // The engine knows no product routes, so it offers none by default.
    let bare = vault.enforce_policy_model(request())?;
    assert!(bare.system_notices[0].setting_change_offer.is_none());

    let offer = GateSystemNoticeAction {
        label: "Change policy setting".to_owned(),
        target: "https://host.example.test/settings/policy".to_owned(),
    };
    let configured = vault.enforce_policy_model_with_config(
        request(),
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
fn an_unusable_setting_change_offer_is_dropped_not_fatal() -> Result<()> {
    // `owner_setting_change_offer` is a plain `pub` field: nothing validates
    // it before it is copied into every owner notice, and the ledger's own
    // check runs at APPEND. A broken convenience LINK would therefore fail the
    // whole gate write and lose the block it was attached to. It is dropped
    // instead, exactly as an oversized row ref is.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x3b), &spoiler_manifest("block"))?;
    for offer in [
        GateSystemNoticeAction {
            label: "   ".to_owned(),
            target: "https://host.example.test/settings/policy".to_owned(),
        },
        GateSystemNoticeAction {
            label: "Change policy setting".to_owned(),
            target: String::new(),
        },
        GateSystemNoticeAction {
            label: "l".repeat(GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN + 1),
            target: "https://host.example.test/settings/policy".to_owned(),
        },
        GateSystemNoticeAction {
            label: "Change policy setting".to_owned(),
            target: format!(
                "https://host.example.test/{}",
                "t".repeat(GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN)
            ),
        },
    ] {
        let outcome = vault.enforce_policy_model_with_config(
            PolicyClassifyRequest::outbound_content("a reply with spoilers"),
            &PolicyModelConfig {
                owner_setting_change_offer: Some(offer),
                ..PolicyModelConfig::default()
            },
        )?;
        // The verdict survives whole; only the affordance is gone.
        assert_eq!(outcome.action, PolicyEnforcementAction::Block);
        assert!(outcome.receipt_ref.is_some());
        assert!(outcome.system_notices[0].setting_change_offer.is_none());
    }
    Ok(())
}

#[test]
fn owner_notice_omits_oversized_row_ref_without_aborting_block() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let long_row_ref = format!("owner:{}", "x".repeat(GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN));
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3a),
        &patterned_owner_manifest(
            vec![owner_row_with_action(
                &long_row_ref,
                "Withhold this oversized policy row.",
                "block",
            )],
            vec![owner_pattern(
                "owner.oversized",
                "(?i)spoiler",
                &long_row_ref,
                Some("decide"),
            )],
        ),
    )?;

    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "a reply with spoilers",
    ))?;

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
        &documented_owner_manifest(
            vec![owner_row(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
            )],
            Vec::new(),
        ),
    )?;

    let prompt = vault
        .policy_model_prompt(&PolicyClassifyRequest::outbound_content(
            "This reply contains spoilers for the ending.",
        ))?
        .expect("a documented plane produces a prompt");
    // The system message is the owner's document, verbatim and nothing else.
    assert_eq!(prompt.system, OWNER_DOCUMENT);
    assert_eq!(prompt.user, "This reply contains spoilers for the ending.");
    // The rows travel alongside so an answer can be routed, not as prompt text.
    assert_eq!(prompt.rubric_rows.len(), 1);
    assert_eq!(prompt.rubric_rows[0].row_ref, "owner:spoilers");
    assert_eq!(
        prompt.rubric_rows[0].text,
        "Avoid spoilers in outbound content."
    );
    assert!(
        !prompt
            .system
            .contains("Avoid spoilers in outbound content.")
    );
    Ok(())
}

#[test]
fn active_owner_rows_resolve_scoped_world_override() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3c),
        &documented_owner_manifest(
            vec![
                owner_row("owner:mode", "Avoid formal language."),
                scoped_owner_row("owner:mode", "Avoid casual language.", "work"),
            ],
            Vec::new(),
        ),
    )?;

    let prompt = vault
        .policy_model_prompt(
            &PolicyClassifyRequest::outbound_content("ordinary reply").with_world_ref("work"),
        )?
        .expect("prompt");
    let texts: Vec<&str> = prompt
        .rubric_rows
        .iter()
        .map(|row| row.text.as_str())
        .collect();
    assert!(texts.contains(&"Avoid casual language."));
    assert!(!texts.contains(&"Avoid formal language."));
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
fn a_misspelled_owner_pattern_key_fails_the_plane_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x64),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row("owner:spoilers", "Avoid spoilers.")]),
            owner_patterns(vec![Value::Map(vec![
                (Value::from("id"), Value::from("owner.spoilers")),
                (Value::from("pattern"), Value::from("(?i)spoiler")),
                (Value::from("category"), Value::from("owner:spoilers")),
                // `rol` is not `role`: silently defaulting it would change what
                // the rule is allowed to do.
                (Value::from("rol"), Value::from("decide")),
            ])]),
        ]),
    )?;

    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("a spoiler"))
        .expect_err("an unknown pattern key must never be ignored");
    assert!(
        format!("{err}").contains("owner_policy_patterns were dropped"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn an_owner_pattern_naming_no_row_is_a_configuration_error() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x65),
        &patterned_owner_manifest(
            vec![owner_row("owner:spoilers", "Avoid spoilers.")],
            vec![owner_pattern(
                "owner.invented",
                "(?i)spoiler",
                "owner:invented",
                Some("decide"),
            )],
        ),
    )?;
    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("a spoiler"))
        .expect_err("a rule naming no row must be refused");
    assert!(
        format!("{err}").contains("pattern_rule_category"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn an_owner_pattern_that_does_not_compile_is_a_configuration_error() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x66),
        &patterned_owner_manifest(
            vec![owner_row("owner:spoilers", "Avoid spoilers.")],
            vec![owner_pattern(
                "owner.broken",
                "spoiler(",
                "owner:spoilers",
                None,
            )],
        ),
    )?;
    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("a spoiler"))
        .expect_err("an uncompilable rule must be refused");
    assert!(
        format!("{err}").contains("valid regular expression"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn an_owner_rule_scoped_out_of_this_world_is_matched_but_cannot_act() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The rule names a row that only exists in the `work` world. In any other
    // world the row is not in play, so the rule is recorded and inert.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x67),
        &patterned_owner_manifest(
            vec![scoped_owner_row(
                "owner:work-only",
                "Avoid spoilers at work.",
                "work",
            )],
            vec![owner_pattern(
                "owner.work-only",
                "(?i)spoiler",
                "owner:work-only",
                Some("decide"),
            )],
        ),
    )?;

    let elsewhere = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "a reply with spoilers",
    ))?;
    assert_eq!(elsewhere.decision, PolicyClassifyDecision::Allow);
    let audit = elsewhere.audit.as_deref().expect("the match is recorded");
    assert_eq!(
        audit.matched_pattern_ids,
        vec!["owner.work-only".to_owned()]
    );
    assert_eq!(audit.acting_pattern_role, None);

    let at_work = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content("a reply with spoilers").with_world_ref("work"),
    )?;
    assert_eq!(at_work.decision, PolicyClassifyDecision::Warn);
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
    put_policy_manifest_bytes(&vault, test_id(0x3f), &spoiler_manifest("block"))?;
    let request = PolicyClassifyRequest::outbound_content("a reply with spoilers");
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
    put_policy_manifest_bytes(
        &vault,
        test_id(0x72),
        &documented_owner_manifest(vec![owner_row("owner:jargon", "Avoid jargon.")], Vec::new()),
    )?;
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    let llm_request = |config: &PolicyModelConfig| -> Result<LlmRequest> {
        Ok(vault
            .policy_model_llm_request(&request, config)?
            .expect("a documented plane produces a request"))
    };

    let default_request = llm_request(&PolicyModelConfig::default())?;
    assert_eq!(
        default_request.envelope.tier.resolved().as_str(),
        "gpt-oss-safeguard-20b"
    );
    assert_eq!(
        default_request.model.as_str(),
        "oneiron/gpt-oss-safeguard-20b@default"
    );

    for (selector, tier, model) in [
        (
            "openrouter:meta/llama-guard-4",
            "openrouter:meta/llama-guard-4",
            "openrouter/meta.llama-guard-4@configured",
        ),
        (
            "endpoint:https://guard.local/v1",
            "endpoint:https://guard.local/v1",
            "endpoint/guard.local.v1@configured",
        ),
        (
            "on-device:qwen3guard-stream-0.6b",
            "on-device:qwen3guard-stream-0.6b",
            "on-device/qwen3guard-stream-0.6b@configured",
        ),
    ] {
        let config = PolicyModelConfig {
            safeguard_binding: SafeguardModelBinding::parse(selector).expect("binding parses"),
            ..PolicyModelConfig::default()
        };
        let built = llm_request(&config)?;
        assert_eq!(built.envelope.tier.resolved().as_str(), tier);
        assert_eq!(built.model.as_str(), model);
    }
    Ok(())
}

#[test]
fn generation_parameters_are_configuration_not_engine_constants() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x48),
        &documented_owner_manifest(vec![owner_row("owner:jargon", "Avoid jargon.")], Vec::new()),
    )?;
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");

    // The default sends no output cap at all — a reasoning safeguard model
    // needs room to think before it answers.
    let default_params = vault
        .policy_model_llm_request(&request, &PolicyModelConfig::default())?
        .expect("request")
        .params;
    assert!(!default_params.contains_key("max_output_tokens"));
    assert_eq!(
        default_params
            .get("reasoning_effort")
            .map(ToString::to_string),
        Some("\"medium\"".to_owned())
    );
    assert_eq!(
        default_params.get("temperature").map(ToString::to_string),
        Some("0.0".to_owned())
    );

    let tuned = PolicyModelConfig {
        generation: PolicyGenerationParams {
            reasoning_effort: PolicyReasoningEffort::High,
            temperature: 0.25,
            max_output_tokens: Some(4096),
        },
        ..PolicyModelConfig::default()
    };
    let tuned_params = vault
        .policy_model_llm_request(&request, &tuned)?
        .expect("request")
        .params;
    assert_eq!(
        tuned_params
            .get("reasoning_effort")
            .map(ToString::to_string),
        Some("\"high\"".to_owned())
    );
    assert_eq!(
        tuned_params
            .get("max_output_tokens")
            .map(ToString::to_string),
        Some("4096".to_owned())
    );
    Ok(())
}

#[test]
fn a_plane_never_ships_another_planes_vocabulary() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x63),
        &documented_owner_manifest(
            vec![owner_row("owner:jargon", "Avoid nautical jargon.")],
            Vec::new(),
        ),
    )?;

    let request = vault
        .policy_model_llm_request(
            &PolicyClassifyRequest::outbound_content("ordinary reply"),
            &PolicyModelConfig::default(),
        )?
        .expect("request");
    let rendered = serde_json::to_string(&request.envelope.response_format)
        .expect("response format serializes");
    assert!(
        !rendered.contains("hosted_legal"),
        "a local owner-plane vault must not be handed the hosted legal \
         vocabulary; schema was: {rendered}"
    );
    assert!(rendered.contains("owner:jargon"));

    // The hosted relay rubric DOES carry it — that plane is the whole reason
    // the vocabulary exists — and carries only the categories ITS policy
    // publishes.
    let hosted_policy = hosted_serious_crime_block();
    let hosted_prompt = super::prompt::render_classify_prompt(
        &PolicyClassifyRequest::outbound_content("ordinary reply"),
        &hosted_policy.policy_document,
        hosted_rubric_rows(&hosted_policy),
        PolicyOutputContract::CategoryJson,
    );
    let hosted_rendered = serde_json::to_string(
        &hosted_prompt
            .llm_request(&PolicyModelConfig::default())
            .envelope
            .response_format,
    )
    .expect("response format serializes");
    assert!(hosted_rendered.contains(HOSTED_SERIOUS_CRIME_LABEL));
    assert!(!hosted_rendered.contains("hosted_legal/ncii"));
    assert!(!hosted_rendered.contains("owner:jargon"));
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
fn a_disabled_plane_never_reports_a_stale_verdict() -> Result<()> {
    // The binding covers the WHOLE manifest frontier, so an edit the disabled
    // plane can never act on used to report its clean allow as stale — and the
    // caller would re-derive its way back to the identical clean allow. A
    // plane that decides nothing has nothing that can go out of date.
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    put_policy_manifest_bytes(
        &vault,
        test_id(0x46),
        &base_policy_manifest(vec![
            owner_policy_enabled(false),
            owner_rows(vec![owner_row("owner:jargon", "Avoid jargon.")]),
        ]),
    )?;
    let verdict = vault.classify_policy_model(request.clone())?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert!(!vault.policy_model_verdict_is_stale(&verdict, &request)?);

    // The manifest moves — new rows, a document, a whole new frontier — and
    // the plane stays off.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x46),
        &base_policy_manifest(vec![
            owner_policy_enabled(false),
            owner_rows(vec![
                owner_row("owner:jargon", "Avoid jargon, firmly."),
                owner_row_with_action("owner:spoilers", "Block spoilers.", "block"),
            ]),
            owner_document(OWNER_DOCUMENT),
            owner_contract("category_json"),
        ]),
    )?;
    assert!(!vault.policy_model_verdict_is_stale(&verdict, &request)?);
    Ok(())
}

#[test]
fn a_verdict_minted_while_the_plane_was_on_is_stale_once_it_is_off() -> Result<()> {
    // The opt-OUT transition. A disabled plane returns the inert clean allow
    // and nothing else, so a `Block` in a caller's hand was decided while the
    // plane was ON. Reading it fresh after the owner switched the plane off
    // would let a rule they retired keep blocking their own content — the
    // sovereignty violation this predicate exists to catch.
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("This reply contains spoilers.");
    let live = vec![
        owner_policy_enabled(true),
        owner_rows(vec![owner_row_with_action(
            "owner:spoilers",
            "Avoid spoilers.",
            "block",
        )]),
        owner_patterns(vec![owner_pattern(
            "owner.spoilers",
            "(?i)spoiler",
            "owner:spoilers",
            Some("decide"),
        )]),
    ];
    put_policy_manifest_bytes(&vault, test_id(0x4b), &base_policy_manifest(live.clone()))?;
    let blocked = vault.classify_policy_model(request.clone())?;
    assert_eq!(blocked.decision, PolicyClassifyDecision::Block);
    assert!(!vault.policy_model_verdict_is_stale(&blocked, &request)?);

    // Nothing about the rules changes; the owner just opts out.
    let mut opted_out = live;
    opted_out[0] = owner_policy_enabled(false);
    put_policy_manifest_bytes(&vault, test_id(0x4b), &base_policy_manifest(opted_out))?;
    assert!(
        vault.policy_model_verdict_is_stale(&blocked, &request)?,
        "a block minted by a live plane must not survive the owner turning it off",
    );

    // The clean allow the disabled plane itself produces is still fresh: it is
    // exactly what re-deriving would return, so reporting it stale would only
    // send the caller round a loop.
    let inert = vault.classify_policy_model(request.clone())?;
    assert_eq!(inert.decision, PolicyClassifyDecision::Allow);
    assert!(!vault.policy_model_verdict_is_stale(&inert, &request)?);
    Ok(())
}

#[test]
fn verdict_stale_when_the_owner_document_changes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    put_policy_manifest_bytes(
        &vault,
        test_id(0x41),
        &documented_owner_manifest(vec![owner_row("owner:jargon", "Avoid jargon.")], Vec::new()),
    )?;
    let verdict = vault.classify_policy_model(request.clone())?;
    assert!(!vault.policy_model_verdict_is_stale(&verdict, &request)?);

    // One byte of the document is a different policy, and every verdict decided
    // under the old one is stale.
    let amended = format!("{OWNER_DOCUMENT}!");
    put_policy_manifest_bytes(
        &vault,
        test_id(0x41),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row("owner:jargon", "Avoid jargon.")]),
            owner_document(&amended),
            owner_contract("category_json"),
        ]),
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
        test_id(0x71),
        &documented_owner_manifest(
            vec![owner_row("owner:jargon", "Avoid nautical jargon.")],
            Vec::new(),
        ),
    )?;
    let backend = static_backend(r#"{"violation":1,"policy_category":"owner:jargon"}"#);
    let verdict = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This answer uses nautical phrasing."),
        &PolicyModelConfig::default(),
        &backend,
        &lease("policy-owner-row"),
    ))?;
    // A row that names no action only asks to be told about.
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
fn the_row_decides_the_action_not_the_model() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The model says "violation"; the ROW says what a violation of it costs.
    // There is no channel for a model to pick `Block` over a `Warn` row.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x43),
        &documented_owner_manifest(
            vec![owner_row_with_action(
                "owner:jargon",
                "Avoid nautical jargon.",
                "warn",
            )],
            Vec::new(),
        ),
    )?;
    let backend = static_backend(r#"{"violation":1,"policy_category":"owner:jargon"}"#);
    let verdict = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("ordinary reply"),
        &PolicyModelConfig::default(),
        &backend,
        &lease("row-decides"),
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Warn);
    Ok(())
}

#[test]
fn an_owner_answer_naming_no_row_fails_the_plane_open() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x44),
        &documented_owner_manifest(
            vec![owner_row("owner:jargon", "Avoid nautical jargon.")],
            Vec::new(),
        ),
    )?;
    let backend = static_backend(r#"{"violation":1,"policy_category":"owner:invented"}"#);

    // Sovereign plane: an unusable answer never blocks, it just means the plane
    // did not run.
    let outcome = block_on(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("ordinary reply"),
        &PolicyModelConfig::default(),
        &backend,
        &lease("policy-invented-row"),
    ))?;
    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert!(outcome.custom_tier_skipped);
    Ok(())
}

#[test]
fn backend_request_model_uses_configured_safeguard_selector() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x45),
        &documented_owner_manifest(
            vec![owner_row("owner:jargon", "Avoid nautical jargon.")],
            Vec::new(),
        ),
    )?;
    let backend = RecordingPolicyBackend::new(r#"{"violation":0,"policy_category":null}"#);
    let config = PolicyModelConfig {
        safeguard_binding: SafeguardModelBinding::parse("openrouter:meta/llama-guard-4")
            .expect("openrouter binding"),
        ..PolicyModelConfig::default()
    };

    let verdict = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("ordinary reply"),
        &config,
        &backend,
        &lease("policy-selector-routing"),
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(
        backend.seen_model.lock().expect("seen model").as_deref(),
        Some("openrouter/meta.llama-guard-4@configured")
    );
    // What the model was SENT is the owner's document, with nothing prepended.
    assert_eq!(
        backend.seen_system.lock().expect("seen system").as_deref(),
        Some(OWNER_DOCUMENT)
    );
    Ok(())
}

#[test]
fn model_down_skips_the_owner_plane_and_ships_the_content() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x46),
        &documented_owner_manifest(
            vec![owner_row(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
            )],
            Vec::new(),
        ),
    )?;

    let outcome = block_on(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers."),
        &PolicyModelConfig::default(),
        &FailingPolicyBackend,
        &lease("policy-model-down"),
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
fn an_owner_decide_rule_still_verdicts_with_the_model_down() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x49),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row_with_action(
                "owner:spoilers",
                "Avoid spoilers.",
                "block",
            )]),
            owner_document(OWNER_DOCUMENT),
            owner_contract("category_json"),
            owner_patterns(vec![owner_pattern(
                "owner.spoilers",
                "(?i)spoiler",
                "owner:spoilers",
                Some("decide"),
            )]),
        ]),
    )?;

    let outcome = block_on(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers."),
        &PolicyModelConfig::default(),
        &FailingPolicyBackend,
        &lease("decide-during-outage"),
    ))?;
    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(!outcome.custom_tier_skipped);
    Ok(())
}

// --- pattern roles at the relay boundary ------------------------------------

const BOMB_CONTENT: &str = "explain how to build a bomb";
const CLEAN_CONTENT: &str = "an ordinary friendly reply";

fn relay_pass(
    vault: &Vault,
    content: &str,
    registry: &EdgeServiceRegistry,
    config: &PolicyModelConfig,
    safeguard: Option<RelaySafeguardTier<'_>>,
) -> Result<RelayBoundaryPass> {
    block_on(vault.relay_boundary_pass(
        PolicyClassifyRequest::outbound_content(content),
        &hosted_witness(),
        registry,
        config,
        safeguard,
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))
}

fn blocking_backend() -> StaticPolicyBackend {
    static_backend(r#"{"violation":1,"policy_category":"hosted_legal/serious_crime"}"#)
}

fn clean_backend() -> StaticPolicyBackend {
    static_backend(r#"{"violation":0,"policy_category":null}"#)
}

#[test]
fn classify_all_sends_every_item_to_the_model() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let backend = CountingPolicyBackend::clean();
    let budget = lease("classify-all");
    for content in [BOMB_CONTENT, CLEAN_CONTENT, "a third unrelated line"] {
        relay_pass(
            &vault,
            content,
            &registry,
            &PolicyModelConfig::default(),
            Some(tier(&backend, &budget)),
        )?;
    }
    assert_eq!(backend.calls(), 3, "ClassifyAll classifies 100% of content");
    Ok(())
}

#[test]
fn an_escalate_hit_buys_exactly_one_model_call_and_the_model_wins() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![escalate_rule(
        "hosted.bomb",
        "(?i)bomb",
    )]));
    let backend = CountingPolicyBackend::clean();
    let budget = lease("escalate");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig {
            relay_classifier_mode: RelayClassifierMode::PatternGated,
            ..PolicyModelConfig::default()
        },
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(backend.calls(), 1);
    // The model overruled the pattern, and the pattern did not get a vote.
    let verdict = pass.boundary_verdict().expect("verdict");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert!(!pass.must_halt_relay());
    assert_eq!(pass.resolution(), Some(RelayResolution::ModelDecided));

    // ... and the overruled hit is STILL receipted. That row is the whole
    // reason a substrate owner can find out their pattern is too wide.
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1, "an overruled escalate is receipted");
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.pattern_matched.hosted.bomb"
    ));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.pattern_role.escalate"
    ));
    assert_eq!(receipts[0].outcome, "relay_boundary_allow");
    Ok(())
}

#[test]
fn a_decide_hit_is_the_verdict_and_calls_no_model() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![decide_rule(
        "hosted.bomb",
        "(?i)bomb",
    )]));
    let backend = CountingPolicyBackend::clean();
    let budget = lease("decide");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(backend.calls(), 0, "a hard rule needs no model");
    let verdict = pass.boundary_verdict().expect("verdict");
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
    assert_eq!(pass.resolution(), Some(RelayResolution::PatternDecided));
    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(
        &receipts[0],
        "gate.relay.resolution.pattern_decided"
    ));
    Ok(())
}

#[test]
fn a_log_only_hit_allows_calls_no_model_and_is_receipted() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![log_rule(
        "hosted.watchlist",
        "(?i)bomb",
    )]));
    let backend = CountingPolicyBackend::clean();
    let budget = lease("log-only");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig {
            relay_classifier_mode: RelayClassifierMode::PatternGated,
            ..PolicyModelConfig::default()
        },
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(backend.calls(), 0, "a log rule never triggers the model");
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(!pass.must_halt_relay());
    assert_eq!(pass.resolution(), Some(RelayResolution::LogOnly));
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert!(has_trace(&receipts[0], "gate.relay.resolution.log_only"));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.pattern_matched.hosted.watchlist"
    ));
    Ok(())
}

#[test]
fn pattern_gated_with_no_hit_allows_with_zero_model_calls_and_its_own_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![escalate_rule(
        "hosted.bomb",
        "(?i)bomb",
    )]));
    let backend = CountingPolicyBackend::clean();
    let budget = lease("gated-miss");
    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &PolicyModelConfig {
            relay_classifier_mode: RelayClassifierMode::PatternGated,
            ..PolicyModelConfig::default()
        },
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(backend.calls(), 0);
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(!pass.must_halt_relay());
    assert_eq!(pass.resolution(), Some(RelayResolution::PatternGatedAllow));
    let receipts = gate_receipts(&vault)?;
    assert_eq!(
        receipts.len(),
        1,
        "an allow nothing examined is a distinct fact, and is recorded"
    );
    assert!(has_trace(
        &receipts[0],
        "gate.relay.resolution.pattern_gated_allow"
    ));
    assert!(has_trace(
        &receipts[0],
        "gate.relay.classifier_mode.pattern_gated"
    ));
    Ok(())
}

#[test]
fn the_strictest_matching_role_acts_and_every_id_is_receipted() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // All three roles match the same content. `Decide` is strictest, so it
    // acts — and the other two are still named in the receipt.
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![
        log_rule("hosted.log", "(?i)bomb"),
        escalate_rule("hosted.escalate", "(?i)build"),
        decide_rule("hosted.decide", "(?i)explain"),
    ]));
    let backend = CountingPolicyBackend::clean();
    let budget = lease("precedence");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(backend.calls(), 0, "Decide short-circuits the model");
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Block
    );
    let audit = pass
        .boundary_verdict()
        .expect("verdict")
        .audit
        .as_deref()
        .expect("audit");
    assert_eq!(
        audit.matched_pattern_ids,
        vec![
            "hosted.log".to_owned(),
            "hosted.escalate".to_owned(),
            "hosted.decide".to_owned()
        ]
    );
    assert_eq!(audit.acting_pattern_role, Some(PolicyPatternRole::Decide));
    let receipts = gate_receipts(&vault)?;
    for id in ["hosted.log", "hosted.escalate", "hosted.decide"] {
        assert!(
            has_trace(
                &receipts[0],
                &format!("gate.policy_model.pattern_matched.{id}")
            ),
            "missing matched id {id}"
        );
    }
    Ok(())
}

#[test]
fn ties_on_strictness_resolve_to_the_rule_written_first() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![
        decide_rule("hosted.first", "(?i)bomb"),
        decide_rule("hosted.second", "(?i)build"),
    ]));
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        None,
    )?;
    let audit = pass
        .boundary_verdict()
        .expect("verdict")
        .audit
        .as_deref()
        .expect("audit");
    assert_eq!(
        audit.matched_pattern_ids,
        vec!["hosted.first".to_owned(), "hosted.second".to_owned()]
    );
    assert_eq!(pass.resolution(), Some(RelayResolution::PatternDecided));
    Ok(())
}

// --- outage behaviour per mode ----------------------------------------------

#[test]
fn a_hosted_pass_with_no_model_tier_degrades_and_halts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        None,
    )?;
    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::SafeguardModelTierAbsent)
    );
    assert!(
        pass.must_halt_relay(),
        "the hosted plane is fail-closed: an unanswered policy stops the relay"
    );
    Ok(())
}

#[test]
fn a_hosted_policy_with_no_output_contract_degrades_on_its_own_cause() -> Result<()> {
    // Registration refuses a contract-less policy, so this shape reaches the
    // relay only where the registry was bypassed. There IS a model here — what
    // is missing is the shape of the answer — so the degrade must not borrow
    // the missing-tier code and send a reader looking for a tier that exists.
    let (_tmp, vault) = temp_vault();
    let mut registry = fixture_edge_service_registry();
    registry.bind_unvalidated_for_testing(
        HOSTED_EDGE_SERVICE,
        ConnectionClass::LocalVaultViaHostedConnector,
        HostedLegalPolicy {
            output_contract: None,
            ..hosted_serious_crime_block()
        },
    );
    let backend = clean_backend();
    let budget = lease("no-output-contract");
    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::OutputContractUndeclared)
    );
    assert_eq!(
        RelayBoundaryDegrade::OutputContractUndeclared.as_str(),
        "output_contract_undeclared"
    );
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn a_decide_rule_still_verdicts_while_the_model_is_down() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![decide_rule(
        "hosted.bomb",
        "(?i)bomb",
    )]));
    let budget = lease("outage-decide");
    let caught = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        Some(tier(&FailingPolicyBackend, &budget)),
    )?;
    assert_eq!(
        caught.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Block
    );
    assert!(caught.degraded().is_none(), "the rule answered it");

    // Content the rule does not reach has no coverage at all during an outage,
    // so it degrades and halts.
    let clean = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &PolicyModelConfig::default(),
        Some(tier(&FailingPolicyBackend, &budget)),
    )?;
    assert_eq!(
        clean.degraded(),
        Some(RelayBoundaryDegrade::SafeguardModelUnavailable)
    );
    assert!(clean.must_halt_relay());
    Ok(())
}

#[test]
fn pattern_gated_outage_only_degrades_what_escalated() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_policy_with_rules(vec![escalate_rule(
        "hosted.bomb",
        "(?i)bomb",
    )]));
    let config = PolicyModelConfig {
        relay_classifier_mode: RelayClassifierMode::PatternGated,
        ..PolicyModelConfig::default()
    };
    let budget = lease("gated-outage");

    // Nothing escalated, so no model was needed and nothing degraded.
    let untouched = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &registry,
        &config,
        Some(tier(&FailingPolicyBackend, &budget)),
    )?;
    assert!(untouched.degraded().is_none());
    assert!(!untouched.must_halt_relay());

    // An escalation with the model down is a real gap, and halts.
    let escalated = relay_pass(
        &vault,
        BOMB_CONTENT,
        &registry,
        &config,
        Some(tier(&FailingPolicyBackend, &budget)),
    )?;
    assert_eq!(
        escalated.degraded(),
        Some(RelayBoundaryDegrade::SafeguardModelUnavailable)
    );
    assert!(escalated.must_halt_relay());
    Ok(())
}

#[test]
fn an_unreadable_answer_is_a_classification_failure_not_an_allow() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let budget = lease("unreadable");
    for body in [
        "not json at all",
        r#"{"violation":2,"policy_category":null}"#,
        r#"{"violation":1,"policy_category":null}"#,
        r#"{"violation":1,"policy_category":"hosted_legal/ncii"}"#,
        r#"{"violation":0,"policy_category":"hosted_legal/serious_crime"}"#,
        r#"{"violation":0,"policy_category":null,"extra":"field"}"#,
    ] {
        let backend = static_backend(body);
        let pass = relay_pass(
            &vault,
            CLEAN_CONTENT,
            &registry,
            &PolicyModelConfig::default(),
            Some(tier(&backend, &budget)),
        )?;
        assert_eq!(
            pass.degraded(),
            Some(RelayBoundaryDegrade::SafeguardModelResponseUnusable),
            "body: {body}"
        );
        assert!(pass.must_halt_relay(), "body: {body}");
    }
    Ok(())
}

#[test]
fn the_owner_plane_fails_open_where_the_hosted_plane_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x4a),
        &documented_owner_manifest(
            vec![owner_row("owner:spoilers", "Avoid spoilers.")],
            Vec::new(),
        ),
    )?;
    // The same unreadable answer, on the two planes. The owner's plane ships
    // the content; the hosted plane stops the relay.
    let backend = static_backend("not json at all");
    let owner = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content(CLEAN_CONTENT),
        &PolicyModelConfig::default(),
        &backend,
        &lease("owner-fails-open"),
    ))?;
    assert_eq!(owner.decision, PolicyClassifyDecision::Allow);

    let budget = lease("hosted-fails-closed");
    let hosted = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    assert!(hosted.must_halt_relay());
    Ok(())
}

// --- output contract presets -------------------------------------------------

#[test]
fn every_output_contract_round_trips_through_the_relay() -> Result<()> {
    let budget = lease("contracts");
    for (contract, clean, violating) in [
        (PolicyOutputContract::Binary, "0", "1"),
        (
            PolicyOutputContract::CategoryJson,
            r#"{"violation":0,"policy_category":null}"#,
            r#"{"violation":1,"policy_category":"hosted_legal/serious_crime"}"#,
        ),
        (
            PolicyOutputContract::RationaleJson,
            r#"{"violation":0,"policy_category":null,"rule_ids":[],"confidence":"high","rationale":"nothing in this text is instructional"}"#,
            r#"{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":["SC-1"],"confidence":"high","rationale":"actionable instruction"}"#,
        ),
    ] {
        let policy = HostedLegalPolicy {
            output_contract: Some(contract),
            ..hosted_serious_crime_block()
        };
        let registry = hosted_edge_registry(policy);

        let (_tmp, vault) = temp_vault();
        let clean_backend = static_backend(clean);
        let clean_pass = relay_pass(
            &vault,
            CLEAN_CONTENT,
            &registry,
            &PolicyModelConfig::default(),
            Some(tier(&clean_backend, &budget)),
        )?;
        assert_eq!(
            clean_pass.boundary_verdict().expect("verdict").decision,
            PolicyClassifyDecision::Allow,
            "contract: {contract:?}"
        );
        assert!(clean_pass.degraded().is_none(), "contract: {contract:?}");

        let (_tmp, vault) = temp_vault();
        let violating_backend = static_backend(violating);
        let violating_pass = relay_pass(
            &vault,
            BOMB_CONTENT,
            &registry,
            &PolicyModelConfig::default(),
            Some(tier(&violating_backend, &budget)),
        )?;
        assert_eq!(
            violating_pass.boundary_verdict().expect("verdict").decision,
            PolicyClassifyDecision::Block,
            "contract: {contract:?}"
        );
        assert!(violating_pass.must_halt_relay(), "contract: {contract:?}");
    }
    Ok(())
}

#[test]
fn a_binary_violation_resolves_to_the_strictest_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Binary carries no label, so the plane's strictest row governs — Block
    // over Warn, whatever order they were registered in.
    let policy = HostedLegalPolicy {
        output_contract: Some(PolicyOutputContract::Binary),
        rows: vec![
            hosted_row(
                "hosted:ncii",
                HostedLegalCategory::Ncii,
                HostedLegalAction::Warn,
                "Flag non-consensual intimate imagery.",
            ),
            hosted_row(
                "hosted:serious-crime",
                HostedLegalCategory::SeriousCrime,
                HostedLegalAction::Block,
                "Withhold serious-crime facilitation.",
            ),
        ],
        ..hosted_serious_crime_block()
    };
    let backend = static_backend("1");
    let budget = lease("binary-strictest");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    let verdict = pass.boundary_verdict().expect("verdict");
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
    Ok(())
}

#[test]
fn rationale_fields_land_in_the_verdict_and_the_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        output_contract: Some(PolicyOutputContract::RationaleJson),
        ..hosted_serious_crime_block()
    };
    let backend = static_backend(
        r#"{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":["SC-1","SC-2"],"confidence":"high","rationale":"the text gives step-by-step instructions"}"#,
    );
    let budget = lease("rationale");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    let audit = pass
        .boundary_verdict()
        .expect("verdict")
        .audit
        .as_deref()
        .expect("audit");
    assert_eq!(
        audit.model_rule_ids,
        vec!["SC-1".to_owned(), "SC-2".to_owned()]
    );
    assert_eq!(audit.model_confidence.as_deref(), Some("high"));
    assert_eq!(
        audit.model_rationale.as_deref(),
        Some("the text gives step-by-step instructions")
    );

    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(&receipts[0], "gate.policy_model.model_rule.sc-1"));
    assert!(has_trace(&receipts[0], "gate.policy_model.model_rule.sc-2"));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.model_confidence.high"
    ));
    Ok(())
}

#[test]
fn an_oversized_rule_id_array_cannot_flood_the_ledger() -> Result<()> {
    // The array is model-supplied and nobody validated it, and every id
    // becomes a reason code. Left uncapped, one answer writes one ledger row
    // carrying thousands of them.
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        output_contract: Some(PolicyOutputContract::RationaleJson),
        ..hosted_serious_crime_block()
    };
    let flood: Vec<String> = (0..POLICY_MODEL_RULE_IDS_MAX_COUNT * 40)
        .map(|index| format!("\"SC-{index}\""))
        .collect();
    let body = format!(
        r#"{{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":[{}],"confidence":"high","rationale":"flood"}}"#,
        flood.join(",")
    );
    let backend = StaticPolicyBackend { body };
    let budget = lease("rule-id-flood");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    let audit = pass
        .boundary_verdict()
        .expect("verdict")
        .audit
        .as_deref()
        .expect("audit");
    assert_eq!(audit.model_rule_ids.len(), POLICY_MODEL_RULE_IDS_MAX_COUNT);
    // Truncated, not refused: a verbose answer is a verbose model, and the
    // verdict it carried still stands.
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Block
    );
    let receipts = gate_receipts(&vault)?;
    let rule_codes = receipts[0]
        .policy_trace
        .iter()
        .filter(|trace| trace.starts_with("gate.policy_model.model_rule."))
        .count();
    assert_eq!(rule_codes, POLICY_MODEL_RULE_IDS_MAX_COUNT);
    Ok(())
}

#[test]
fn the_receipt_write_refuses_a_binding_that_moved_after_the_pass() -> Result<()> {
    // The pass re-checks its binding and returns; the row is written in a
    // SEPARATE transaction afterwards. Nothing in the relay entry point can
    // inject a manifest move into that gap, so the unit that closes it is
    // driven directly: a pass carrying a binding that is already stale by the
    // time the row is written.
    //
    // Without the re-check the row would assert that stale binding, and a
    // later CloudVault verification recomputing the hash locally would find a
    // receipt attesting policy state nobody can reproduce.
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let config = PolicyModelConfig::default();
    let stale = PolicyContentBinding {
        content_hash: [0x5a; 32],
        read_frontier_hash: [0x5a; 32],
    };
    let pass = RelayBoundaryPass::classified(
        PolicyClassifyVerdict::clean_allow(stale, &config),
        None,
        true,
        RelayResolution::ModelDecided,
    );
    let verdict = pass.boundary_verdict().expect("verdict").clone();

    vault.append_relay_receipt_binding_checked(
        &super::relay::RelayReceipt {
            request: &request,
            domain: &hosted_witness(),
            pass: &pass,
            receipt_breach: None,
            hosted: None,
            config: &config,
        },
        &verdict,
        "relay_boundary_allow",
        vec!["gate.relay.classify.ran".to_owned()],
        Vec::new(),
    )?;

    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert!(
        has_trace(
            &receipts[0],
            "gate.relay.degraded.policy_binding_moved_mid_pass"
        ),
        "the row records the degrade rather than the dead binding"
    );
    Ok(())
}

#[test]
fn a_manifest_moving_after_the_pass_is_caught_by_the_receipt_write() -> Result<()> {
    // The pass re-checks its binding and returns; the row is written in a
    // separate transaction afterwards. A manifest that moves in THAT gap would
    // otherwise be receipted under a binding nobody can reproduce — the same
    // hole the mid-pass re-check closes one seam earlier.
    //
    // The move is staged between the two by writing the manifest from the
    // backend, which returns after the pass's own re-check has run: the pass
    // settles, and the receipt write is the next thing to look.
    let (_tmp, vault) = temp_vault();
    // The moving backend rewrites THIS id, so the seed must use it too — a
    // second manifest id would duplicate the row_ref across manifests and the
    // resolver would drop the rows instead of moving the frontier.
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let backend = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("block"),
        body: r#"{"violation":0}"#,
        keep_moving: true,
        calls: AtomicUsize::new(0),
    };
    let budget = lease("receipt-binding-recheck");

    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    // The pass itself already degrades here — that is the mid-pass re-check
    // doing its job. What this pins is that the ROW says so, written under a
    // binding the ledger can reproduce rather than the dead one.
    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::PolicyBindingMovedMidPass)
    );
    let receipts = gate_receipts(&vault)?;
    assert!(
        receipts
            .iter()
            .any(|receipt| has_trace(receipt, "gate.relay.degraded.policy_binding_moved_mid_pass")),
        "the degrade names itself in the ledger"
    );
    Ok(())
}

/// A backend that rewrites the vault's policy manifest DURING the model call —
/// the await the owner-plane pass spends on a network round trip, which is
/// exactly the window an owner tightening a row lands in.
struct ManifestMovingBackend<'v> {
    vault: &'v Vault,
    manifest: Vec<u8>,
    body: &'static str,
    /// Moves the manifest on every call rather than only the first, so the
    /// re-derivation lands on a manifest that has moved again.
    keep_moving: bool,
    calls: AtomicUsize,
}

impl LlmBackend for ManifestMovingBackend<'_> {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 || self.keep_moving {
            let mut manifest = self.manifest.clone();
            if call > 0 {
                // A different manifest each time, so the frontier keeps
                // moving instead of settling on the same bytes.
                manifest = base_policy_manifest(vec![
                    owner_policy_enabled(true),
                    owner_rows(vec![owner_row_with_action(
                        "owner:spoilers",
                        &format!("Block spoilers, revision {call}."),
                        "block",
                    )]),
                    owner_document(OWNER_DOCUMENT),
                    owner_contract("category_json"),
                ]);
            }
            put_policy_manifest_bytes(self.vault, test_id(0x48), &manifest)
                .expect("mid-call manifest write");
        }
        let body = self.body.to_owned();
        Box::pin(async move { Ok(text_response(body)) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// The manifest the moving backend installs: the same row, tightened.
fn spoilers_manifest(action: &str) -> Vec<u8> {
    base_policy_manifest(vec![
        owner_policy_enabled(true),
        owner_rows(vec![owner_row_with_action(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
            action,
        )]),
        owner_document(OWNER_DOCUMENT),
        owner_contract("category_json"),
    ])
}

#[test]
fn a_manifest_that_moved_mid_call_is_not_enforced_stale() -> Result<()> {
    // The pass snapshots the manifest, then awaits a round trip. An owner who
    // tightens `warn` to `block` during that await must not have the
    // pre-change verdict enforced against post-change policy: the engine would
    // be acting on a rule that no longer exists.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let backend = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("block"),
        body: r#"{"violation":1,"policy_category":"owner:spoilers"}"#,
        keep_moving: false,
        calls: AtomicUsize::new(0),
    };
    let outcome = block_on(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("a reply with spoilers"),
        &PolicyModelConfig::default(),
        &backend,
        &lease("stale-manifest"),
    ))?;

    // Re-derived against what is in force: the row is a block now.
    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(outcome.outbound_halted);
    assert!(outcome.final_content.is_none());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn a_relay_manifest_that_moved_mid_call_is_derived_again() -> Result<()> {
    // The hosted plane's half of the same window. Its pass binds a verdict to
    // the vault's policy state, then awaits a round trip; state that moves
    // during that await leaves the pass about to receipt under a frontier
    // nobody could recompute. Derived again, ONCE, exactly as the owner plane
    // does at its enforcement door.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let backend = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("block"),
        body: r#"{"violation":0}"#,
        keep_moving: false,
        calls: AtomicUsize::new(0),
    };
    let budget = lease("relay-stale-manifest");
    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        2,
        "derived again, once"
    );
    assert_eq!(pass.degraded(), None, "the second derivation settled");
    assert_eq!(pass.resolution(), Some(RelayResolution::ModelDecided));
    assert!(!pass.must_halt_relay());
    Ok(())
}

#[test]
fn a_relay_manifest_that_will_not_settle_degrades_the_hosted_pass() -> Result<()> {
    // Derived twice and stale twice. Here the two planes part: the owner plane
    // is sovereign and fails OPEN, the hosted plane is fail-CLOSED. A verdict
    // it cannot pin to a policy is exactly the unexamined allow this plane
    // exists to refuse, so it degrades — and a degrade with a hosted policy in
    // play halts the relay.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let backend = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("block"),
        body: r#"{"violation":0}"#,
        keep_moving: true,
        calls: AtomicUsize::new(0),
    };
    let budget = lease("relay-unsettled-manifest");
    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        2,
        "derived twice, no more"
    );
    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::PolicyBindingMovedMidPass),
    );
    assert_eq!(pass.resolution(), Some(RelayResolution::Unresolved));
    assert!(
        pass.must_halt_relay(),
        "the hosted plane is fail-closed: an unpinnable verdict stops the relay",
    );

    let receipts = gate_receipts(&vault)?;
    assert!(
        receipts
            .iter()
            .any(|receipt| has_trace(receipt, "gate.relay.degraded.policy_binding_moved_mid_pass")),
        "the degrade names itself in the ledger",
    );
    Ok(())
}

#[test]
fn a_manifest_that_will_not_settle_fails_the_owner_plane_open_with_a_receipt() -> Result<()> {
    // Derived twice and stale twice: the manifest is moving faster than a pass
    // can be taken. The owner plane is sovereign, so it lets the content
    // through — and leaves a row saying that is what happened, rather than
    // enforcing a rule it cannot name.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("warn"))?;
    let backend = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("block"),
        body: r#"{"violation":1,"policy_category":"owner:spoilers"}"#,
        keep_moving: true,
        calls: AtomicUsize::new(0),
    };
    let original = "a reply with spoilers";
    let outcome = block_on(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content(original),
        &PolicyModelConfig::default(),
        &backend,
        &lease("unsettled-manifest"),
    ))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert_eq!(outcome.final_content.as_deref(), Some(original));
    assert!(outcome.custom_tier_skipped);
    assert!(outcome.receipt_ref.is_some());
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts[0].outcome, "owner_plane_stale_fail_open");
    assert!(has_trace(&receipts[0], "gate.policy_model.stale_manifest"));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.owner_plane_fail_open"
    ));
    Ok(())
}

/// A backend whose one answer arrives split across several text parts, the way
/// a streaming or chunking provider hands one back.
struct SplitAnswerBackend {
    parts: Vec<&'static str>,
}

impl LlmBackend for SplitAnswerBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let content = self
            .parts
            .iter()
            .map(|text| ContentPart::Text {
                text: (*text).to_owned(),
            })
            .collect();
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content,
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

#[test]
fn an_answer_split_across_content_parts_is_read_whole() -> Result<()> {
    // Reading only the first non-blank part parses a fragment, a fragment is
    // an unreadable answer, and an unreadable answer HALTS the hosted relay —
    // so a provider that chunks its output would take the plane down for a
    // reason that was never about the content.
    let (_tmp, vault) = temp_vault();
    let backend = SplitAnswerBackend {
        parts: vec![
            r#"{"violation":1,"#,
            "  ",
            r#""policy_category":"hosted_legal/serious_crime"}"#,
        ],
    };
    let budget = lease("split-answer");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    assert!(pass.degraded().is_none(), "a split answer is not a degrade");
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Block
    );
    assert_eq!(pass.resolution(), Some(RelayResolution::ModelDecided));
    Ok(())
}

#[test]
fn the_model_rationale_is_an_audit_row_not_a_reader_notice() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        output_contract: Some(PolicyOutputContract::RationaleJson),
        ..hosted_serious_crime_block()
    };
    let backend = static_backend(
        r#"{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":[],"confidence":"high","rationale":"model reasoning the reader is not shown"}"#,
    );
    let budget = lease("rationale-audience");
    relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    let receipts = gate_receipts(&vault)?;
    let receipt = &receipts[0];
    // The FIRST notice — the one a caller surfaces — is the reader's, and it
    // does not carry the model's reasoning.
    let body = receipt.fields.get("system_notice").expect("notice body");
    assert!(!body.contains("model reasoning"));
    assert_eq!(
        receipt
            .fields
            .get("system_notice_audience")
            .map(String::as_str),
        Some(SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL)
    );
    // The audit row rides in the same receipt, named for what it is.
    assert!(has_trace(
        receipt,
        &format!("gate.system_notice.{SYSTEM_NOTICE_TYPE_MODEL_RATIONALE}")
    ));
    Ok(())
}

#[test]
fn a_clean_allow_keeps_the_rationale_for_the_pattern_that_fired() -> Result<()> {
    // The row the design turns on: an `Escalate` pattern fired, the model
    // looked and said `violation: 0`, and its stated reason is exactly the
    // data that tells the substrate owner their pattern is too wide. A clean
    // allow attributes itself to no plane, so deriving the plane from the
    // verdict's category dropped the audit row precisely here — the calling
    // plane is passed instead, because both call sites know it statically.
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        output_contract: Some(PolicyOutputContract::RationaleJson),
        ..hosted_policy_with_rules(vec![escalate_rule("hosted.bomb", "(?i)bomb")])
    };
    let backend = static_backend(
        r#"{"violation":0,"policy_category":null,"rule_ids":[],"confidence":"high","rationale":"the passage discusses policy history, not method"}"#,
    );
    let budget = lease("clean-allow-rationale");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    let verdict = pass.boundary_verdict().expect("verdict");
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(verdict.category, PolicyVerdictCategory::None);
    assert_eq!(verdict.plane(), None);

    let notice = super::notice::policy_model_rationale_notice(
        verdict,
        PolicyPlane::HostedLegal,
        Some(HOSTED_VERSION),
    )
    .expect("a clean allow with a rationale still files its audit row");
    assert_eq!(notice.audience, SYSTEM_NOTICE_AUDIENCE_AUDIT);
    assert_eq!(
        notice.policy_plane.as_deref(),
        Some(PolicyPlane::HostedLegal.as_str())
    );
    assert_eq!(
        notice.body,
        "the passage discusses policy history, not method"
    );

    // And it reaches the ledger, not just the caller.
    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(
        &receipts[0],
        &format!("gate.system_notice.{SYSTEM_NOTICE_TYPE_MODEL_RATIONALE}")
    ));
    Ok(())
}

#[test]
fn the_audit_notice_names_its_own_channel_and_audience() {
    let binding = relay_skip_content_binding(&PolicyClassifyRequest::outbound_content("candidate"));
    let verdict = PolicyClassifyVerdict::new(
        PolicyClassifyDecision::Warn,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:row".to_owned(),
        },
        PolicyConfidence::MEDIUM,
        binding,
        &PolicyModelConfig::default(),
    )
    .with_audit(PolicyPassAudit {
        model_rationale: Some("because the policy says so".to_owned()),
        ..PolicyPassAudit::default()
    });
    let notice =
        super::notice::policy_model_rationale_notice(&verdict, PolicyPlane::OwnerPolicy, None)
            .expect("a rationale produces an audit row");
    assert_eq!(notice.audience, SYSTEM_NOTICE_AUDIENCE_AUDIT);
    assert_eq!(notice.channel, SYSTEM_NOTICE_CHANNEL_AUDIT);
    assert_eq!(notice.notice_type, SYSTEM_NOTICE_TYPE_MODEL_RATIONALE);
    assert_eq!(notice.body, "because the policy says so");
    assert_eq!(
        notice.policy_plane.as_deref(),
        Some(PolicyPlane::OwnerPolicy.as_str())
    );
    // The owner plane publishes no versioned document, so it names no version.
    assert_eq!(notice.policy_version, None);

    // No rationale, no row.
    let bare = PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default());
    assert!(
        super::notice::policy_model_rationale_notice(&bare, PolicyPlane::OwnerPolicy, None)
            .is_none()
    );
}

// --- registration is where a hosted policy is held to account ---------------

#[test]
fn hosted_registration_rejects_a_policy_it_could_not_enforce() {
    let long_id = "x".repeat(POLICY_PATTERN_ID_MAX_LEN + 1);
    let long_pattern = "a".repeat(POLICY_PATTERN_MAX_LEN + 1);
    let too_many: Vec<PolicyPatternRule> = (0..=POLICY_PATTERN_RULES_MAX)
        .map(|index| escalate_rule(&format!("rule.{index}"), "(?i)bomb"))
        .collect();

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
            "policy_document",
            HostedLegalPolicy {
                policy_document: String::new(),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "policy_document",
            HostedLegalPolicy {
                policy_document: "d".repeat(POLICY_DOCUMENT_MAX_LEN + 1),
                ..hosted_serious_crime_block()
            },
        ),
        (
            "output_contract",
            HostedLegalPolicy {
                output_contract: None,
                ..hosted_serious_crime_block()
            },
        ),
        (
            "pattern_rule_pattern",
            hosted_policy_with_rules(vec![escalate_rule("hosted.broken", "bomb(")]),
        ),
        (
            "pattern_rule_pattern",
            hosted_policy_with_rules(vec![escalate_rule("hosted.long", &long_pattern)]),
        ),
        (
            "pattern_rule_id",
            hosted_policy_with_rules(vec![escalate_rule("", "(?i)bomb")]),
        ),
        (
            "pattern_rule_id",
            hosted_policy_with_rules(vec![escalate_rule("   ", "(?i)bomb")]),
        ),
        (
            "pattern_rule_id",
            hosted_policy_with_rules(vec![escalate_rule(&long_id, "(?i)bomb")]),
        ),
        (
            "pattern_rule_id",
            hosted_policy_with_rules(vec![escalate_rule("has a space", "(?i)bomb")]),
        ),
        (
            "pattern_rule_id",
            hosted_policy_with_rules(vec![
                escalate_rule("hosted.same", "(?i)bomb"),
                escalate_rule("hosted.same", "(?i)build"),
            ]),
        ),
        (
            "pattern_rule_category",
            hosted_policy_with_rules(vec![PolicyPatternRule::new(
                "hosted.offplane",
                "(?i)bomb",
                "hosted_legal/ncii",
            )]),
        ),
        (
            "pattern_rule_category",
            hosted_policy_with_rules(vec![PolicyPatternRule::new(
                "hosted.owner",
                "(?i)bomb",
                "owner_policy",
            )]),
        ),
        ("pattern_rules", hosted_policy_with_rules(too_many)),
    ] {
        let mut registry = fixture_edge_service_registry();
        let err = registry
            .register_hosted_legal_policy(HOSTED_EDGE_SERVICE, policy)
            .expect_err("an unenforceable hosted policy must be rejected at registration");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::RelayHostedLegalPolicyInvalid,
            "field: {field}"
        );
        assert!(format!("{err}").contains(field), "field: {field}");
        // The rejection is total: nothing partial was bound to the service.
        assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());
    }
}

#[test]
fn a_hosted_policy_docs_url_must_be_https() {
    // `docs_url` becomes the link a notice hands the reader to go read the rule
    // they were judged under. A non-https scheme there is either not a document
    // at all, or one that can be rewritten between us and them.
    for docs_url in [
        "http://policy.example.test/hosted",
        "javascript:alert(1)",
        "data:text/html,<p>policy</p>",
        "policy.example.test/hosted",
        "ftp://policy.example.test/hosted",
        // A bare scheme passes a prefix check and points at nothing.
        "https://",
        "HTTPS://",
        "https://   ",
    ] {
        let mut registry = fixture_edge_service_registry();
        let err = registry
            .register_hosted_legal_policy(
                HOSTED_EDGE_SERVICE,
                HostedLegalPolicy {
                    docs_url: docs_url.to_owned(),
                    ..hosted_serious_crime_block()
                },
            )
            .expect_err("a non-https docs_url must be rejected at registration");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::RelayHostedLegalPolicyInvalid,
            "docs_url: {docs_url:?}"
        );
        assert!(
            format!("{err}").contains("docs_url"),
            "docs_url: {docs_url:?}"
        );
        assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());
    }

    // Schemes are case-insensitive, so the check is too.
    for docs_url in [HOSTED_DOCS_URL, "HTTPS://policy.example.test/hosted"] {
        let mut registry = fixture_edge_service_registry();
        registry
            .register_hosted_legal_policy(
                HOSTED_EDGE_SERVICE,
                HostedLegalPolicy {
                    docs_url: docs_url.to_owned(),
                    ..hosted_serious_crime_block()
                },
            )
            .expect("an https docs_url registers");
        assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_some());
    }
}

#[test]
fn hosted_registration_rejects_a_row_that_carries_no_rule() {
    // The rows ARE the rubric. A blank `text` is handed to the model as the
    // rule it should judge against — and, worse, counts as coverage of its
    // category, so a blank row can be the reason a category is "covered". A
    // blank `row_ref` names nothing a reader could go and read.
    for (field, row) in [
        (
            "row_ref",
            hosted_row(
                "   ",
                HostedLegalCategory::SeriousCrime,
                HostedLegalAction::Block,
                "Withhold credible facilitation of mass harm.",
            ),
        ),
        (
            "row_text",
            hosted_row(
                "hosted:serious-crime",
                HostedLegalCategory::SeriousCrime,
                HostedLegalAction::Block,
                "   ",
            ),
        ),
    ] {
        let mut registry = fixture_edge_service_registry();
        let err = registry
            .register_hosted_legal_policy(HOSTED_EDGE_SERVICE, hosted_policy(vec![row]))
            .expect_err("an unreadable row must be refused at registration");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::RelayHostedLegalPolicyInvalid
        );
        assert!(format!("{err}").contains(field), "unexpected error: {err}");
        assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());
    }
}

#[test]
fn hosted_registration_rejects_two_rows_of_one_category() {
    // `row_for_category` takes the first match, so the second row here would
    // never fire — a block silently shadowed by a warn written above it. That
    // is an enforcement outage disguised as a policy, and it is refused where
    // every other unenforceable shape is: at registration.
    let mut registry = fixture_edge_service_registry();
    let err = registry
        .register_hosted_legal_policy(
            HOSTED_EDGE_SERVICE,
            hosted_policy(vec![
                hosted_row(
                    "hosted:crime-warn",
                    HostedLegalCategory::SeriousCrime,
                    HostedLegalAction::Warn,
                    "Flag facilitation of mass harm.",
                ),
                hosted_row(
                    "hosted:crime-block",
                    HostedLegalCategory::SeriousCrime,
                    HostedLegalAction::Block,
                    "Withhold facilitation of mass harm.",
                ),
            ]),
        )
        .expect_err("two rows of one category must be refused");
    assert!(
        format!("{err}").contains("row_category"),
        "unexpected error: {err}"
    );
    assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());
}

#[test]
fn owner_rows_sharing_a_row_ref_are_dropped_rather_than_shadowed() -> Result<()> {
    // Same hole on the owner plane: resolution finds the first row of a ref,
    // so a second one with a stricter action would never fire. The manifest
    // drops the rows instead, and a plane that is ON says so rather than
    // enforcing half a policy. One ref under two WORLDS is a different shape
    // and stays legal — that is the scoped override, pinned by
    // `active_owner_rows_resolve_scoped_world_override`.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x39),
        &enabled_owner_manifest(vec![
            owner_row_with_action("owner:spoilers", "Warn about spoilers.", "warn"),
            owner_row_with_action("owner:spoilers", "Block spoilers.", "block"),
        ]),
    )?;
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(policy.owner_policy_rows_dropped());
    drop(rtxn);

    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("a reply"))
        .expect_err("an enabled plane must not classify against shadowed rows");
    assert!(
        format!("{err}").contains("owner_policy_rows"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn owner_rows_sharing_a_row_ref_across_manifests_are_dropped_too() -> Result<()> {
    // The same shadowing, assembled across two manifest entities instead of
    // inside one. Resolution CONCATENATES every manifest's rows and then
    // first-matches over the result, so each manifest is individually well
    // formed and the block still never fires. Splitting a policy in two must
    // not buy a rule that silently swallows another.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3a),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:spoilers",
            "Warn about spoilers.",
            "warn",
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3b),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:spoilers",
            "Block spoilers.",
            "block",
        )]),
    )?;
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(policy.owner_policy_rows_dropped());
    assert!(policy.active_owner_policy_rows(None).is_empty());
    drop(rtxn);

    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("a reply"))
        .expect_err("an enabled plane must not classify against shadowed rows");
    assert!(
        format!("{err}").contains("owner_policy_rows"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn one_row_ref_under_two_worlds_survives_a_manifest_split() -> Result<()> {
    // The scoped override is the shape the PAIR key exists to protect, and it
    // is just as legal split across manifests as it is inside one. Keying on
    // the ref alone would turn a legitimate world-scoped policy into dropped
    // rows the moment its author filed the two worlds separately.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3c),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:spoilers",
            "Warn about spoilers.",
            "warn",
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3d),
        &enabled_owner_manifest(vec![scoped_owner_row(
            "owner:spoilers",
            "Block spoilers at work.",
            "work",
        )]),
    )?;
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(!policy.owner_policy_rows_dropped());
    assert_eq!(policy.active_owner_policy_rows(Some("work")).len(), 1);
    Ok(())
}

#[test]
fn the_policy_hash_encodes_every_length_in_a_fixed_eight_bytes() {
    // A KNOWN VECTOR, and the reason for it: lengths ride into the digest as
    // big-endian `u64`, never as a bare `usize`. A `usize` is four bytes on a
    // 32-bit target and eight on a 64-bit one, so hashing it directly would
    // make the policy hash depend on the word size of whoever computed it —
    // and the hash is what a receipt attests, so a 32-bit relay would never
    // agree with a 64-bit vault that they had seen the same policy, and the
    // attestation would fail closed forever. This literal is what a conforming
    // implementation produces on EVERY architecture.
    let policy = HostedLegalPolicy {
        jurisdiction: "test-jurisdiction".to_owned(),
        version: "2026-08-01".to_owned(),
        policy_hash: String::new(),
        docs_url: HOSTED_DOCS_URL.to_owned(),
        rows: vec![hosted_row(
            "hosted:ncii",
            HostedLegalCategory::Ncii,
            HostedLegalAction::Warn,
            "Flag intimate imagery shared without consent.",
        )],
        policy_document: "POLICY".to_owned(),
        output_contract: Some(PolicyOutputContract::Binary),
        pattern_rules: vec![PolicyPatternRule::new("p.one", "x", "hosted_legal/ncii")],
    };
    assert_eq!(
        policy.derive_policy_hash(),
        "4e4df5d69b237d460e40bc05b87736f6d62b17b6c6f07f7488f8aaddb810dbc4"
    );
}

#[test]
fn the_registered_hash_covers_the_policy_document() {
    // The attestation is only worth something if it names the enforced TEXT.
    // Amend one byte of the document and every earlier receipt stops being
    // evidence about the policy now in force.
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let original = registered_policy(&registry);
    assert_ne!(
        original.policy_hash, "sha256:fixture-not-derived",
        "the registry derives the hash rather than trusting the caller"
    );
    assert_eq!(original.policy_hash, original.derive_policy_hash());

    let amended_registry = hosted_edge_registry(HostedLegalPolicy {
        policy_document: format!("{HOSTED_DOCUMENT}."),
        ..hosted_serious_crime_block()
    });
    let amended = registered_policy(&amended_registry);
    assert_eq!(amended.version, original.version);
    assert_ne!(
        amended.policy_hash, original.policy_hash,
        "one byte of the document must move the hash"
    );

    // A receipt attesting the original does not attest the amendment.
    let binding = relay_skip_content_binding(&PolicyClassifyRequest::outbound_content("candidate"));
    let receipt = PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default())
        .attesting_hosted_plane(&original);
    assert!(receipt.attests_hosted_plane(&original));
    assert!(!receipt.attests_hosted_plane(&amended));
}

#[test]
fn the_registered_hash_covers_the_rows_and_the_rules() {
    let base = registered_policy(&hosted_edge_registry(hosted_serious_crime_block()));
    let rowed = registered_policy(&hosted_edge_registry(HostedLegalPolicy {
        rows: vec![hosted_row(
            "hosted:serious-crime",
            HostedLegalCategory::SeriousCrime,
            HostedLegalAction::Warn,
            "Withhold credible facilitation of serious violence or mass harm.",
        )],
        ..hosted_serious_crime_block()
    }));
    let ruled = registered_policy(&hosted_edge_registry(hosted_policy_with_rules(vec![
        escalate_rule("hosted.bomb", "(?i)bomb"),
    ])));
    let rerolled = registered_policy(&hosted_edge_registry(hosted_policy_with_rules(vec![
        decide_rule("hosted.bomb", "(?i)bomb"),
    ])));

    assert_ne!(base.policy_hash, rowed.policy_hash);
    assert_ne!(base.policy_hash, ruled.policy_hash);
    assert_ne!(
        ruled.policy_hash, rerolled.policy_hash,
        "changing a rule's role changes what is enforced"
    );
}

#[test]
fn hosted_legal_policy_binds_to_a_registered_service_identity() {
    let mut registry = fixture_edge_service_registry();
    registry
        .register_hosted_legal_policy(HOSTED_EDGE_SERVICE, hosted_serious_crime_block())
        .expect("registering a policy on a known service succeeds");

    let bound = registry
        .hosted_legal_policy(HOSTED_EDGE_IDENTITY)
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

// --- the hosted legal plane at the relay boundary ---------------------------

#[test]
fn hosted_relay_runs_the_hosted_legal_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let backend = blocking_backend();
    let budget = lease("hosted-runs");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert!(pass.ran_relay_classify());
    let verdict = pass.boundary_verdict().expect("hosted relay runs a pass");
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
    let backend = CountingPolicyBackend::clean();
    let budget = lease("no-policy");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &no_hosted_policy_registry(),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(backend.calls(), 0);
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert_eq!(pass.resolution(), Some(RelayResolution::NoPolicyInPlay));
    assert!(!pass.must_halt_relay());
    assert!(gate_receipts(&vault)?.is_empty());
    Ok(())
}

#[test]
fn hosted_warn_relays_the_content_and_does_not_halt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        rows: vec![hosted_row(
            "hosted:serious-crime",
            HostedLegalCategory::SeriousCrime,
            HostedLegalAction::Warn,
            "Flag credible facilitation of serious violence.",
        )],
        ..hosted_serious_crime_block()
    };
    let backend = blocking_backend();
    let budget = lease("hosted-warn");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Warn
    );
    assert!(!pass.must_halt_relay());

    // A warn still carries an enforcement signal, so it is receipted.
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "relay_boundary_warn");
    Ok(())
}

#[test]
fn hosted_notices_are_attributed_to_the_hosted_service() -> Result<()> {
    for action in [HostedLegalAction::Warn, HostedLegalAction::Block] {
        let (_tmp, vault) = temp_vault();
        let policy = HostedLegalPolicy {
            rows: vec![hosted_row(
                "hosted:serious-crime",
                HostedLegalCategory::SeriousCrime,
                action,
                "Serious-crime facilitation.",
            )],
            ..hosted_serious_crime_block()
        };
        let backend = blocking_backend();
        let budget = lease("hosted-notice");
        relay_pass(
            &vault,
            BOMB_CONTENT,
            &hosted_edge_registry(policy),
            &PolicyModelConfig::default(),
            Some(tier(&backend, &budget)),
        )?;

        let receipts = gate_receipts(&vault)?;
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
        let body = fields.get("system_notice").expect("notice body");
        assert!(body.contains(HOSTED_JURISDICTION), "body: {body}");
        // The vault owner did not write this rule and is not blamed for it.
        assert!(!body.contains("your policy"), "body: {body}");
        assert!(has_trace(
            &receipts[0],
            "gate.policy_model.plane.hosted_legal"
        ));
    }
    Ok(())
}

#[test]
fn the_hosted_document_is_what_reaches_the_model() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let backend = RecordingPolicyBackend::new(r#"{"violation":0,"policy_category":null}"#);
    let budget = lease("hosted-document");
    relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    assert_eq!(
        backend.seen_system.lock().expect("system").as_deref(),
        Some(HOSTED_DOCUMENT),
        "the system message is the substrate owner's document, verbatim"
    );
    assert_eq!(
        backend.seen_user.lock().expect("user").as_deref(),
        Some(CLEAN_CONTENT),
        "the user message is the candidate, verbatim — the engine adds no words"
    );
    Ok(())
}

#[test]
fn byo_path_never_evaluates_hosted_legal_policy() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // A policy that WOULD block this content, on a path that never reaches us.
    let backend = CountingPolicyBackend::clean();
    let budget = lease("byo");
    let pass = block_on(vault.relay_boundary_pass(
        PolicyClassifyRequest::outbound_content(BOMB_CONTENT),
        &byo_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    assert_eq!(pass, RelayBoundaryPass::NotRelayedByUs);
    assert_eq!(backend.calls(), 0);
    assert!(!pass.ran_relay_classify());
    assert!(pass.boundary_verdict().is_none());
    assert!(!pass.must_halt_relay());

    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "relay_not_relayed");
    assert!(has_trace(&receipts[0], "gate.relay.classify.skipped"));
    // No hosted-legal verdict was reached, so no hosted notice exists.
    assert!(!receipts[0].fields.contains_key("system_notice"));
    Ok(())
}

#[test]
fn owner_rows_are_never_evaluated_at_the_relay() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x50), &spoiler_manifest("block"))?;

    // The vault-egress classify DOES fire the owner rule.
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
    let backend = clean_backend();
    let budget = lease("relay-owner-blind");
    let pass = relay_pass(
        &vault,
        "This reply contains spoilers.",
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    let verdict = pass.boundary_verdict().expect("hosted relay runs a pass");
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
fn relay_block_writes_audit_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let backend = blocking_backend();
    let budget = lease("relay-block-receipt");
    let pass = block_on(
        vault.relay_boundary_pass(
            PolicyClassifyRequest::outbound_content(BOMB_CONTENT)
                .with_caller_ref("relay:hosted-connector"),
            &hosted_witness(),
            &hosted_edge_registry(hosted_serious_crime_block()),
            &PolicyModelConfig::default(),
            Some(tier(&backend, &budget)),
            &EMPTY_VAULT_SIDE_VERDICTS,
        ),
    )?;
    assert!(pass.must_halt_relay());

    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.outcome, "relay_boundary_block");
    for expected in [
        "gate.relay.trust_domain.local_via_hosted_connector",
        "gate.relay.classifier_mode.classify_all",
        "gate.relay.classify.ran",
        "gate.relay.resolution.model_decided",
        "gate.policy_model.block",
        "gate.policy_model.hosted_legal.serious_crime",
    ] {
        assert!(has_trace(receipt, expected), "missing trace {expected}");
    }
    Ok(())
}

#[test]
fn a_model_examined_clean_allow_writes_no_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let backend = clean_backend();
    let budget = lease("clean-allow");
    let pass = relay_pass(
        &vault,
        CLEAN_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;
    assert_eq!(
        pass.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(pass.degraded().is_none());
    assert!(
        gate_receipts(&vault)?.is_empty(),
        "the one pass with nothing to say writes nothing"
    );
    Ok(())
}

#[test]
fn relay_pass_fails_closed_on_a_malformed_manifest() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x52), b"not a policy manifest")?;

    let backend = clean_backend();
    let budget = lease("malformed");
    let err = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )
    .expect_err("a malformed manifest must fail the relay pass closed");
    assert!(
        format!("{err}").contains("malformed"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn a_max_length_jurisdiction_still_produces_a_receiptable_notice() -> Result<()> {
    // The jurisdiction bound is derived from the ledger's notice-body bound,
    // and that bound is paid for whichever hosted template is LONGEST — the
    // warn one. Checking only the shorter block template would leave the case
    // the arithmetic is actually about untested, so both run here with the
    // longest jurisdiction the registry accepts.
    let longest = "j".repeat(HOSTED_LEGAL_JURISDICTION_MAX_LEN);
    for (action, halts) in [
        (HostedLegalAction::Warn, false),
        (HostedLegalAction::Block, true),
    ] {
        let (_tmp, vault) = temp_vault();
        let policy = HostedLegalPolicy {
            jurisdiction: longest.clone(),
            rows: vec![hosted_row(
                "hosted:serious-crime",
                HostedLegalCategory::SeriousCrime,
                action,
                "Withhold credible facilitation of serious violence or mass harm.",
            )],
            ..hosted_serious_crime_block()
        };
        let backend = blocking_backend();
        let budget = lease("longest-jurisdiction");
        let pass = relay_pass(
            &vault,
            BOMB_CONTENT,
            &hosted_edge_registry(policy),
            &PolicyModelConfig::default(),
            Some(tier(&backend, &budget)),
        )?;
        assert_eq!(pass.must_halt_relay(), halts, "action: {action:?}");

        let receipts = gate_receipts(&vault)?;
        assert_eq!(receipts.len(), 1, "action: {action:?}");
        assert!(
            receipts[0]
                .fields
                .get("system_notice")
                .expect("notice body")
                .contains(&longest),
            "action: {action:?}"
        );
    }
    Ok(())
}

// --- cloud-vault receipt verification ---------------------------------------

fn cloud_pass(
    vault: &Vault,
    request: PolicyClassifyRequest,
    registry: &EdgeServiceRegistry,
    verdicts: &dyn VaultSideVerdictSource,
    safeguard: Option<RelaySafeguardTier<'_>>,
) -> Result<RelayBoundaryPass> {
    block_on(vault.relay_boundary_pass(
        request,
        &cloud_witness(),
        registry,
        &PolicyModelConfig::default(),
        safeguard,
        verdicts,
    ))
}

#[test]
fn cloud_vault_receipt_without_hosted_attestation_reruns_the_hosted_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // A clean vault-side Allow that verifies on content, frontier and safeguard
    // selector — and says nothing about the hosted plane. Trusting it would
    // hand this payload straight through the hosted service's own legal policy.
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };
    let backend = blocking_backend();
    let budget = lease("cloud-unattested");

    let pass = cloud_pass(
        &vault,
        request,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &source,
        Some(tier(&backend, &budget)),
    )?;
    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.boundary_verdict().expect("hosted pass ran").decision,
        PolicyClassifyDecision::Block
    );
    assert!(pass.must_halt_relay());
    assert_eq!(
        *source.requested_hash.lock().expect("requested hash lock"),
        Some(binding.content_hash)
    );
    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(
        &receipts[0],
        "gate.relay.vault_receipt_untrusted.hosted_plane_unattested"
    ));
    Ok(())
}

#[test]
fn cloud_vault_receipt_with_hosted_attestation_trusts_without_rerunning() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The same payload, but the vault-side pass says it ran THIS hosted policy.
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default())
            .attesting_hosted_plane(&registered_policy(&registry)),
        requested_hash: Mutex::new(None),
    };
    let backend = CountingPolicyBackend::clean();
    let budget = lease("cloud-attested");

    let pass = cloud_pass(
        &vault,
        request,
        &registry,
        &source,
        Some(tier(&backend, &budget)),
    )?;
    assert_eq!(pass, RelayBoundaryPass::TrustedVaultSide);
    assert_eq!(backend.calls(), 0);
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
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let superseded = registered_policy(&hosted_edge_registry(HostedLegalPolicy {
        version: "2020-01-01".to_owned(),
        ..hosted_serious_crime_block()
    }));
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default())
            .attesting_hosted_plane(&superseded),
        requested_hash: Mutex::new(None),
    };
    let backend = blocking_backend();
    let budget = lease("cloud-superseded");

    let pass = cloud_pass(
        &vault,
        request,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &source,
        Some(tier(&backend, &budget)),
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
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
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
    let backend = blocking_backend();
    let budget = lease("cloud-warn");

    let pass = cloud_pass(
        &vault,
        request,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &source,
        Some(tier(&backend, &budget)),
    )?;
    assert_eq!(
        pass.boundary_verdict().expect("hosted pass ran").decision,
        PolicyClassifyDecision::Block
    );
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_missing_receipt_falls_back_to_the_hosted_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
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

    let backend = blocking_backend();
    let budget = lease("cloud-missing");
    let pass = cloud_pass(
        &vault,
        request,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &EMPTY_VAULT_SIDE_VERDICTS,
        Some(tier(&backend, &budget)),
    )?;
    // Missing evidence cannot create a skip: the hosted pass runs and blocks.
    assert!(pass.ran_relay_classify());
    assert!(pass.must_halt_relay());
    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(
        &receipts[0],
        "gate.relay.vault_receipt_untrusted.missing"
    ));
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

    let pass = cloud_pass(
        &vault,
        request,
        &no_hosted_policy_registry(),
        &verdicts,
        None,
    )?;
    assert_eq!(pass, RelayBoundaryPass::TrustedVaultSide);
    Ok(())
}

#[test]
fn in_memory_vault_side_verdicts_miss_uses_hosted_fallback() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let verdicts = InMemoryVaultSideVerdicts::new();

    let pass = cloud_pass(
        &vault,
        request,
        &no_hosted_policy_registry(),
        &verdicts,
        None,
    )?;
    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.boundary_verdict()
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
    let pass = cloud_pass(
        &vault,
        request,
        &no_hosted_policy_registry(),
        &verdicts,
        None,
    )?;
    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.boundary_verdict()
            .expect("wrong-family miss fallback")
            .decision,
        PolicyClassifyDecision::Allow
    );
    Ok(())
}

#[test]
fn cloud_vault_receipt_binding_mismatch_fails_closed_to_the_hosted_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
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
    let backend = blocking_backend();
    let budget = lease("cloud-binding-mismatch");
    let pass = cloud_pass(
        &vault,
        request,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &source,
        Some(tier(&backend, &budget)),
    )?;
    assert!(pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_content_hash_mismatch_audits_exact_cause() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
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
    cloud_pass(&vault, request, &no_hosted_policy_registry(), &source, None)?;
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert!(has_trace(
        &receipts[0],
        "gate.relay.vault_receipt_untrusted.binding_mismatch"
    ));
    Ok(())
}

#[test]
fn cloud_vault_safeguard_binding_mismatch_falls_back_and_audits() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let mut receipt = PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default());
    receipt.safeguard_binding = "stale-safeguard".to_owned();
    let source = StaticVaultSideVerdicts {
        verdict: receipt,
        requested_hash: Mutex::new(None),
    };

    let pass = cloud_pass(&vault, request, &no_hosted_policy_registry(), &source, None)?;
    assert_eq!(
        pass.boundary_verdict().expect("fallback verdict").decision,
        PolicyClassifyDecision::Allow
    );
    let receipts = gate_receipts(&vault)?;
    assert!(has_trace(
        &receipts[0],
        "gate.relay.vault_receipt_untrusted.safeguard_binding_mismatch"
    ));
    Ok(())
}

#[test]
fn cloud_vault_non_allow_receipts_halt_and_record_real_decisions() -> Result<()> {
    for (decision, outcome) in [
        (PolicyClassifyDecision::Block, "relay_boundary_block"),
        (
            PolicyClassifyDecision::RouteToHelp,
            "relay_boundary_route_to_help",
        ),
        (PolicyClassifyDecision::Warn, "relay_boundary_warn"),
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

        let pass = cloud_pass(&vault, request, &no_hosted_policy_registry(), &source, None)?;
        assert!(matches!(pass, RelayBoundaryPass::Classified(_)));
        assert_eq!(
            pass.must_halt_relay(),
            decision != PolicyClassifyDecision::Warn
        );
        // The relay verified WHAT was judged, never HOW. No hosted policy is
        // bound here, so the attestation check never ran and the vault-side
        // verdict may well have been decided by a `Decide` pattern with no
        // model call at all — recording `model_decided` would assert a model
        // ran on no evidence.
        assert_eq!(pass.resolution(), Some(RelayResolution::VaultSideDecided));
        let receipts = gate_receipts(&vault)?;
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, outcome);
        assert!(has_trace(
            &receipts[0],
            "gate.relay.resolution.vault_side_decided"
        ));
        assert!(!has_trace(
            &receipts[0],
            "gate.relay.resolution.model_decided"
        ));
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
    let content = || PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let binding = vault.relay_verify_binding(&content(), &PolicyModelConfig::default())?;
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default()),
        requested_hash: Mutex::new(None),
    };
    cloud_pass(
        &vault,
        content(),
        &no_hosted_policy_registry(),
        &source,
        None,
    )?;
    block_on(vault.relay_boundary_pass(
        content(),
        &byo_witness(),
        &no_hosted_policy_registry(),
        &PolicyModelConfig::default(),
        None,
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 2);
    let outcomes = receipts
        .iter()
        .map(|receipt| receipt.outcome.as_str())
        .collect::<Vec<_>>();
    assert!(outcomes.contains(&"relay_trusted_vault_side"));
    assert!(outcomes.contains(&"relay_not_relayed"));
    assert!(
        receipts
            .iter()
            .all(|receipt| has_trace(receipt, "gate.relay.classify.skipped"))
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
fn a_degraded_pass_halts_only_where_a_hosted_policy_was_in_play() {
    // The contract stated directly, both sides of the line. A hosted policy in
    // play means the fail-closed plane lost coverage, so the relay stops; with
    // no hosted policy there was never anything for the outage to uncover, and
    // the owner plane is sovereign — it never gains a halt it did not ask for.
    let binding = relay_skip_content_binding(&PolicyClassifyRequest::outbound_content("candidate"));
    let verdict = PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default());
    for degrade in [
        RelayBoundaryDegrade::SafeguardModelUnavailable,
        RelayBoundaryDegrade::SafeguardModelResponseUnusable,
        RelayBoundaryDegrade::SafeguardModelTierAbsent,
        RelayBoundaryDegrade::OutputContractUndeclared,
    ] {
        assert!(
            !classified_pass(verdict.clone(), Some(degrade), false).must_halt_relay(),
            "owner-plane-only degrade must not halt: {degrade:?}"
        );
        assert!(
            classified_pass(verdict.clone(), Some(degrade), true).must_halt_relay(),
            "hosted-plane degrade must halt: {degrade:?}"
        );
    }
    // Undegraded, a clean allow still relays whichever plane was in play.
    for hosted_policy_in_play in [false, true] {
        assert!(!classified_pass(verdict.clone(), None, hosted_policy_in_play).must_halt_relay());
    }
}

/// A classified pass built directly, for the unit pins that state the halt
/// contract without running a relay.
fn classified_pass(
    verdict: PolicyClassifyVerdict,
    degraded: Option<RelayBoundaryDegrade>,
    hosted_policy_in_play: bool,
) -> RelayBoundaryPass {
    RelayBoundaryPass::Classified(Box::new(RelayClassifiedPass {
        verdict,
        degraded,
        hosted_policy_in_play,
        resolution: RelayResolution::ModelDecided,
    }))
}

#[test]
fn a_relay_with_no_hosted_policy_bound_never_degrades_at_all() -> Result<()> {
    // With nothing bound to the attested identity the safeguard model is never
    // called, so a downed model cannot even produce a degrade, let alone a halt.
    let (_tmp, vault) = temp_vault();
    let budget = lease("relay-unbound-no-degrade");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &no_hosted_policy_registry(),
        &PolicyModelConfig::default(),
        Some(tier(&FailingPolicyBackend, &budget)),
    )?;
    assert!(pass.degraded().is_none());
    assert!(!pass.must_halt_relay());
    Ok(())
}

#[test]
fn cloud_vault_untrusted_receipt_with_backend_runs_and_degrades() -> Result<()> {
    let (_tmp, vault) = temp_vault();
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
    let budget = lease("cloud-fallback-backend-down");

    let pass = cloud_pass(
        &vault,
        PolicyClassifyRequest::outbound_content("a clean span"),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &source,
        Some(tier(&FailingPolicyBackend, &budget)),
    )?;
    assert_eq!(
        pass.boundary_verdict().expect("fallback verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert_eq!(
        pass.degraded(),
        Some(RelayBoundaryDegrade::SafeguardModelUnavailable)
    );
    Ok(())
}

// --- both planes, one round trip --------------------------------------------

#[test]
fn both_planes_are_called_concurrently_each_under_its_own_document() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &documented_owner_manifest(
            vec![owner_row_with_action(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
                "warn",
            )],
            Vec::new(),
        ),
    )?;

    // The rendezvous backend refuses to answer EITHER caller until both have
    // arrived, so completing at all is the proof that the two calls were in
    // flight together. Sequentially the first would wait forever.
    let backend = RendezvousBackend::new();
    let budget = lease("both-planes");
    let pass = block_on(vault.classify_both_planes(
        PolicyClassifyRequest::outbound_content(BOMB_CONTENT),
        &hosted_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;

    // Each plane was asked under ITS OWN document.
    let documents = backend.documents();
    assert_eq!(documents.len(), 2, "both planes issued a call");
    assert!(documents.contains(&OWNER_DOCUMENT.to_owned()));
    assert!(documents.contains(&HOSTED_DOCUMENT.to_owned()));

    // ... and each verdict landed in its own plane's machinery.
    assert_eq!(pass.owner.decision, PolicyClassifyDecision::Warn);
    assert_eq!(
        pass.owner.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
        }
    );
    assert!(!pass.owner_model_skipped);

    let relay_verdict = pass.relay.boundary_verdict().expect("relay ran");
    assert_eq!(relay_verdict.decision, PolicyClassifyDecision::Block);
    assert_eq!(relay_verdict.plane(), Some(PolicyPlane::HostedLegal));
    assert!(pass.relay.must_halt_relay());
    Ok(())
}

#[test]
fn a_dual_plane_pass_receipts_both_planes() -> Result<()> {
    // The dual-plane entry hands the owner verdict back RAW — it never routes
    // through enforcement, which is where an owner verdict is normally
    // receipted. Without a row written here a vault owner reading their own
    // ledger would find only the hosted service's verdict about their content
    // and no trace that their own plane ran at all.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x71),
        &documented_owner_manifest(
            vec![owner_row_with_action(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
                "warn",
            )],
            Vec::new(),
        ),
    )?;
    let backend = RendezvousBackend::new();
    let budget = lease("both-planes-receipted");
    let pass = block_on(vault.classify_both_planes(
        PolicyClassifyRequest::outbound_content(BOMB_CONTENT),
        &hosted_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(pass.owner.decision, PolicyClassifyDecision::Warn);

    let receipts = gate_receipts(&vault)?;
    let owner_row = receipts
        .iter()
        .find(|receipt| receipt.outcome == "owner_plane_warn")
        .expect("the owner plane's own row");
    assert!(has_trace(owner_row, "gate.relay.owner_plane.classify.ran"));
    assert!(has_trace(owner_row, "gate.policy_model.plane.owner_policy"));
    assert!(has_trace(owner_row, "gate.policy_model.warn"));
    assert!(
        receipts
            .iter()
            .any(|receipt| receipt.outcome == "relay_boundary_block"),
        "the hosted plane's row is still written"
    );
    Ok(())
}

#[test]
fn the_owner_enforce_door_refuses_a_hosted_plane_verdict() -> Result<()> {
    // The two halves of a dual-plane pass answer the SAME request, so a hosted
    // verdict carries the same binding, the same selector and the same
    // frontier as the owner one — the staleness check cannot tell them apart.
    // Handed `pass.relay` instead of `pass.owner`, one field over, this door
    // would enforce a hosted service's decision as the vault owner's own.
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary content");
    let config = PolicyModelConfig::default();
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    // Built from the OWNER verdict for this very request, then marked as
    // hosted-attested. Binding, selector and frontier are therefore identical
    // to what the door would derive — the staleness check has nothing to catch,
    // and the attestation is the only thing separating the two. That is the
    // real shape of the mistake: one field of a `DualPlanePass` instead of the
    // other.
    let owner_verdict = vault.classify_policy_model_with_config(request.clone(), &config)?;
    let hosted_verdict = owner_verdict
        .clone()
        .attesting_hosted_plane(&registered_policy(&registry));
    assert!(
        !vault.policy_model_verdict_is_stale_with_config(&hosted_verdict, &request, &config)?,
        "the staleness check cannot tell the planes apart — that is why this door must"
    );

    let refused =
        vault.enforce_policy_model_verdict(request.clone(), &config, hosted_verdict, false);
    assert!(matches!(refused, Err(Error::PolicyVerdictNotInForce)));

    // The owner's own verdict for the same request still enforces. The door
    // refuses a PLANE, not a shape.
    assert!(
        vault
            .enforce_policy_model_verdict(request, &config, owner_verdict, false)
            .is_ok()
    );
    Ok(())
}

#[test]
fn the_documented_dual_plane_flow_receipts_one_owner_decision() -> Result<()> {
    // `classify_both_planes` decides, then hands the owner half back for the
    // vault to enforce, and `enforce_policy_model_verdict` is the door it
    // hands it to. One decision, so one row: two would count the same warn
    // twice in the pattern-tuning totals those rows exist for, under two
    // different outcome names.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x73),
        &documented_owner_manifest(
            vec![owner_row_with_action(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
                "warn",
            )],
            Vec::new(),
        ),
    )?;
    let backend = RendezvousBackend::new();
    let budget = lease("one-owner-receipt");
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let pass = block_on(vault.classify_both_planes(
        request.clone(),
        &hosted_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(pass.owner.decision, PolicyClassifyDecision::Warn);

    let enforcement = vault.enforce_policy_model_verdict(
        request,
        &PolicyModelConfig::default(),
        pass.owner,
        pass.owner_model_skipped,
    )?;
    assert_eq!(enforcement.action, PolicyEnforcementAction::Warn);
    assert_eq!(
        enforcement.receipt_ref, None,
        "the producing door owns the row, so enforcement returns no receipt of its own",
    );

    let receipts = gate_receipts(&vault)?;
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.outcome == "owner_plane_warn")
            .count(),
        1,
        "the deciding door writes the owner plane's one row",
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.outcome == "warn")
            .count(),
        0,
        "enforcement must not re-record the decision under its own outcome",
    );
    Ok(())
}

#[test]
fn enforcing_a_verdict_about_other_content_is_refused() -> Result<()> {
    // Request, config and verdict arrive here as three independent arguments,
    // so nothing but this check stops a caller enforcing one question's answer
    // against another question's content. A verdict decided about a blocked
    // string would otherwise halt an unrelated reply — and be receipted
    // against that reply's metadata.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x74),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row_with_action(
                "owner:spoilers",
                "Avoid spoilers.",
                "block",
            )]),
            owner_patterns(vec![owner_pattern(
                "owner.spoilers",
                "(?i)spoiler",
                "owner:spoilers",
                Some("decide"),
            )]),
        ]),
    )?;
    let spoiler_request = PolicyClassifyRequest::outbound_content("This reply contains spoilers.");
    let blocked = vault.classify_policy_model(spoiler_request.clone())?;
    assert_eq!(blocked.decision, PolicyClassifyDecision::Block);

    // Its own request still enforces.
    let honest = vault.enforce_policy_model_verdict(
        spoiler_request,
        &PolicyModelConfig::default(),
        blocked.clone(),
        false,
    )?;
    assert_eq!(honest.action, PolicyEnforcementAction::Block);

    // Another request's content does not.
    let other_request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let refused = vault.enforce_policy_model_verdict(
        other_request,
        &PolicyModelConfig::default(),
        blocked,
        false,
    );
    assert!(
        matches!(refused, Err(Error::PolicyVerdictNotInForce)),
        "a verdict about other content must be refused, not enforced",
    );
    Ok(())
}

#[test]
fn enforcing_a_verdict_the_manifest_moved_under_is_refused() -> Result<()> {
    // The other half of the same check: the verdict IS this request's, but the
    // owner edited the policy since it was decided. This door has no model to
    // re-derive with, so it sends the caller back rather than enforcing a rule
    // that may no longer say what it said.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x75),
        &enabled_owner_manifest(vec![owner_row("owner:jargon", "Avoid jargon.")]),
    )?;
    let request = PolicyClassifyRequest::outbound_content(CLEAN_CONTENT);
    let verdict = vault.classify_policy_model(request.clone())?;
    assert!(!vault.policy_model_verdict_is_stale(&verdict, &request)?);

    put_policy_manifest_bytes(
        &vault,
        test_id(0x75),
        &enabled_owner_manifest(vec![
            owner_row("owner:jargon", "Avoid jargon."),
            owner_row_with_action("owner:spoilers", "Block spoilers.", "block"),
        ]),
    )?;
    let refused =
        vault.enforce_policy_model_verdict(request, &PolicyModelConfig::default(), verdict, false);
    assert!(
        matches!(refused, Err(Error::PolicyVerdictNotInForce)),
        "a verdict the manifest moved under must be refused, not enforced",
    );
    Ok(())
}

#[test]
fn a_dual_plane_owner_model_failure_leaves_a_fail_open_row() -> Result<()> {
    // The owner plane is sovereign, so a downed model resolves to `Allow` and
    // the content flows. Recording nothing would make that indistinguishable
    // from a clean allow the model actually examined — the ledger has to say
    // the plane fell open.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x72),
        &documented_owner_manifest(
            vec![owner_row_with_action(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
                "block",
            )],
            Vec::new(),
        ),
    )?;
    let budget = lease("owner-fail-open");
    let pass = block_on(vault.classify_both_planes(
        PolicyClassifyRequest::outbound_content(BOMB_CONTENT),
        &hosted_witness(),
        &no_hosted_policy_registry(),
        &PolicyModelConfig::default(),
        Some(tier(&FailingPolicyBackend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(pass.owner.decision, PolicyClassifyDecision::Allow);
    assert!(pass.owner_model_skipped);

    let receipts = gate_receipts(&vault)?;
    let owner_row = receipts
        .iter()
        .find(|receipt| receipt.outcome == "owner_plane_allow")
        .expect("a fail-open allow is still a row");
    assert!(has_trace(owner_row, "gate.relay.owner_plane.model_skipped"));
    assert!(has_trace(owner_row, "gate.relay.owner_plane.fail_open"));
    Ok(())
}

#[test]
fn both_planes_stay_separate_when_only_one_is_configured() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // No owner plane at all: the hosted plane still decides the relay, and the
    // owner's verdict is a clean allow rather than a borrowed hosted one.
    let backend = blocking_backend();
    let budget = lease("one-plane");
    let pass = block_on(vault.classify_both_planes(
        PolicyClassifyRequest::outbound_content(BOMB_CONTENT),
        &hosted_witness(),
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(pass.owner.decision, PolicyClassifyDecision::Allow);
    assert_eq!(pass.owner.category, PolicyVerdictCategory::None);
    assert!(pass.relay.must_halt_relay());
    Ok(())
}

// --- sealed connection identity and the attested relay domain ---------------

/// Fixture edge-service registrations: the engine ships the validation
/// mechanism and NO service identities, so the registration data a
/// deployment's connector-edge wiring would supply from its manifest is
/// provided here as test fixtures.
fn fixture_edge_services() -> [(&'static str, ConnectionClass); 4] {
    [
        (CLOUD_EDGE_SERVICE, ConnectionClass::CloudVaultPeer),
        (
            HOSTED_EDGE_SERVICE,
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
        CLOUD_EDGE_IDENTITY,
        HOSTED_EDGE_IDENTITY,
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
fn the_relay_takes_its_hosted_policy_from_the_attested_identity() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The policy is bound to `push-relay`. The pass runs under `slack-hosted`,
    // so nothing applies to it — the caller has no way to reach for another
    // service's jurisdiction, because it never names one.
    let mut registry = fixture_edge_service_registry();
    registry.register_hosted_legal_policy(
        "push-relay",
        hosted_policy_with_rules(vec![decide_rule("hosted.bomb", "(?i)bomb")]),
    )?;

    let request = || PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let unbound = block_on(vault.relay_boundary_pass(
        request(),
        &hosted_witness(),
        &registry,
        &PolicyModelConfig::default(),
        None,
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert_eq!(
        unbound.boundary_verdict().expect("verdict").decision,
        PolicyClassifyDecision::Allow
    );
    assert!(!unbound.must_halt_relay());

    // The same content under the identity the policy IS bound to blocks.
    let bound_witness = AttestedRelayDomain::for_testing(
        RelayTrustDomain::LocalViaHostedConnector,
        "connector-edge:push-relay",
    );
    let bound = block_on(vault.relay_boundary_pass(
        request(),
        &bound_witness,
        &registry,
        &PolicyModelConfig::default(),
        None,
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert!(bound.must_halt_relay());
    Ok(())
}

#[test]
fn from_edge_auth_rejects_identity_class_mismatch() {
    // The hosted connector is registered as a local-vault relay edge; it may
    // never claim cloud-vault peer standing (which would skip the hosted pass).
    let registry = fixture_edge_service_registry();
    let err = AuthenticatedConnectionIdentity::from_edge_auth(
        HOSTED_EDGE_IDENTITY,
        ConnectionClass::CloudVaultPeer,
        &registry,
    )
    .expect_err("hosted connector claiming cloud-vault peer must be rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::RelayAttestationClassMismatch
    );
    let message = format!("{err}");
    assert!(message.contains(HOSTED_EDGE_IDENTITY));
    assert!(message.contains("cloud_vault_peer"));
    assert!(message.contains("local_vault_via_hosted_connector"));

    // The mirror: the cloud-vault peer may not present as a hosted connector
    // (which would force a redundant re-run on already-classified content).
    let err = AuthenticatedConnectionIdentity::from_edge_auth(
        CLOUD_EDGE_IDENTITY,
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
            CLOUD_EDGE_IDENTITY,
            ConnectionClass::CloudVaultPeer,
            RelayTrustDomain::CloudVault,
        ),
        (
            HOSTED_EDGE_IDENTITY,
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
        (CLOUD_EDGE_IDENTITY, ConnectionClass::CloudVaultPeer),
        (
            HOSTED_EDGE_IDENTITY,
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
        HOSTED_EDGE_IDENTITY,
        ConnectionClass::LocalVaultViaHostedConnector,
    );
    let witness = HostedEdgeAttestation::new().attest(&identity);
    let backend = blocking_backend();
    let budget = lease("attested-witness");
    let pass = block_on(vault.relay_boundary_pass(
        PolicyClassifyRequest::outbound_content(BOMB_CONTENT),
        &witness,
        &hosted_edge_registry(hosted_serious_crime_block()),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
    ))?;
    assert!(pass.ran_relay_classify());
    assert_eq!(
        pass.boundary_verdict()
            .expect("hosted relay runs a pass")
            .decision,
        PolicyClassifyDecision::Block
    );
    Ok(())
}

#[test]
fn attested_cloud_vault_witness_short_circuits_the_pass() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = edge_auth_identity(CLOUD_EDGE_IDENTITY, ConnectionClass::CloudVaultPeer);
    let witness = AttestedRelayDomain::from_connection_identity(&identity);
    assert_eq!(witness.service_identity(), CLOUD_EDGE_IDENTITY);
    let request = PolicyClassifyRequest::outbound_content(BOMB_CONTENT);
    let binding = vault.relay_verify_binding(&request, &PolicyModelConfig::default())?;
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    let source = StaticVaultSideVerdicts {
        verdict: PolicyClassifyVerdict::clean_allow(binding, &PolicyModelConfig::default())
            .attesting_hosted_plane(&registered_policy(&registry)),
        requested_hash: Mutex::new(None),
    };
    let pass = block_on(vault.relay_boundary_pass(
        request,
        &witness,
        &registry,
        &PolicyModelConfig::default(),
        None,
        &source,
    ))?;
    assert_eq!(pass, RelayBoundaryPass::TrustedVaultSide);
    assert!(!pass.ran_relay_classify());
    Ok(())
}
