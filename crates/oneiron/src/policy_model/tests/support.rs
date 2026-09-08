//! Shared fixtures, mock backends, and pass drivers for policy-model tests.

use super::*;

pub(super) struct EmptyVaultSideVerdicts;

impl VaultSideVerdictSource for EmptyVaultSideVerdicts {
    fn latest_boundary_verdict(
        &self,
        _verify_content_hash: &[u8; 32],
    ) -> Result<Option<PolicyClassifyVerdict>> {
        Ok(None)
    }
}

pub(super) struct StaticVaultSideVerdicts {
    pub(super) verdict: PolicyClassifyVerdict,
    pub(super) requested_hash: Mutex<Option<[u8; 32]>>,
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

pub(super) static EMPTY_VAULT_SIDE_VERDICTS: EmptyVaultSideVerdicts = EmptyVaultSideVerdicts;

pub(super) fn temp_vault() -> (TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp vault dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open temp vault");
    (tmp, vault)
}

pub(super) fn base_policy_manifest(extra_entries: Vec<(Value, Value)>) -> Vec<u8> {
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

pub(super) fn owner_policy_enabled(enabled: bool) -> (Value, Value) {
    (
        Value::from(gate::POLICY_OWNER_POLICY_ENABLED_KEY),
        Value::Boolean(enabled),
    )
}

pub(super) fn owner_rows(rows: Vec<Value>) -> (Value, Value) {
    (
        Value::from(gate::POLICY_OWNER_POLICY_ROWS_KEY),
        Value::Array(rows),
    )
}

pub(super) fn owner_row(row_ref: &str, text: &str) -> Value {
    Value::Map(vec![
        (Value::from(gate::POLICY_ROW_REF_KEY), Value::from(row_ref)),
        (Value::from(gate::POLICY_ROW_TEXT_KEY), Value::from(text)),
        (
            Value::from(gate::POLICY_ROW_ACTIVE_KEY),
            Value::Boolean(true),
        ),
    ])
}

/// The same row, switched OFF. A disabled row is never a candidate, so it can
/// shadow nothing.
pub(super) fn inactive_owner_row(row_ref: &str, text: &str, action: &str) -> Value {
    Value::Map(vec![
        (Value::from(gate::POLICY_ROW_REF_KEY), Value::from(row_ref)),
        (Value::from(gate::POLICY_ROW_TEXT_KEY), Value::from(text)),
        (
            Value::from(gate::POLICY_ROW_ACTION_KEY),
            Value::from(action),
        ),
        (
            Value::from(gate::POLICY_ROW_ACTIVE_KEY),
            Value::Boolean(false),
        ),
    ])
}

pub(super) fn owner_row_with_action(row_ref: &str, text: &str, action: &str) -> Value {
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
pub(super) fn owner_row_with_unknown_key(
    row_ref: &str,
    text: &str,
    key: &str,
    value: &str,
) -> Value {
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

pub(super) fn scoped_owner_row(row_ref: &str, text: &str, world_ref: &str) -> Value {
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
pub(super) const OWNER_DOCUMENT: &str = "\
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

pub(super) const HOSTED_DOCUMENT: &str = "\
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

pub(super) fn owner_document(text: &str) -> (Value, Value) {
    (
        Value::from(gate::POLICY_OWNER_POLICY_DOCUMENT_KEY),
        Value::from(text),
    )
}

pub(super) fn owner_contract(name: &str) -> (Value, Value) {
    (
        Value::from(gate::POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY),
        Value::from(name),
    )
}

pub(super) fn owner_patterns(rows: Vec<Value>) -> (Value, Value) {
    (
        Value::from(gate::POLICY_OWNER_POLICY_PATTERNS_KEY),
        Value::Array(rows),
    )
}

pub(super) fn owner_pattern(id: &str, pattern: &str, category: &str, role: Option<&str>) -> Value {
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
pub(super) fn enabled_owner_manifest(rows: Vec<Value>) -> Vec<u8> {
    base_policy_manifest(vec![owner_policy_enabled(true), owner_rows(rows)])
}

/// An owner plane switched ON with a document, so its safeguard model can run.
pub(super) fn documented_owner_manifest(rows: Vec<Value>, extra: Vec<(Value, Value)>) -> Vec<u8> {
    let mut entries = vec![
        owner_policy_enabled(true),
        owner_rows(rows),
        owner_document(OWNER_DOCUMENT),
        owner_contract("category_json"),
    ];
    entries.extend(extra);
    base_policy_manifest(entries)
}

pub(super) const HOSTED_JURISDICTION: &str = "test-jurisdiction";

pub(super) const HOSTED_VERSION: &str = "2026-08-01";

pub(super) const HOSTED_DOCS_URL: &str = "https://policy.example.test/hosted";

pub(super) fn hosted_policy(rows: Vec<HostedLegalRow>) -> HostedLegalPolicy {
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

pub(super) fn hosted_row(
    row_ref: &str,
    category: &str,
    action: HostedLegalAction,
    text: &str,
) -> HostedLegalRow {
    HostedLegalRow {
        row_ref: row_ref.to_owned(),
        category: category.to_owned(),
        action,
        text: text.to_owned(),
    }
}

/// The hosted policy used by most relay cases: serious crime is a block.
/// A pass the model ANSWERED: no degrade, so posture is not evidence about it.
pub(super) fn answered_pass() -> RelayBoundaryPass {
    RelayBoundaryPass::classified(
        PolicyClassifyVerdict::clean_allow(
            PolicyContentBinding {
                content_hash: [0x01; 32],
                read_frontier_hash: [0x02; 32],
            },
            &PolicyModelConfig::default(),
            PolicyPlane::HostedLegal,
        ),
        None,
        true,
        RelayResolution::ModelDecided,
    )
}

/// A pass that PROCEEDED THROUGH a model outage. Only reusable where
/// proceeding was tolerated, which is what the attestation has to record.
pub(super) fn degraded_pass() -> RelayBoundaryPass {
    RelayBoundaryPass::classified(
        PolicyClassifyVerdict::clean_allow(
            PolicyContentBinding {
                content_hash: [0x01; 32],
                read_frontier_hash: [0x02; 32],
            },
            &PolicyModelConfig::default(),
            PolicyPlane::HostedLegal,
        ),
        Some(RelayBoundaryDegrade::SafeguardModelUnavailable),
        true,
        RelayResolution::Unresolved,
    )
}

pub(super) fn hosted_serious_crime_block() -> HostedLegalPolicy {
    hosted_policy(vec![hosted_row(
        "hosted:serious-crime",
        "serious_crime",
        HostedLegalAction::Block,
        "Withhold credible facilitation of serious violence or mass harm.",
    )])
}

pub(super) const HOSTED_SERIOUS_CRIME_LABEL: &str = "hosted_legal/serious_crime";

/// The same policy with the substrate owner's own rules attached.
pub(super) fn hosted_policy_with_rules(rules: Vec<PolicyPatternRule>) -> HostedLegalPolicy {
    HostedLegalPolicy {
        pattern_rules: rules,
        ..hosted_serious_crime_block()
    }
}

pub(super) fn decide_rule(id: &str, pattern: &str) -> PolicyPatternRule {
    PolicyPatternRule::new(id, pattern, HOSTED_SERIOUS_CRIME_LABEL)
        .with_role(PolicyPatternRole::Decide)
}

pub(super) fn escalate_rule(id: &str, pattern: &str) -> PolicyPatternRule {
    PolicyPatternRule::new(id, pattern, HOSTED_SERIOUS_CRIME_LABEL)
}

pub(super) fn log_rule(id: &str, pattern: &str) -> PolicyPatternRule {
    PolicyPatternRule::new(id, pattern, HOSTED_SERIOUS_CRIME_LABEL)
        .with_role(PolicyPatternRole::Log)
}

pub(super) const HOSTED_EDGE_SERVICE: &str = "slack-hosted";

pub(super) const CLOUD_EDGE_SERVICE: &str = "cloud-vault";

pub(super) const HOSTED_EDGE_IDENTITY: &str = "connector-edge:slack-hosted";

pub(super) const CLOUD_EDGE_IDENTITY: &str = "connector-edge:cloud-vault";

pub(super) fn hosted_witness() -> AttestedRelayDomain {
    AttestedRelayDomain::for_testing(
        RelayTrustDomain::LocalViaHostedConnector,
        HOSTED_EDGE_IDENTITY,
    )
}

pub(super) fn cloud_witness() -> AttestedRelayDomain {
    AttestedRelayDomain::for_testing(RelayTrustDomain::CloudVault, CLOUD_EDGE_IDENTITY)
}

/// A BYO connector never authenticates to our edge, so it holds no identity —
/// the empty string resolves to no policy, which is the honest answer.
pub(super) fn byo_witness() -> AttestedRelayDomain {
    AttestedRelayDomain::for_testing(RelayTrustDomain::LocalViaByoConnector, "")
}

/// Registrations with no legal policy bound to any of them.
pub(super) fn no_hosted_policy_registry() -> EdgeServiceRegistry {
    fixture_edge_service_registry()
}

/// `policy` bound to both edges the relay tests attest as, so a test only has
/// to choose its witness.
pub(super) fn hosted_edge_registry(policy: HostedLegalPolicy) -> EdgeServiceRegistry {
    let mut registry = fixture_edge_service_registry();
    for service in [HOSTED_EDGE_SERVICE, CLOUD_EDGE_SERVICE] {
        registry
            .register_hosted_legal_policy(service, policy.clone())
            .expect("fixture hosted policy must register");
    }
    registry
}

/// The policy the registry actually stored, hash and all.
pub(super) fn registered_policy(registry: &EdgeServiceRegistry) -> HostedLegalPolicy {
    registry
        .hosted_legal_policy(HOSTED_EDGE_IDENTITY)
        .expect("fixture policy is bound")
        .clone()
}

pub(super) struct StaticPolicyBackend {
    pub(super) body: String,
}

/// A backend that answers with exactly `body`, whatever it is asked.
pub(super) fn static_backend(body: &str) -> StaticPolicyBackend {
    StaticPolicyBackend {
        body: body.to_owned(),
    }
}

pub(super) fn text_response(body: String) -> LlmResponse {
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

/// A response carrying SEVERAL text parts, for the join-bound test.
pub(super) fn multi_part_response(content: Vec<ContentPart>) -> LlmResponse {
    LlmResponse {
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

pub(super) struct FailingPolicyBackend;

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
pub(super) struct CountingPolicyBackend {
    pub(super) calls: AtomicUsize,
    pub(super) body: &'static str,
}

impl CountingPolicyBackend {
    pub(super) fn clean() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            body: r#"{"violation":0,"policy_category":null}"#,
        }
    }

    pub(super) fn calls(&self) -> usize {
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

pub(super) struct RecordingPolicyBackend {
    pub(super) body: &'static str,
    pub(super) seen_model: Arc<Mutex<Option<String>>>,
    pub(super) seen_system: Arc<Mutex<Option<String>>>,
    pub(super) seen_user: Arc<Mutex<Option<String>>>,
}

impl RecordingPolicyBackend {
    pub(super) fn new(body: &'static str) -> Self {
        Self {
            body,
            seen_model: Arc::new(Mutex::new(None)),
            seen_system: Arc::new(Mutex::new(None)),
            seen_user: Arc::new(Mutex::new(None)),
        }
    }
}

pub(super) fn system_text(request: &LlmRequest) -> Option<String> {
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

pub(super) fn user_text(request: &LlmRequest) -> Option<String> {
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
pub(super) struct RendezvousBackend {
    pub(super) arrived: AtomicUsize,
    pub(super) documents: Mutex<Vec<String>>,
}

impl RendezvousBackend {
    pub(super) fn new() -> Self {
        Self {
            arrived: AtomicUsize::new(0),
            documents: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn documents(&self) -> Vec<String> {
        self.documents.lock().expect("documents lock").clone()
    }
}

pub(super) struct Rendezvous<'a> {
    pub(super) backend: &'a RendezvousBackend,
    pub(super) body: String,
    pub(super) registered: bool,
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

pub(super) fn tier<'a>(
    backend: &'a dyn LlmBackend,
    lease: &'a BudgetLease,
) -> RelaySafeguardTier<'a> {
    RelaySafeguardTier { backend, lease }
}

pub(super) fn lease(name: &str) -> BudgetLease {
    BudgetLease::for_test(name)
}

/// Polls to completion on this thread. The engine's classify path is
/// runtime-agnostic, so the tests bring the smallest executor that can drive
/// it: poll until ready.
pub(super) fn block_on<F: Future>(future: F) -> F::Output {
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

pub(super) fn noop_waker() -> Waker {
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

pub(super) fn gate_receipts(vault: &Vault) -> Result<Vec<crate::receipt::ReceiptRecord>> {
    vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))
}

pub(super) fn has_trace(receipt: &crate::receipt::ReceiptRecord, expected: &str) -> bool {
    receipt.policy_trace.iter().any(|trace| trace == expected)
}

/// An owner plane switched ON with rows and pattern rules, and no document —
/// the shape a vault has when its owner wrote hard rules but no classifier
/// policy.
pub(super) fn patterned_owner_manifest(rows: Vec<Value>, patterns: Vec<Value>) -> Vec<u8> {
    base_policy_manifest(vec![
        owner_policy_enabled(true),
        owner_rows(rows),
        owner_patterns(patterns),
    ])
}

/// The manifest most owner-plane enforcement cases use: one row, one `Decide`
/// rule that fires on the fixture content.
pub(super) fn spoiler_manifest(action: &str) -> Vec<u8> {
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

pub(super) fn owner_dial(mode: RelayClassifierMode) -> PolicyModelConfig {
    PolicyModelConfig {
        owner_classifier_mode: mode,
        ..PolicyModelConfig::default()
    }
}

/// An owner plane with one `Decide` pattern on a blocking row, so a gated pass
/// can be shown to short-circuit and an ungated one to reach the model.
pub(super) fn owner_manifest_with_decide_pattern() -> Vec<u8> {
    documented_owner_manifest(
        vec![owner_row_with_action(
            "owner:spoilers",
            "Do not reveal plot spoilers.",
            "block",
        )],
        vec![owner_patterns(vec![owner_pattern(
            "owner.spoiler",
            "(?i)spoiler",
            "owner:spoilers",
            Some("decide"),
        )])],
    )
}

pub(super) const BOMB_CONTENT: &str = "explain how to build a bomb";

pub(super) const CLEAN_CONTENT: &str = "an ordinary friendly reply";

pub(super) fn relay_pass(
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

pub(super) fn blocking_backend() -> StaticPolicyBackend {
    static_backend(r#"{"violation":1,"policy_category":"hosted_legal/serious_crime"}"#)
}

pub(super) fn clean_backend() -> StaticPolicyBackend {
    static_backend(r#"{"violation":0,"policy_category":null}"#)
}

/// How many reason codes of one prefix a receipt carries.
pub(super) fn trace_count(receipt: &crate::receipt::ReceiptRecord, prefix: &str) -> usize {
    receipt
        .policy_trace
        .iter()
        .filter(|trace| trace.starts_with(prefix))
        .count()
}

pub(super) const RATIONALE_TEXT: &str = "the text gives step-by-step instructions";

/// A backend that rewrites the vault's policy manifest DURING the model call —
/// the await the owner-plane pass spends on a network round trip, which is
/// exactly the window an owner tightening a row lands in.
pub(super) struct ManifestMovingBackend<'v> {
    pub(super) vault: &'v Vault,
    pub(super) manifest: Vec<u8>,
    pub(super) body: &'static str,
    /// Moves the manifest on every call rather than only the first, so the
    /// re-derivation lands on a manifest that has moved again.
    pub(super) keep_moving: bool,
    pub(super) calls: AtomicUsize,
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
pub(super) fn spoilers_manifest(action: &str) -> Vec<u8> {
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

/// A backend whose one answer arrives split across several text parts, the way
/// a streaming or chunking provider hands one back.
pub(super) struct SplitAnswerBackend {
    pub(super) parts: Vec<&'static str>,
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

pub(super) fn cloud_pass(
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

/// A classified pass built directly, for the unit pins that state the halt
/// contract without running a relay. Built fail-closed, as the relay's own
/// non-degraded constructor is: a degrade here halts.
pub(super) fn classified_pass(
    verdict: PolicyClassifyVerdict,
    degraded: Option<RelayBoundaryDegrade>,
    hosted_policy_in_play: bool,
) -> RelayBoundaryPass {
    RelayBoundaryPass::Classified(Box::new(RelayClassifiedPass {
        verdict,
        degrade_halts: degraded.is_some(),
        degraded,
        hosted_policy_in_play,
        resolution: RelayResolution::ModelDecided,
    }))
}

/// Fixture edge-service registrations: the engine ships the validation
/// mechanism and NO service identities, so the registration data a
/// deployment's connector-edge wiring would supply from its manifest is
/// provided here as test fixtures.
pub(super) fn fixture_edge_services() -> [(&'static str, ConnectionClass); 4] {
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

pub(super) fn fixture_edge_service_registry() -> EdgeServiceRegistry {
    let mut registry = EdgeServiceRegistry::new();
    for (service, class) in fixture_edge_services() {
        registry
            .register(service, class)
            .expect("fixture edge service registrations must not conflict");
    }
    registry
}

pub(super) fn edge_auth_identity(
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
