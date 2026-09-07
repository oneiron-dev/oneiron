use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;
use crate::attempt_queue::{
    AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome,
};
use crate::llm::{
    BudgetDenied, BudgetLease, LlmBackend, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId,
};
use crate::{Vault, VaultConfig};

/// A secret that must never appear anywhere. Tests assert its ABSENCE, so it
/// deliberately never enters any BYOA type: the point is that there is no
/// field it could enter.
const NEVER_A_PAYLOAD: &str = "sk-live-THIS-MUST-NEVER-BE-PERSISTED";
const HANDLE: &str = "custody://byoa/endpoint-key";

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn handle(value: &str) -> SandboxCredentialHandle {
    SandboxCredentialHandle::new(value).expect("valid credential handle")
}

fn model(value: &str) -> ModelId {
    ModelId::new(value).expect("valid model id")
}

fn endpoint_spec() -> ByoEndpointSpec {
    let mut model_slug_map = BTreeMap::new();
    model_slug_map.insert("fast".to_owned(), model("byo/fast@1"));
    model_slug_map.insert("smart".to_owned(), model("byo/smart@2"));
    ByoEndpointSpec {
        base_url: "https://endpoint.example.com/v1".to_owned(),
        credential_ref: handle(HANDLE),
        protocol: ByoEndpointProtocol::OpenAiCompat,
        model_slug_map,
    }
}

fn attach_spec() -> ProtocolAttachSpec {
    ProtocolAttachSpec {
        protocol: ProtocolAttachKind::Mcp,
        server_ref: "mcp://tools.example.com".to_owned(),
        credential_ref: Some(handle("custody://byoa/mcp-token")),
    }
}

fn cli_spec() -> CliSandboxSpec {
    CliSandboxSpec {
        program: "/usr/bin/foreign-agent".to_owned(),
        argv: vec!["--task".to_owned(), "review".to_owned()],
        checkout_id: CheckoutId::from_bytes([7_u8; 16]).expect("checkout id"),
        egress_profile_ref: "egress/foreign-default".to_owned(),
        credential_handles: vec![handle("custody://byoa/cli-token")],
    }
}

// ---------------------------------------------------------------------------
// Test doubles for the two injected seams
// ---------------------------------------------------------------------------

struct StubBackend;

impl LlmBackend for StubBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async { Err(BudgetDenied::AdmissionDenied.into()) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(BudgetDenied::AdmissionDenied.into())
    }
}

/// Resolves any well-formed endpoint config. It never sees a secret, because
/// the spec it is handed cannot carry one.
struct StubFactory;

impl ByoEndpointBackendFactory for StubFactory {
    fn resolve_backend(&self, spec: &ByoEndpointSpec) -> ByoaResult<Arc<dyn LlmBackend>> {
        assert!(
            !format!("{spec:?}").contains(NEVER_A_PAYLOAD),
            "the factory seam must only ever receive custody handles"
        );
        Ok(Arc::new(StubBackend))
    }
}

/// The default-deny port: this is what a direct-network attempt meets.
struct DenyAllEgress;

impl ByoaEgressPort for DenyAllEgress {
    fn open(&mut self, profile_ref: &str, _intent_ref: &str) -> ByoaResult<ByoaEgressLease> {
        Err(ByoaError::EgressDenied {
            profile_ref: profile_ref.to_owned(),
            reason: "no lease for this intent".to_owned(),
        })
    }
}

struct GrantingEgress {
    expires_at: u64,
    allowed_hosts: Vec<String>,
    profile_ref: Option<String>,
}

impl GrantingEgress {
    fn new(expires_at: u64) -> Self {
        Self {
            expires_at,
            allowed_hosts: vec!["api.example.com".to_owned()],
            profile_ref: None,
        }
    }
}

impl ByoaEgressPort for GrantingEgress {
    fn open(&mut self, profile_ref: &str, _intent_ref: &str) -> ByoaResult<ByoaEgressLease> {
        Ok(ByoaEgressLease {
            lease_id: [3_u8; 16],
            profile_ref: self
                .profile_ref
                .clone()
                .unwrap_or_else(|| profile_ref.to_owned()),
            allowed_hosts: self.allowed_hosts.clone(),
            expires_at: self.expires_at,
            audit_ref: EntityId::from_bytes([9_u8; 16]).expect("audit ref"),
        })
    }
}

fn dispatcher(vault: &Vault) -> ByoaDispatcher<'_, StubFactory, DenyAllEgress> {
    ByoaDispatcher::new(vault, StubFactory, DenyAllEgress)
}

// ---------------------------------------------------------------------------
// T0 — endpoint connector round-trip, slug lookup, backend resolution
// ---------------------------------------------------------------------------

#[test]
fn endpoint_connector_round_trips_and_resolves_a_backend() {
    let (_dir, vault) = open_vault();
    let spec = endpoint_spec();

    let payload = encode_byoa_attempt_payload(&ByoaAttemptPayload {
        schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
        connector: ByoaConnectorSpec::Endpoint(spec.clone()),
        parent_attempt: None,
    })
    .expect("encode endpoint connector");
    let decoded = decode_byoa_attempt_payload(&payload).expect("decode endpoint connector");
    assert_eq!(
        decoded.connector,
        ByoaConnectorSpec::Endpoint(spec.clone()),
        "an endpoint connector must survive the durable round trip unchanged"
    );
    assert_eq!(decoded.connector.kind(), ByoaConnectorKind::Endpoint);
    assert_eq!(ByoaConnectorKind::Endpoint.wire_value(), 1);

    // Deterministic lookup: the map is ordered, so the same slug always
    // resolves to the same model.
    assert_eq!(
        spec.model_for_slug("fast").expect("bound slug").as_str(),
        "byo/fast@1"
    );
    assert_eq!(
        spec.model_for_slug("smart").expect("bound slug").as_str(),
        "byo/smart@2"
    );

    // Unknown slug is a refusal, not a pass-through to the far side.
    let denied = spec
        .model_for_slug("unbound")
        .expect_err("an unbound slug must be refused");
    assert!(
        matches!(denied, ByoaError::Backend(_)),
        "unknown slug refusal, got {denied:?}"
    );

    let backend = dispatcher(&vault)
        .endpoint_backend(&spec)
        .expect("factory resolves a backend");
    // The seam yields a trait object, so the provider codec stays host-owned.
    let _: Arc<dyn LlmBackend> = backend;
}

#[test]
fn endpoint_door_refuses_a_base_url_that_is_not_a_bare_http_url() {
    let (_dir, vault) = open_vault();
    for bad in [
        "",
        "endpoint.example.com",
        "ftp://endpoint.example.com",
        "https://endpoint.example.com/ path",
    ] {
        let mut spec = endpoint_spec();
        spec.base_url = bad.to_owned();
        assert!(
            dispatcher(&vault).endpoint_backend(&spec).is_err(),
            "base_url {bad:?} must be refused at the door"
        );
    }

    let mut spec = endpoint_spec();
    spec.model_slug_map.clear();
    assert!(
        dispatcher(&vault).endpoint_backend(&spec).is_err(),
        "an endpoint binding no slug can address nothing and must be refused"
    );
}

// ---------------------------------------------------------------------------
// T1 — credential redaction
// ---------------------------------------------------------------------------

#[test]
fn no_connector_surface_can_carry_a_raw_credential() {
    let (_dir, vault) = open_vault();
    let connector = ByoaConnectorSpec::Endpoint(endpoint_spec());

    let payload = encode_byoa_attempt_payload(&ByoaAttemptPayload {
        schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
        connector: connector.clone(),
        parent_attempt: None,
    })
    .expect("encode");

    // The durable payload carries the HANDLE and nothing else credential-like.
    let payload_text = String::from_utf8_lossy(&payload).into_owned();
    assert!(
        payload_text.contains(HANDLE),
        "the payload must carry the custody handle so the host can resolve it"
    );
    assert!(
        !payload_text.contains(NEVER_A_PAYLOAD),
        "no secret material may reach a durable attempt payload"
    );

    // The same holds for every rendering a reviewer or a log would see.
    let rendered = format!("{connector:?}");
    assert!(rendered.contains(HANDLE));
    assert!(!rendered.contains(NEVER_A_PAYLOAD));

    // And for the terminal receipt.
    let mut dispatcher = dispatcher(&vault);
    let attempt = dispatch_and_claim(&vault, &mut dispatcher, connector, "redaction-worker");
    let receipt = dispatcher
        .capture_terminal_exhaust(CaptureByoaExhaust {
            attempt_id: attempt.id,
            lease_owner: "redaction-worker".to_owned(),
            attempt_count: attempt.attempt_count,
            disposition: ByoaTerminalDisposition::Completed,
            exhaust: ByoaExhaust {
                stdout: b"done".to_vec(),
                ..ByoaExhaust::default()
            },
            reason: None,
            now: 40,
        })
        .expect("capture");
    assert!(!format!("{receipt:?}").contains(NEVER_A_PAYLOAD));

    // The whole inventory of credential-adjacent material is references.
    let handles = ByoaConnectorSpec::CliSandbox(cli_spec());
    assert_eq!(handles.credential_handles().len(), 1);
    assert_eq!(
        handles.credential_handles()[0].as_str(),
        "custody://byoa/cli-token"
    );
}

// ---------------------------------------------------------------------------
// T2 — MCP is the only protocol attach
// ---------------------------------------------------------------------------

#[test]
fn mcp_attach_round_trips_and_a2a_has_no_variant() {
    let spec = attach_spec();
    let payload = encode_byoa_attempt_payload(&ByoaAttemptPayload {
        schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
        connector: ByoaConnectorSpec::ProtocolAttach(spec.clone()),
        parent_attempt: None,
    })
    .expect("encode attach");
    let decoded = decode_byoa_attempt_payload(&payload).expect("decode attach");
    assert_eq!(decoded.connector, ByoaConnectorSpec::ProtocolAttach(spec));
    assert_eq!(
        decoded.connector.kind(),
        ByoaConnectorKind::ProtocolAttach,
        "attach kind is derived from the variant, never from a separate tag"
    );
    assert_eq!(ProtocolAttachKind::Mcp.as_str(), "mcp");

    // A2A is refused at the TYPE level on the write path: `ProtocolAttachKind`
    // has exactly one variant, so there is no value to construct. This asserts
    // the matching refusal on the READ path, which is the only way a foreign
    // label could arrive.
    let a2a = ProtocolAttachKind::try_from("a2a".to_owned());
    assert!(a2a.is_err(), "a2a must not decode into a v1 attach kind");
    let unknown = ProtocolAttachKind::try_from("grpc".to_owned());
    assert!(unknown.is_err(), "no catch-all attach kind exists");
}

// ---------------------------------------------------------------------------
// T3 — CLI sandbox: foreign tier, argv-only, egress only through the port
// ---------------------------------------------------------------------------

#[test]
fn cli_sandbox_runs_foreign_tier_and_refuses_a_command_line() {
    assert_eq!(
        CliSandboxSpec::boundary_contract().tier(),
        SandboxGuestTier::Foreign,
        "a foreign program never picks its own trust tier"
    );

    let spec = cli_spec();
    let payload = encode_byoa_attempt_payload(&ByoaAttemptPayload {
        schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
        connector: ByoaConnectorSpec::CliSandbox(spec.clone()),
        parent_attempt: None,
    })
    .expect("encode cli");
    let decoded = decode_byoa_attempt_payload(&payload).expect("decode cli");
    assert_eq!(decoded.connector, ByoaConnectorSpec::CliSandbox(spec));
    assert_eq!(decoded.connector.kind(), ByoaConnectorKind::CliSandbox);
    assert_eq!(ByoaConnectorKind::CliSandbox.wire_value(), 3);

    for bad_program in [
        "sh -c 'echo hi'",
        "/usr/bin/agent && curl example.com",
        "/usr/bin/agent | tee out",
        "",
    ] {
        let mut spec = cli_spec();
        spec.program = bad_program.to_owned();
        assert!(
            validate_connector(&ByoaConnectorSpec::CliSandbox(spec)).is_err(),
            "program {bad_program:?} is a command line, not an executable"
        );
    }
}

#[test]
fn cli_egress_is_denied_without_a_lease_and_scoped_with_one() {
    let (_dir, vault) = open_vault();
    let spec = cli_spec();

    // A direct-network attempt has no lease, and there is no other door.
    let mut denied_dispatcher = ByoaDispatcher::new(&vault, StubFactory, DenyAllEgress);
    let denial = denied_dispatcher
        .authorize_cli_egress(&spec, "api.example.com", "intent-1", 100)
        .expect_err("network without a lease must be denied");
    let ByoaError::EgressDenied { profile_ref, .. } = denial else {
        panic!("expected an egress denial, got {denial:?}");
    };
    assert_eq!(profile_ref, spec.egress_profile_ref);

    // The leased path carries scope, expiry, and the audit reference.
    let mut granted = ByoaDispatcher::new(&vault, StubFactory, GrantingEgress::new(500));
    let lease = granted
        .authorize_cli_egress(&spec, "api.example.com", "intent-1", 100)
        .expect("leased egress is granted");
    assert_eq!(lease.profile_ref, spec.egress_profile_ref);
    assert_eq!(lease.allowed_hosts, vec!["api.example.com".to_owned()]);
    assert_eq!(lease.expires_at, 500);
    assert_eq!(
        lease.audit_ref,
        EntityId::from_bytes([9_u8; 16]).expect("id")
    );
    assert_ne!(lease.lease_id, [0_u8; 16]);

    // Scope is real: a host outside the lease is refused, and a lookalike
    // suffix never sneaks past the label boundary.
    assert!(
        granted
            .authorize_cli_egress(&spec, "evil.example.net", "intent-1", 100)
            .is_err()
    );
    assert!(
        !lease.permits_host("notapi.example.com", 100),
        "suffix matching must respect label boundaries"
    );
    assert!(lease.permits_host("edge.api.example.com", 100));

    // Expiry is real: the same lease grants nothing once its window closes.
    assert!(!lease.permits_host("api.example.com", 500));
    let mut expired = ByoaDispatcher::new(&vault, StubFactory, GrantingEgress::new(100));
    assert!(
        expired
            .authorize_cli_egress(&spec, "api.example.com", "intent-1", 100)
            .is_err(),
        "an already-expired lease is a denial, not a grant"
    );

    // A port that answers for the wrong profile is not trusted either.
    let mut mismatched = GrantingEgress::new(500);
    mismatched.profile_ref = Some("egress/some-other-profile".to_owned());
    let mut wrong = ByoaDispatcher::new(&vault, StubFactory, mismatched);
    assert!(
        wrong
            .authorize_cli_egress(&spec, "api.example.com", "intent-1", 100)
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// T4 — terminal exhaust becomes ONE artifact version, idempotently
// ---------------------------------------------------------------------------

fn dispatch_and_claim<E: ByoaEgressPort>(
    vault: &Vault,
    dispatcher: &mut ByoaDispatcher<'_, StubFactory, E>,
    connector: ByoaConnectorSpec,
    lease_owner: &str,
) -> AttemptRecord {
    let outcome = dispatcher
        .dispatch(DispatchByoa {
            connector,
            task_ref: None,
            parent_attempt_id: None,
            run_id: Some("byoa-run".to_owned()),
            dedupe_key: None,
            now: 10,
        })
        .expect("dispatch");
    assert!(matches!(outcome, ByoaDispatchOutcome::Dispatched(_)));
    assert_eq!(outcome.status().attempt.kind, BYOA_ATTEMPT_KIND);

    let queue = AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(claimed) = queue
        .claim_kind(
            BYOA_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: lease_owner.to_owned(),
                now: 20,
            },
        )
        .expect("claim")
    else {
        panic!("the dispatched row must be claimable");
    };
    claimed
}

fn sample_exhaust() -> ByoaExhaust {
    ByoaExhaust {
        transcript: Some(b"turn 1\nturn 2".to_vec()),
        stdout: b"built ok".to_vec(),
        stderr: b"warning: none".to_vec(),
        diff_bundle: Some(b"diff --git a b".to_vec()),
        checkpoint_frontier: vec!["refs/heads/work@".to_owned() + &"a".repeat(40)],
    }
}

#[test]
fn exhaust_capture_writes_one_artifact_version_and_is_idempotent() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let attempt = dispatch_and_claim(
        &vault,
        &mut dispatcher,
        ByoaConnectorSpec::CliSandbox(cli_spec()),
        "capture-worker",
    );
    let actor_id = byoa_runtime_actor().expect("runtime actor").entity_ref();
    assert_eq!(
        vault.get_entity_type(&actor_id).expect("actor lookup"),
        None
    );

    let request = |now| CaptureByoaExhaust {
        attempt_id: attempt.id,
        lease_owner: "capture-worker".to_owned(),
        attempt_count: attempt.attempt_count,
        disposition: ByoaTerminalDisposition::Completed,
        exhaust: sample_exhaust(),
        reason: None,
        now,
    };

    let first = dispatcher
        .capture_terminal_exhaust(request(30))
        .expect("first capture");
    assert_eq!(
        vault.get_entity_type(&actor_id).expect("persisted actor"),
        Some(crate::registry::ENTITY_TYPE_PERSON),
        "capture must persist the Agent-class writer before appending its ledger claim"
    );
    let actor_raw = vault.get_raw(&actor_id).expect("actor bytes");
    assert_eq!(first.artifact_version, 1);
    assert_eq!(
        first.artifact_id,
        byoa_exhaust_artifact_id(attempt.id).expect("derived artifact id"),
        "the artifact address is derived from the attempt, not minted per capture"
    );
    assert!(
        first
            .result_ref
            .as_str()
            .starts_with(BYOA_RESULT_REF_PREFIX)
    );
    assert_eq!(
        first.attempt.result_ref().map(AttemptResultRef::as_str),
        Some(first.result_ref.as_str()),
        "the row must point at the artifact the capture wrote"
    );

    // Repeating the same capture converges instead of minting a second
    // version of the same evidence.
    let second = dispatcher
        .capture_terminal_exhaust(request(31))
        .expect("repeat capture");
    assert_eq!(second.result_ref, first.result_ref);
    assert_eq!(second.artifact_version, 1);
    assert_eq!(
        vault.get_raw(&actor_id).expect("actor after retry"),
        actor_raw,
        "retry must reuse the actor without rewriting its body or timestamps"
    );
    assert_eq!(
        vault
            .blob_artifact_versions(&first.artifact_id)
            .expect("version chain")
            .len(),
        1,
        "one terminal attempt has exactly one canonical exhaust version"
    );

    // The stored bytes are the exhaust, canonically encoded under this
    // module's media type.
    let (artifact_id, version) =
        parse_byoa_result_ref(&first.result_ref).expect("result ref parses back");
    assert_eq!(artifact_id, first.artifact_id);
    assert_eq!(version, 1);
    let body = vault
        .get_blob_artifact(&artifact_id)
        .expect("artifact read")
        .expect("artifact exists");
    assert_eq!(body.media_type, BYOA_EXHAUST_MEDIA_TYPE);
    let bytes = vault
        .read_blob_artifact_version(&artifact_id, version)
        .expect("version read")
        .expect("version bytes");
    let (decoded_attempt, disposition, exhaust) =
        decode_byoa_exhaust(&bytes).expect("exhaust decodes");
    assert_eq!(decoded_attempt, attempt.id);
    assert_eq!(disposition, ByoaTerminalDisposition::Completed);
    assert_eq!(exhaust, sample_exhaust());

    // Capture already settled the row; a matching generic completion is a no-op.
    assert_eq!(second.attempt.state, AttemptState::Completed);
    let CompleteOutcome::AlreadyCompleted(completed) = AttemptQueue::new(&vault)
        .complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "capture-worker".to_owned(),
            attempt_count: attempt.attempt_count,
            now: 32,
        })
        .expect("complete")
    else {
        panic!("capture must already have completed the attempt");
    };
    assert_eq!(
        completed.result_ref().map(AttemptResultRef::as_str),
        Some(first.result_ref.as_str()),
        "settling must not drop the artifact the row already published"
    );
}

#[test]
fn capture_refuses_an_incompatible_runtime_actor_without_overwriting_it() {
    let (_dir, vault) = open_vault();
    let actor_id = byoa_runtime_actor().expect("runtime actor").entity_ref();
    vault
        .put_blob_artifact(
            &actor_id,
            &BlobArtifactBody::new("not-an-actor", "text/plain"),
            TimeRange { start: 5, end: 5 },
            5,
        )
        .expect("conflicting entity");
    let original = vault.get_raw(&actor_id).expect("original entity");
    let mut dispatcher = dispatcher(&vault);
    let attempt = dispatch_and_claim(
        &vault,
        &mut dispatcher,
        ByoaConnectorSpec::CliSandbox(cli_spec()),
        "capture-worker",
    );
    let before = custody_snapshot(&vault);
    let refused = dispatcher
        .capture_terminal_exhaust(CaptureByoaExhaust {
            attempt_id: attempt.id,
            lease_owner: "capture-worker".to_owned(),
            attempt_count: attempt.attempt_count,
            disposition: ByoaTerminalDisposition::Completed,
            exhaust: sample_exhaust(),
            reason: None,
            now: 30,
        })
        .expect_err("an incompatible actor must not be replaced");
    assert!(matches!(
        refused,
        ByoaError::Store(Error::ActorClassMismatch { .. })
    ));
    assert_eq!(
        custody_snapshot(&vault),
        before,
        "all staged custody must roll back"
    );
    assert_eq!(
        vault.get_raw(&actor_id).expect("entity after refusal"),
        original
    );
    let artifact_id = byoa_exhaust_artifact_id(attempt.id).expect("artifact id");
    assert!(
        vault
            .blob_artifact_head(&artifact_id)
            .expect("head")
            .is_none()
    );
    assert_eq!(
        AttemptQueue::new(&vault).get(attempt.id).expect("row"),
        Some(attempt)
    );
}

#[test]
fn abandoned_capture_settles_the_row_and_stays_idempotent() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let attempt = dispatch_and_claim(
        &vault,
        &mut dispatcher,
        ByoaConnectorSpec::CliSandbox(cli_spec()),
        "abandon-worker",
    );

    let request = |now| CaptureByoaExhaust {
        attempt_id: attempt.id,
        lease_owner: "abandon-worker".to_owned(),
        attempt_count: attempt.attempt_count,
        disposition: ByoaTerminalDisposition::Abandoned,
        exhaust: sample_exhaust(),
        reason: Some("foreign process exited without a result".to_owned()),
        now,
    };

    let first = dispatcher
        .capture_terminal_exhaust(request(30))
        .expect("abandon capture");
    assert_eq!(first.attempt.state, AttemptState::Abandoned);
    assert!(first.attempt.state.is_terminal());
    assert!(!first.attempt.state.is_running());
    assert_eq!(
        first.attempt.last_error.as_deref(),
        Some("foreign process exited without a result"),
        "an abandonment records why it stopped"
    );
    assert_eq!(
        first.attempt.result_ref().map(AttemptResultRef::as_str),
        Some(first.result_ref.as_str())
    );

    // The second capture takes the AlreadyAbandoned path and reports the same
    // artifact, with no second version behind it.
    let second = dispatcher
        .capture_terminal_exhaust(request(31))
        .expect("repeat abandon capture");
    assert_eq!(second.result_ref, first.result_ref);
    assert_eq!(second.attempt.state, AttemptState::Abandoned);
    assert_eq!(
        vault
            .blob_artifact_versions(&first.artifact_id)
            .expect("chain")
            .len(),
        1
    );
}

#[test]
fn capture_refuses_an_empty_exhaust_and_an_unclaimed_row() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let outcome = dispatcher
        .dispatch(DispatchByoa {
            connector: ByoaConnectorSpec::CliSandbox(cli_spec()),
            task_ref: None,
            parent_attempt_id: None,
            run_id: None,
            dedupe_key: None,
            now: 10,
        })
        .expect("dispatch");
    let attempt = outcome.status().attempt.clone();
    assert_eq!(attempt.state, AttemptState::Queued);
    let before = custody_snapshot(&vault);

    // Nothing durable was produced, so there is nothing to point at.
    assert!(
        dispatcher
            .capture_terminal_exhaust(CaptureByoaExhaust {
                attempt_id: attempt.id,
                lease_owner: "nobody".to_owned(),
                attempt_count: attempt.attempt_count,
                disposition: ByoaTerminalDisposition::Abandoned,
                exhaust: ByoaExhaust::default(),
                reason: Some("stopped".to_owned()),
                now: 20,
            })
            .is_err(),
        "an abandonment with no evidence must be refused"
    );

    // A queued row was never carried by anyone, so it cannot be abandoned.
    let refused = dispatcher
        .capture_terminal_exhaust(CaptureByoaExhaust {
            attempt_id: attempt.id,
            lease_owner: "nobody".to_owned(),
            attempt_count: attempt.attempt_count,
            disposition: ByoaTerminalDisposition::Abandoned,
            exhaust: sample_exhaust(),
            reason: Some("stopped".to_owned()),
            now: 20,
        })
        .expect_err("a pre-lease row is cancelled, never abandoned");
    assert!(
        matches!(
            refused,
            ByoaError::Store(Error::InvalidAttemptQueueTransition {
                action: "abandon",
                state: "queued",
            })
        ),
        "capture must reach the queue fence, not fail on a missing blob writer: {refused:?}"
    );
    assert_eq!(custody_snapshot(&vault), before);
}

#[test]
fn dispatch_is_advisory_deduped_and_carries_its_lineage() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let parent = AttemptId::now();

    let request = || DispatchByoa {
        connector: ByoaConnectorSpec::Endpoint(endpoint_spec()),
        task_ref: Some(EntityId::from_bytes([5_u8; 16]).expect("task ref")),
        parent_attempt_id: Some(parent),
        run_id: Some("byoa-run".to_owned()),
        dedupe_key: Some("byoa:dedupe".to_owned()),
        now: 10,
    };

    let ByoaDispatchOutcome::Dispatched(first) = dispatcher.dispatch(request()).expect("dispatch")
    else {
        panic!("expected a fresh dispatch");
    };
    let ByoaDispatchOutcome::Existing(second) = dispatcher.dispatch(request()).expect("dispatch")
    else {
        panic!("a live dedupe key must return the existing row");
    };
    assert_eq!(first.attempt.id, second.attempt.id);
    assert_eq!(first.connector_kind, ByoaConnectorKind::Endpoint);
    assert_eq!(
        first.attempt.task_ref,
        Some(EntityId::from_bytes([5_u8; 16]).expect("task ref").to_hex()),
        "the owning task rides the existing queue backlink"
    );

    let payload = decode_byoa_attempt_payload(&first.attempt.payload).expect("payload decodes");
    assert_eq!(
        payload.parent_attempt,
        Some(*parent.as_bytes()),
        "the spawn lineage rides the payload, not a new queue column"
    );
    assert_eq!(payload.schema_version, BYOA_CONNECTOR_SCHEMA_VERSION);
}

#[test]
fn a_payload_from_an_unknown_schema_version_is_refused() {
    let payload = encode_byoa_attempt_payload(&ByoaAttemptPayload {
        schema_version: BYOA_CONNECTOR_SCHEMA_VERSION + 1,
        connector: ByoaConnectorSpec::Endpoint(endpoint_spec()),
        parent_attempt: None,
    })
    .expect("encode");
    assert!(
        decode_byoa_attempt_payload(&payload).is_err(),
        "a future schema version must fail closed, never decode partially"
    );
}

#[test]
fn result_ref_shape_is_enforced_in_both_directions() {
    let artifact_id = EntityId::from_bytes([11_u8; 16]).expect("artifact id");
    let result_ref = byoa_result_ref(&artifact_id, 7).expect("build result ref");
    assert_eq!(
        result_ref.as_str(),
        format!("{BYOA_RESULT_REF_PREFIX}{}@7", artifact_id.to_hex())
    );
    assert_eq!(
        parse_byoa_result_ref(&result_ref).expect("parse"),
        (artifact_id, 7)
    );

    for bad in ["not-a-ref", "blob-artifact:zz@1", "blob-artifact:nope"] {
        let raw = AttemptResultRef::new(bad).expect("non-empty reference");
        assert!(
            parse_byoa_result_ref(&raw).is_err(),
            "reference {bad:?} is not this module's shape"
        );
    }
}

// Qodo regressions: refusals must leave actors, artifacts, assets, ledger claims,
// result rows, and dedupe ownership unchanged, not merely return an error.
type CustodyRows = Vec<(Vec<u8>, Vec<u8>)>;

fn custody_snapshot(vault: &Vault) -> [CustodyRows; 4] {
    let txn = vault.store.env.read_txn().expect("snapshot transaction");
    [
        &vault.store.entities,
        &vault.store.vault_meta,
        &vault.store.attempt_records,
        &vault.store.attempt_dedupe,
    ]
    .map(|db| {
        db.iter(&txn)
            .expect("snapshot iterator")
            .map(|row| {
                let (key, value) = row.expect("snapshot row");
                (key.to_vec(), value.to_vec())
            })
            .collect()
    })
}

fn capture_request(
    attempt: &AttemptRecord,
    disposition: ByoaTerminalDisposition,
) -> CaptureByoaExhaust {
    CaptureByoaExhaust {
        attempt_id: attempt.id,
        lease_owner: attempt
            .lease_owner
            .clone()
            .unwrap_or_else(|| "worker".to_owned()),
        attempt_count: attempt.attempt_count,
        disposition,
        exhaust: sample_exhaust(),
        reason: Some("executor stopped".to_owned()),
        now: 30,
    }
}

#[test]
fn endpoint_credentials_and_malformed_authorities_are_refused_at_every_door() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    for url in [
        "https://user:password@example.com",
        "https://user@example.com",
        "https://@example.com",
        "https://user%3Apassword@example.com",
        "https://example.com#password",
        "https://example.com?api_key=password",
        "https://",
        "https:///path",
        "https://?query",
        "https://[invalid]/",
        "https://example.com:99999/",
        "https://example.com:/",
        "https://example.com\\@other.example/",
    ] {
        let before = custody_snapshot(&vault);
        let mut spec = endpoint_spec();
        spec.base_url = url.to_owned();
        assert!(!format!("{spec:?}").contains("password"));
        assert!(dispatcher.endpoint_backend(&spec).is_err(), "{url}");
        let payload = ByoaAttemptPayload {
            schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
            connector: ByoaConnectorSpec::Endpoint(spec),
            parent_attempt: None,
        };
        assert!(encode_byoa_attempt_payload(&payload).is_err(), "{url}");
        let unchecked = rmp_serde::to_vec_named(&payload).expect("unchecked fixture");
        assert!(decode_byoa_attempt_payload(&unchecked).is_err(), "{url}");
        assert!(
            dispatcher
                .dispatch(DispatchByoa {
                    connector: payload.connector,
                    task_ref: None,
                    parent_attempt_id: None,
                    run_id: None,
                    dedupe_key: None,
                    now: 10,
                })
                .is_err(),
            "{url}"
        );
        assert_eq!(custody_snapshot(&vault), before, "{url}");
    }
    for url in [
        "http://localhost:8080/v1",
        "https://example.com/v1/",
        "http://127.0.0.1:8000/v1",
        "https://[::1]:443/v1",
    ] {
        let mut spec = endpoint_spec();
        spec.base_url = url.to_owned();
        validate_endpoint(&spec).expect("valid bare HTTP(S) endpoint");
    }
}

#[test]
fn dedupe_reports_the_persisted_connector_not_the_losing_request() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let request = |connector| DispatchByoa {
        connector,
        task_ref: None,
        parent_attempt_id: None,
        run_id: None,
        dedupe_key: Some("same-work".to_owned()),
        now: 10,
    };
    let first = dispatcher
        .dispatch(request(ByoaConnectorSpec::ProtocolAttach(attach_spec())))
        .expect("first dispatch");
    for connector in [
        ByoaConnectorSpec::Endpoint(endpoint_spec()),
        ByoaConnectorSpec::CliSandbox(cli_spec()),
    ] {
        let before = custody_snapshot(&vault);
        let duplicate = dispatcher.dispatch(request(connector)).expect("dedupe");
        assert!(matches!(duplicate, ByoaDispatchOutcome::Existing(_)));
        assert_eq!(duplicate.status(), first.status());
        assert_eq!(
            duplicate.status().connector_kind,
            ByoaConnectorKind::ProtocolAttach
        );
        assert_eq!(custody_snapshot(&vault), before);
    }
}

#[test]
fn capture_refuses_wrong_owner_generation_kind_and_payload_without_writes() {
    for case in [
        "owner",
        "generation",
        "kind",
        "payload",
        "schema",
        "missing",
    ] {
        let (_dir, vault) = open_vault();
        let mut dispatcher = dispatcher(&vault);
        let mut payload = ByoaAttemptPayload {
            schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
            connector: ByoaConnectorSpec::CliSandbox(cli_spec()),
            parent_attempt: None,
        };
        if case == "schema" {
            payload.schema_version += 1;
        }
        let kind = if case == "kind" {
            "other.executor"
        } else {
            BYOA_ATTEMPT_KIND
        };
        let queue = AttemptQueue::new(&vault);
        queue
            .enqueue(EnqueueAttempt {
                kind: kind.to_owned(),
                payload: if case == "payload" {
                    vec![0xff]
                } else {
                    encode_byoa_attempt_payload(&payload).expect("fixture payload")
                },
                dedupe_key: Some("custody-owner".to_owned()),
                run_id: None,
                now: 10,
            })
            .expect("enqueue fixture");
        let ClaimOutcome::Claimed(attempt) = queue
            .claim_kind(
                kind,
                ClaimAttempt {
                    lease_owner: "worker".to_owned(),
                    now: 20,
                },
            )
            .expect("claim")
        else {
            panic!("missing fixture");
        };
        for disposition in [
            ByoaTerminalDisposition::Completed,
            ByoaTerminalDisposition::Abandoned,
        ] {
            let mut request = capture_request(&attempt, disposition);
            match case {
                "owner" => request.lease_owner = "intruder".to_owned(),
                "generation" => request.attempt_count += 1,
                "missing" => request.attempt_id = AttemptId::now(),
                _ => {}
            }
            let before = custody_snapshot(&vault);
            assert!(
                dispatcher.capture_terminal_exhaust(request).is_err(),
                "{case}"
            );
            assert_eq!(custody_snapshot(&vault), before, "{case}");
        }
    }
}

#[test]
fn capture_rejects_precreated_artifacts_even_with_canonical_metadata() {
    for canonical in [false, true] {
        let (_dir, vault) = open_vault();
        let mut dispatcher = dispatcher(&vault);
        let attempt = dispatch_and_claim(
            &vault,
            &mut dispatcher,
            ByoaConnectorSpec::CliSandbox(cli_spec()),
            "worker",
        );
        let id = byoa_exhaust_artifact_id(attempt.id).expect("artifact id");
        let body = if canonical {
            BlobArtifactBody::new(
                byoa_exhaust_artifact_name(attempt.id),
                BYOA_EXHAUST_MEDIA_TYPE,
            )
        } else {
            BlobArtifactBody::new("caller-owned", "text/plain")
        };
        vault
            .put_blob_artifact(&id, &body, TimeRange { start: 25, end: 25 }, 25)
            .expect("precreated artifact");
        let before = custody_snapshot(&vault);
        let error = dispatcher
            .capture_terminal_exhaust(capture_request(
                &attempt,
                ByoaTerminalDisposition::Completed,
            ))
            .expect_err("collision");
        assert!(matches!(
            error,
            ByoaError::Store(Error::InvalidAgentDispatchInput(ERR_ARTIFACT_COLLISION))
        ));
        assert_eq!(custody_snapshot(&vault), before);
    }
}

#[test]
fn invalid_abandon_reason_rolls_back_all_custody() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let attempt = dispatch_and_claim(
        &vault,
        &mut dispatcher,
        ByoaConnectorSpec::CliSandbox(cli_spec()),
        "worker",
    );
    for reason in [String::new(), "x".repeat(2049)] {
        let mut request = capture_request(&attempt, ByoaTerminalDisposition::Abandoned);
        request.reason = Some(reason);
        let before = custody_snapshot(&vault);
        assert!(dispatcher.capture_terminal_exhaust(request).is_err());
        assert_eq!(custody_snapshot(&vault), before);
    }
}

#[test]
fn divergent_captures_never_grow_the_canonical_chain() {
    for disposition in [
        ByoaTerminalDisposition::Completed,
        ByoaTerminalDisposition::Abandoned,
    ] {
        let (_dir, vault) = open_vault();
        let mut dispatcher = dispatcher(&vault);
        let attempt = dispatch_and_claim(
            &vault,
            &mut dispatcher,
            ByoaConnectorSpec::CliSandbox(cli_spec()),
            "worker",
        );
        let first = dispatcher
            .capture_terminal_exhaust(capture_request(&attempt, disposition))
            .expect("first capture");
        let before = custody_snapshot(&vault);
        for n in 0..8 {
            let mut request = capture_request(&attempt, disposition);
            request.exhaust.stdout = format!("divergent {n}").into_bytes();
            request.now += n;
            let retry = dispatcher.capture_terminal_exhaust(request);
            if disposition == ByoaTerminalDisposition::Abandoned {
                assert_eq!(retry.expect("first abandonment wins"), first);
            } else {
                assert!(retry.is_err(), "live result content is write-once");
            }
            assert_eq!(custody_snapshot(&vault), before);
        }
        assert_eq!(
            vault
                .blob_artifact_versions(&first.artifact_id)
                .expect("chain")
                .len(),
            1
        );
        for change in ["owner", "generation", "disposition"] {
            let mut request = capture_request(&attempt, disposition);
            match change {
                "owner" => request.lease_owner = "intruder".to_owned(),
                "generation" => request.attempt_count += 1,
                _ => request.disposition = ByoaTerminalDisposition::Failed,
            }
            assert!(
                dispatcher.capture_terminal_exhaust(request).is_err(),
                "{change}"
            );
            assert_eq!(custody_snapshot(&vault), before);
        }
    }
}

#[test]
fn terminal_recapture_requires_matching_disposition_content_and_retained_fence() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let attempt = dispatch_and_claim(
        &vault,
        &mut dispatcher,
        ByoaConnectorSpec::Endpoint(endpoint_spec()),
        "worker",
    );
    let first = dispatcher
        .capture_terminal_exhaust(capture_request(
            &attempt,
            ByoaTerminalDisposition::Completed,
        ))
        .expect("capture");
    AttemptQueue::new(&vault)
        .complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "worker".to_owned(),
            attempt_count: attempt.attempt_count,
            now: 31,
        })
        .expect("complete");
    let before = custody_snapshot(&vault);
    let retry = dispatcher
        .capture_terminal_exhaust(capture_request(
            &attempt,
            ByoaTerminalDisposition::Completed,
        ))
        .expect("terminal retry");
    assert_eq!(retry.attempt.state, AttemptState::Completed);
    assert_eq!(retry.result_ref, first.result_ref);
    for disposition in [
        ByoaTerminalDisposition::Failed,
        ByoaTerminalDisposition::Cancelled,
        ByoaTerminalDisposition::Abandoned,
    ] {
        assert!(
            dispatcher
                .capture_terminal_exhaust(capture_request(&attempt, disposition))
                .is_err()
        );
    }
    let mut wrong_owner = capture_request(&attempt, ByoaTerminalDisposition::Completed);
    wrong_owner.lease_owner = "intruder".to_owned();
    assert!(dispatcher.capture_terminal_exhaust(wrong_owner).is_err());
    assert_eq!(custody_snapshot(&vault), before);
}

#[test]
fn concurrent_identical_captures_commit_exactly_one_version() {
    let (_dir, vault) = open_vault();
    let mut initial = dispatcher(&vault);
    let attempt = dispatch_and_claim(
        &vault,
        &mut initial,
        ByoaConnectorSpec::CliSandbox(cli_spec()),
        "worker",
    );
    let barrier = std::sync::Barrier::new(2);
    let captures = std::thread::scope(|scope| {
        let capture = || {
            barrier.wait();
            dispatcher(&vault)
                .capture_terminal_exhaust(capture_request(
                    &attempt,
                    ByoaTerminalDisposition::Abandoned,
                ))
                .expect("concurrent capture")
        };
        let first = scope.spawn(capture);
        let second = scope.spawn(capture);
        (
            first.join().expect("first worker"),
            second.join().expect("second worker"),
        )
    });
    assert_eq!(captures.0, captures.1);
    assert_eq!(
        vault
            .blob_artifact_versions(&captures.0.artifact_id)
            .expect("chain")
            .len(),
        1
    );
}

#[test]
fn exhaust_stream_and_aggregate_limits_apply_before_capture_and_on_decode() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let attempt = dispatch_and_claim(
        &vault,
        &mut dispatcher,
        ByoaConnectorSpec::CliSandbox(cli_spec()),
        "worker",
    );
    for stream in 0..4 {
        let mut exhaust = ByoaExhaust::default();
        let bytes = vec![0xff; BYOA_MAX_EXHAUST_STREAM_BYTES + 1];
        match stream {
            0 => exhaust.transcript = Some(bytes),
            1 => exhaust.stdout = bytes,
            2 => exhaust.stderr = bytes,
            _ => exhaust.diff_bundle = Some(bytes),
        }
        let before = custody_snapshot(&vault);
        let mut request = capture_request(&attempt, ByoaTerminalDisposition::Completed);
        request.exhaust = exhaust;
        assert!(
            dispatcher
                .capture_terminal_exhaust(request.clone())
                .is_err()
        );
        let unchecked = rmp_serde::to_vec_named(&ByoaExhaustEnvelope {
            schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
            attempt_id: *attempt.id.as_bytes(),
            lease_owner: "worker".to_owned(),
            attempt_count: attempt.attempt_count,
            disposition: request.disposition,
            exhaust: request.exhaust,
        })
        .expect("unchecked exhaust fixture");
        assert!(decode_byoa_exhaust(&unchecked).is_err());
        assert_eq!(custody_snapshot(&vault), before);
    }
    let mut at_limit = ByoaExhaust {
        stdout: vec![0xff; BYOA_MAX_EXHAUST_STREAM_BYTES],
        stderr: vec![0xff; BYOA_MAX_EXHAUST_STREAM_BYTES],
        ..ByoaExhaust::default()
    };
    validate_exhaust(&at_limit).expect("inclusive aggregate limit");
    at_limit.checkpoint_frontier.push("x".to_owned());
    assert!(matches!(
        validate_exhaust(&at_limit),
        Err(ByoaError::Store(Error::InvalidAgentDispatchInput(
            ERR_EXHAUST_TOO_LARGE
        )))
    ));
    let before = custody_snapshot(&vault);
    let mut request = capture_request(&attempt, ByoaTerminalDisposition::Completed);
    request.exhaust = at_limit;
    assert!(dispatcher.capture_terminal_exhaust(request).is_err());
    assert_eq!(custody_snapshot(&vault), before);
    assert!(decode_byoa_exhaust(&vec![0; MAX_EXHAUST_ENCODED_BYTES + 1]).is_err());
}

#[test]
fn capture_racing_settlement_leaves_no_unattached_artifact() {
    let (_dir, vault) = open_vault();
    let mut initial = dispatcher(&vault);
    let attempt = dispatch_and_claim(
        &vault,
        &mut initial,
        ByoaConnectorSpec::Endpoint(endpoint_spec()),
        "worker",
    );
    let barrier = std::sync::Barrier::new(2);
    let capture = std::thread::scope(|scope| {
        let captured = scope.spawn(|| {
            barrier.wait();
            dispatcher(&vault).capture_terminal_exhaust(capture_request(
                &attempt,
                ByoaTerminalDisposition::Completed,
            ))
        });
        let settled = scope.spawn(|| {
            barrier.wait();
            AttemptQueue::new(&vault)
                .complete(CompleteAttempt {
                    id: attempt.id,
                    lease_owner: "worker".to_owned(),
                    attempt_count: attempt.attempt_count,
                    now: 31,
                })
                .expect("settlement");
        });
        settled.join().expect("settling worker");
        captured.join().expect("capturing worker")
    });
    let record = AttemptQueue::new(&vault)
        .get(attempt.id)
        .expect("row")
        .expect("attempt");
    assert_eq!(record.state, AttemptState::Completed);
    let artifact = byoa_exhaust_artifact_id(attempt.id).expect("artifact");
    match capture {
        Ok(receipt) => {
            assert_eq!(record.result_ref, Some(receipt.result_ref));
            assert_eq!(
                vault
                    .blob_artifact_versions(&artifact)
                    .expect("chain")
                    .len(),
                1
            );
        }
        Err(_) => {
            assert!(record.result_ref.is_none());
            assert!(
                vault
                    .get_blob_artifact(&artifact)
                    .expect("artifact lookup")
                    .is_none()
            );
            assert!(
                vault
                    .blob_artifact_versions(&artifact)
                    .expect("chain")
                    .is_empty()
            );
            assert!(
                vault
                    .get_entity_type(&byoa_runtime_actor().expect("actor").entity_ref())
                    .expect("actor lookup")
                    .is_none()
            );
        }
    }
}

#[test]
fn recapture_refuses_replaced_metadata_and_extended_history() {
    for changed in ["metadata", "history"] {
        let (_dir, vault) = open_vault();
        let mut dispatcher = dispatcher(&vault);
        let attempt = dispatch_and_claim(
            &vault,
            &mut dispatcher,
            ByoaConnectorSpec::Endpoint(endpoint_spec()),
            "worker",
        );
        let request = capture_request(&attempt, ByoaTerminalDisposition::Completed);
        let receipt = dispatcher
            .capture_terminal_exhaust(request.clone())
            .expect("capture");
        let occurred = TimeRange { start: 31, end: 31 };
        if changed == "metadata" {
            vault
                .put_blob_artifact(
                    &receipt.artifact_id,
                    &BlobArtifactBody::new("replaced", "text/plain"),
                    occurred,
                    31,
                )
                .expect("external metadata write");
        } else {
            vault
                .append_blob_artifact_version(
                    &receipt.artifact_id,
                    b"unrelated",
                    &BlobVersionProvenance::UserUpload,
                    byoa_runtime_actor().expect("actor"),
                    occurred,
                    31,
                )
                .expect("external history append");
        }
        let before = custody_snapshot(&vault);
        assert!(
            dispatcher.capture_terminal_exhaust(request).is_err(),
            "{changed}"
        );
        assert_eq!(custody_snapshot(&vault), before);
    }
}

fn execution_fence(attempt: &AttemptRecord) -> ByoaExecutionFence {
    ByoaExecutionFence {
        attempt_id: attempt.id,
        lease_owner: attempt.lease_owner.clone().expect("claimed owner"),
        attempt_count: attempt.attempt_count,
    }
}

fn ready_result<T>(future: impl std::future::Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match std::future::Future::poll(future.as_mut(), &mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("the injected test backend must complete immediately"),
    }
}

fn execution_llm_request() -> LlmRequest {
    use crate::llm::{
        CallClass, CallEnvelope, CallPurpose, ModelLocality, ModelTierRef, ResponseFormat,
        TierPrecedence,
    };
    LlmRequest {
        model: model("byo/fast@1"),
        envelope: CallEnvelope {
            purpose: CallPurpose::AutoCheck,
            class: CallClass::BestEffort,
            tier: TierPrecedence {
                per_call: None,
                vault_policy: None,
                purpose_default: None,
                global_default: ModelTierRef("standard".to_owned()),
            },
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
        },
        messages: Vec::new(),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    }
}

struct RecordingBackend(std::sync::atomic::AtomicUsize);

impl LlmBackend for RecordingBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        use crate::llm::{
            ContentPart, FinishReason, LlmMessage, LlmMessageRole, LlmResponse, LlmUsage,
        };
        assert_eq!(request.model, model("byo/fast@1"));
        assert_eq!(lease.id(), "execution-budget");
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: "generated output".to_owned(),
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
            })
        })
    }
    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(BudgetDenied::AdmissionDenied.into())
    }
}

struct RecordingFactory(Arc<RecordingBackend>);
impl ByoEndpointBackendFactory for RecordingFactory {
    fn resolve_backend(&self, spec: &ByoEndpointSpec) -> ByoaResult<Arc<dyn LlmBackend>> {
        assert_eq!(spec, &endpoint_spec());
        Ok(self.0.clone())
    }
}

#[test]
fn endpoint_execution_invokes_the_backend_with_the_stored_model_and_budget() {
    let (_dir, vault) = open_vault();
    let attempt = dispatch_and_claim(
        &vault,
        &mut dispatcher(&vault),
        ByoaConnectorSpec::Endpoint(endpoint_spec()),
        "worker",
    );
    let backend = Arc::new(RecordingBackend(std::sync::atomic::AtomicUsize::new(0)));
    let mut dispatcher =
        ByoaDispatcher::new(&vault, RecordingFactory(backend.clone()), DenyAllEgress);
    let fence = execution_fence(&attempt);
    let lease = BudgetLease::for_test("execution-budget");
    let exhaust =
        ready_result(dispatcher.execute_endpoint(&fence, "fast", execution_llm_request(), &lease))
            .expect("backend generated output");
    assert!(
        String::from_utf8_lossy(exhaust.transcript.as_ref().expect("transcript"))
            .contains("generated output")
    );
    assert_eq!(backend.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    for slug in ["smart", "unknown"] {
        assert!(
            ready_result(dispatcher.execute_endpoint(
                &fence,
                slug,
                execution_llm_request(),
                &lease
            ))
            .is_err()
        );
    }
    let mut stale = fence.clone();
    stale.attempt_count += 1;
    assert!(
        ready_result(dispatcher.execute_endpoint(&stale, "fast", execution_llm_request(), &lease))
            .is_err()
    );
    let mut oversized = execution_llm_request();
    oversized.params.insert(
        "input".to_owned(),
        serde_json::Value::String("x".repeat(BYOA_MAX_EXHAUST_STREAM_BYTES + 1)),
    );
    assert!(ready_result(dispatcher.execute_endpoint(&fence, "fast", oversized, &lease)).is_err());
    assert_eq!(backend.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    let mut request = capture_request(&attempt, ByoaTerminalDisposition::Completed);
    request.exhaust = exhaust;
    dispatcher
        .capture_terminal_exhaust(request)
        .expect("capture generated output");
    assert!(
        ready_result(dispatcher.execute_endpoint(&fence, "fast", execution_llm_request(), &lease))
            .is_err()
    );
    assert_eq!(backend.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}

struct RecordingMcp {
    calls: usize,
    oversized: bool,
}
impl ByoaMcpExecutor for RecordingMcp {
    fn attach_and_run(
        &mut self,
        spec: &ProtocolAttachSpec,
        input: &[u8],
        budget: ExecutionBudget,
    ) -> ByoaResult<ByoaExhaust> {
        assert_eq!(spec, &attach_spec());
        assert!(budget.is_bounded());
        self.calls += 1;
        Ok(ByoaExhaust {
            stdout: if self.oversized {
                vec![0; BYOA_MAX_EXHAUST_STREAM_BYTES + 1]
            } else {
                input.to_vec()
            },
            ..ByoaExhaust::default()
        })
    }
}

#[test]
fn mcp_execution_invokes_only_the_matching_fenced_connector_and_bounds_output() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let attempt = dispatch_and_claim(
        &vault,
        &mut dispatcher,
        ByoaConnectorSpec::ProtocolAttach(attach_spec()),
        "worker",
    );
    let fence = execution_fence(&attempt);
    let budget = ExecutionBudget::new(30, 128, 8);
    let mut client = RecordingMcp {
        calls: 0,
        oversized: false,
    };
    let exhaust = dispatcher
        .execute_mcp(&fence, b"mcp output", budget, &mut client)
        .expect("MCP call");
    assert_eq!(exhaust.stdout, b"mcp output");
    assert_eq!(client.calls, 1);
    assert!(
        dispatcher
            .execute_mcp(
                &fence,
                b"input",
                ExecutionBudget::new(0, 128, 8),
                &mut client
            )
            .is_err()
    );
    let mut stale = fence.clone();
    stale.attempt_count += 1;
    assert!(
        dispatcher
            .execute_mcp(&stale, b"input", budget, &mut client)
            .is_err()
    );
    let endpoint = dispatch_and_claim(
        &vault,
        &mut dispatcher,
        ByoaConnectorSpec::Endpoint(endpoint_spec()),
        "worker",
    );
    assert!(
        dispatcher
            .execute_mcp(&execution_fence(&endpoint), b"input", budget, &mut client)
            .is_err()
    );
    assert_eq!(client.calls, 1);
    client.oversized = true;
    assert!(
        dispatcher
            .execute_mcp(&fence, b"input", budget, &mut client)
            .is_err()
    );
    let mut request = capture_request(&attempt, ByoaTerminalDisposition::Completed);
    request.exhaust = exhaust;
    dispatcher
        .capture_terminal_exhaust(request)
        .expect("capture MCP output");
}

struct CheckoutFacts;
impl CheckoutFactSink for CheckoutFacts {
    fn apply_checkout_fact(
        &mut self,
        _mutation: crate::checkout::CheckoutFactMutation,
    ) -> crate::checkout::CheckoutResult<()> {
        Ok(())
    }
}
#[derive(Default)]
struct CheckoutPulse(Option<crate::checkout::CheckoutLivenessPulse>);
impl CheckoutLiveness for CheckoutPulse {
    fn publish(
        &mut self,
        pulse: crate::checkout::CheckoutLivenessPulse,
    ) -> crate::checkout::CheckoutResult<()> {
        self.0 = Some(pulse);
        Ok(())
    }
    fn current(
        &self,
        id: CheckoutId,
    ) -> crate::checkout::CheckoutResult<Option<crate::checkout::CheckoutLivenessPulse>> {
        Ok(self
            .0
            .as_ref()
            .filter(|pulse| pulse.checkout_id == id)
            .cloned())
    }
    fn clear(&mut self, _id: CheckoutId, _epoch: u64) -> crate::checkout::CheckoutResult<()> {
        self.0 = None;
        Ok(())
    }
}

struct RecordingCli(usize);
impl ByoaCliExecutor for RecordingCli {
    fn run(
        &mut self,
        spec: &CliSandboxSpec,
        checkout: &CheckoutLeaseAct,
        boundary: SandboxBoundaryContract,
        budget: ExecutionBudget,
        authorize: &mut dyn FnMut(&str, u64) -> ByoaResult<ByoaEgressLease>,
    ) -> ByoaResult<ByoaExhaust> {
        assert_eq!(spec, &cli_spec());
        assert_eq!(checkout.checkout_id, spec.checkout_id);
        assert_eq!(checkout.state, CheckoutLeaseState::Active);
        assert_eq!(boundary.tier(), SandboxGuestTier::Foreign);
        assert!(budget.is_bounded());
        self.0 += 1;
        assert!(
            authorize("api.example.com", 29).is_err(),
            "time cannot regress"
        );
        assert!(
            authorize("unleased.example.net", 30).is_err(),
            "no direct network fallback"
        );
        let lease = authorize("api.example.com", 30)?;
        assert!(lease.permits_host("api.example.com", 30));
        Ok(ByoaExhaust {
            stdout: b"foreign guest output".to_vec(),
            ..ByoaExhaust::default()
        })
    }
}

#[test]
fn cli_execution_requires_live_checkout_foreign_boundary_and_scoped_egress() {
    let (_dir, vault) = open_vault();
    let mut denied = dispatcher(&vault);
    let attempt = dispatch_and_claim(
        &vault,
        &mut denied,
        ByoaConnectorSpec::CliSandbox(cli_spec()),
        "worker",
    );
    let fence = execution_fence(&attempt);
    let budget = ExecutionBudget::new(30, 128, 8);
    let mut checkouts = CheckoutLeaseService::new(&vault, CheckoutFacts, CheckoutPulse::default());
    let mut guest = RecordingCli(0);
    assert!(
        denied
            .execute_cli(&fence, budget, &checkouts, &mut guest, 30)
            .is_err()
    );
    assert_eq!(guest.0, 0, "missing checkout must not invoke host code");
    checkouts
        .claim(crate::checkout::CheckoutClaimRequest {
            checkout_id: cli_spec().checkout_id,
            task_ref: EntityId::from_bytes([5; 16]).expect("task"),
            repo_ref: crate::codebase::RepoRef::parse(
                "github:owner/repo#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect("repo"),
            holder_ref: "worker".to_owned(),
            task_class: crate::checkout::CheckoutTaskClass::Build,
            ttl_secs: Some(100),
            now: 25,
        })
        .expect("checkout lease");
    assert!(
        denied
            .execute_cli(&fence, budget, &checkouts, &mut guest, 30)
            .is_err()
    );
    assert_eq!(
        guest.0, 1,
        "host reached default-deny egress, not a socket fallback"
    );
    let mut granted = ByoaDispatcher::new(&vault, StubFactory, GrantingEgress::new(500));
    assert!(
        granted
            .execute_cli(&fence, budget, &checkouts, &mut guest, 125)
            .is_err()
    );
    assert!(
        granted
            .execute_cli(
                &fence,
                ExecutionBudget::new(30, 0, 8),
                &checkouts,
                &mut guest,
                30
            )
            .is_err()
    );
    assert_eq!(
        guest.0, 1,
        "expired checkout and invalid budget must refuse before invocation"
    );
    let exhaust = granted
        .execute_cli(&fence, budget, &checkouts, &mut guest, 30)
        .expect("guest ran");
    assert_eq!(guest.0, 2);
    let mut request = capture_request(&attempt, ByoaTerminalDisposition::Completed);
    request.exhaust = exhaust;
    let receipt = granted
        .capture_terminal_exhaust(request)
        .expect("capture guest output");
    assert_eq!(receipt.attempt.result_ref, Some(receipt.result_ref));
}

#[test]
fn abort_after_capture_append_rolls_back_artifact_actor_and_attempt_together() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let attempt = dispatch_and_claim(
        &vault,
        &mut dispatcher,
        ByoaConnectorSpec::CliSandbox(cli_spec()),
        "worker",
    );
    let before = custody_snapshot(&vault);
    let outcome: ByoaResult<()> = vault.try_with_write_txn(|wtxn| {
        let receipt = dispatcher.capture_terminal_exhaust_in_txn(
            wtxn,
            capture_request(&attempt, ByoaTerminalDisposition::Abandoned),
        )?;
        assert!(
            read_blob_artifact_head_in_txn(&vault.store, wtxn, &receipt.artifact_id)?.is_some()
        );
        assert_eq!(
            AttemptQueue::new(&vault)
                .get_in_write_txn(wtxn, attempt.id)?
                .expect("staged row")
                .state,
            AttemptState::Abandoned
        );
        Err(invalid("injected failure after append"))
    });
    assert!(outcome.is_err());
    assert_eq!(custody_snapshot(&vault), before);
    let receipt = dispatcher
        .capture_terminal_exhaust(capture_request(
            &attempt,
            ByoaTerminalDisposition::Abandoned,
        ))
        .expect("retry after rollback");
    assert_eq!(receipt.artifact_version, 1);
    assert_eq!(
        vault
            .blob_artifact_versions(&receipt.artifact_id)
            .expect("chain")
            .len(),
        1
    );
}

#[test]
fn old_exhaust_without_retained_fence_is_still_readable() {
    let attempt_id = AttemptId::now();
    let envelope = ByoaExhaustEnvelope {
        schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
        attempt_id: *attempt_id.as_bytes(),
        lease_owner: "worker".to_owned(),
        attempt_count: 1,
        disposition: ByoaTerminalDisposition::Completed,
        exhaust: sample_exhaust(),
    };
    let mut legacy = serde_json::to_value(envelope).expect("fixture");
    let fields = legacy.as_object_mut().expect("envelope object");
    fields.remove("lease_owner");
    fields.remove("attempt_count");
    let bytes = rmp_serde::to_vec_named(&legacy).expect("old envelope");
    assert_eq!(
        decode_byoa_exhaust(&bytes).expect("read legacy exhaust"),
        (
            attempt_id,
            ByoaTerminalDisposition::Completed,
            sample_exhaust()
        )
    );
}

mod successor;
