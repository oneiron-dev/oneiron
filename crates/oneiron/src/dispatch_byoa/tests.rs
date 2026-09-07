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

    // Attaching a result does not settle the row; the worker still does.
    assert_eq!(second.attempt.state, AttemptState::Leased);
    let CompleteOutcome::Completed(completed) = AttemptQueue::new(&vault)
        .complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "capture-worker".to_owned(),
            attempt_count: attempt.attempt_count,
            now: 32,
        })
        .expect("complete")
    else {
        panic!("expected a fresh completion");
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
