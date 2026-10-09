use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;
use crate::attempt_queue::{
    AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use crate::error::ArtifactError;
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
        user_login: false,
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
            user_login: false,
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
fn capture_refuses_an_empty_exhaust_and_an_unclaimed_row() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let outcome = dispatcher
        .dispatch(DispatchByoa {
            user_login: false,
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
            ByoaError::Store(Error::Artifact(
                ArtifactError::InvalidAttemptQueueTransition {
                    action: "abandon",
                    state: "queued",
                }
            ))
        ),
        "capture must reach the queue fence, not fail on a missing blob writer: {refused:?}"
    );
    assert_eq!(custody_snapshot(&vault), before);
}

#[test]
fn a_payload_from_an_unknown_schema_version_is_refused() {
    let payload = encode_byoa_attempt_payload(&ByoaAttemptPayload {
        user_login: false,
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

/// Every custody row. The store clock's floors are not custody: any committed
/// write moves them once the wall clock crosses a second.
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
            .filter(|(key, _)| {
                key.as_slice() != crate::ports::CLOCK_FLOOR
                    && key.as_slice() != crate::ports::ID_FLOOR
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
            user_login: false,
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
                    user_login: false,
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
        user_login: false,
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
            user_login: false,
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
            ByoaError::Store(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                ERR_ARTIFACT_COLLISION
            )))
        ));
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
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            purpose: CallPurpose::AutoCheck,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AutoCheck,
                ModelTierRef("standard".into()),
            ),
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

mod successor;

#[test]
fn user_login_is_refused_before_cloud_dispatch_but_allowed_locally() {
    let mut config = VaultConfig::device();
    config.privacy = crate::config::VaultPrivacyConfig {
        posture: crate::config::HostingPrivacyPosture::Hosted,
        data_key_custody: crate::config::VaultDataKeyCustody::HostManagedKms {
            key_ref: "test-kms".into(),
        },
    };
    let (_cloud_dir, cloud) = crate::test_util::open_test_vault_with(config);
    let (_local_dir, local) = open_vault();
    let request = || DispatchByoa {
        user_login: true,
        connector: ByoaConnectorSpec::CliSandbox(cli_spec()),
        task_ref: None,
        parent_attempt_id: None,
        run_id: None,
        dedupe_key: None,
        now: 10,
    };
    assert!(matches!(
        dispatcher(&cloud).dispatch(request()),
        Err(ByoaError::CloudLoginRefused)
    ));
    assert!(matches!(
        dispatcher(&local).dispatch(request()),
        Ok(ByoaDispatchOutcome::Dispatched(_))
    ));
}
