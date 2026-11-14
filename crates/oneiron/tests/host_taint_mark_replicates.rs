//! Census L6-32 (ARCH-0069 `#exhaust-taint-open`; Engine RULING
//! L6-32-CARRIER = A): a host's taint mark rides the BLOB_ARTIFACT body, the
//! one carrier that replicates. A synced replica reads the mark and exports
//! the artifact redacted, a second mark keeps each secret's lowest
//! generation, and a mark on any other row is refused. An endpoint
//! execution carries its host's receipt (the factory's
//! `ByoEndpointBinding::secret_taint_refs`) into the captured artifact, and
//! a malformed receipt is refused before the backend is called.
//!
//! Public doors only, plus `test_doors::host_taint_replica` for the
//! own-device replay.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::batch::export::{ExportImportRefusal, ImportRefusalReason};
use oneiron::blob_artifact::BlobArtifactBody;
use oneiron::code_sandbox::SandboxCredentialHandle;
use oneiron::dispatch_byoa::{
    BYOA_ATTEMPT_KIND, ByoEndpointBackendFactory, ByoEndpointBinding, ByoEndpointProtocol,
    ByoEndpointSpec, ByoaConnectorSpec, ByoaDispatcher, ByoaEgressLease, ByoaEgressPort, ByoaError,
    ByoaExecutionFence, ByoaResult, ByoaTerminalDisposition, CaptureByoaExhaust, DispatchByoa,
};
use oneiron::error::ArtifactError;
use oneiron::llm::{
    BudgetDenied, BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart, FinishReason,
    LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_lease::SecretTaintRef;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::host_taint_replica::replicate_entities;
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SECRET: &str = "build-token";
const OTHER: &str = "deploy-key";
const AT: TimeRange = TimeRange { start: 10, end: 10 };

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

fn taint(secret_ref: &str, generation: u32) -> SecretTaintRef {
    SecretTaintRef {
        secret_ref: secret_ref.to_owned(),
        generation,
    }
}

/// An artifact put clean, as a build output is before its host marks it.
fn untainted_artifact(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &BlobArtifactBody::new("build.bin", "application/octet-stream"),
        AT,
        10,
    )?;
    Ok(id)
}

#[test]
fn a_host_mark_reaches_a_synced_replica() -> TestResult {
    let (_source_dir, source) = open_vault()?;
    let id = untainted_artifact(&source)?;
    source.mark_artifact_tainted(&id, &[taint(SECRET, 0)])?;
    let marked = source.artifact_taint_refs(&id)?;
    assert_eq!(
        marked,
        vec![taint(SECRET, 0)],
        "the vault that took the mark reads it"
    );

    let (_replica_dir, replica) = open_vault()?;
    replicate_entities(&source, &replica, &[id])?;
    assert_eq!(
        replica.artifact_taint_refs(&id)?,
        marked,
        "the replica reads the host's mark from the replicated artifact row"
    );
    assert!(
        replica.artifact_taint_state(&id)?.is_tainted(),
        "the replica's artifact is not clean"
    );
    let body = replica
        .get_blob_artifact(&id)?
        .ok_or("the replica holds the artifact")?;
    assert_eq!(
        (body.name.as_str(), body.media_type.as_str()),
        ("build.bin", "application/octet-stream"),
        "the mark keeps the body's other keys"
    );
    assert_eq!(body.secret_taint_refs, marked, "the body is the carrier");
    Ok(())
}

#[test]
fn a_replica_exports_a_host_marked_artifact_redacted() -> TestResult {
    let (_source_dir, source) = open_vault()?;
    let id = untainted_artifact(&source)?;
    source.mark_artifact_tainted(&id, &[taint(SECRET, 0)])?;
    let (_replica_dir, replica) = open_vault()?;
    replicate_entities(&source, &replica, &[id])?;

    let bundle: serde_json::Value =
        serde_json::from_slice(&replica.export_entity_bundle_json(&[id])?)?;
    let hex = id.to_hex();
    let row = bundle["entities"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["id"].as_str() == Some(hex.as_str()))
        })
        .ok_or("the replica's bundle carries the artifact row")?;
    assert!(
        row["body"].is_null(),
        "the replica nulls the host-marked artifact's body: {row}"
    );
    assert_eq!(
        bundle["manifest"]["secrets_nulled"]["payloads"],
        serde_json::Value::Bool(true),
        "and its manifest says the payloads are nulled: {}",
        bundle["manifest"]
    );
    Ok(())
}

#[test]
fn a_second_host_mark_keeps_each_secrets_lowest_generation() -> TestResult {
    let (_source_dir, source) = open_vault()?;
    let id = untainted_artifact(&source)?;
    source.mark_artifact_tainted(&id, &[taint(SECRET, 1)])?;
    source.mark_artifact_tainted(&id, &[taint(SECRET, 3), taint(OTHER, 0)])?;
    // The carrier keeps the refs sorted by secret name, as the read does.
    let want = vec![taint(SECRET, 1), taint(OTHER, 0)];
    assert_eq!(
        source.artifact_taint_refs(&id)?,
        want,
        "the marks are a union, and a secret named twice keeps its lowest generation"
    );

    let (_replica_dir, replica) = open_vault()?;
    replicate_entities(&source, &replica, &[id])?;
    assert_eq!(
        replica.artifact_taint_refs(&id)?,
        want,
        "the replica reads the same union"
    );
    Ok(())
}

#[test]
fn a_host_mark_on_a_row_that_is_no_artifact_is_refused() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let person = EntityId::now();
    vault.put_entity(&person, ENTITY_TYPE_PERSON, AT, 10, b"owen")?;
    let absent = EntityId::now();
    for id in [person, absent] {
        assert!(
            vault
                .mark_artifact_tainted(&id, &[taint(SECRET, 0)])
                .is_err(),
            "a host mark rides a blob artifact only: {id:?}"
        );
        assert_eq!(
            vault.artifact_taint_refs(&id)?,
            Vec::<SecretTaintRef>::new(),
            "a refused mark writes nothing: {id:?}"
        );
    }
    Ok(())
}

/// Guard, not a red case: the whole-vault archive carries a host-marked
/// artifact only redacted, and its manifest refuses the row's import as a
/// redacted body, on main (the sidecar) as on this head (the body carrier).
/// A restore of that archive fails on main today (FIX-LIST
/// RESTORE-REFUSES-NULLED-ROW), so the guard reads the archive's manifest.
#[test]
fn a_host_marked_artifact_goes_redacted_in_the_whole_vault_archive() -> TestResult {
    let (_source_dir, source) = open_vault()?;
    let id = untainted_artifact(&source)?;
    source.mark_artifact_tainted(&id, &[taint(SECRET, 0)])?;
    let archive = source.export_whole_vault(true)?;
    let refusals = &archive.manifest().import_refusals;
    assert!(
        refusals.iter().any(|refusal| matches!(
            refusal,
            ExportImportRefusal::Entity {
                entity_id,
                reason: ImportRefusalReason::RedactedBody,
            } if entity_id == &id.to_hex()
        )),
        "the archive carries the host-marked artifact only redacted: {refusals:?}"
    );
    Ok(())
}

struct CountingEndpointBackend {
    calls: AtomicUsize,
}

impl LlmBackend for CountingEndpointBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: "endpoint output".to_owned(),
                        signature: None,
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(BudgetDenied::AdmissionDenied.into())
    }
}

struct EndpointReceiptFactory {
    backend: Arc<CountingEndpointBackend>,
    secret_taint_refs: Vec<SecretTaintRef>,
}

impl ByoEndpointBackendFactory for EndpointReceiptFactory {
    fn resolve_backend(&self, _spec: &ByoEndpointSpec) -> ByoaResult<ByoEndpointBinding> {
        Ok(ByoEndpointBinding {
            backend: self.backend.clone(),
            secret_taint_refs: self.secret_taint_refs.clone(),
        })
    }
}

struct DenyAllEndpointEgress;

impl ByoaEgressPort for DenyAllEndpointEgress {
    fn open(&mut self, profile_ref: &str, _intent_ref: &str) -> ByoaResult<ByoaEgressLease> {
        Err(ByoaError::EgressDenied {
            profile_ref: profile_ref.to_owned(),
            reason: "no egress lease granted".to_owned(),
        })
    }
}

fn receipt_endpoint_spec() -> Result<ByoEndpointSpec, Box<dyn std::error::Error>> {
    Ok(ByoEndpointSpec {
        base_url: "https://endpoint.example.com/v1".to_owned(),
        credential_ref: SandboxCredentialHandle::new("custody://endpoint/access-key")?,
        protocol: ByoEndpointProtocol::OpenAiCompat,
        model_slug_map: BTreeMap::from([("fast".to_owned(), ModelId::new("byo/fast@1")?)]),
    })
}

fn receipt_endpoint_request() -> Result<LlmRequest, Box<dyn std::error::Error>> {
    Ok(LlmRequest {
        model: ModelId::new("byo/fast@1")?,
        envelope: CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::AutoCheck,
            class: CallClass::BestEffort,
            tier: TierPrecedence {
                per_seat: None,
                vault_policy: None,
                purpose_default: None,
                global_default: ModelTierRef("standard".to_owned()),
                seat: None,
            },
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
            host_keyless: false,
            host_paid: false,
            seat_effort: None,
        },
        messages: Vec::new(),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    })
}

fn dispatch_and_claim_receipt_endpoint(
    vault: &Vault,
    dispatcher: &mut ByoaDispatcher<'_, EndpointReceiptFactory, DenyAllEndpointEgress>,
) -> Result<ByoaExecutionFence, Box<dyn std::error::Error>> {
    let outcome = dispatcher.dispatch(DispatchByoa {
        user_login: false,
        connector: ByoaConnectorSpec::Endpoint(receipt_endpoint_spec()?),
        task_ref: None,
        dev_refs: None,
        parent_attempt_id: None,
        run_id: Some("endpoint-receipt-run".to_owned()),
        dedupe_key: None,
        now: 10,
    })?;
    let ClaimOutcome::Claimed(attempt) = AttemptQueue::new(vault).claim_kind(
        BYOA_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "endpoint-worker".to_owned(),
            now: 20,
        },
    )?
    else {
        return Err("the dispatched endpoint must be claimable".into());
    };
    assert_eq!(attempt.id, outcome.status().attempt.id);
    Ok(ByoaExecutionFence {
        attempt_id: attempt.id,
        lease_owner: attempt
            .lease_owner
            .ok_or("the endpoint must have a lease owner")?,
        attempt_count: attempt.attempt_count,
    })
}

fn poll_endpoint_once<T>(future: impl std::future::Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match std::future::Future::poll(future.as_mut(), &mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => panic!("the endpoint backend must complete immediately"),
    }
}

#[test]
fn an_endpoint_execution_carries_its_host_receipt_into_the_capture() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let backend = Arc::new(CountingEndpointBackend {
        calls: AtomicUsize::new(0),
    });
    let mut dispatcher = ByoaDispatcher::new(
        &vault,
        EndpointReceiptFactory {
            backend: backend.clone(),
            secret_taint_refs: vec![taint(SECRET, 2)],
        },
        DenyAllEndpointEgress,
    );
    let fence = dispatch_and_claim_receipt_endpoint(&vault, &mut dispatcher)?;
    let lease = BudgetLease::for_test("endpoint-receipt-budget");
    let exhaust = poll_endpoint_once(dispatcher.execute_endpoint(
        &fence,
        "fast",
        receipt_endpoint_request()?,
        &lease,
    ))?;
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(exhaust.secret_taint_refs, vec![taint(SECRET, 2)]);

    let receipt = dispatcher.capture_terminal_exhaust(CaptureByoaExhaust {
        attempt_id: fence.attempt_id,
        lease_owner: fence.lease_owner,
        attempt_count: fence.attempt_count,
        disposition: ByoaTerminalDisposition::Completed,
        exhaust,
        reason: None,
        now: 30,
    })?;
    let artifact = receipt.artifact_id;
    assert_eq!(
        vault.artifact_taint_refs(&artifact)?,
        vec![taint(SECRET, 2)]
    );

    let (_replica_dir, replica) = open_vault()?;
    replicate_entities(&vault, &replica, &[artifact])?;
    assert_eq!(
        replica.artifact_taint_refs(&artifact)?,
        vec![taint(SECRET, 2)]
    );
    Ok(())
}

#[test]
fn an_endpoint_binding_with_malformed_refs_is_refused() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let backend = Arc::new(CountingEndpointBackend {
        calls: AtomicUsize::new(0),
    });
    let mut dispatcher = ByoaDispatcher::new(
        &vault,
        EndpointReceiptFactory {
            backend: backend.clone(),
            secret_taint_refs: vec![taint(SECRET, 0), taint(SECRET, 1)],
        },
        DenyAllEndpointEgress,
    );
    let fence = dispatch_and_claim_receipt_endpoint(&vault, &mut dispatcher)?;
    let lease = BudgetLease::for_test("endpoint-receipt-budget");
    let result = poll_endpoint_once(dispatcher.execute_endpoint(
        &fence,
        "fast",
        receipt_endpoint_request()?,
        &lease,
    ));
    assert!(matches!(
        result,
        Err(ByoaError::Store(oneiron::Error::Artifact(
            ArtifactError::InvalidAgentDispatchInput(_)
        )))
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
