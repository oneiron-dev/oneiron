#![cfg(oneiron_test_support)]
//! L10-05: the generic job status and result read, canon's
//! `GET /v1/core/jobs/{job_id}` (0002c §6.1.13) over the `vault.runs.job`
//! verb. A job is one attempt row, read by its 32-hex id. The owner reads any
//! job and its result reference, at the route and through the verb alike; an
//! agent reads a job it runs, its error included; a person who runs none of
//! it is refused a job it may not read and an id no row holds alike; a
//! facet-narrowed slip is refused before the door; the owner's unknown id is
//! not found and a malformed one a bad request. Bodies are read as JSON
//! values, so the file compiles where the route does not exist.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test core_job_read`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, DEFAULT_BASE_LOGICAL_ID};
use oneiron::attempt_queue::{
    AttemptResultRef, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt, EnqueueOutcome,
    RetryAttempt, SetAttemptResult,
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{AttemptQueue, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The verb the route serves, at its facade path.
const VERB_PATH: &str = "/v1/core/facade/vault.runs.job";
/// A queue kind no pump serves, so nothing but the fixture moves its row.
const JOB_KIND: &str = "test.core_job";
const JOB_RUN: &str = "run-core-job";
/// The reference the plain job's producer writes as its result.
const JOB_RESULT: &str = "artifact:core-job:v1";
const LEASE_OWNER: &str = "core-job-read";
const AGENT_ERROR: &str = "the agent's own words about its failure";
const SCOPE_REFUSAL: &str = "request does not have the required scope";

/// A holder's own slip and the key that proves it.
struct Credential {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// Who signs a request: the self-hosted root (the owner), or a holder.
enum Caller<'a> {
    Owner(&'a HostSlipIssuer, &'a CapabilitySlip),
    Holder(&'a Credential),
}

/// A serving install with its owner, whose queue holds one settled plain
/// job with a result reference.
struct OwnerHost {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    job: String,
    _dir: tempfile::TempDir,
}

impl OwnerHost {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (_owner, _owner_proof) = embedded_owner(&vault)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let job = settled_job(&vault)?;
        let server = SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("core-job-read".into()),
                ..Default::default()
            },
        )?;
        Ok(Self {
            app: build_app(Arc::new(server)),
            vault,
            issuer,
            root,
            job,
            _dir: dir,
        })
    }

    fn owner(&self) -> Caller<'_> {
        Caller::Owner(&self.issuer, &self.root)
    }
}

/// A vault whose default agent ran one TASK's try, which failed with the
/// agent's own words and was retried; the agent's plain and facet-narrowed
/// slips, and a person's slip who runs none of it.
struct AgentRun {
    app: Router,
    vault: Arc<Vault>,
    task_ref: EntityId,
    job: String,
    agent: Credential,
    narrow: Credential,
    stranger: Credential,
    _dir: tempfile::TempDir,
}

impl AgentRun {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        let (agent, _) = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
            .ok_or("the default agent is seeded")?;
        // The first-party actor the default policy manifest grants an Auto
        // ceiling, so its TASK create takes direct effect.
        let creator = person(&vault, EntityId::from_bytes([0xE1; 16])?)?;
        let receipt = vault.memory(creator, EdgeActorClass::Agent).tasks_create(
            &TaskCreateSpec::new(
                rmpv::Value::Nil,
                Some("read the job".to_owned()),
                Some(creator),
                None,
            )
            .with_assignee(TaskAssignee::AgentDef {
                agent_def_ref: agent,
            }),
        )?;
        let task_ref = receipt.task_ref.ok_or("the TASK is minted")?;
        let Some(TaskRouteOutcome::AgentDispatch { attempt_ref, .. }) = receipt.route else {
            return Err("an agent-definition assignee routes to an agent dispatch".into());
        };
        let queue = AttemptQueue::new(&vault);
        let mut claimed = None;
        for _ in 0..32 {
            let ClaimOutcome::Claimed(row) = queue.claim_kind(
                DREAMER_RUNNER_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: LEASE_OWNER.to_owned(),
                    now: u64::MAX,
                },
            )?
            else {
                break;
            };
            if row.id == attempt_ref {
                claimed = Some(row);
                break;
            }
        }
        let claimed = claimed.ok_or("the TASK's attempt is ready to claim")?;
        let claimed_at = claimed.claimed_at.ok_or("a claim records its time")?;
        queue.retry(RetryAttempt {
            id: claimed.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: claimed.attempt_count,
            backoff_until: claimed_at + 3_600_000,
            last_error: Some(AGENT_ERROR.to_owned()),
            now: claimed_at,
        })?;

        let work = EntityId::now();
        vault.put_entity(
            &work,
            oneiron::registry::ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"work",
        )?;
        let facets = ScopeAxis::Some(BTreeSet::from([ScopeId(work)]));

        // HTTP trusts the logged issuer of each mint, not auth_secret.
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-core-job-read")?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let mint =
            |holder: EntityId, class: &str, seed: u8, facets: Option<&ScopeAxis<ScopeId>>| {
                let key = SigningKey::from_bytes(&[seed; 32]);
                let mut claims = root.claims.clone();
                claims.parent_id = None;
                claims.slip_id = [seed; 32];
                claims.holder_ref = holder.to_hex();
                claims.binding_key = key.verifying_key().to_bytes();
                claims.actor_class = Some(class.to_owned());
                claims.scope = Scope::top();
                claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
                if let Some(facets) = facets {
                    claims.scope.facets = facets.clone();
                }
                Ok::<_, Box<dyn std::error::Error>>(Credential {
                    slip: vault.mint_capability_slip(&issuer, claims)?,
                    key,
                })
            };
        let agent_credential = mint(agent, "agent", 0x65, None)?;
        let narrow = mint(agent, "agent", 0x66, Some(&facets))?;
        let stranger = person(&vault, EntityId::now())?;
        let stranger = mint(stranger, "human", 0x67, None)?;
        let server = Arc::new(SyncServer::new(vault.clone(), SyncServerConfig::default())?);
        Ok(Self {
            app: build_app(server),
            vault,
            task_ref,
            job: hex(attempt_ref.as_bytes()),
            agent: agent_credential,
            narrow,
            stranger,
            _dir: dir,
        })
    }
}

fn person(vault: &Vault, id: EntityId) -> TestResult<EntityId> {
    vault.put_entity(
        &id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a person of the vault",
    )?;
    Ok(id)
}

/// One plain job run to its end: enqueued, claimed, its result reference
/// set and completed. Its id as 32 hex.
fn settled_job(vault: &Vault) -> TestResult<String> {
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(queued) = queue.enqueue(EnqueueAttempt {
        kind: JOB_KIND.to_owned(),
        payload: b"{}".to_vec(),
        dedupe_key: None,
        run_id: Some(JOB_RUN.to_owned()),
        now: vault.now_recorded_at(),
    })?
    else {
        return Err("a job with no dedupe key is enqueued fresh".into());
    };
    let ClaimOutcome::Claimed(claimed) = queue.claim_kind(
        JOB_KIND,
        ClaimAttempt {
            lease_owner: LEASE_OWNER.to_owned(),
            now: u64::MAX,
        },
    )?
    else {
        return Err("the job is ready to claim".into());
    };
    assert_eq!(claimed.id, queued.id, "the claim takes the job");
    queue.set_result(SetAttemptResult {
        id: claimed.id,
        lease_owner: LEASE_OWNER.to_owned(),
        attempt_count: claimed.attempt_count,
        result_ref: AttemptResultRef::new(JOB_RESULT)?,
        now: vault.now_recorded_at(),
    })?;
    queue.complete(CompleteAttempt {
        id: claimed.id,
        lease_owner: LEASE_OWNER.to_owned(),
        attempt_count: claimed.attempt_count,
        now: vault.now_recorded_at(),
    })?;
    Ok(hex(claimed.id.as_bytes()))
}

/// One request as `caller`, signed for this instant: a GET of `path`, or a
/// POST of `body` to it.
async fn send(
    app: &Router,
    vault: &Vault,
    caller: &Caller<'_>,
    path: &str,
    body: Option<&Value>,
) -> TestResult<(u16, Value)> {
    let timestamp = vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = holder_proof_challenge(timestamp, &nonce);
    let (slip, signature) = match caller {
        Caller::Owner(issuer, root) => (*root, issuer.binding_proof(root, &challenge)?),
        Caller::Holder(credential) => (
            &credential.slip,
            credential
                .key
                .sign(&credential.slip.binding_transcript(&challenge)?)
                .to_bytes()
                .to_vec(),
        ),
    };
    let binding = json!({
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": hex(&signature),
    });
    let request = Request::builder()
        .method(if body.is_some() { "POST" } else { "GET" })
        .uri(path)
        .header("authorization", format!("Bearer {}", slip.to_token()?))
        .header("x-oneiron-binding", binding.to_string());
    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?,
        None => request.body(Body::empty())?,
    };
    let response = app.clone().oneshot(request).await?;
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    Ok((status, body))
}

fn job_path(job: &str) -> String {
    format!("/v1/core/jobs/{job}")
}

/// A well-formed job id no row holds.
fn unknown_job() -> String {
    EntityId::now().to_hex()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn owner_reads_a_settled_job_and_its_result_reference() -> TestResult {
    on_engine_stack(owner_reads_the_settled_job)
}

async fn owner_reads_the_settled_job() -> TestResult {
    let host = OwnerHost::new()?;
    let owner = host.owner();
    let (status, read) = send(&host.app, &host.vault, &owner, &job_path(&host.job), None).await?;
    assert_eq!(status, 200, "the owner reads the job: {read}");
    let job = &read["job"];
    assert_eq!(job["branch"], host.job.as_str(), "{read}");
    assert_eq!(job["state"], "Completed", "{read}");
    assert_eq!(job["worker_kind"], JOB_KIND, "{read}");
    assert_eq!(job["run_id"], JOB_RUN, "{read}");
    assert!(
        job["task_ref"].is_null(),
        "a plain job realizes no TASK: {read}"
    );
    assert_eq!(
        job["result_ref"], JOB_RESULT,
        "the result is the reference the producer wrote: {read}"
    );
    let created = job["created_at"]
        .as_u64()
        .ok_or("the job names when it was created")?;
    let settled = job["settled_at"]
        .as_u64()
        .ok_or("a settled job names when it settled")?;
    assert!(settled >= created, "{read}");

    let (status, verb) = send(
        &host.app,
        &host.vault,
        &owner,
        VERB_PATH,
        Some(&json!({ "job": host.job })),
    )
    .await?;
    assert_eq!(
        status, 200,
        "the owner reads the job through its verb: {verb}"
    );
    assert_eq!(verb, read, "the route and the verb answer one read");
    Ok(())
}

#[test]
fn agent_reads_its_own_job_with_its_error() -> TestResult {
    on_engine_stack(agent_reads_its_own_job)
}

async fn agent_reads_its_own_job() -> TestResult {
    let run = AgentRun::new()?;
    let agent = Caller::Holder(&run.agent);
    let (status, read) = send(&run.app, &run.vault, &agent, &job_path(&run.job), None).await?;
    assert_eq!(status, 200, "the agent reads the job it runs: {read}");
    let job = &read["job"];
    assert_eq!(job["branch"], run.job.as_str(), "{read}");
    assert_eq!(
        job["last_error"], AGENT_ERROR,
        "the agent reads its own words: {read}"
    );
    assert_eq!(job["task_ref"], run.task_ref.to_hex().as_str(), "{read}");
    assert_eq!(
        job["worker_kind"], AGENT_DISPATCH_ATTEMPT_TYPE,
        "a runner row names its attempt type as the run tree does: {read}"
    );
    Ok(())
}

#[test]
fn stranger_is_refused_a_job_it_does_not_run() -> TestResult {
    on_engine_stack(stranger_is_refused)
}

async fn stranger_is_refused() -> TestResult {
    let run = AgentRun::new()?;
    let stranger = Caller::Holder(&run.stranger);
    let (status, known) = send(&run.app, &run.vault, &stranger, &job_path(&run.job), None).await?;
    assert_eq!(
        status, 403,
        "a person who runs none of it is refused: {known}"
    );
    assert_eq!(known["error"]["code"], "FORBIDDEN", "{known}");
    assert!(
        known["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("vault.runs.job")),
        "{known}"
    );
    assert!(
        !known.to_string().contains(AGENT_ERROR),
        "the refusal serves nothing of the job: {known}"
    );
    let (status, unknown) = send(
        &run.app,
        &run.vault,
        &stranger,
        &job_path(&unknown_job()),
        None,
    )
    .await?;
    assert_eq!(
        status, 403,
        "an id no row holds is refused alike: {unknown}"
    );
    assert_eq!(
        (&unknown["error"]["code"], &unknown["error"]["message"]),
        (&known["error"]["code"], &known["error"]["message"]),
        "a refusal does not tell which jobs exist"
    );
    Ok(())
}

#[test]
fn narrowed_slip_is_refused_the_job() -> TestResult {
    on_engine_stack(narrowed_slip_is_refused)
}

async fn narrowed_slip_is_refused() -> TestResult {
    let run = AgentRun::new()?;
    let narrow = Caller::Holder(&run.narrow);
    let (status, body) = send(&run.app, &run.vault, &narrow, &job_path(&run.job), None).await?;
    assert_eq!(
        status, 403,
        "a facet-limited slip was served its own job: {body}"
    );
    assert_eq!(body["error"]["code"], "FORBIDDEN", "{body}");
    assert_eq!(body["error"]["message"], SCOPE_REFUSAL, "{body}");
    Ok(())
}

#[test]
fn unknown_and_malformed_job_ids() -> TestResult {
    on_engine_stack(unknown_and_malformed_ids)
}

async fn unknown_and_malformed_ids() -> TestResult {
    let host = OwnerHost::new()?;
    let owner = host.owner();
    let unknown = unknown_job();
    let (status, body) = send(&host.app, &host.vault, &owner, &job_path(&unknown), None).await?;
    assert_eq!(status, 404, "no row holds the id: {body}");
    assert_eq!(body["error"]["code"], "NOT_FOUND", "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains(&unknown)),
        "the refusal names the job: {body}"
    );
    let (status, body) = send(&host.app, &host.vault, &owner, &job_path("not-hex"), None).await?;
    assert_eq!(status, 400, "a job id is 32 hex: {body}");
    assert_eq!(body["error"]["code"], "BAD_REQUEST", "{body}");
    Ok(())
}
