#![cfg(oneiron_test_support)]
//! The HTTP facade refuses facet-limited credentials before reading run
//! branches or spend leases, while an unrestricted run actor reads its branches.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test run_reader_record_scope`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::agent_dispatch::DEFAULT_BASE_LOGICAL_ID;
use oneiron::agent_dispatch::budget_doors::SpendScopeRequest;
use oneiron::attempt_queue::{ClaimAttempt, ClaimOutcome, RetryAttempt};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof_challenge};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::task_verb::run_doors::{RunBranchesRequest, RunBranchesView};
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::{AttemptQueue, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::Value;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const AGENT_ERROR: &str = "the agent's own words about its failure";
const SCOPE_REFUSAL: &str = "request does not have the required scope";

struct Credential {
    slip: CapabilitySlip,
    key: SigningKey,
}

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    task_ref: EntityId,
    branch: String,
    plain: Credential,
    narrow: Credential,
    _dir: tempfile::TempDir,
}

impl Fixture {
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
        let creator = EntityId::from_bytes([0xE1; 16])?;
        vault.put_entity(
            &creator,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a person of the shared vault",
        )?;
        let receipt = vault.memory(creator, EdgeActorClass::Agent).tasks_create(
            &TaskCreateSpec::new(
                rmpv::Value::Nil,
                Some("read the run tree".to_owned()),
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
                    lease_owner: "run-tree-reader".to_owned(),
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
            lease_owner: "run-tree-reader".to_owned(),
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
        assert!(!vault.row_in_facets(&task_ref, &facets)?);

        // HTTP trusts the logged issuer of each mint, not auth_secret. Root
        // this fixture explicitly; the app needs no retained signing key.
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-run-reader-record-scope")?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let key = SigningKey::from_bytes(&[0x65; 32]);
        let mut claims = root.claims;
        claims.parent_id = None;
        claims.holder_ref = agent.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("agent".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        claims.slip_id = [0x65; 32];
        let plain = Credential {
            slip: vault.mint_capability_slip(&issuer, claims.clone())?,
            key: key.clone(),
        };
        claims.slip_id = [0x66; 32];
        claims.scope.facets = facets;
        let narrow = Credential {
            slip: vault.mint_capability_slip(&issuer, claims)?,
            key,
        };
        let server = Arc::new(SyncServer::new(vault.clone(), SyncServerConfig::default())?);
        Ok(Self {
            app: build_app(server),
            vault,
            task_ref,
            branch: hex(attempt_ref.as_bytes()),
            plain,
            narrow,
            _dir: dir,
        })
    }

    async fn facade(
        &self,
        credential: &Credential,
        verb: &str,
        input: Value,
    ) -> TestResult<(u16, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = credential
            .key
            .sign(&credential.slip.binding_transcript(&challenge)?)
            .to_bytes();
        let binding = serde_json::json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header(
                "authorization",
                format!("Bearer {}", credential.slip.to_token()?),
            )
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        Ok((status, serde_json::from_slice(&body)?))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn assert_record_scope_refusal(status: u16, body: &Value) {
    assert_eq!(
        status, 403,
        "expected a record-scope refusal: status={status}, body={body}"
    );
    assert_eq!(
        body["error"]["code"], "FORBIDDEN",
        "status={status}, body={body}"
    );
    // The facade drops ApiError.details (including required_scope), but
    // preserves this guard's exact message, unlike an engine door refusal.
    assert_eq!(
        body["error"]["message"], SCOPE_REFUSAL,
        "status={status}, body={body}"
    );
}

#[test]
fn a_narrowed_credential_is_refused_the_run_branches() -> TestResult {
    on_engine_stack(narrowed_credential_and_the_run_branches)
}

async fn narrowed_credential_and_the_run_branches() -> TestResult {
    let fixture = Fixture::new()?;
    let input = serde_json::to_value(RunBranchesRequest {
        task_ref: fixture.task_ref,
    })?;
    let (status, body) = fixture
        .facade(&fixture.plain, "vault.runs.branches.get", input.clone())
        .await?;
    assert_eq!(
        status, 200,
        "the plain credential reaches the branches: {body}"
    );
    let branches: RunBranchesView = serde_json::from_value(body)?;
    assert_eq!(branches.branches.len(), 2);
    let retried = branches
        .branches
        .iter()
        .find(|branch| branch.branch == fixture.branch)
        .ok_or("the response holds the retried try")?;
    assert_eq!(retried.last_error.as_deref(), Some(AGENT_ERROR));

    let (status, body) = fixture
        .facade(&fixture.narrow, "vault.runs.branches.get", input)
        .await?;
    assert_eq!(
        status, 403,
        "a facet-limited credential was served the run's branches: {body}"
    );
    assert_record_scope_refusal(status, &body);
    Ok(())
}

#[test]
fn a_narrowed_credential_is_refused_the_spend_lease() -> TestResult {
    on_engine_stack(narrowed_credential_and_the_spend_lease)
}

async fn narrowed_credential_and_the_spend_lease() -> TestResult {
    let fixture = Fixture::new()?;
    // A TASK id is well-formed hex but names no attempt's spend scope. The
    // old guard reaches the door's own-scope refusal, not a record-scope one.
    let input = serde_json::to_value(SpendScopeRequest {
        scope: fixture.task_ref.to_hex(),
    })?;
    let (status, body) = fixture
        .facade(&fixture.narrow, "vault.budgets.lease", input)
        .await?;
    assert_record_scope_refusal(status, &body);
    Ok(())
}
