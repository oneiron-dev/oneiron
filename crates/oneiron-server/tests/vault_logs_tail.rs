//! `vault.jobs.logs.tail` on the issuer (pass 34, 7.2 and 14.2; row Q3; Q3-2-WAIT = C): an
//! attempt's log is read on its machine by byte offset, by the attempt's requester or the owner
//! only, and a call with `wait_ms` answers when bytes arrive, when the stream ends, or when the
//! wait passes. Its reply is never kept: a same-id retry finds the call's admission intent
//! settled and is refused with none of the first ask's bytes, and a new read asks the machine
//! again.
//!
//! The machine is a scripted node client behind the `gpu_backend` test door; the attempt is an
//! agent's GPU job on the fake offer with the dispatch row a vault machine's issuer writes. The
//! verb runs over the real facade route.
//!
//! Red: at the base (#10462's head a859a9ec) plus this file alone, the target does not build (no
//! `oneiron::work_order::LogsTail`, no `use_job_nodes` door) and the facade has no
//! `vault.jobs.logs.tail` row. The same-id retry test is red with `LOGS_TAIL_VERB` taken out of
//! `invocations::UNKEPT_REPLY_VERBS` (review round 1 of #10466): the retry is answered the first
//! ask's kept bytes.
//!
//! Run on the fleet, not on a workstation:
//! ```sh
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test vault_logs_tail
//! ```
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::gpu_job::{
    GpuConnectorError, GpuJobConnector, GpuJobSignal, GpuJobSpec, GpuResourceRef,
    GpuResourceStatus, GpuTermination,
};
use oneiron::job_dispatch::{DispatchPhase, JobDispatch};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND};
use oneiron::work_order::{LOGS_TAIL_VERB, LogsTail, LogsTailTruncation};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::gpu_execution_node::issuer::{JobNodeClient, NodeCallError};
use oneiron_server::gpu_execution_node::wire::{
    JobAnswer, JobRequest, JobStatusAnswer, JobStatusRequest, LogStream, LogTail, LogTailRequest,
};
use oneiron_server::test_doors::gpu_backend::{
    gpu_jobs_section, grant_gpu_allocation, register_gpu_backend, use_job_nodes,
};
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const GPU_QUOTE: &str = "vault.gpu.jobs.quote";
const GPU_START: &str = "vault.gpu.jobs.start";
const MAXIMUM_SECS: u64 = 100;
const GPU_JOBS: &str = r#"
[offers.h100-test]
class = "h100"
provider = "example-cloud"
region = "test-region"
backend = "fake"
price_per_second = 2
cost_unit = "credit-micros"
catalog_revision = "gpu-prices-1"
startup_secs = 0
teardown_secs = 0
rounding_secs = 1
"#;

/// The offer's provider: it starts every job and never ends one.
struct FakeGpu;

impl GpuJobConnector for FakeGpu {
    fn create(&self, key: &str, _: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        Ok(GpuResourceRef(format!("resource-{key}")))
    }

    fn find(&self, _: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        Ok(None)
    }

    fn status(&self, _: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        Ok(GpuResourceStatus::Pending)
    }

    fn signal(&self, _: &GpuResourceRef, _: GpuJobSignal) -> Result<(), GpuConnectorError> {
        Ok(())
    }

    fn terminate(&self, _: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        Ok(GpuTermination::Confirmed { billed_secs: 0 })
    }
}

/// One attempt's stdout on the scripted machine, and every `Tail` it was asked.
#[derive(Default)]
struct LogScript {
    stdout: Vec<u8>,
    ended: bool,
    /// Bytes the workload writes just before the `Tail` with this index (0-based) is read.
    writes_before: Option<(usize, Vec<u8>)>,
    tails: Vec<(EntityId, LogTailRequest)>,
}

/// A node client that answers `Tail` from [`LogScript`] and nothing else.
#[derive(Default)]
struct ScriptedMachine(Mutex<LogScript>);

impl ScriptedMachine {
    fn script(&self) -> MutexGuard<'_, LogScript> {
        self.0.lock().expect("log script")
    }

    fn tails(&self) -> usize {
        self.script().tails.len()
    }
}

fn only_tail() -> NodeCallError {
    NodeCallError::Unreachable {
        reason: "the scripted machine answers only Tail".to_owned(),
    }
}

impl JobNodeClient for ScriptedMachine {
    fn job(&self, _: EntityId, _: &JobRequest) -> Result<JobAnswer, NodeCallError> {
        Err(only_tail())
    }

    fn job_status(
        &self,
        node: EntityId,
        request: &JobStatusRequest,
    ) -> Result<JobStatusAnswer, NodeCallError> {
        let JobStatusRequest::Tail(tail) = request else {
            return Err(only_tail());
        };
        let mut script = self.script();
        if script
            .writes_before
            .as_ref()
            .is_some_and(|(at, _)| *at == script.tails.len())
            && let Some((_, bytes)) = script.writes_before.take()
        {
            script.stdout.extend(bytes);
        }
        script.tails.push((node, tail.clone()));
        let len = u64::try_from(script.stdout.len()).expect("log length");
        let from = tail.offset.min(len);
        let to = from.saturating_add(u64::from(tail.max)).min(len);
        let bytes = script.stdout
            [usize::try_from(from).expect("offset")..usize::try_from(to).expect("offset")]
            .to_vec();
        Ok(JobStatusAnswer::Tail(LogTail {
            bytes,
            next_offset: to,
            ended: script.ended && to == len,
            truncated: None,
        }))
    }
}

struct Agent {
    principal: EntityId,
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: Arc<HostSlipIssuer>,
    owner_slip: CapabilitySlip,
    owner_token: String,
    machine: Arc<ScriptedMachine>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("logs-tail-fixture".into()),
                gpu_jobs: gpu_jobs_section(GPU_JOBS).expect("the fake offer"),
                ..Default::default()
            },
        )
        .expect("server"),
    );
    register_gpu_backend(&server, "fake", Arc::new(FakeGpu));
    grant_gpu_allocation(&server, 1_000_000, "credit-micros").expect("host allocation");
    let machine = Arc::new(ScriptedMachine::default());
    assert!(
        use_job_nodes(&server, Arc::clone(&machine) as Arc<dyn JobNodeClient>),
        "the server calls machines through the script"
    );
    let issuer = Arc::new(vault.load_host_slip_issuer().expect("host slip issuer"));
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    vault.hold_checkpoint_root_signer(issuer.clone());
    Fixture {
        _dir: dir,
        vault,
        app: build_app(server),
        issuer,
        owner_slip,
        owner_token,
        machine,
    }
}

impl Fixture {
    fn pair_agent(&self, name: &str, seed: u8) -> Agent {
        let principal = self
            .vault
            .ensure_agent_principal(name)
            .expect("agent principal");
        let holder = SigningKey::from_bytes(&[seed; 32]);
        let key = holder.verifying_key().to_bytes();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let holder_ref = principal.to_hex();
        let link = self
            .vault
            .issue_pairing_link_for_principal(
                &self.issuer,
                scope,
                3600,
                PairingPrincipal {
                    holder_ref: Some(holder_ref.clone()),
                    actor_class: Some("agent".to_owned()),
                    ..Default::default()
                },
            )
            .expect("pairing link");
        let transcript =
            pairing_binding_transcript(&link.code, &key, &holder_ref).expect("pairing transcript");
        let slip = self
            .vault
            .redeem_pairing_link(
                &self.issuer,
                &link.code,
                &holder_ref,
                key,
                &holder.sign(&transcript).to_bytes(),
            )
            .expect("redeem agent pairing");
        let token = slip.to_token().expect("agent token");
        Agent {
            principal,
            holder,
            slip,
            token,
        }
    }

    async fn post(
        &self,
        verb: &str,
        token: &str,
        body: Value,
        invocation: Option<&str>,
        sign: impl FnOnce(&[u8]) -> String,
    ) -> (StatusCode, Value) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = sign(challenge.as_bytes());
        let mut request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json");
        if let Some(invocation) = invocation {
            request = request.header("x-oneiron-invocation", invocation);
        }
        let request = request
            .body(Body::from(body.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("facade body");
        let body = serde_json::from_slice(&bytes).expect("facade JSON");
        (status, body)
    }

    async fn as_owner(&self, verb: &str, body: Value) -> (StatusCode, Value) {
        self.post(verb, &self.owner_token, body, None, |challenge| {
            hex(&self
                .issuer
                .binding_proof(&self.owner_slip, challenge)
                .expect("owner holder proof"))
        })
        .await
    }

    async fn as_agent(&self, agent: &Agent, verb: &str, body: Value) -> (StatusCode, Value) {
        self.as_agent_under(agent, verb, body, None).await
    }

    /// `agent` calls `verb`, naming `invocation` in `x-oneiron-invocation` when given.
    async fn as_agent_under(
        &self,
        agent: &Agent,
        verb: &str,
        body: Value,
        invocation: Option<&str>,
    ) -> (StatusCode, Value) {
        self.post(verb, &agent.token, body, invocation, |challenge| {
            let transcript = agent
                .slip
                .binding_transcript(challenge)
                .expect("agent binding transcript");
            hex(&agent.holder.sign(&transcript).to_bytes())
        })
        .await
    }

    async fn mint(&self, agent: &Agent, verbs: &[&str]) -> EntityId {
        let verbs: Vec<&str> = std::iter::once("read")
            .chain(verbs.iter().copied())
            .collect();
        let body = ok(self
            .as_owner(
                "vault.agents.grants.mint",
                json!({
                    "agent": agent.principal,
                    "authority_scope": {
                        "worlds": {"kind": "all"},
                        "facets": {"kind": "all"},
                        "bands": {"kind": "all"},
                        "audience": {"kind": "all"},
                        "verbs": {"kind": "some", "values": verbs},
                        "sensitivity": {"kind": "at_most", "value": "restricted"},
                    },
                }),
            )
            .await);
        assert_eq!(body["grant"]["confers"], true, "{body}");
        serde_json::from_value(body["grant"]["grant_ref"].clone()).expect("minted Grant id")
    }

    /// `agent` starts a GPU job on the fake offer under `grant`, and the issuer's dispatch row
    /// sends its one chunk to `machine`: the attempt's key.
    async fn attempt_on(&self, agent: &Agent, grant: EntityId, machine: EntityId) -> String {
        let allowed = ok(self
            .as_owner(
                "vault.gpu.jobs.allow",
                json!({"grant": grant, "maximum_secs": MAXIMUM_SECS}),
            )
            .await);
        assert_eq!(allowed["maximum_secs"], MAXIMUM_SECS, "{allowed}");
        let quote = ok(self
            .as_agent(
                agent,
                GPU_QUOTE,
                json!({
                    "offer": "h100-test",
                    "job_type": "fine-tune",
                    "image": "registry.example.com/trainer@sha256:00",
                    "maximum_secs": MAXIMUM_SECS,
                    "inputs": {},
                    "resume_job": null,
                }),
            )
            .await);
        let started = ok(self
            .as_agent(agent, GPU_START, json!({"quote": quote, "resume": false}))
            .await);
        let job: EntityId = serde_json::from_value(started["job"].clone()).expect("job id");
        let row = self
            .vault
            .gpu_job(&job)
            .expect("job read")
            .expect("job row");
        assert_eq!(row.started_by, Some(agent.principal));
        let key = row.chunk().expect("one chunk").idempotency_key.clone();
        let now_ms = self.vault.now_recorded_at();
        self.vault
            .insert_job_dispatch(JobDispatch {
                key: key.clone(),
                job,
                chunk: 0,
                workload: "a".repeat(64),
                machine,
                submit: Vec::new(),
                issued_at_ms: now_ms,
                not_after_ms: now_ms + 60_000,
                phase: DispatchPhase::Submitted,
                held: None,
                sent_boot: None,
                closed: None,
                history_lost_at_ms: None,
            })
            .expect("dispatch row");
        key
    }
}

fn ok((status, body): (StatusCode, Value)) -> Value {
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

fn tail(reply: (StatusCode, Value)) -> LogsTail {
    serde_json::from_value(ok(reply)).expect("logs tail answer")
}

fn stdout_from(key: &str, offset: u64) -> Value {
    json!({"attempt": key, "stream": "stdout", "offset": offset})
}

#[test]
fn a_caller_who_is_neither_the_requester_nor_the_owner_reads_no_log() {
    run_on_engine_stack("logs-tail-readers", || async {
        let fixture = setup();
        let requester = fixture.pair_agent("log-requester", 0x71);
        let other = fixture.pair_agent("log-reader", 0x72);
        let unnamed = fixture.pair_agent("log-unnamed", 0x73);
        let grant = fixture
            .mint(&requester, &[GPU_QUOTE, GPU_START, LOGS_TAIL_VERB])
            .await;
        fixture.mint(&other, &[LOGS_TAIL_VERB]).await;
        fixture.mint(&unnamed, &[GPU_QUOTE]).await;
        let machine = EntityId::now();
        let key = fixture.attempt_on(&requester, grant, machine).await;
        fixture.machine.script().stdout = b"step 1 of 3\n".to_vec();

        let by_requester = tail(
            fixture
                .as_agent(&requester, LOGS_TAIL_VERB, stdout_from(&key, 0))
                .await,
        );
        assert_eq!(by_requester.bytes, "step 1 of 3\n");
        assert_eq!(by_requester.next_offset, 12);
        assert!(!by_requester.ended);
        assert_eq!(by_requester.truncated, None);
        let by_owner = tail(fixture.as_owner(LOGS_TAIL_VERB, stdout_from(&key, 0)).await);
        assert_eq!(by_owner, by_requester);
        {
            let script = fixture.machine.script();
            assert_eq!(script.tails.len(), 2);
            for (node, asked) in &script.tails {
                assert_eq!(*node, machine, "the read goes to the attempt's machine");
                assert_eq!(asked.key, key);
                assert_eq!(asked.stream, LogStream::Stdout);
                assert_eq!(asked.offset, 0);
            }
        }

        let (other_status, refused) = fixture
            .as_agent(&other, LOGS_TAIL_VERB, stdout_from(&key, 0))
            .await;
        let (missing_status, missing) = fixture
            .as_agent(&other, LOGS_TAIL_VERB, stdout_from(&"f".repeat(32), 0))
            .await;
        assert_eq!(other_status, StatusCode::NOT_FOUND, "{refused}");
        assert_eq!(refused["error"]["code"], MEMORY_CODE_NOT_FOUND, "{refused}");
        assert_eq!(missing_status, other_status, "{missing}");
        // Per-call request and receipt ids can differ, but the refusal cannot.
        for field in ["code", "message", "suggestions", "reasonCodes"] {
            assert_eq!(
                refused["error"][field], missing["error"][field],
                "{field}: {refused} vs {missing}"
            );
        }
        let (status, forbidden) = fixture
            .as_agent(&unnamed, LOGS_TAIL_VERB, stdout_from(&key, 0))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{forbidden}");
        assert_eq!(
            forbidden["error"]["code"], MEMORY_CODE_FORBIDDEN,
            "{forbidden}"
        );
        assert_eq!(
            fixture.machine.tails(),
            2,
            "a caller who may not read the log makes no call to the machine"
        );
    });
}

#[test]
fn a_waiting_tail_answers_when_bytes_arrive_or_the_stream_ends_and_an_unwaited_one_at_once() {
    run_on_engine_stack("logs-tail-wait", || async {
        let fixture = setup();
        let requester = fixture.pair_agent("log-follower", 0x74);
        let grant = fixture
            .mint(&requester, &[GPU_QUOTE, GPU_START, LOGS_TAIL_VERB])
            .await;
        let key = fixture.attempt_on(&requester, grant, EntityId::now()).await;

        let at_once = tail(
            fixture
                .as_agent(&requester, LOGS_TAIL_VERB, stdout_from(&key, 0))
                .await,
        );
        assert_eq!(at_once.bytes, "");
        assert_eq!(at_once.next_offset, 0);
        assert!(!at_once.ended);
        assert_eq!(fixture.machine.tails(), 1, "no wait_ms: one ask");

        // The workload writes before the waiting call's second ask.
        fixture.machine.script().writes_before = Some((2, b"loss 0.41\n".to_vec()));
        let waited = tail(
            fixture
                .as_agent(
                    &requester,
                    LOGS_TAIL_VERB,
                    json!({"attempt": key, "stream": "stdout", "offset": 0, "wait_ms": 20_000}),
                )
                .await,
        );
        assert_eq!(waited.bytes, "loss 0.41\n");
        assert_eq!(waited.next_offset, 10);
        assert!(!waited.ended);
        assert_eq!(
            fixture.machine.tails(),
            3,
            "asked again once a second, and answered at the ask that read the bytes, not at the \
             wait's end"
        );

        let before = fixture.machine.tails();
        let timed_out = tail(
            fixture
                .as_agent(
                    &requester,
                    LOGS_TAIL_VERB,
                    json!({"attempt": key, "stream": "stdout", "offset": 10, "wait_ms": 1_200}),
                )
                .await,
        );
        assert_eq!(timed_out.bytes, "");
        assert_eq!(timed_out.next_offset, 10);
        assert!(!timed_out.ended);
        assert!(
            fixture.machine.tails() >= before + 2,
            "it waited a second and asked again before the wait passed"
        );

        fixture.machine.script().ended = true;
        let before = fixture.machine.tails();
        let ended = tail(
            fixture
                .as_agent(
                    &requester,
                    LOGS_TAIL_VERB,
                    json!({"attempt": key, "stream": "stdout", "offset": 10, "wait_ms": 20_000}),
                )
                .await,
        );
        assert_eq!(ended.bytes, "");
        assert_eq!(ended.next_offset, 10);
        assert!(ended.ended, "the stream's end answers at once");
        assert_eq!(fixture.machine.tails(), before + 1);

        let page = tail(
            fixture
                .as_agent(
                    &requester,
                    LOGS_TAIL_VERB,
                    json!({"attempt": key, "stream": "stdout", "offset": 0, "max": 4}),
                )
                .await,
        );
        assert_eq!(page.bytes, "loss");
        assert_eq!(page.next_offset, 4);
        assert!(!page.ended, "more follows the page");
    });
}

#[test]
fn a_same_id_retry_gets_no_kept_bytes_and_a_new_read_asks_the_machine_again() {
    run_on_engine_stack("logs-tail-retry", || async {
        let fixture = setup();
        let requester = fixture.pair_agent("log-retrier", 0x75);
        let grant = fixture
            .mint(&requester, &[GPU_QUOTE, GPU_START, LOGS_TAIL_VERB])
            .await;
        let key = fixture.attempt_on(&requester, grant, EntityId::now()).await;
        let invocation = EntityId::now().to_hex();
        fixture.machine.script().stdout = b"epoch 1\n".to_vec();

        let first = tail(
            fixture
                .as_agent_under(
                    &requester,
                    LOGS_TAIL_VERB,
                    stdout_from(&key, 0),
                    Some(&invocation),
                )
                .await,
        );
        assert_eq!(first.bytes, "epoch 1\n");
        assert_eq!(fixture.machine.tails(), 1);

        fixture
            .machine
            .script()
            .stdout
            .extend_from_slice(b"epoch 2\n");
        let (status, retried) = fixture
            .as_agent_under(
                &requester,
                LOGS_TAIL_VERB,
                stdout_from(&key, 0),
                Some(&invocation),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "the retry finds its admission intent settled, and no kept reply answers it: {retried}"
        );
        assert_eq!(retried["error"]["code"], "INVALID_STATE", "{retried}");
        assert!(
            !retried.to_string().contains("epoch 1"),
            "no byte of the first ask is answered again: {retried}"
        );
        assert_eq!(
            fixture.machine.tails(),
            1,
            "a refused retry asks the machine nothing"
        );

        let next = tail(
            fixture
                .as_agent_under(
                    &requester,
                    LOGS_TAIL_VERB,
                    stdout_from(&key, 8),
                    Some(&EntityId::now().to_hex()),
                )
                .await,
        );
        assert_eq!(fixture.machine.tails(), 2, "a new read asks the machine");
        assert_eq!(next.bytes, "epoch 2\n");
        assert_eq!(next.next_offset, 16);
    });
}

#[test]
fn a_character_the_read_cuts_short_is_left_for_the_next_read_while_the_stream_runs() {
    // "é" is the two bytes C3 A9.
    let cut = LogsTail::from_machine(b"caf\xC3", 4, false, None);
    assert_eq!(cut.bytes, "caf");
    assert_eq!(
        cut.next_offset, 3,
        "the next read starts at the cut character"
    );
    let whole = LogsTail::from_machine(b"\xC3\xA9 ok", 9, false, None);
    assert_eq!(whole.bytes, "é ok");
    assert_eq!(whole.next_offset, 9);
    let ended = LogsTail::from_machine(b"caf\xC3", 4, true, None);
    assert_eq!(
        ended.bytes, "caf\u{FFFD}",
        "nothing follows an ended stream's last byte"
    );
    assert_eq!(ended.next_offset, 4);
    assert!(ended.ended);
    let alone = LogsTail::from_machine(b"\xC3", 1, false, None);
    assert_eq!(
        alone.bytes, "\u{FFFD}",
        "a read of only a cut character still moves on"
    );
    assert_eq!(alone.next_offset, 1);
    let invalid = LogsTail::from_machine(b"a\xFFb", 3, false, Some(5));
    assert_eq!(invalid.bytes, "a\u{FFFD}b");
    assert_eq!(invalid.next_offset, 3);
    assert_eq!(invalid.truncated, Some(LogsTailTruncation { dropped: 5 }));
}
