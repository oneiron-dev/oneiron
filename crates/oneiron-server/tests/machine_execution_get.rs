#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! `vault.machines.execution.get` (pass 33 door 11, `33-exec-node/DESIGN.md`
//! section 6): who may read it, which machines it asks, and what it shows of
//! each answer.
//!
//! - Over the real mesh (`support/mesh_machines.rs`): A serves the read; B is
//!   an enabled node whose one issuer is A; C is another of the owner's
//!   machines that runs no jobs.
//! - By script: the asks and their order, the key pages and every way a
//!   machine gives no answer, through a [`JobNodeClient`] that answers by
//!   script.
//! - The reader check (the owner, or an agent whose Grant lists the verb),
//!   in the engine and through the served facade row.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test machine_execution_get`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/execution_nodes.rs"]
mod execution_nodes;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use execution_nodes::{NodeFiles, PROBE_TEMPLATE};
use mesh_machines::{Machine, Machines, TestResult, at};
use oneiron::authority::{
    ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal,
    pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, Memory,
};
use oneiron::sync::mesh_path::SYNC_ALPN;
use oneiron::test_doors::steward;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, MACHINES_EXECUTION_GET_VERB,
    MachineExecution, MachineExecutionReply, MachineExecutionRequest, MachineExecutionTarget,
    MachineGpuView, MachineKeyState, MachineKeysView, MachineLiveKey, MachineNodeView,
    create_agent_definition_as, machine_execution_targets_as, mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::gpu_execution_node::issuer::node_status::NodeAsker;
use oneiron_server::gpu_execution_node::issuer::{
    JobNodeClient, MACHINE_EXECUTION_KEY_PAGES_MAX, NodeCallError, SystemIssuerClock,
    read_machine_execution,
};
use oneiron_server::gpu_execution_node::wire::{
    JOB_ALPN, JOB_STATUS_ALPN, JobAnswer, JobRefusal, JobRequest, JobState, JobStatusAnswer,
    JobStatusRequest, KeyEntry, KeyPage, NodeAnswer,
};
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const A: usize = 0;
const B: usize = 1;
const C: usize = 2;
const BOTH: [&[u8]; 2] = [JOB_ALPN, JOB_STATUS_ALPN];

// --- By script -----------------------------------------------------------

type JobScript = Box<dyn Fn(&JobRequest) -> Result<JobAnswer, NodeCallError> + Send + Sync>;
type StatusScript =
    Box<dyn Fn(&JobStatusRequest) -> Result<JobStatusAnswer, NodeCallError> + Send + Sync>;

/// A machine that answers by script and counts the asks on each protocol.
struct ScriptedMachine {
    job: JobScript,
    status: StatusScript,
    job_asks: AtomicUsize,
    status_asks: AtomicUsize,
}

impl ScriptedMachine {
    fn new(job: JobScript, status: StatusScript) -> Arc<Self> {
        Arc::new(Self {
            job,
            status,
            job_asks: AtomicUsize::new(0),
            status_asks: AtomicUsize::new(0),
        })
    }

    fn asks(&self) -> (usize, usize) {
        (
            self.job_asks.load(Ordering::SeqCst),
            self.status_asks.load(Ordering::SeqCst),
        )
    }
}

impl JobNodeClient for ScriptedMachine {
    fn job(&self, _node: EntityId, request: &JobRequest) -> Result<JobAnswer, NodeCallError> {
        self.job_asks.fetch_add(1, Ordering::SeqCst);
        (self.job)(request)
    }

    fn job_status(
        &self,
        _node: EntityId,
        request: &JobStatusRequest,
    ) -> Result<JobStatusAnswer, NodeCallError> {
        self.status_asks.fetch_add(1, Ordering::SeqCst);
        (self.status)(request)
    }
}

fn no_job_ask() -> JobScript {
    Box::new(|request| panic!("no oneiron/job/1 ask was expected: {request:?}"))
}

fn no_status_ask() -> StatusScript {
    Box::new(|request| panic!("no oneiron/job-status/1 ask was expected: {request:?}"))
}

fn no_keys() -> StatusScript {
    Box::new(|_| {
        Ok(JobStatusAnswer::Keys(KeyPage {
            entries: Vec::new(),
            next: None,
        }))
    })
}

/// Another machine of the vault's, with the grants this vault holds for it.
fn target(job_grant: bool, job_status_grant: bool) -> MachineExecutionTarget {
    MachineExecutionTarget {
        machine: EntityId::now(),
        name: Some("mel".to_owned()),
        this_install: false,
        job_grant,
        job_status_grant,
    }
}

fn entry(key: &str, state: JobState) -> KeyEntry {
    KeyEntry {
        key: key.to_owned(),
        state,
        ended: None,
    }
}

/// An enabled node's offer.
fn offer() -> NodeAnswer {
    NodeAnswer {
        enabled: true,
        paused: None,
        drained: None,
        templates: Vec::new(),
        scopes: Vec::new(),
        disk_free_bytes: 200 << 30,
        disk_reserved_bytes: 0,
        disk_reserve_bytes: 50 << 30,
        epoch: None,
        swept: true,
        boot_id: "boot-1".to_owned(),
        engine_version: "0.0.0-test".to_owned(),
    }
}

fn read_one(machine: &Arc<ScriptedMachine>, target: MachineExecutionTarget) -> MachineExecution {
    let client: Arc<dyn JobNodeClient> = Arc::clone(machine) as Arc<dyn JobNodeClient>;
    let mut reply = read_machine_execution(Ok(client), &SystemIssuerClock, vec![target]);
    assert_eq!(reply.machines.len(), 1, "one machine asked, one answered");
    reply.machines.remove(0)
}

/// Under the status grant alone, the machine's keys are read page by page from
/// each page's `next`; the keys that ended are left out, and nothing is asked
/// on `oneiron/job/1`.
#[test]
fn a_machines_keys_are_read_page_by_page_and_its_ended_keys_left_out() {
    let machine = ScriptedMachine::new(
        no_job_ask(),
        Box::new(|request| match request {
            JobStatusRequest::Keys { after: None } => Ok(JobStatusAnswer::Keys(KeyPage {
                entries: vec![entry("k1", JobState::Held), entry("k2", JobState::Ended)],
                next: Some("page-2".to_owned()),
            })),
            JobStatusRequest::Keys { after: Some(after) } if after == "page-2" => {
                Ok(JobStatusAnswer::Keys(KeyPage {
                    entries: vec![entry("k3", JobState::Running)],
                    next: None,
                }))
            }
            other => panic!("only the two pages of keys were expected: {other:?}"),
        }),
    );
    let shown = read_one(&machine, target(false, true));
    assert_eq!(shown.live_keys.state, "answered", "{shown:?}");
    assert!(shown.live_keys.asked_at_ms.is_some(), "{shown:?}");
    assert_eq!(
        shown.live_keys.answer,
        Some(vec![
            MachineLiveKey {
                key: "k1".to_owned(),
                state: MachineKeyState::Held,
            },
            MachineLiveKey {
                key: "k3".to_owned(),
                state: MachineKeyState::Running,
            },
        ]),
        "the live keys of both pages, without the ended one"
    );
    assert_eq!(shown.node, MachineNodeView::not_asked("no_job_grant"));
    assert_eq!(
        shown.availability,
        MachineGpuView::not_asked("no_job_grant")
    );
    assert_eq!(machine.asks(), (0, 2), "two pages, no ask on oneiron/job/1");
}

/// A machine that names a next page on every page holds the read no longer
/// than the page bound: its keys are unknown, and none is shown.
#[test]
fn a_machine_that_keeps_naming_a_next_page_is_shown_with_its_keys_unknown() {
    let machine = ScriptedMachine::new(
        no_job_ask(),
        Box::new(|_| {
            Ok(JobStatusAnswer::Keys(KeyPage {
                entries: vec![entry("k1", JobState::Running)],
                next: Some("again".to_owned()),
            }))
        }),
    );
    let shown = read_one(&machine, target(false, true));
    assert_eq!(shown.live_keys.state, "unknown", "{shown:?}");
    assert_eq!(shown.live_keys.answer, None);
    assert_eq!(
        shown.live_keys.error.as_deref(),
        Some(format!("more than {MACHINE_EXECUTION_KEY_PAGES_MAX} pages of keys").as_str())
    );
    assert_eq!(machine.asks(), (0, MACHINE_EXECUTION_KEY_PAGES_MAX));
}

/// A machine that refuses its offer is shown refused with its code; its GPUs
/// are not asked, and its keys still are under the status grant.
#[test]
fn a_refused_offer_is_shown_with_its_code_and_its_gpus_are_not_asked() {
    let machine = ScriptedMachine::new(
        Box::new(|request| match request {
            JobRequest::Node => Ok(JobAnswer::Refused(JobRefusal::NotIssuer)),
            other => panic!("only the offer was expected on oneiron/job/1: {other:?}"),
        }),
        no_keys(),
    );
    let shown = read_one(&machine, target(true, true));
    assert_eq!(shown.node.state, "refused", "{shown:?}");
    assert_eq!(shown.node.refusal.as_deref(), Some("not_issuer"));
    assert_eq!(
        shown.availability,
        MachineGpuView::not_asked("offer_not_answered")
    );
    assert_eq!(shown.live_keys.answer, Some(Vec::new()));
    assert_eq!(machine.asks(), (1, 1), "the offer once, the keys once");
}

/// An offer that gets no answer in time leaves the GPUs unasked; the status
/// protocol is asked apart and still lists the keys (EM-1).
#[test]
fn a_machine_whose_offer_times_out_is_still_asked_its_keys() {
    let machine = ScriptedMachine::new(Box::new(|_| Err(NodeCallError::Timeout)), no_keys());
    let shown = read_one(&machine, target(true, true));
    assert_eq!(shown.node.state, "unknown", "{shown:?}");
    assert_eq!(
        shown.node.error.as_deref(),
        Some(NodeCallError::Timeout.to_string().as_str())
    );
    assert_eq!(
        shown.availability,
        MachineGpuView::not_asked("offer_not_answered")
    );
    assert_eq!(shown.live_keys.state, "answered", "{shown:?}");
    assert_eq!(machine.asks(), (1, 1));
}

/// A machine that answers its offer and then gives no answer about its GPUs
/// is shown with its offer, its GPUs unknown, and its keys still read.
#[test]
fn a_gpu_ask_that_gets_no_answer_leaves_the_offer_and_the_keys() {
    let machine = ScriptedMachine::new(
        Box::new(|request| match request {
            JobRequest::Node => Ok(JobAnswer::Node(offer())),
            JobRequest::Availability => Err(NodeCallError::Unreachable {
                reason: "the stream closed".to_owned(),
            }),
            other => panic!("only the offer and the GPUs were expected: {other:?}"),
        }),
        no_keys(),
    );
    let shown = read_one(&machine, target(true, true));
    assert_eq!(shown.node.state, "answered", "{shown:?}");
    assert!(shown.node.answer.as_ref().is_some_and(|node| node.enabled));
    assert_eq!(shown.availability.state, "unknown", "{shown:?}");
    assert_eq!(shown.live_keys.state, "answered", "{shown:?}");
    assert_eq!(machine.asks(), (2, 1), "the offer, the GPUs, the keys");
}

/// A server that is not the vault's issuer asks nothing: each ask a granted
/// machine would get says why. This install and a machine without a grant
/// are shown with their own reasons.
#[test]
fn a_server_that_is_not_the_issuer_and_this_install_ask_nothing() {
    let machine = ScriptedMachine::new(no_job_ask(), no_status_ask());
    let mut this_install = target(true, true);
    this_install.this_install = true;
    let granted = target(true, true);
    let ungranted = target(false, false);
    let reply = read_machine_execution(
        Err("not_the_issuer"),
        &SystemIssuerClock,
        vec![this_install.clone(), granted, ungranted.clone()],
    );
    let views = |shown: &MachineExecution| {
        (
            shown.node.not_asked.clone(),
            shown.availability.not_asked.clone(),
            shown.live_keys.not_asked.clone(),
        )
    };
    let why = |offer: &str, keys: &str| {
        (
            Some(offer.to_owned()),
            Some(offer.to_owned()),
            Some(keys.to_owned()),
        )
    };
    assert_eq!(
        reply.machines.iter().map(views).collect::<Vec<_>>(),
        vec![
            why("this_install", "this_install"),
            why("not_the_issuer", "not_the_issuer"),
            why("no_job_grant", "no_job_status_grant"),
        ]
    );
    let client: Arc<dyn JobNodeClient> = Arc::clone(&machine) as Arc<dyn JobNodeClient>;
    let reply = read_machine_execution(
        Ok(client),
        &SystemIssuerClock,
        vec![this_install, ungranted],
    );
    assert_eq!(
        reply.machines.iter().map(views).collect::<Vec<_>>(),
        vec![
            why("this_install", "this_install"),
            why("no_job_grant", "no_job_status_grant"),
        ]
    );
    assert_eq!(machine.asks(), (0, 0));
}

// --- The reader check ----------------------------------------------------

/// An enabled agent the owner defines, with one Grant listing `verbs`.
fn agent_with_grant(vault: &Vault, agent_id: &str, verbs: &[&str]) -> TestResult<EntityId> {
    let owner = steward::owner(vault).map_err(at("the owner's proof"))?;
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        &owner,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Reads the owner's machines",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))?,
        },
    )
    .map_err(at("the owner defines the agent"))?;
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    mint_agent_grant_as(
        vault,
        &owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .map_err(at("the owner mints the agent's Grant"))?;
    Ok(agent)
}

fn owner_memory(vault: &Vault) -> TestResult<Memory<'_>> {
    let actor = vault
        .ensure_embedded_owner_actor()
        .map_err(at("the owner's actor"))?;
    Ok(vault.memory(actor, EdgeActorClass::Human))
}

/// The owner reads under their own proof; an agent reads only under a live
/// Grant that lists the verb (and `read`, without which a Grant confers
/// nothing). A machine that is not 32 hex is a bad request; one the vault's
/// authority names no machine by is not found.
#[test]
fn an_agent_is_shown_the_machines_only_under_a_grant_that_lists_the_verb() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = steward::open_owner_carrier_vault(dir.path()).map_err(at("open the vault"))?;
    let owner = steward::owner(&vault).map_err(at("the owner's proof"))?;
    let all = MachineExecutionRequest::default();

    let by_owner = machine_execution_targets_as(&owner_memory(&vault)?, Some(&owner), &all)
        .map_err(at("the owner reads"))?;
    assert_eq!(
        by_owner.targets,
        Vec::new(),
        "no machine holds a job grant here"
    );

    let reader = agent_with_grant(
        &vault,
        "machine-reader",
        &["read", MACHINES_EXECUTION_GET_VERB],
    )?;
    let lister = agent_with_grant(&vault, "machine-lister", &["read", "vault.machines.list"])?;
    let no_read = agent_with_grant(&vault, "machine-no-read", &[MACHINES_EXECUTION_GET_VERB])?;
    let as_agent = |agent: EntityId| {
        machine_execution_targets_as(&vault.memory(agent, EdgeActorClass::Agent), None, &all)
    };
    assert_eq!(
        as_agent(reader)
            .map_err(at("the reader's Grant lists the verb"))?
            .targets,
        Vec::new()
    );
    for (agent, why) in [
        (lister, "a Grant of another verb"),
        (no_read, "a Grant without read"),
    ] {
        let refused = as_agent(agent).expect_err(why);
        assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{why}: {refused:?}");
    }

    let not_hex = MachineExecutionRequest {
        machine: Some("mel".to_owned()),
    };
    let refused = machine_execution_targets_as(&owner_memory(&vault)?, Some(&owner), &not_hex)
        .expect_err("a machine that is not 32 hex");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    let no_machine = MachineExecutionRequest {
        machine: Some(EntityId::now().to_hex()),
    };
    let refused = machine_execution_targets_as(&owner_memory(&vault)?, Some(&owner), &no_machine)
        .expect_err("an id the authority names no machine by");
    assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND, "{refused:?}");
    Ok(())
}

// --- Over the real mesh --------------------------------------------------

/// A, B and C, where A is the vault's issuer of vault machine jobs, B is a
/// node whose one issuer is A and holds its own job grant, and B grants A
/// both job protocols. A holds B's grant on `oneiron/job/1` alone, and C's on
/// both; C, which runs no jobs, grants A both.
async fn issuer_node_and_other(files: &NodeFiles) -> TestResult<Machines> {
    let mesh = Machines::start_with(3, |index, machines| match index {
        A => {
            let mut issuer = NodeFiles::none();
            issuer.gpu_jobs.vault_machine.issuer = Some(machines[A]);
            issuer
        }
        B => files.enabled(B, machines[A]),
        _ => NodeFiles::none(),
    })
    .await?;
    mesh.grant(B, A, &BOTH)?;
    mesh.grant(A, B, &[JOB_ALPN])?;
    mesh.grant(C, A, &BOTH)?;
    mesh.grant(A, C, &BOTH)?;
    mesh.grant_own(B, &[JOB_ALPN])?;
    Ok(mesh)
}

/// A's read as its owner, asked off the runtime as the door asks.
async fn read_as_owner(
    a: &Machine,
    input: MachineExecutionRequest,
) -> TestResult<MachineExecutionReply> {
    let vault = Arc::clone(&a.device.vault);
    let asker = NodeAsker::of(&a.served.server);
    tokio::task::spawn_blocking(move || -> Result<MachineExecutionReply, String> {
        let owner = steward::owner(&vault).map_err(|error| format!("{error:?}"))?;
        let memory = owner_memory(&vault).map_err(|error| error.to_string())?;
        let targets = machine_execution_targets_as(&memory, Some(&owner), &input)
            .map_err(|error| format!("{error:?}"))?;
        let client = asker.client(targets.serving_machine);
        Ok(read_machine_execution(
            client,
            &SystemIssuerClock,
            targets.targets,
        ))
    })
    .await?
    .map_err(Into::into)
}

fn shown(reply: &MachineExecutionReply, machine: &Machine) -> TestResult<MachineExecution> {
    let hex = machine.device.machine.to_hex();
    reply
        .machines
        .iter()
        .find(|shown| shown.machine == hex)
        .cloned()
        .ok_or_else(|| format!("machine {hex} is not shown: {reply:?}").into())
}

#[test]
fn the_owner_is_shown_each_granted_machine_as_it_answers_over_the_mesh() -> TestResult {
    on_engine_stack(owner_is_shown_each_granted_machine)
}

async fn owner_is_shown_each_granted_machine() -> TestResult {
    let files = NodeFiles::new()?;
    let mesh = issuer_node_and_other(&files).await?;
    let (a, b, c) = (mesh.machine(A), mesh.machine(B), mesh.machine(C));
    let reply = read_as_owner(a, MachineExecutionRequest::default()).await?;
    assert_eq!(
        reply.machines.len(),
        2,
        "B and C hold A's grants: {reply:?}"
    );

    // B answers its issuer what it offers. Its GPUs are what its driver
    // reads on this host: a host with no driver it can read refuses them.
    let node = shown(&reply, b)?;
    assert!(node.job_grant && !node.job_status_grant, "{node:?}");
    assert_eq!(node.node.state, "answered", "{node:?}");
    assert!(node.node.asked_at_ms.is_some(), "B was asked: {node:?}");
    let offer = node.node.answer.as_ref().ok_or("B must answer its offer")?;
    assert!(offer.enabled, "B is an enabled node: {offer:?}");
    assert_eq!(
        offer
            .templates
            .iter()
            .map(|template| template.name.as_str())
            .collect::<Vec<_>>(),
        [PROBE_TEMPLATE],
        "B offers its one template"
    );
    assert_eq!(offer.templates[0].digest.len(), 64, "{offer:?}");
    match node.availability.state.as_str() {
        "answered" => {}
        "refused" => assert_eq!(
            node.availability.refusal.as_deref(),
            Some("devices_unreadable"),
            "{node:?}"
        ),
        other => panic!("B's GPUs must be answered or refused as unreadable: {other}: {node:?}"),
    }
    assert_eq!(
        node.live_keys,
        MachineKeysView::not_asked("no_job_status_grant"),
        "A holds no status grant of B's"
    );

    // C runs no jobs. It is reachable (A dials it on sync), and its listener
    // refuses both job protocols at the handshake: its offer and its keys are
    // unknown, with the dial's error, and its GPUs are not asked.
    let transport = a.served.transport()?;
    let sync = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        transport.dial(c.device.machine, SYNC_ALPN),
    )
    .await
    .map_err(|_| "A's dial of C on sync hung")?
    .map_err(at("A dials C on sync"))?;
    sync.close();
    let other = shown(&reply, c)?;
    assert!(other.job_grant && other.job_status_grant, "{other:?}");
    let timeout = NodeCallError::Timeout.to_string();
    for (ask, state, error) in [
        ("offer", &other.node.state, &other.node.error),
        ("keys", &other.live_keys.state, &other.live_keys.error),
    ] {
        assert_eq!(state, "unknown", "C's {ask}: {other:?}");
        let error = error.as_deref().ok_or("C's dial error")?;
        assert!(
            !error.is_empty() && error != timeout,
            "C's {ask} is refused at the handshake, not timed out: {other:?}"
        );
    }
    assert_eq!(
        other.availability,
        MachineGpuView::not_asked("offer_not_answered")
    );

    // A named alone: shown as this install, with no ask.
    let this = read_as_owner(
        a,
        MachineExecutionRequest {
            machine: Some(a.device.machine.to_hex()),
        },
    )
    .await?;
    let this = shown(&this, a)?;
    assert!(this.this_install, "{this:?}");
    assert_eq!(this.node, MachineNodeView::not_asked("this_install"));
    mesh.stop().await;
    Ok(())
}

// --- The served row ------------------------------------------------------

/// A served vault and its owner's slip.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

/// One paired agent credential.
struct Agent {
    principal: EntityId,
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn serve() -> TestResult<Served> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(
        Vault::open(dir.path(), VaultConfig::device()).map_err(at("open the served vault"))?,
    );
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("machine-execution".into()),
                ..Default::default()
            },
        )
        .map_err(at("the served server"))?,
    );
    let issuer = vault
        .load_host_slip_issuer()
        .map_err(at("the host slip issuer"))?;
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .map_err(at("the owner's root slip"))?;
    let owner_token = owner_slip.to_token().map_err(at("the owner's token"))?;
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .map_err(at("this install's live machine profile"))?;
    Ok(Served {
        _dir: dir,
        app: build_app(server),
        vault,
        issuer,
        owner_slip,
        owner_token,
    })
}

/// Pairs one agent as `token agent` does, over the real pairing route.
async fn pair_agent(served: &Served, name: &str, seed: [u8; 32]) -> TestResult<Agent> {
    let principal = served
        .vault
        .ensure_agent_principal(name)
        .map_err(at("the agent's principal"))?;
    let holder = SigningKey::from_bytes(&seed);
    let binding_key = holder.verifying_key().to_bytes();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
    let link = served
        .vault
        .issue_pairing_link_for_principal(
            &served.issuer,
            scope,
            3600,
            PairingPrincipal {
                holder_ref: Some(principal.to_hex()),
                actor_class: Some("agent".to_owned()),
                ..Default::default()
            },
        )
        .map_err(at("the agent's pairing link"))?;
    let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
        .map_err(at("the pairing transcript"))?;
    let body = json!({
        "code": link.code,
        "holder_ref": principal.to_hex(),
        "binding_key": hex(&binding_key),
        "signature": hex(&holder.sign(&transcript).to_bytes()),
    });
    let request = Request::post("/v1/core/pairing/redeem")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))?;
    let response = served.app.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK, "pairing redeem status");
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await?)?;
    let token = body["token"].as_str().ok_or("a paired token")?.to_owned();
    Ok(Agent {
        principal,
        holder,
        slip: CapabilitySlip::from_token(&token).map_err(at("the paired slip"))?,
        token,
    })
}

fn challenge(served: &Served) -> (u64, String, String) {
    let timestamp = served.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    (timestamp, nonce, challenge)
}

async fn post(
    served: &Served,
    token: &str,
    binding: Value,
    verb: &str,
    body: Value,
) -> TestResult<(StatusCode, Value)> {
    let request = Request::post(format!("/v1/core/facade/{verb}"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding.to_string())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))?;
    let response = served.app.clone().oneshot(request).await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await?)?;
    Ok((status, body))
}

/// `verb` as the owner, on its own proof.
async fn as_owner(served: &Served, verb: &str, body: Value) -> TestResult<(StatusCode, Value)> {
    let (timestamp, nonce, challenge) = challenge(served);
    let signature = hex(&served
        .issuer
        .binding_proof(&served.owner_slip, challenge.as_bytes())
        .map_err(at("the owner's holder proof"))?);
    let binding = json!({"timestamp": timestamp, "nonce": nonce, "signature": signature});
    post(served, &served.owner_token, binding, verb, body).await
}

/// `verb` as `agent`, on its own credential.
async fn as_agent(
    served: &Served,
    agent: &Agent,
    verb: &str,
    body: Value,
) -> TestResult<(StatusCode, Value)> {
    let (timestamp, nonce, challenge) = challenge(served);
    let transcript = agent
        .slip
        .binding_transcript(challenge.as_bytes())
        .map_err(at("the agent's binding transcript"))?;
    let signature = hex(&agent.holder.sign(&transcript).to_bytes());
    let binding = json!({"timestamp": timestamp, "nonce": nonce, "signature": signature});
    post(served, &agent.token, binding, verb, body).await
}

/// The served row answers the owner, refuses an agent with no Grant that
/// lists it, and answers that agent once the owner's Grant lists it.
#[test]
fn the_served_row_answers_the_owner_and_an_agent_only_under_its_grant() -> TestResult {
    on_engine_stack(served_row_answers_the_owner_and_a_granted_agent)
}

async fn served_row_answers_the_owner_and_a_granted_agent() -> TestResult {
    let served = serve()?;
    let (status, reply) = as_owner(&served, MACHINES_EXECUTION_GET_VERB, json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["machines"], json!([]), "no machine holds a job grant");
    let this = served
        .vault
        .local_machine()
        .map_err(at("read the served install"))?
        .ok_or("the served install has a machine")?
        .id
        .to_hex();
    let (status, reply) = as_owner(
        &served,
        MACHINES_EXECUTION_GET_VERB,
        json!({"machine": this}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["machines"][0]["this_install"], json!(true), "{reply}");
    assert_eq!(
        reply["machines"][0]["node"]["not_asked"],
        json!("this_install"),
        "{reply}"
    );

    let agent = pair_agent(&served, "machine-reader", [0x5a; 32]).await?;
    let (status, refused) =
        as_agent(&served, &agent, MACHINES_EXECUTION_GET_VERB, json!({})).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");

    let (status, minted) = as_owner(
        &served,
        "vault.agents.grants.mint",
        json!({
            "agent": agent.principal.to_hex(),
            "authority_scope": {
                "worlds": {"kind": "all"},
                "facets": {"kind": "all"},
                "bands": {"kind": "all"},
                "audience": {"kind": "all"},
                "verbs": {"kind": "some", "values": ["read", MACHINES_EXECUTION_GET_VERB]},
                "sensitivity": {"kind": "at_most", "value": "restricted"},
            },
        }),
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the owner mints the Grant: {minted}"
    );
    let (status, reply) = as_agent(&served, &agent, MACHINES_EXECUTION_GET_VERB, json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["machines"], json!([]), "{reply}");
    Ok(())
}
