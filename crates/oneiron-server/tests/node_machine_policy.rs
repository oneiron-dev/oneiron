//! Row P0 (pass 34, `34-compute-general/DESIGN.md` sections 2.4 and 10; EM-17 = A): the
//! owner's machine policy rows, read by the execution node from its own vault, and the stricter
//! of them and the box's `[execution_node]` file applying.
//!
//! The fixture is the owner's home H, the install where his agents work (the node's one issuer),
//! and one device N of H, whose vault the node reads. The owner's changes on H are his signed
//! acts; N takes H's authority history ([`Home::share_history`]) and writes the rows from the
//! acts its own fold counts. A row an agent or the engine writes on H stays on H (RULING
//! SETTING-7A-2-DECIDERS = A; ANSWER P0-HOLDER-ACTS = A).
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test node_machine_policy`.

#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mesh_machines::{Device, Home, TestResult, at, home};
use oneiron::EntityId;
use oneiron::authority::ActSurface;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::job_workload::BoundRequirement;
use oneiron::job_workload::{DeviceKind, DeviceLease, DevicePlacement, Sharing};
use oneiron::machine_policy::{CachePolicy, ExecutionState, machine_item, machine_part_item};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, set_line};
use oneiron::test_doors::setting::set_setting_as_engine;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron_server::gpu_execution_node::jobs::{
    IssuerNotLive, NodeAdmission, NodeControls, NodeJobSettings, NodeJobs, NodeKey,
};
use oneiron_server::gpu_execution_node::wire::{
    DeviceClaim, HoldRef, JobAnswer, JobEnd, JobReceipt, JobReserve, JobState, JobSubmit,
    NetworkMode, OutputDecl, ResourceRequest, ScopeKind, SignedJobSubmit, SlotSelector, Starter,
    WorkloadPin,
};
use oneiron_server::gpu_execution_node::{
    DrainClearBy, ExecutionNode, GpuDeviceOffer, GpuSlotTable, NvidiaSmiProbe,
};
use oneiron_server::test_doors::node_jobs::{ScriptedAdmission, ScriptedNode, ScriptedSigner};
use serde_json::{Value, json};

/// The issuer the node's file names: the gate is not what these tests read.
const ISSUER: &str = "5d1e3c8a9b7f4e21a0c6d2b8f3e9a714";

/// The one device the box offers.
const GPU: &str = "GPU-0f1e2d3c";

const EXECUTION: &str = "machines.execution";
const DRAIN_CLEAR_BY: &str = "machines.drain.clear_by";
const READINESS_EVERY_SECS: &str = "jobs.readiness.every_secs";
const SET: &str = "vault.settings.set";

/// The box's file: an enabled node holding the template `probe`, which may use no network or the
/// host's, with `extra` lines in the `[execution_node]` table.
fn node_text(dir: &Path, extra: &str) -> String {
    format!(
        r#"[execution_node]
enabled = true
issuers = ["{ISSUER}"]
state_dir = "{state}"
work_dir = "{work}"
disk_reserve_gib = 50
{extra}

[execution_node.templates.probe]
repo = "/srv/git/probe.git"
entries = ["tools/units/*.sh"]
interpreter = ["/usr/bin/bash"]
network = ["none", "host"]
max_secs = 1800
memory_gib = 8
disk_gib = 4
"#,
        state = dir.join("state").display(),
        work = dir.join("work").display(),
    )
}

/// The node of device N, reading its file at `file` and offering [`GPU`].
fn node_of(device: &Device, file: &Path) -> ExecutionNode {
    ExecutionNode::new(
        file.to_path_buf(),
        Arc::clone(&device.vault),
        Arc::new(GpuSlotTable::new(
            Arc::new(NvidiaSmiProbe),
            GpuDeviceOffer {
                offered: BTreeSet::from([GPU.to_owned()]),
                ..GpuDeviceOffer::default()
            },
        )),
    )
}

/// H, N enrolled on it with H's history, and N's node with the box file of `extra`.
struct Rig {
    _files: tempfile::TempDir,
    file: PathBuf,
    home: Home,
    device: Device,
    node: ExecutionNode,
}

impl Rig {
    fn new(extra: &str) -> TestResult<Self> {
        let home = home()?;
        let device = home.enrol(0x51)?;
        home.share_history(&[&device])?;
        let files = tempfile::tempdir()?;
        let file = files.path().join("execution-node.toml");
        std::fs::write(&file, node_text(files.path(), extra))?;
        let node = node_of(&device, &file);
        Ok(Self {
            _files: files,
            file,
            home,
            device,
            node,
        })
    }

    /// The box rewrites its file with `extra`.
    fn box_writes(&self, extra: &str) -> TestResult {
        let dir = self
            .file
            .parent()
            .ok_or("FIXTURE: the file has a directory")?;
        std::fs::write(&self.file, node_text(dir, extra))?;
        Ok(())
    }

    /// N's item, or `<N>/<name>` for one of its devices or templates.
    fn item(&self, part: Option<&str>) -> String {
        part.map_or_else(
            || machine_item(self.device.machine),
            |name| machine_part_item(self.device.machine, name),
        )
    }

    /// The owner's change of `key` for N (or one of its parts) on H, then N takes H's history.
    fn owner_sets(&self, key: &str, part: Option<&str>, value: Value) -> TestResult {
        let outcome = self
            .home
            .vault()
            .set_setting(
                SettingCaller::Owner(self.home.owner()),
                row(key, &self.item(part), value),
            )
            .map_err(at("the owner's change on H"))?;
        if !matches!(outcome, SetSettingOutcome::Applied { .. }) {
            return Err(format!("the owner's change applies: {outcome:?}").into());
        }
        self.home.share_history(&[&self.device])
    }

    /// `agent`'s change of `machines.execution` for N on H.
    fn agent_sets(&self, agent: EntityId, state: &str) -> TestResult<SetSettingOutcome> {
        self.home
            .vault()
            .set_setting(
                SettingCaller::Agent(agent),
                row(EXECUTION, &self.item(None), json!({ "state": state })),
            )
            .map_err(at("the agent's change on H"))
    }

    /// An agent on H whose live Grant lists `machines.execution`'s line and the setting door.
    fn agent(&self) -> TestResult<EntityId> {
        let vault = self.home.vault();
        let owner = self.home.owner();
        let agent = vault.new_entity_id().map_err(at("the agent's id"))?;
        create_agent_definition_as(
            vault,
            owner,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("machine-policy-agent-{}", agent.to_hex()),
                    "desc": "machine policy fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))?,
            },
        )
        .map_err(at("the owner creates the agent"))?;
        let line = set_line(EXECUTION);
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            ["read", SET, line.as_str()]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        );
        let minted = mint_agent_grant_as(
            vault,
            owner,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope: scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
                check_in_ref: None,
            },
        )
        .map_err(at("the owner mints the agent's Grant"))?;
        if !minted.grant.confers {
            return Err("FIXTURE: the agent's Grant confers".into());
        }
        Ok(agent)
    }

    /// `machines.execution` for N as H's install reads it (the issuer's read).
    fn issuer_reads(&self) -> TestResult<ExecutionState> {
        Ok(self
            .home
            .vault()
            .machine_policy(self.device.machine, &[], &[])
            .map_err(at("H's read of N's policy"))?
            .execution
            .state)
    }

    /// `machines.execution` for N as N's own vault reads it (the node's read).
    fn node_reads(&self) -> TestResult<ExecutionState> {
        Ok(self
            .device
            .vault
            .machine_policy(self.device.machine, &[], &[])
            .map_err(at("N's read of its policy"))?
            .execution
            .state)
    }

    /// The cache budget for N as N's own vault reads it.
    fn node_cache(&self) -> TestResult<CachePolicy> {
        Ok(self
            .device
            .vault
            .machine_policy(self.device.machine, &[], &[])
            .map_err(at("N's read of its cache budget"))?
            .cache)
    }

    /// The pin of `probe` as the node holds it now, asking `network`.
    fn pin(&self, network: NetworkMode) -> TestResult<WorkloadPin> {
        let digest = self
            .node
            .template_digest("probe")
            .ok_or("the node holds the template probe")?;
        Ok(pin(&digest, network))
    }
}

/// A value row of `key` for `item`, at the vault.
fn row(key: &str, item: &str, value: Value) -> SetSetting {
    SetSetting {
        item: Some(item.to_owned()),
        ..SetSetting::vault_value(key, value)
    }
}

/// A pin of `probe` at `digest` that fits it, asking `network`, with one GPU claim.
fn pin(digest: &str, network: NetworkMode) -> WorkloadPin {
    WorkloadPin {
        template: "probe".to_owned(),
        template_digest: digest.to_owned(),
        commit: "a".repeat(40),
        contract_sha256: "b".repeat(64),
        contract_path: "contracts/probe.json".to_owned(),
        entry: "tools/units/run.sh".to_owned(),
        args: Vec::new(),
        request: ResourceRequest {
            cpu_threads: 0,
            memory_mib: 4 * 1_024,
            disk_mib: 1_024,
            devices: vec![DeviceClaim {
                kind: DeviceKind::Gpu,
                count: 1,
                memory_mib: 1_024,
                features: vec!["cuda".to_owned()],
                sharing: Sharing::Exclusive,
            }],
            maximum_secs: 1_800,
        },
        scope: ScopeKind::Host,
        network,
        outputs: vec![OutputDecl {
            name: "verdict.json".to_owned(),
            returnable: false,
        }],
    }
}

/// The placement of a pin on [`GPU`], leasing `host_memory_mib`.
fn on_gpu(host_memory_mib: u64) -> DevicePlacement {
    DevicePlacement {
        devices: vec![DeviceLease {
            claim: 0,
            device_id: GPU.to_owned(),
            sharing: Sharing::Exclusive,
        }],
        host_memory_mib,
    }
}

const GIB: u64 = 1 << 30;

#[test]
fn the_node_applies_the_stricter_of_box_ceiling_and_owner_policy() -> TestResult {
    let rig = Rig::new("")?;
    let node = &rig.node;
    assert_eq!(
        node.controls().refusal(),
        None,
        "no row: the box's file alone, enabled"
    );

    // Execution: the owner's pause binds an enabled box; the box's own pause names itself
    // first; a box that turns the node off is off whatever the owner says.
    rig.owner_sets(EXECUTION, None, json!({ "state": "paused" }))?;
    assert_eq!(
        node.controls().refusal().as_deref(),
        Some("node_paused: owner: paused"),
        "the owner's pause, signed on H, binds the node through its own fold"
    );
    assert_eq!(node.node_answer().paused.as_deref(), Some("owner: paused"));
    let marker = rig.file.with_file_name("execution-node.toml.paused");
    std::fs::write(&marker, "operator at the box\n")?;
    assert_eq!(
        node.controls().refusal().as_deref(),
        Some("node_paused: operator at the box")
    );
    std::fs::remove_file(&marker)?;
    rig.owner_sets(EXECUTION, None, json!({ "state": "draining" }))?;
    assert_eq!(
        node.controls().refusal().as_deref(),
        Some("node_paused: owner: draining"),
        "before row P3 a drain stops new work as a pause does"
    );
    rig.owner_sets(EXECUTION, None, json!({ "state": "on" }))?;
    assert_eq!(node.controls().refusal(), None);
    rig.box_writes("owner_policy = false")?;
    rig.owner_sets(EXECUTION, None, json!({ "state": "paused" }))?;
    assert_eq!(
        node.controls().refusal(),
        None,
        "a box that does not accept owner policy obeys its file alone"
    );
    rig.box_writes("")?;
    assert_eq!(
        node.controls().refusal().as_deref(),
        Some("node_paused: owner: paused")
    );
    rig.owner_sets(EXECUTION, None, json!({ "state": "on" }))?;

    // Hours: a machine with no hour of the week takes no new work.
    rig.owner_sets(
        "machines.windows",
        None,
        json!({ "hours": [], "mains_only": false }),
    )?;
    assert_eq!(
        node.controls().refusal().as_deref(),
        Some("node_paused: owner: outside the machine's hours")
    );
    let every_hour: Vec<u8> = (0..168).collect();
    rig.owner_sets(
        "machines.windows",
        None,
        json!({ "hours": every_hour, "mains_only": false }),
    )?;
    assert_eq!(node.controls().refusal(), None);

    // Network: the box opens `host` to the template; the owner's default opens `none` only.
    let host = rig.pin(NetworkMode::Host)?;
    assert_eq!(
        node.admit_pin(&host),
        Err("network_not_permitted: not opened by the owner".to_owned())
    );
    assert_eq!(node.admit_pin(&rig.pin(NetworkMode::None)?), Ok(()));
    let offered = |node: &ExecutionNode| {
        node.node_answer()
            .templates
            .iter()
            .find(|offer| offer.name == "probe")
            .map(|offer| offer.network.clone())
    };
    assert_eq!(offered(node), Some(vec![NetworkMode::None]));
    rig.owner_sets(
        "machines.templates.network",
        Some("probe"),
        json!(["none", "host"]),
    )?;
    assert_eq!(
        node.admit_pin(&host),
        Ok(()),
        "the owner opened what the box allows"
    );
    assert_eq!(
        offered(node),
        Some(vec![NetworkMode::None, NetworkMode::Host])
    );

    // Disk: the larger of the box's reserve and the owner's kept disk.
    assert_eq!(node.node_answer().disk_reserve_bytes, 50 * GIB);
    rig.owner_sets("machines.keep_headroom", None, json!({ "disk_gib": 80 }))?;
    assert_eq!(node.node_answer().disk_reserve_bytes, 80 * GIB);
    rig.owner_sets("machines.keep_headroom", None, json!({ "disk_gib": 10 }))?;
    assert_eq!(node.node_answer().disk_reserve_bytes, 50 * GIB);

    // Memory: the box's job memory against what launched keys hold; the owner's kept memory
    // takes the rest of the machine.
    let none = rig.pin(NetworkMode::None)?;
    rig.box_writes("job_memory_gib = 8")?;
    let none_now = rig.pin(NetworkMode::None)?;
    assert_eq!(none_now.template_digest, none.template_digest);
    assert_eq!(node.admit_placement(&none, &on_gpu(4 * 1_024), 0), Ok(()));
    assert_eq!(
        node.admit_placement(&none, &on_gpu(4 * 1_024), 6 * 1_024),
        Err("memory_room: the machine's work memory is held".to_owned()),
        "8 GiB of job memory, 6 held: a 4 GiB launch does not fit"
    );
    rig.box_writes("")?;
    rig.owner_sets(
        "machines.keep_headroom",
        None,
        json!({ "memory_mib": u64::MAX / 2 }),
    )?;
    assert_eq!(
        node.admit_placement(&none, &on_gpu(4 * 1_024), 0),
        Err("memory_room: the machine's work memory is held".to_owned()),
        "the owner keeps the whole machine: no room for work"
    );
    rig.owner_sets("machines.keep_headroom", None, json!({}))?;
    assert_eq!(node.admit_placement(&none, &on_gpu(4 * 1_024), 0), Ok(()));

    // A device the owner withholds is out of the launch commit.
    rig.owner_sets(
        "machines.devices.offered",
        Some(GPU),
        json!({ "offered": false, "max_claimants": 1 }),
    )?;
    assert_eq!(
        node.admit_placement(&none, &on_gpu(4 * 1_024), 0),
        Err(format!("device_withheld: {GPU}"))
    );

    // The cache budget: N's own read gives the owner's figure and every other at its default
    // (the node's cache pass, row P2, applies the smaller of each figure and the box's).
    assert_eq!(rig.node_cache()?, CachePolicy::DEFAULT);
    rig.owner_sets("placement.cache.cap_gib", None, json!(40))?;
    assert_eq!(
        rig.node_cache()?,
        CachePolicy {
            cap_gib: 40,
            ..CachePolicy::DEFAULT
        }
    );
    Ok(())
}

#[test]
fn an_agent_may_pause_a_machine_and_needs_the_owner_to_turn_it_on() -> TestResult {
    let rig = Rig::new("")?;
    let agent = rig.agent()?;

    // The agent pauses N on H, the issuer's install: it applies there at once, and H sends N no
    // new work. Its row stays on H, so the node's own read does not move (P0-HOLDER-ACTS = A).
    let paused = rig.agent_sets(agent, "paused")?;
    assert!(
        matches!(paused, SetSettingOutcome::Applied { .. }),
        "a holder tightens at once: {paused:?}"
    );
    assert_eq!(rig.issuer_reads()?, ExecutionState::Paused);
    rig.home.share_history(&[&rig.device])?;
    assert_eq!(rig.node_reads()?, ExecutionState::On);

    // Turning it back on is a loosening: it waits on the owner, and nothing moves.
    let on = rig.agent_sets(agent, "on")?;
    assert!(
        matches!(on, SetSettingOutcome::Pending { .. }),
        "a holder's loosening asks the owner: {on:?}"
    );
    assert_eq!(rig.issuer_reads()?, ExecutionState::Paused);

    // The owner's `on` is his act: it replaces the agent's row on H.
    rig.owner_sets(EXECUTION, None, json!({ "state": "on" }))?;
    assert_eq!(rig.issuer_reads()?, ExecutionState::On);

    // The owner's own pause reaches the node; the agent may drain further at once on H, may not
    // turn it on, and the owner's `on` turns the node on everywhere.
    rig.owner_sets(EXECUTION, None, json!({ "state": "paused" }))?;
    assert_eq!(
        rig.node.controls().refusal().as_deref(),
        Some("node_paused: owner: paused")
    );
    let drained = rig.agent_sets(agent, "draining")?;
    assert!(
        matches!(drained, SetSettingOutcome::Applied { .. }),
        "a holder tightens over the owner's own row at once: {drained:?}"
    );
    assert_eq!(rig.issuer_reads()?, ExecutionState::Draining);
    let on = rig.agent_sets(agent, "on")?;
    assert!(
        matches!(on, SetSettingOutcome::Pending { .. }),
        "the agent cannot turn the machine on: {on:?}"
    );
    rig.home.share_history(&[&rig.device])?;
    assert_eq!(
        rig.node.controls().refusal().as_deref(),
        Some("node_paused: owner: paused")
    );
    rig.owner_sets(EXECUTION, None, json!({ "state": "on" }))?;
    assert_eq!(rig.issuer_reads()?, ExecutionState::On);
    assert_eq!(
        rig.node.controls().refusal(),
        None,
        "the owner turned it on"
    );
    Ok(())
}

#[test]
fn a_policy_row_the_owner_did_not_sign_changes_nothing_on_the_node() -> TestResult {
    let rig = Rig::new("")?;
    rig.owner_sets(EXECUTION, None, json!({ "state": "paused" }))?;
    assert_eq!(
        rig.node.controls().refusal().as_deref(),
        Some("node_paused: owner: paused")
    );

    // The issuer's engine turns N on on its own install: its row is the issuer's alone.
    let engine = set_setting_as_engine(
        rig.home.vault(),
        None,
        row(EXECUTION, &rig.item(None), json!({ "state": "on" })),
    )
    .map_err(at("the issuer's engine writes its row"))?;
    assert!(
        matches!(engine, SetSettingOutcome::Applied { .. }),
        "{engine:?}"
    );
    assert_eq!(rig.issuer_reads()?, ExecutionState::On);
    rig.home.share_history(&[&rig.device])?;
    assert_eq!(rig.node_reads()?, ExecutionState::Paused);
    assert_eq!(
        rig.node.controls().refusal().as_deref(),
        Some("node_paused: owner: paused"),
        "no row another machine's engine writes moves the node"
    );

    // The issuer's agent asks to open the host network to the template on its install: a
    // loosening, which waits on the owner (or is refused), and the node's offer does not move.
    let agent = rig.agent()?;
    let opened = rig.home.vault().set_setting(
        SettingCaller::Agent(agent),
        row(
            "machines.templates.network",
            &rig.item(Some("probe")),
            json!(["none", "host"]),
        ),
    );
    assert!(
        !matches!(opened, Ok(SetSettingOutcome::Applied { .. })),
        "an agent's loosening never applies by itself: {opened:?}"
    );
    rig.home.share_history(&[&rig.device])?;
    assert_eq!(
        rig.node.admit_pin(&rig.pin(NetworkMode::Host)?),
        Err("network_not_permitted: not opened by the owner".to_owned())
    );

    // Only the owner's act moves it.
    rig.owner_sets(EXECUTION, None, json!({ "state": "on" }))?;
    assert_eq!(rig.node.controls().refusal(), None);
    Ok(())
}

/// The template and digest the scripted job service holds.
const STAGED_TEMPLATE: &str = "open-models";
const STAGED_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NOW_MS: u64 = 1_800_000_000_000;
const WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The job service's admission for the launch commit test: the node's controls from N's real
/// node, which reads the owner's rows from N's own vault; every other check from the scripted
/// parts.
struct PolicyAdmission {
    node: ExecutionNode,
    scripted: Arc<ScriptedAdmission>,
}

impl NodeAdmission for PolicyAdmission {
    fn controls(&self) -> NodeControls {
        self.node.controls()
    }

    fn issuer_live(&self, issuer: EntityId) -> Result<(), IssuerNotLive> {
        NodeAdmission::issuer_live(&*self.scripted, issuer)
    }

    fn admit_pin(&self, pin: &WorkloadPin) -> Result<(), String> {
        NodeAdmission::admit_pin(&*self.scripted, pin)
    }

    fn template_digest(&self, template: &str) -> Option<String> {
        NodeAdmission::template_digest(&*self.scripted, template)
    }

    fn template_requires(&self, template: &str) -> Option<Vec<BoundRequirement>> {
        NodeAdmission::template_requires(&*self.scripted, template)
    }

    fn admit_placement(
        &self,
        pin: &WorkloadPin,
        placement: &DevicePlacement,
        held_mib: u64,
    ) -> Result<(), String> {
        NodeAdmission::admit_placement(&*self.scripted, pin, placement, held_mib)
    }

    fn disk_room(&self, booked_mib: u64, request_mib: u64) -> Result<(), String> {
        NodeAdmission::disk_room(&*self.scripted, booked_mib, request_mib)
    }

    fn job_settings(&self) -> NodeJobSettings {
        NodeAdmission::job_settings(&*self.scripted)
    }
}

/// A pin of the scripted template, with one 22 GiB GPU claim.
fn staged_pin() -> WorkloadPin {
    let mut pin = pin(STAGED_DIGEST, NetworkMode::None);
    pin.template = STAGED_TEMPLATE.to_owned();
    pin.request.memory_mib = 22 * 1_024;
    pin.request.devices[0].memory_mib = 22 * 1_024;
    pin.request.devices[0].features = Vec::new();
    pin
}

fn reserve(issuer: EntityId, key: &str, pin: &WorkloadPin) -> JobReserve {
    JobReserve {
        key: key.to_owned(),
        pin: pin.clone(),
        slot: SlotSelector::default(),
        issuer,
        starter: Starter::Owner,
        issued_at_ms: NOW_MS,
        not_after_ms: NOW_MS + 300_000,
    }
}

fn submit(issuer: EntityId, key: &str, pin: &WorkloadPin) -> TestResult<SignedJobSubmit> {
    let submit = JobSubmit {
        key: key.to_owned(),
        job: EntityId::now(),
        chunk: 0,
        pin: pin.clone(),
        slot: SlotSelector::default(),
        maximum_secs: pin.request.maximum_secs,
        issued_at_ms: NOW_MS,
        not_after_ms: NOW_MS + 300_000,
        issuer,
        starter: Starter::Owner,
        hold: HoldRef {
            reservation: format!("hold-{key}"),
            generation: 1,
        },
        authority_heads: Vec::new(),
        continues: None,
    };
    SignedJobSubmit::sign(submit, ScriptedSigner::new(issuer).as_ref())
        .map_err(at("the issuer signs"))
}

fn receipt(answer: JobAnswer) -> TestResult<JobReceipt> {
    match answer {
        JobAnswer::Receipt(signed) => Ok(signed.receipt),
        other => Err(format!("expected a receipt, got {other:?}").into()),
    }
}

/// Waits until `key` exists and `done` holds for it: the staging worker and the launch commit
/// run on threads of their own and signal nothing a test could await.
fn wait_for(jobs: &NodeJobs, key: &str, done: impl Fn(&NodeKey) -> bool) -> TestResult<NodeKey> {
    // testkit-lint: allow(wall-clock) bounds a wait on the node's own worker threads
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        let found = jobs.keys().into_iter().find(|entry| entry.key == key);
        if let Some(found) = found.filter(|entry| done(entry)) {
            return Ok(found);
        }
        // testkit-lint: allow(wall-clock) the same bound
        if std::time::Instant::now() >= deadline {
            return Err(format!("key {key} did not reach the state").into());
        }
        // testkit-lint: allow(sleep) the poll interval; the worker threads signal nothing
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn the_owners_pause_during_staging_refuses_the_launch_inside_the_launch_commit() -> TestResult {
    let rig = Rig::new("")?;
    let dir = tempfile::tempdir()?;
    let scripted = ScriptedNode::new(
        dir.path(),
        rig.device.machine,
        STAGED_TEMPLATE,
        STAGED_DIGEST,
        NOW_MS,
    );
    let mut parts = scripted.parts();
    parts.admission = Arc::new(PolicyAdmission {
        node: node_of(&rig.device, &rig.file),
        scripted: Arc::clone(&scripted.admission),
    });
    let jobs = NodeJobs::open(scripted.paths.clone(), parts)?;
    let issuer = EntityId::now();
    let pin = staged_pin();

    // The owner pauses N after the submit, while the key stages: the launch commit reads his row
    // from N's own fold, and the key ends refused, its unit never started.
    let key = "job-p0/paused";
    scripted.stager.hold();
    assert_eq!(
        receipt(jobs.reserve(issuer, reserve(issuer, key, &pin)))?.state,
        JobState::Held
    );
    assert_eq!(
        receipt(jobs.submit(issuer, submit(issuer, key, &pin)?))?.state,
        JobState::Accepted
    );
    assert!(scripted.stager.wait_entered(1, WAIT), "the key stages");
    rig.owner_sets(EXECUTION, None, json!({ "state": "paused" }))?;
    scripted.stager.let_go();
    let ended = wait_for(&jobs, key, |entry| entry.state == JobState::Ended)?;
    assert!(
        matches!(&ended.end, Some(JobEnd::LaunchRefused { reason }) if reason == "node_paused: owner: paused"),
        "{:?}",
        ended.end
    );
    assert_eq!(scripted.units.starts(key), 0, "no unit started");

    // The owner turns N back on: the next key launches.
    rig.owner_sets(EXECUTION, None, json!({ "state": "on" }))?;
    let next = "job-p0/on";
    assert_eq!(
        receipt(jobs.reserve(issuer, reserve(issuer, next, &pin)))?.state,
        JobState::Held
    );
    assert_eq!(
        receipt(jobs.submit(issuer, submit(issuer, next, &pin)?))?.state,
        JobState::Accepted
    );
    wait_for(&jobs, next, |entry| entry.state == JobState::Launching)?;
    jobs.tick();
    wait_for(&jobs, next, |entry| entry.state == JobState::Running)?;
    Ok(())
}

/// Row P0 with row Q4 (pass 34 2.4 and 7.3): a passed readiness check clears the node's drain
/// only when the box's `drain_clear_by` and the owner's `machines.drain.clear_by` both leave it to
/// the check. The owner's `owner` keeps the drain for the box, since no owner act reaches the
/// node's own drain yet, and the box's `person_at_box` holds whatever the owner's row says.
#[test]
fn a_passing_readiness_check_clears_the_drain_only_when_the_owner_leaves_it_to_the_check()
-> TestResult {
    let rig = Rig::new("")?;
    let clear_by = |rig: &Rig| NodeAdmission::job_settings(&rig.node).drain_clear_by;
    assert_eq!(
        clear_by(&rig),
        DrainClearBy::AfterReadinessCheck,
        "with no row of the owner's, the box's default leaves the clear to the check"
    );

    rig.owner_sets(DRAIN_CLEAR_BY, None, json!({ "by": "owner" }))?;
    assert_eq!(
        clear_by(&rig),
        DrainClearBy::PersonAtBox,
        "the owner's `owner` keeps the node's drain from the check"
    );

    rig.owner_sets(
        DRAIN_CLEAR_BY,
        None,
        json!({ "by": "after_readiness_check" }),
    )?;
    assert_eq!(
        clear_by(&rig),
        DrainClearBy::AfterReadinessCheck,
        "the owner gives the clear back to the check"
    );

    rig.box_writes(r#"drain_clear_by = "person_at_box""#)?;
    assert_eq!(
        clear_by(&rig),
        DrainClearBy::PersonAtBox,
        "the box's `person_at_box` holds under the owner's `after_readiness_check`"
    );
    Ok(())
}

/// Row P0 with row Q4 (pass 34 6.3 and 7.3): the node checks itself at the shorter of the box's
/// `readiness_every_secs` and the owner's `jobs.readiness.every_secs`, and at the box's alone when
/// its file does not accept the owner's policy.
#[test]
fn the_node_checks_itself_at_the_shorter_of_the_box_and_owner_periods() -> TestResult {
    let rig = Rig::new("readiness_every_secs = 900")?;
    let every_secs = |rig: &Rig| NodeAdmission::job_settings(&rig.node).readiness_every_secs;
    assert_eq!(every_secs(&rig), 900, "no row of the owner's: the box's");

    rig.owner_sets(READINESS_EVERY_SECS, None, json!(60))?;
    assert_eq!(every_secs(&rig), 60, "the owner's shorter period");

    rig.owner_sets(READINESS_EVERY_SECS, None, json!(3600))?;
    assert_eq!(every_secs(&rig), 900, "the box's shorter period");

    rig.box_writes("readiness_every_secs = 7200")?;
    assert_eq!(
        every_secs(&rig),
        3600,
        "the owner's period, now the shorter"
    );

    rig.box_writes("readiness_every_secs = 7200\nowner_policy = false")?;
    assert_eq!(
        every_secs(&rig),
        7200,
        "a box that does not accept the owner's policy keeps its own"
    );
    Ok(())
}
