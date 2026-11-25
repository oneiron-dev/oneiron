//! `vault.machines.status`'s node half (design pass 34 section 5 and row Q2): the issuer asks
//! each of the owner's machines its `Node` answer and says what came back. A machine that gives
//! no answer is `unknown`, never idle or stopped (pass 34 invariant I3), and its last sample, the
//! capacity claim it wrote itself, still shows with its age. A node that answered with a refusal
//! says which; this install and a removed machine are not asked.
//!
//! The issuer's calls go to a scripted node, so this runs without a mesh. Fleet command:
//! `cargo test --locked -p oneiron-server --all-features --test machine_status`.
use std::collections::BTreeMap;
use std::sync::Mutex;

use oneiron::EntityId;
use oneiron::machine_capacity::{MachineCapacity, MachinePower};
use oneiron::machine_names::MachineNameSource;
use oneiron::task_verb::sdk::{
    MachineCapacityView, MachineListItem, MachineNodeView, MachineStatusItem, MachineStatusReply,
};
use oneiron_server::gpu_execution_node::issuer::node_status::ask_nodes;
use oneiron_server::gpu_execution_node::issuer::{JobNodeClient, NodeCallError};
use oneiron_server::gpu_execution_node::wire::{
    JobAnswer, JobRefusal, JobRequest, JobStatusAnswer, JobStatusRequest, NodeAnswer,
};

/// When the status is read, on the issuer's clock.
const READ_AT_MS: u64 = 1_764_000_000_000;
/// When each machine last measured its capacity: an hour before, in Unix seconds.
const MEASURED_AT: u64 = READ_AT_MS / 1_000 - 3_600;

fn id(n: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x05;
    bytes[15] = n;
    EntityId::from_bytes_unchecked(bytes)
}

fn this_install() -> EntityId {
    id(1)
}
fn answering() -> EntityId {
    id(2)
}
fn refusing() -> EntityId {
    id(3)
}
fn unreachable() -> EntityId {
    id(4)
}
fn removed() -> EntityId {
    id(5)
}

/// The scripted nodes: each machine's answer to `Node`, and every machine asked.
struct ScriptedNodes {
    answers: BTreeMap<EntityId, Result<JobAnswer, NodeCallError>>,
    asked: Mutex<Vec<EntityId>>,
}

impl JobNodeClient for ScriptedNodes {
    fn job(&self, node: EntityId, request: &JobRequest) -> Result<JobAnswer, NodeCallError> {
        assert!(
            matches!(request, JobRequest::Node),
            "the status asks Node only"
        );
        self.asked.lock().expect("the script's lock").push(node);
        self.answers
            .get(&node)
            .cloned()
            .unwrap_or(Err(NodeCallError::Unreachable {
                reason: "no route to the machine".to_owned(),
            }))
    }

    fn job_status(
        &self,
        _node: EntityId,
        _request: &JobStatusRequest,
    ) -> Result<JobStatusAnswer, NodeCallError> {
        panic!("the status never asks the status protocol")
    }
}

fn node_answer() -> NodeAnswer {
    NodeAnswer {
        enabled: true,
        paused: Some("owner at the box".to_owned()),
        drained: None,
        templates: Vec::new(),
        scopes: Vec::new(),
        disk_free_bytes: 200 << 30,
        disk_reserved_bytes: 0,
        disk_reserve_bytes: 50 << 30,
        epoch: Some("ab".repeat(16)),
        swept: true,
        boot_id: "boot-7".to_owned(),
        engine_version: "0.0.0-test".to_owned(),
    }
}

fn capacity() -> MachineCapacity {
    MachineCapacity {
        cores: 16,
        memory_total_bytes: 64 << 30,
        memory_reserve_bytes: 4 << 30,
        memory_available_bytes: 40 << 30,
        gpu_memory_mib: vec![24_576],
        disk_total_bytes: 2 << 40,
        disk_free_bytes: 1 << 40,
        power: MachinePower::Mains,
        agent_memory_budget_bytes: 2 << 30,
        agents: 18,
        measured_at: MEASURED_AT,
    }
}

/// One machine as the vault half lists it: its capacity claim, and its node not asked yet.
fn item(machine: EntityId, this_install: bool, role: &str) -> MachineStatusItem {
    MachineStatusItem {
        machine: MachineListItem {
            machine: machine.to_hex(),
            class: "computer".to_owned(),
            role: Some(role.to_owned()),
            live: role != "removed",
            name: format!("machine-{}", machine.as_bytes()[15]),
            name_source: MachineNameSource::Class,
            owner_name: None,
            reported_name: None,
            reported_model: None,
            this_install,
            revision: "00".repeat(32),
        },
        capacity: Some(MachineCapacityView::of(&capacity(), READ_AT_MS)),
        node: MachineNodeView::not_asked("not_reached"),
    }
}

fn node_of(reply: &MachineStatusReply, machine: EntityId) -> &MachineStatusItem {
    reply
        .machines
        .iter()
        .find(|item| item.machine.machine == machine.to_hex())
        .expect("the machine is listed")
}

#[test]
fn machine_status_shows_an_unreachable_node_as_unknown_with_its_last_sample_age() {
    let nodes = ScriptedNodes {
        answers: BTreeMap::from([
            (answering(), Ok(JobAnswer::Node(node_answer()))),
            (refusing(), Ok(JobAnswer::Refused(JobRefusal::NotIssuer))),
            (unreachable(), Err(NodeCallError::Timeout)),
        ]),
        asked: Mutex::new(Vec::new()),
    };
    let mut reply = MachineStatusReply {
        machines: vec![
            item(this_install(), true, "yours"),
            item(answering(), false, "execution_node"),
            item(refusing(), false, "execution_node"),
            item(unreachable(), false, "execution_node"),
            item(removed(), false, "removed"),
        ],
        read_at_ms: READ_AT_MS,
    };

    ask_nodes(&mut reply, &nodes, READ_AT_MS);

    // This install and a removed machine are not asked.
    let mut asked = nodes.asked.lock().expect("the script's lock").clone();
    asked.sort();
    assert_eq!(asked, vec![answering(), refusing(), unreachable()]);
    assert_eq!(node_of(&reply, this_install()).node.state, "not_asked");
    assert_eq!(
        node_of(&reply, this_install()).node.not_asked.as_deref(),
        Some("this_install")
    );
    assert_eq!(
        node_of(&reply, removed()).node.not_asked.as_deref(),
        Some("removed")
    );

    // A node that answered shows its answer, paused as it said.
    let answered = &node_of(&reply, answering()).node;
    assert_eq!(answered.state, "answered");
    assert_eq!(answered.asked_at_ms, Some(READ_AT_MS));
    let answer = answered.answer.as_ref().expect("the node's answer");
    assert!(answer.enabled);
    assert_eq!(answer.paused.as_deref(), Some("owner at the box"));

    // A refusal says which.
    let refused = &node_of(&reply, refusing()).node;
    assert_eq!(refused.state, "refused");
    assert_eq!(refused.refusal.as_deref(), Some("not_issuer"));
    assert!(refused.answer.is_none());

    // No answer in time: unknown, with no answer and no figure of its own, and the machine's
    // last sample still shows, an hour old.
    let silent = node_of(&reply, unreachable());
    assert_eq!(silent.node.state, "unknown");
    assert!(silent.node.answer.is_none());
    assert_eq!(
        silent.node.error.as_deref(),
        Some(NodeCallError::Timeout.to_string().as_str())
    );
    let sample = silent.capacity.as_ref().expect("the last capacity claim");
    assert_eq!(sample.measured_at_ms, MEASURED_AT * 1_000);
    assert_eq!(sample.age_ms, 3_600_000);
    assert_eq!(sample.agents, 18);
}
