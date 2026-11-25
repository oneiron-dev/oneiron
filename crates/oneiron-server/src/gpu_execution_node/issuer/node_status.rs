//! The node half of `vault.machines.status` (design pass 34 section 5, row Q2): the issuer asks
//! each machine its `Node` answer on `oneiron/job/1` and says what came back. Nothing is stored:
//! an answer is a sample, and a machine that does not answer is `unknown`, never idle (pass 34
//! invariant I3). The calls run at once, one thread each, so the read waits at most one call
//! timeout however many machines the vault has.
use oneiron::EntityId;
use oneiron::task_verb::sdk::{
    MachineNodeAnswer, MachineNodeView, MachineStatusItem, MachineStatusReply,
};

use super::job_refusal_code;
use super::node_client::{JobNodeClient, NodeCallError};
use crate::gpu_execution_node::wire::{JobAnswer, JobRequest, NodeAnswer};

/// Why a machine of the list is not asked: this install, or a removed machine.
fn not_asked_why(item: &MachineStatusItem) -> Option<&'static str> {
    if item.machine.this_install {
        Some("this_install")
    } else if item.machine.role.as_deref() == Some("removed") {
        Some("removed")
    } else {
        None
    }
}

/// Asks every machine of `reply` that is not this install and not removed for its `Node`
/// answer through `client`, at `asked_at_ms`, and writes what came back on its row. A call
/// that could not start leaves its machine `not_asked` with why; a call that started and did
/// not come back leaves it `unknown`. The other rows keep their answers.
pub fn ask_nodes(reply: &mut MachineStatusReply, client: &dyn JobNodeClient, asked_at_ms: u64) {
    let asks: Vec<(usize, EntityId)> = reply
        .machines
        .iter()
        .enumerate()
        .filter(|(_, item)| not_asked_why(item).is_none())
        .filter_map(|(index, item)| {
            EntityId::from_hex(&item.machine.machine)
                .ok()
                .map(|machine| (index, machine))
        })
        .collect();
    for item in &mut reply.machines {
        if let Some(why) = not_asked_why(item) {
            item.node = MachineNodeView::not_asked(why);
        }
    }
    let views: Vec<(usize, MachineNodeView)> = std::thread::scope(|scope| {
        let calls: Vec<_> = asks
            .iter()
            .map(|&(index, machine)| {
                let call = std::thread::Builder::new()
                    .name("machine-status-node".to_owned())
                    .spawn_scoped(scope, move || {
                        node_view(client.job(machine, &JobRequest::Node), asked_at_ms)
                    });
                (index, call)
            })
            .collect();
        calls
            .into_iter()
            .map(|(index, call)| {
                let view = match call {
                    Err(_) => MachineNodeView::not_asked("call_not_started"),
                    Ok(call) => call.join().unwrap_or_else(|_| {
                        MachineNodeView::unknown(
                            "the call to the machine failed".to_owned(),
                            asked_at_ms,
                        )
                    }),
                };
                (index, view)
            })
            .collect()
    });
    for (index, view) in views {
        reply.machines[index].node = view;
    }
}

/// What one `Node` call says about the machine.
#[must_use]
pub fn node_view(answer: Result<JobAnswer, NodeCallError>, asked_at_ms: u64) -> MachineNodeView {
    match answer {
        Ok(JobAnswer::Node(node)) => MachineNodeView::answered(node_answer(node), asked_at_ms),
        Ok(JobAnswer::Refused(refusal)) => {
            MachineNodeView::refused(job_refusal_code(&refusal).to_owned(), asked_at_ms)
        }
        Ok(other) => MachineNodeView::unknown(
            format!("the machine answered another request: {other:?}"),
            asked_at_ms,
        ),
        Err(error) => MachineNodeView::unknown(error.to_string(), asked_at_ms),
    }
}

fn node_answer(node: NodeAnswer) -> MachineNodeAnswer {
    MachineNodeAnswer {
        enabled: node.enabled,
        paused: node.paused,
        drained: node.drained,
        templates: node
            .templates
            .into_iter()
            .map(|template| template.name)
            .collect(),
        disk_free_bytes: node.disk_free_bytes,
        disk_reserved_bytes: node.disk_reserved_bytes,
        disk_reserve_bytes: node.disk_reserve_bytes,
        epoch: node.epoch,
        swept: node.swept,
        boot_id: node.boot_id,
        engine_version: node.engine_version,
    }
}
