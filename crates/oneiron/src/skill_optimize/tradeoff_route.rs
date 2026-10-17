//! The Coach's tradeoff router (FIX-LIST 817; the Engine's call "OF-495
//! tradeoff router"). A skill tradeoff ask bound to a project's goal is asked
//! on a TASK of each project whose board it has reached, as a visible turn in
//! that project's home room (`vault.projects.route_tradeoff`). The Coach never
//! speaks in a room: it hands the call to the project's leader. A leader agent
//! is dispatched with a brief naming the call; a person leader gets an Ask
//! carrying it. The TASK is the project's newest one that a run of the skill
//! served, else the project's newest TASK. A project with neither, or with no
//! live leader, is left to the ask's climb toward the owner.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::context_projection::ContextSpec;
use crate::entity_id::bytes_to_hex_lower;
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::{
    PROVENANCE_OPTIMIZE_OF_KEY, PROVENANCE_OPTIMIZE_RECEIPTS_KEY, SkillTradeoffAsk, TradeoffRole,
    pending_skill_tradeoff_asks, skill_tradeoff_ask,
};
use crate::{EntityId, Result, Vault};

/// The producer of a person leader's Ask.
pub const TRADEOFF_ROUTE_NOTIFICATION_PRODUCER: &str = "coach.tradeoff_route";
/// The verb a leader calls to ask the question on its project's board.
const ROUTE_VERB: &str = "vault.projects.route_tradeoff";

/// One hand-off per `(proposal, project, question digest)`: a dispatched
/// leader or an asked person is not handed the same call again.
const ISSUED: SideTable<String, TradeoffRouteIssue, Named> =
    SideTable::new(&side_table::SKILL_TRADEOFF_ROUTE);

/// Who the route call was handed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeoffRouteChannel {
    /// The leader agent, by the dispatched attempt (32 hex).
    Dispatched { attempt: String },
    /// The person leader, by an Ask in their inbox.
    Asked { person: String },
}

/// One handed-off route call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TradeoffRouteIssue {
    pub proposal: String,
    pub project: String,
    pub question_digest: String,
    /// The TASK the call names.
    pub task: String,
    pub channel: TradeoffRouteChannel,
    pub at: u64,
}

/// What one pass did, per reached project of each pending ask.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TradeoffRouteReport {
    pub dispatched: u32,
    pub asked: u32,
    /// Routed already, or handed off already.
    pub held: u32,
    /// No TASK, or no live leader: left to the climb.
    pub skipped: u32,
    /// A hand-off that failed; the next pass tries again.
    pub failed: u32,
}

enum Handed {
    Dispatched,
    Asked,
    Held,
    Skipped,
}

/// One routing pass over the pending project-bound tradeoff asks.
pub(crate) fn run_tradeoff_route(vault: &Vault, now: u64) -> Result<TradeoffRouteReport> {
    let mut report = TradeoffRouteReport::default();
    for listed in pending_skill_tradeoff_asks(vault)? {
        // The single read applies the learning cap the list does not.
        let Some(ask) = skill_tradeoff_ask(vault, &listed.question.proposal)? else {
            continue;
        };
        if ask.question.project.is_none() {
            continue;
        }
        let digest = ask.question.digest()?;
        let served = served_tasks(vault, &ask)?;
        for project in reached(&ask) {
            let handed = route_project(vault, &ask, project, &digest, &served, now);
            let tally = match handed {
                Ok(Handed::Dispatched) => &mut report.dispatched,
                Ok(Handed::Asked) => &mut report.asked,
                Ok(Handed::Held) => &mut report.held,
                Ok(Handed::Skipped) => &mut report.skipped,
                Err(_) => &mut report.failed,
            };
            *tally += 1;
        }
    }
    Ok(report)
}

/// The projects an ask may be routed to: its goal's project and every board
/// its climb has reached.
fn reached(ask: &SkillTradeoffAsk) -> BTreeSet<EntityId> {
    let reach = usize::try_from(ask.rung).map_or(usize::MAX, |rung| rung.saturating_add(1));
    ask.question
        .project
        .into_iter()
        .chain(
            ask.question
                .roles
                .iter()
                .take(reach)
                .filter_map(|role| match role {
                    TradeoffRole::Board { project, .. } => Some(*project),
                    _ => None,
                }),
        )
        .collect()
}

/// The TASKs the skill's runs served: the proposal's evidence receipts whose
/// pack loaded the skill it revises, by their attempts' TASK.
fn served_tasks(vault: &Vault, ask: &SkillTradeoffAsk) -> Result<BTreeSet<EntityId>> {
    let mut tasks = BTreeSet::new();
    let Some(proposal) = vault.get_skill_record(&ask.question.proposal)? else {
        return Ok(tasks);
    };
    let rmpv::Value::Map(provenance) = &proposal.provenance else {
        return Ok(tasks);
    };
    let field = |name: &str| {
        provenance
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    let Some(skill_id) = field(PROVENANCE_OPTIMIZE_OF_KEY).and_then(rmpv::Value::as_str) else {
        return Ok(tasks);
    };
    let receipts = field(PROVENANCE_OPTIMIZE_RECEIPTS_KEY)
        .and_then(rmpv::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let queue = AttemptQueue::new(vault);
    for receipt in receipts.iter().filter_map(rmpv::Value::as_str) {
        let loaded = crate::receipt::attempt_pack_receipt(vault, receipt)?
            .and_then(|record| record.pack_manifest_skills())
            .is_some_and(|skills| {
                skills
                    .iter()
                    .any(|entry| entry.split_once('@').is_some_and(|(id, _)| id == skill_id))
            });
        let attempt = receipt
            .strip_prefix("attempt:")
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .and_then(|id| AttemptId::from_bytes(id.as_bytes()).ok());
        if let (true, Some(attempt)) = (loaded, attempt)
            && let Some(record) = queue.get(attempt)?
            && let Some(task) = record
                .task_ref
                .as_deref()
                .and_then(|hex| EntityId::from_hex(hex).ok())
        {
            tasks.insert(task);
        }
    }
    Ok(tasks)
}

/// Hands one reached project's route call to its leader, once.
fn route_project(
    vault: &Vault,
    ask: &SkillTradeoffAsk,
    project: EntityId,
    digest: &str,
    served: &BTreeSet<EntityId>,
    now: u64,
) -> Result<Handed> {
    let proposal = ask.question.proposal;
    let key = format!("{}:{}:{digest}", proposal.to_hex(), project.to_hex());
    let (task, leader) = {
        let txn = vault.store.env.read_txn()?;
        if ISSUED.get(&vault.store, &txn, &key)?.is_some()
            || crate::task_verb::project_tradeoff_routed_in(vault, &txn, proposal, project, digest)?
        {
            return Ok(Handed::Held);
        }
        let Some((record, effective)) = vault.effective_project_in_txn(&txn, project)? else {
            return Ok(Handed::Skipped);
        };
        let placed: Vec<EntityId> = record
            .tasks
            .iter()
            .filter_map(|hex| EntityId::from_hex(hex).ok())
            .collect();
        let served_here: Vec<EntityId> = placed
            .iter()
            .copied()
            .filter(|task| served.contains(task))
            .collect();
        let task = match newest(vault, &txn, &served_here)? {
            Some(task) => Some(task),
            None => newest(vault, &txn, &placed)?,
        };
        let Some(task) = task else {
            return Ok(Handed::Skipped);
        };
        let Ok(leader) = EntityId::from_hex(&effective.leader) else {
            return Ok(Handed::Skipped);
        };
        let kind = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &leader)?
            .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
            .map(|header| header.entity_type);
        let leader = match kind {
            Some(crate::registry::ENTITY_TYPE_AGENT_DEF) => Leader::Agent(leader),
            Some(crate::registry::ENTITY_TYPE_PERSON)
                if crate::consent::person_is_live_in_txn(vault, &txn, &leader)? =>
            {
                Leader::Person(leader)
            }
            _ => return Ok(Handed::Skipped),
        };
        (task, leader)
    };
    let call = serde_json::json!({
        "verb": ROUTE_VERB,
        "input": {"task_ref": task.to_hex(), "proposal_ref": proposal.to_hex()},
    });
    let issue = |channel| TradeoffRouteIssue {
        proposal: proposal.to_hex(),
        project: project.to_hex(),
        question_digest: digest.to_owned(),
        task: task.to_hex(),
        channel,
        at: now,
    };
    match leader {
        Leader::Agent(agent) => {
            let briefing = format!(
                "A skill tradeoff is waiting for project {project}'s board. Ask it there: call \
                 {ROUTE_VERB} with {input}. Only ask the question; do not answer the tradeoff.",
                project = project.to_hex(),
                input = call["input"],
            );
            let outcome = AgentDispatcher::new(vault).dispatch_with_context(
                DispatchAgent {
                    target: AgentDispatchTarget::Custom(agent),
                    parent_attempt: None,
                    dedupe_key: Some(format!(
                        "tradeoff_route:{}",
                        &blake3::hash(key.as_bytes()).to_hex()[..32]
                    )),
                    run_id: Some(format!("tradeoff-route:{}", proposal.to_hex())),
                    now,
                },
                AgentSpawnContext {
                    context_spec: Some(ContextSpec::default().with_briefing(briefing)),
                    ..AgentSpawnContext::default()
                },
            )?;
            let (AgentDispatchOutcome::Dispatched(status) | AgentDispatchOutcome::Existing(status)) =
                outcome
            else {
                return Ok(Handed::Skipped);
            };
            let issued = issue(TradeoffRouteChannel::Dispatched {
                attempt: bytes_to_hex_lower(status.attempt.id.as_bytes()),
            });
            vault.with_write_txn_grouped(|txn| ISSUED.put(&vault.store, txn, &key, &issued))?;
            Ok(Handed::Dispatched)
        }
        Leader::Person(person) => {
            let issued = issue(TradeoffRouteChannel::Asked {
                person: person.to_hex(),
            });
            vault.with_write_txn_grouped(|txn| {
                vault.record_notification_in_txn(
                    txn,
                    &crate::inbox::NotificationEvent {
                        kind: crate::inbox::NotificationKind::Ask,
                        source: crate::inbox::NotificationSource {
                            producer: TRADEOFF_ROUTE_NOTIFICATION_PRODUCER.to_owned(),
                            event: format!("{key}:{}", person.to_hex()),
                            result: Some(call.to_string()),
                            ..crate::inbox::NotificationSource::default()
                        },
                        subject_refs: vec![task, proposal, project],
                        recipient: Some(person),
                        created_at: now,
                        origin_conversation: None,
                    },
                )?;
                ISSUED.put(&vault.store, txn, &key, &issued)
            })?;
            Ok(Handed::Asked)
        }
    }
}

enum Leader {
    Agent(EntityId),
    Person(EntityId),
}

/// The most recently created of `tasks`; `None` when none names a TASK.
fn newest(vault: &Vault, txn: &heed::RoTxn<'_>, tasks: &[EntityId]) -> Result<Option<EntityId>> {
    let mut newest = None;
    for task in tasks {
        if let Some(created) = crate::task_verb::task_created_at_in(vault, txn, *task)?
            && newest.is_none_or(|(at, id)| (created, *task) > (at, id))
        {
            newest = Some((created, *task));
        }
    }
    Ok(newest.map(|(_, task)| task))
}
