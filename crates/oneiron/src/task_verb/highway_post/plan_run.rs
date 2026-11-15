//! Plan mode's run (Engine ruling RUN = A, Fri 13 Nov 03:05): the owner's
//! approval of a plan-doc that names an agent definition lands the plan's
//! run in the approving writer, as the owner's own post to that definition
//! would land: a TASK whose brief pins the plan at the approved revision,
//! asks the plan's steps as its done-means and carries the plan's budget.
//! Entry: `Memory::land_plan_run_in_txn`.

use super::*;
use crate::llm::decision::Reversibility;
use crate::llm::decision::questions::QuestionCriteria;
use crate::note::PlanDocBody;
use crate::task_verb::ask_types::{TaskAskDefault, TaskAskTarget};
use crate::task_verb::consts::TASK_BRIEF_SCHEMA;
use crate::task_verb::{
    BriefConstraints, BriefContext, BriefIntent, Criterion, DoneMeans, EscalationRule,
    EscalationTrigger, PinnedRef, SpawnPins, TypeRef,
};

/// The intent key of plan `plan`'s run at `revision`: one run per approved
/// revision.
fn plan_run_key(plan: EntityId, revision: &[u8; 32]) -> String {
    format!(
        "plan:{}@{}",
        plan.to_hex(),
        crate::entity_id::bytes_to_hex_lower(revision)
    )
}

/// The brief of plan `plan`'s run at `revision`, read from its text as
/// `body`: the title as objective and need, the scope asked as constraint
/// notes, the budget as its pinned budget, the plan pinned at the revision
/// as the one read-first handle, and each step a criterion that must hold.
/// It escalates to `owner` when blocked, when it needs wider scope or when
/// it overspends, and holds when nobody answers. The type is the team
/// tree's root, the unsure placement.
fn plan_run_brief(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
    plan: EntityId,
    revision: &[u8; 32],
    body: &PlanDocBody,
) -> MemoryResult<QueueTaskBrief> {
    let tree = crate::agent_dispatch::load_team_type_tree_in_txn(vault, txn, None)?;
    let root = tree
        .node(crate::task_type::ROOT_TYPE_NODE)
        .ok_or(Error::InvariantViolation("a task type tree holds its root"))?;
    Ok(QueueTaskBrief {
        schema: TASK_BRIEF_SCHEMA,
        type_ref: TypeRef {
            node_id: root.entity_id()?,
            tree_version: tree.version,
        },
        objective: body.title.clone(),
        intent: BriefIntent {
            need: body.title.clone(),
            care: None,
        },
        constraints: BriefConstraints {
            notes: body.scope_asked.clone(),
            pins: SpawnPins {
                budget: body.budget,
                ..SpawnPins::default()
            },
            ..BriefConstraints::default()
        },
        context: BriefContext {
            read_first: vec![PinnedRef {
                target: plan,
                frontier: None,
                digest: *revision,
            }],
            ..BriefContext::default()
        },
        success: DoneMeans {
            question: format!("Is the approved plan \"{}\" carried out?", body.title),
            criteria: QuestionCriteria {
                yes_if_all: body
                    .steps
                    .iter()
                    .map(|step| Criterion {
                        text: step.clone(),
                        evidence_ref: None,
                    })
                    .collect(),
                ..QuestionCriteria::default()
            },
            outcome_binding: None,
            browser_checks: Vec::new(),
            strict_verified_reuse: false,
        },
        settled: Vec::new(),
        escalation: EscalationRule {
            to: TaskAskTarget::People([owner].into_iter().collect()),
            triggers: vec![
                EscalationTrigger::Blocked,
                EscalationTrigger::ScopeWiden,
                EscalationTrigger::SpendOver,
            ],
            default: TaskAskDefault::Hold,
            until: None,
            reversibility: Reversibility::ReversibleRead,
            question_ref: None,
        },
        project_ref: None,
        composed: None,
    })
}

impl Memory<'_> {
    /// Lands the run of plan `plan`, approved at `revision` by this handle's
    /// actor, the owner, inside the approving writer: the owner's post to
    /// agent definition `agent_def_ref` under intent key
    /// `plan:<plan>@<revision>`, minted, routed to its agent and assigned.
    /// A revision approved again keeps the run its first approval landed.
    /// Returns the run's TASK.
    ///
    /// # Errors
    ///
    /// The refusals a settled post's landing meets, such as an agent
    /// definition that is gone.
    pub(crate) fn land_plan_run_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        plan: EntityId,
        revision: &[u8; 32],
        body: &PlanDocBody,
        agent_def_ref: EntityId,
    ) -> MemoryResult<EntityId> {
        let key = PostKey::of(&TaskVia::Wire, &plan_run_key(plan, revision))?;
        let task_ref = EntityId::derive(
            TASK_POST_ID_DOMAIN,
            &[self.actor().as_bytes(), key.stored.as_bytes()],
        )?;
        if task_verb_body_in(self.vault(), &*wtxn, task_ref)?.is_some() {
            return Ok(task_ref);
        }
        let brief = plan_run_brief(self.vault(), &*wtxn, self.actor(), plan, revision, body)?;
        let post = TaskPost {
            intent_key: key.text.clone(),
            brief,
            assignee: TaskAssignee::AgentDef { agent_def_ref },
            spec: None,
            ttl: None,
            label: Some(body.title.clone()),
            parent_ref: None,
            due_at: None,
            watch: false,
        };
        let digest = request_digest(self.actor(), &key.text, &post, None)?;
        let origin = task_create_origin_in_txn(self, &*wtxn, None)?;
        self.land_settled_post_in_txn(
            wtxn,
            task_ref,
            &post,
            &post_provenance(&key.stored, &digest, None),
            origin.as_ref(),
            self.vault().now_recorded_at(),
            false,
        )?;
        Ok(task_ref)
    }
}
