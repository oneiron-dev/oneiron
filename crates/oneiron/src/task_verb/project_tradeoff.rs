//! A project-bound skill tradeoff over the project's own doors (ARCH-0053
//! §10a, ARCH-0067 tasks and asks). The A/B question the skill gate keeps for
//! a goal joined to a project rides an ordinary project ask: the exact
//! question is witnessed as a visible TURN in the project's home room, and
//! that TURN is the question an ask on one of the project's TASKs carries.
//!
//! The gate's ask row stays the domain state. The route row here is a
//! reference from the project ask to the gate's question, never an authority:
//! an answer on the project ask settles nothing by itself, and only
//! [`Memory::tasks_settle_project_tradeoff`] (an authenticated person's pick)
//! or [`Memory::tasks_settle_project_tradeoff_as_agent`] (a bound agent's
//! pick) hands it to the gate, whose role and digest checks decide it. A
//! route voided because its question moved cuts its ask Stale in the same
//! commit, so the old ask stops waiting for its deadline; that question,
//! asked again, opens a fresh ask after the void one. The pick the
//! gate learns is proposed for the project's goal record; the project's
//! members read those proposals here and a vault owner may dismiss one.
use std::collections::{BTreeMap, BTreeSet};

use super::ConsultPayloadRef;
use super::ask_types::*;
use super::create_validation::consult_refusal;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, WitnessAuthor, WitnessMessage,
    WitnessTurn, verify_actor_binding,
};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::{
    HeldOutVerdict, ProjectGoalRevisionProposal, SkillTradeoffAsk, TradeoffChoice, TradeoffRole,
};
use serde::{Deserialize, Serialize};

/// The home-room TURN one question was witnessed as. Its ids are reserved
/// before the speak, so a retry lands the same TURN instead of a second one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionTurn {
    turn: EntityId,
    message: EntityId,
    occurred_at: u64,
}

/// What one project ask carries: the gate's question by reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectTradeoffRoute {
    proposal: EntityId,
    question_digest: String,
    project: EntityId,
    task: EntityId,
    turn: EntityId,
    state: RouteState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum RouteState {
    Open,
    /// The gate settled the question this ask carried.
    Settled {
        verdict: EntityId,
        at: u64,
    },
    /// The question moved before a pick settled it. Its answers settle
    /// nothing; the current question is routed as a new ask.
    Void {
        at: u64,
    },
}

/// `(proposal, project, question digest)` → the question's TURN there.
const QUESTION_TURNS: SideTable<(EntityId, EntityId, String), QuestionTurn, Named> =
    SideTable::new(&side_table::TASK_PROJECT_TRADEOFF_TURN);

/// `ask group` → the skill tradeoff it carries.
const ROUTES: SideTable<EntityId, ProjectTradeoffRoute, Named> =
    SideTable::new(&side_table::TASK_PROJECT_TRADEOFF_ASK);

/// Whether an ask on `project`'s TASK reaches people the tradeoff ask has
/// reached: the joined project's own, or a parent board it climbed to.
fn reaches(ask: &SkillTradeoffAsk, project: EntityId) -> bool {
    let reached = usize::try_from(ask.rung).map_or(usize::MAX, |rung| rung.saturating_add(1));
    ask.question.project == Some(project)
        || ask.question.roles.iter().take(reached).any(
            |role| matches!(role, TradeoffRole::Board { project: board, .. } if *board == project),
        )
}

/// Whether a route already carries this exact question to `project`, open or
/// settled (the Coach's tradeoff router, FIX-LIST 817). A void route does not:
/// its question moved.
pub(crate) fn project_tradeoff_routed_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    proposal: EntityId,
    project: EntityId,
    question_digest: &str,
) -> crate::Result<bool> {
    Ok(ROUTES
        .scan(&vault.store, txn)?
        .into_iter()
        .any(|(_, route)| {
            route.proposal == proposal
                && route.project == project
                && route.question_digest == question_digest
                && !matches!(route.state, RouteState::Void { .. })
        }))
}

/// When `task` was created; `None` when it names no TASK. The Coach's
/// tradeoff router picks the newest TASK of a project by it.
pub(crate) fn task_created_at_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> crate::Result<Option<u64>> {
    Ok(super::wire_decode::task_verb_body_in(vault, txn, task)?.map(|body| body.created_at))
}

/// Whether admitting `new` voids the open route `old`: the same proposal
/// asked again under another question digest, on any TASK or project. The
/// one supersession rule for routed tradeoff asks.
fn superseded_by(old: &ProjectTradeoffRoute, new: &ProjectTradeoffRoute) -> bool {
    old.state == RouteState::Open
        && old.proposal == new.proposal
        && old.question_digest != new.question_digest
}

/// The preference a pick teaches, spelled as the goal record spells one.
fn preference(prefer: &BTreeSet<String>, over: &BTreeSet<String>) -> String {
    let side = |axes: &BTreeSet<String>| axes.iter().cloned().collect::<Vec<_>>().join("+");
    format!("prefer {} over {}", side(prefer), side(over))
}

impl Memory<'_> {
    /// Ask the A/B question pending on `proposal` on a project TASK. The
    /// question's goal must be joined to a project, and `task` must sit in
    /// that project's task list or in the list of a parent whose board the
    /// ask has climbed to. The exact question is witnessed as a visible TURN
    /// in that project's home room under the room's speaking rules (once per
    /// question and project), and [`Self::tasks_ask_project`] asks the
    /// project's leader and board with that TURN as its question. A retry for
    /// the same question replays the same ask; a question that returns after
    /// its route was voided opens a fresh ask beside the void one.
    pub fn tasks_route_project_tradeoff(
        &self,
        task: EntityId,
        proposal: EntityId,
    ) -> MemoryResult<TaskAskReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let vault = self.vault();
        let ask = crate::skill_optimize::skill_tradeoff_ask(vault, &proposal)?
            .ok_or_else(|| MemoryError::not_found("no tradeoff ask is pending on this proposal"))?;
        let digest = ask.question.digest()?;
        let (project, room) = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            let (project, _) = vault.project_ask_route_in_txn(&txn, task)?;
            if !reaches(&ask, project) {
                return Err(MemoryError::bad_request(
                    "the task's project holds no board this tradeoff ask has reached",
                ));
            }
            let (record, _) = vault
                .effective_project_in_txn(&txn, project)?
                .ok_or(crate::Error::EntityNotFound)?;
            (project, EntityId::from_hex(&record.home_room)?)
        };
        let turn = self.tradeoff_question_turn(&ask, &digest, project, room)?;
        let mut what = TaskAskQuestion::new(ConsultPayloadRef::Turn(turn));
        what.options = BTreeMap::from([
            (
                TaskAskOptionId::new("approve")?,
                preference(&ask.question.gains, &ask.question.losses),
            ),
            (
                TaskAskOptionId::new("reject")?,
                preference(&ask.question.losses, &ask.question.gains),
            ),
        ]);
        let mut spec = TaskAskSpec::shorthand(None, what, None, TaskAskDefault::Hold);
        spec.intent_key = format!("skill_tradeoff/{}/{digest}", proposal.to_hex());
        let route = ProjectTradeoffRoute {
            proposal,
            question_digest: digest,
            project,
            task,
            turn,
            state: RouteState::Open,
        };
        self.tasks_ask_project_with(task, &spec, Some(route))
    }

    /// The TURN `ask`'s question is witnessed as in `project`'s home room,
    /// speaking it first when no earlier route landed it.
    fn tradeoff_question_turn(
        &self,
        ask: &SkillTradeoffAsk,
        digest: &str,
        project: EntityId,
        room: EntityId,
    ) -> MemoryResult<EntityId> {
        let vault = self.vault();
        let key = (ask.question.proposal, project, digest.to_owned());
        let reserved = vault.with_write_txn_grouped(|txn| {
            if let Some(row) = QUESTION_TURNS.get(&vault.store, txn, &key)? {
                return Ok(row);
            }
            let row = QuestionTurn {
                turn: vault.store.clock.entity_id()?,
                message: vault.store.clock.entity_id()?,
                occurred_at: vault.store.clock.now_recorded_at(),
            };
            QUESTION_TURNS.put(&vault.store, txn, &key, &row)?;
            Ok(row)
        })?;
        let landed = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            vault
                .get_entity_type_in_txn(&txn, &reserved.message)?
                .is_some()
        };
        if !landed {
            let content = serde_json::to_string(&ask.question)
                .map_err(|_| MemoryError::bad_request("tradeoff question encoding failed"))?;
            self.rooms_speak(&WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: Some(reserved.turn.to_hex()),
                quote: None,
                thread_audience: None,
                messages: vec![WitnessMessage {
                    id: Some(reserved.message.to_hex()),
                    author: if self.actor_class() == EdgeActorClass::Human {
                        WitnessAuthor::User
                    } else {
                        WitnessAuthor::Companion
                    },
                    message_type: "skill_tradeoff_question".into(),
                    content,
                    metadata: Some(serde_json::json!({
                        "skill_tradeoff_proposal": ask.question.proposal.to_hex(),
                        "skill_tradeoff_question_digest": digest,
                    })),
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: reserved.occurred_at,
                assertions: Default::default(),
            })?;
        }
        Ok(reserved.turn)
    }

    /// Settle the skill tradeoff a routed project ask carries with this
    /// caller's pick. `owner` must be this caller's own proof. The route and
    /// the gate's current question are read again: a question replaced since
    /// the ask refuses and voids the route and its ask, so an answer to an
    /// older question never settles a newer one. Otherwise the gate's own
    /// door ([`crate::skill_optimize::settle_skill_tradeoff_ask`]) decides,
    /// with its role and digest checks. The settlement and the route's close
    /// are two writes, in that order.
    pub fn tasks_settle_project_tradeoff(
        &self,
        ask: TaskAskHandle,
        owner: &AuthenticatedOwner,
        choice: TradeoffChoice,
    ) -> MemoryResult<HeldOutVerdict> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let vault = self.vault();
        if owner.revalidate_person(vault)? != self.actor() {
            return Err(consult_refusal(
                MEMORY_CODE_FORBIDDEN,
                "the pick's proof names another person than this caller",
                "Settle with the caller's own proof.",
            ));
        }
        let route = self.pending_project_tradeoff_route(ask)?;
        let now = vault.store.clock.now_recorded_at();
        let verdict = crate::skill_optimize::settle_skill_tradeoff_ask(
            vault,
            owner,
            &route.proposal,
            &route.question_digest,
            choice,
            now,
        )?;
        close_route(
            vault,
            ask.group_ref,
            RouteState::Settled {
                verdict: verdict.id,
                at: now,
            },
        )?;
        Ok(verdict)
    }

    /// Settle the skill tradeoff a routed project ask carries with this
    /// agent caller's pick: an agent holding a responsible role the ask has
    /// reached (ROLES-EVERYWHERE), such as an agent board member. The agent
    /// is this bound caller, never a field of the request, and no person's
    /// proof stands in for it. The route and question are read again as for
    /// [`Self::tasks_settle_project_tradeoff`]; the gate's agent door
    /// ([`crate::skill_optimize::settle_skill_tradeoff_ask_as_agent`]) then
    /// decides, with its live role and digest checks. The settlement and the
    /// route's close are two writes, in that order.
    pub fn tasks_settle_project_tradeoff_as_agent(
        &self,
        ask: TaskAskHandle,
        choice: TradeoffChoice,
    ) -> MemoryResult<HeldOutVerdict> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        if self.actor_class() != EdgeActorClass::Agent {
            return Err(consult_refusal(
                MEMORY_CODE_FORBIDDEN,
                "only an agent caller settles a project tradeoff without a person's proof",
                "Settle with the caller's own proof.",
            ));
        }
        let vault = self.vault();
        let agent = crate::write_envelope::WriteActor::new(self.actor(), self.actor_class());
        let route = self.pending_project_tradeoff_route(ask)?;
        let now = vault.store.clock.now_recorded_at();
        let verdict = crate::skill_optimize::settle_skill_tradeoff_ask_as_agent(
            vault,
            &agent,
            &route.proposal,
            &route.question_digest,
            choice,
            now,
        )?;
        close_route(
            vault,
            ask.group_ref,
            RouteState::Settled {
                verdict: verdict.id,
                at: now,
            },
        )?;
        Ok(verdict)
    }

    /// The open route `ask` carries, its gate question read again. No
    /// pending question refuses and leaves the route open; a question
    /// replaced since the ask voids the route and its ask in one commit and
    /// refuses.
    fn pending_project_tradeoff_route(
        &self,
        ask: TaskAskHandle,
    ) -> MemoryResult<ProjectTradeoffRoute> {
        let vault = self.vault();
        let route = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            ROUTES.get(&vault.store, &txn, &ask.group_ref)?
        }
        .ok_or_else(|| MemoryError::not_found("this ask carries no skill tradeoff"))?;
        if route.state != RouteState::Open {
            return Err(MemoryError::bad_request(
                "this ask's skill tradeoff is already closed",
            ));
        }
        // No question stands while the proposal is answered, its goal moved
        // or policy leaves no room to learn a pick; the gate may put this
        // same question again, so that alone does not void the route.
        let Some(current) = crate::skill_optimize::skill_tradeoff_ask(vault, &route.proposal)?
        else {
            return Err(MemoryError::bad_request(
                "no tradeoff question is pending on this proposal now",
            ));
        };
        if current.question.digest()? != route.question_digest {
            let now = vault.store.clock.now_recorded_at();
            close_route(vault, ask.group_ref, RouteState::Void { at: now })?;
            return Err(MemoryError::bad_request_with(
                "the tradeoff question moved since this ask; the ask is void",
                &["Route the current question again."],
            ));
        }
        Ok(route)
    }

    /// The learned preferences proposed for `project`'s goal in force and
    /// not dismissed, oldest first, read in one snapshot with the project's
    /// authority. Only a member the project's folded authority seats reads
    /// them, as it reads the project's asks.
    pub fn projects_goal_revisions(
        &self,
        project: EntityId,
    ) -> MemoryResult<Vec<ProjectGoalRevisionProposal>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let (_, effective) = vault
            .effective_project_in_txn(&txn, project)?
            .ok_or(crate::Error::EntityNotFound)?;
        let actor = self.actor().to_hex();
        if !effective.seats(&actor)
            && effective.leader != actor
            && !effective.board.contains(&actor)
        {
            return Err(consult_refusal(
                MEMORY_CODE_FORBIDDEN,
                "a project's goal revisions are read by its members",
                "Read the goal revisions of a project you sit in.",
            ));
        }
        crate::skill_optimize::project_goal_revision_proposals_in_txn(vault, &txn, project)
            .map_err(MemoryError::from)
    }

    /// Dismiss the proposal one tradeoff question made for `project`'s goal
    /// `expected_goal`. The owner is the host's: this caller, authenticated
    /// as a recorded owner of the vault, never a field of the request.
    /// Returns `false` for an identical retry.
    pub fn projects_goal_dismiss(
        &self,
        project: EntityId,
        expected_goal: EntityId,
        question_digest: &str,
    ) -> MemoryResult<bool> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let vault = self.vault();
        let owner = vault
            .authenticate_recorded_owner(
                self.actor(),
                &self.actor().to_hex(),
                crate::store::GateDecisionId::now(),
            )?
            .ok_or_else(|| {
                consult_refusal(
                    MEMORY_CODE_FORBIDDEN,
                    "a goal revision is dismissed by a vault owner",
                    "Ask a vault owner to dismiss it.",
                )
            })?;
        let at = vault.store.clock.now_recorded_at();
        crate::skill_optimize::dismiss_project_goal_revision_proposal(
            vault,
            &owner,
            project,
            expected_goal,
            question_digest,
            at,
        )
        .map_err(MemoryError::from)
    }
}

/// The intent key a tradeoff ask admits under, read in its admission
/// transaction: `spec`'s own while its group is unrouted, open or settled,
/// and past every voided generation otherwise. A route voided because its
/// question moved keeps its Stale ask, never reopened; the same question
/// asked again opens a fresh ask under `<base>/after/<void group>`, so a
/// retry finds that fresh ask and no counter or clock picks the key.
pub(super) fn advance_void_intent_in(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    spec: &mut TaskAskSpec,
) -> crate::Result<()> {
    let base = spec.intent_key.clone();
    loop {
        let group = super::ask_record::group_id(vault, txn, actor, &spec.intent_key)?;
        let void = ROUTES
            .get(&vault.store, txn, &group)?
            .is_some_and(|route| matches!(route.state, RouteState::Void { .. }));
        if !void {
            return Ok(());
        }
        spec.intent_key = format!("{base}/after/{}", group.to_hex());
    }
}

/// A tradeoff ask's route, written beside its ask: a question replaced
/// since an earlier route voids that route and its ask, on whichever TASK
/// it was routed, and this ask's route opens.
pub(super) fn route_tradeoff_in(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    group: EntityId,
    route: &ProjectTradeoffRoute,
) -> MemoryResult<()> {
    let now = vault.store.clock.now_recorded_at();
    for (old, row) in ROUTES.scan(&vault.store, txn)? {
        if superseded_by(&row, route) {
            close_route_in(vault, txn, old, RouteState::Void { at: now })?;
        }
    }
    ROUTES.put(&vault.store, txn, &group, route)?;
    Ok(())
}

/// Close an open route; a closed one keeps its first close.
fn close_route(vault: &crate::Vault, ask: EntityId, state: RouteState) -> MemoryResult<()> {
    vault.with_write_txn_grouped(|txn| close_route_in(vault, txn, ask, state))?;
    Ok(())
}

/// [`close_route`] inside `txn`. Voiding an open route cuts its ask Stale
/// in the same commit, so its answers settle nothing and it stops waiting
/// for its deadline; a cut that fails aborts the close with it.
fn close_route_in(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    ask: EntityId,
    state: RouteState,
) -> crate::error::Result<()> {
    if let Some(mut route) = ROUTES.get(&vault.store, txn, &ask)?
        && route.state == RouteState::Open
    {
        if let RouteState::Void { at } = state {
            super::ask_settlement::void_in(vault, txn, ask, at)?;
        }
        route.state = state;
        ROUTES.put(&vault.store, txn, &ask, &route)?;
    }
    Ok(())
}
