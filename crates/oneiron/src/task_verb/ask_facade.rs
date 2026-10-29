//! Async scope-authority asks over existing consult TASKs.
//!
//! Entry: `Memory::tasks_ask`.
//! Admission/read/wait operations live in children; ask records belong to `ask_record`.
use super::ask_effect::AskEffect;
use super::ask_record::{self, AskGroup, AskMember};
use super::ask_types::*;
use super::create_validation::{ValidatedTaskCreate, consult_refusal, validate_task_create_in};
use super::task_actor::TaskActor;
use super::{ConsultPayload, TaskAssignee, TaskCreateSpec, TaskKind, TaskTtl};
use super::{
    ask_guest, ask_limits, ask_option_link, ask_policy, ask_settlement, code_consent_word,
    comm_widen, create_validation, fanout_launch, rate_limit, training_offer_ask,
    training_swap_ask, world_privacy_wait,
};
use crate::agent_dispatch::{AgentDispatcher, FanoutCaller, FanoutWork};
use crate::code_run::peer_result_wait;
use crate::entity_id::EntityId;
use crate::gate::PolicyApprovalCeiling;
use crate::memory::{Memory, MemoryError, MemoryResult, facade_provenance, verify_actor_binding};
use crate::side_table::{self, Named, SideTable};

mod admission;
mod read;
mod wait;
pub(crate) use self::wait::settle_waiting_asks;
pub(super) use self::wait::{TASK_ASK_WAITS, signal_waiters};

/// What an ask's admission composes with the asker's own write.
enum AskThen<F> {
    /// A closure run in the admission's transaction, whether the ask goes
    /// out or is held for launch approval: it writes nothing a member TASK
    /// must exist for, and the group it is handed is the one a release mints.
    Now(F),
    /// A typed effect, or none. In `manual` mode the ask may be held for a
    /// launch approval (ASK-3) by the owner, or its project's lead or board;
    /// the effect is kept on its hold and runs as the approval releases the
    /// ask.
    Typed(Option<AskEffect>),
}

/// The closure type of an admission that composes no closure.
type NoClosure = fn(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>;

/// An ask's census, read in one snapshot: its recipients, its effective
/// spec and one validated member TASK per recipient.
struct AskCensus {
    holders: Vec<EntityId>,
    context_class: Option<TaskAskClass>,
    governed_task: Option<EntityId>,
    effective: TaskAskSpec,
    validated: Vec<(ValidatedTaskCreate, bool)>,
    work: Vec<FanoutWork>,
    no_live_route: bool,
}

/// What a first admission, or an approval releasing a held ask, mints.
impl AskCensus {
    /// The validated, session-owned projection: no member TASK or launch
    /// work escapes the ordinary census (FIX 10087).
    pub(super) fn into_session_parts(
        self,
        group_ref: EntityId,
        owner: EntityId,
        requested: &TaskAskSpec,
        question_digest: [u8; 32],
    ) -> super::session_ask::SessionAskParts {
        super::session_ask::SessionAskParts {
            group_ref,
            owner,
            requested: requested.clone(),
            effective: self.effective,
            holders: self.holders,
            question_digest,
        }
    }
}

struct AskMint<'a> {
    group_ref: EntityId,
    request_digest: &'a str,
    requested: TaskAskSpec,
    census: AskCensus,
    question_digest: [u8; 32],
    statement: crate::agent_dispatch::FanoutStatement,
    now: u64,
}

impl Memory<'_> {
    /// Returns at admission. This does not open a trap, lease a run, or wait.
    /// A question answer never stands in for an authenticated consent receipt.
    /// In `manual` mode the ask may be held for the owner's launch approval
    /// (ASK-3), and under `auto` when a host's learned ruling surfaces a
    /// multi-recipient ask to a person (FIX 10181): its receipt names the
    /// hold and no member TASK exists yet.
    pub fn tasks_ask(&self, input: &TaskAskSpec) -> MemoryResult<TaskAskReceipt> {
        self.tasks_ask_composed(input, None)
    }

    /// Compose a closure into the same ask admission transaction. A replay
    /// has already committed its effect and does not execute it twice. In
    /// `manual` mode the ask may be held (ASK-3); the closure runs at
    /// admission all the same, on the group the release mints.
    pub(crate) fn tasks_ask_with_txn_effect(
        &self,
        input: &TaskAskSpec,
        effect: impl FnOnce(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>,
    ) -> MemoryResult<TaskAskReceipt> {
        if !self.has_task_work_turn() {
            return self
                .task_work_memory()
                .tasks_ask_with_txn_effect(input, effect);
        }
        let digest = ask_admission_digest(input)?;
        let auto = self.ask_auto_gate(input);
        self.with_verified_actor_write_txn(|txn| {
            self.admit_ask_in_txn(
                txn,
                input,
                &digest,
                AskThen::Now(effect),
                auto.as_ref(),
                None,
            )
        })
    }

    /// An ask with a typed effect composed beside it, run in its admission
    /// transaction, or kept on its launch hold and run as the owner's
    /// approval releases it. A replay runs it neither time.
    pub(super) fn tasks_ask_composed(
        &self,
        input: &TaskAskSpec,
        effect: Option<AskEffect>,
    ) -> MemoryResult<TaskAskReceipt> {
        if !self.has_task_work_turn() {
            return self.task_work_memory().tasks_ask_composed(input, effect);
        }
        let digest = ask_admission_digest(input)?;
        let auto = self.ask_auto_gate(input);
        self.with_verified_actor_write_txn(|txn| {
            self.admit_ask_in_txn(
                txn,
                input,
                &digest,
                AskThen::<NoClosure>::Typed(effect),
                auto.as_ref(),
                None,
            )
        })
    }

    /// The Auto launch ruling a multi-recipient ask takes before its writer
    /// opens (FIX 10181), where this surface carries a host's decisions. An
    /// ask on any other surface, or composed inside a writer, takes none and
    /// is admitted as before.
    fn ask_auto_gate(&self, input: &TaskAskSpec) -> Option<super::fanout_launch::AskAutoGate> {
        self.task_decisions()
            .and_then(|decisions| super::fanout_launch::AskAutoGate::decide(self, input, decisions))
    }

    /// [`Self::tasks_ask_composed`] inside a transaction an engine writer
    /// already holds (OF-220: a runner's report opens its owner ask in the
    /// runner's own commit). The caller has verified this actor's write on
    /// `txn`; admission is the one body the public door runs.
    pub(super) fn tasks_ask_composed_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: &TaskAskSpec,
        effect: Option<AskEffect>,
    ) -> MemoryResult<TaskAskReceipt> {
        let digest = ask_admission_digest(input)?;
        self.admit_ask_in_txn(
            txn,
            input,
            &digest,
            AskThen::<NoClosure>::Typed(effect),
            None,
            None,
        )
    }

    /// The ask of a consult interruption's frozen consent case (FIX 10692),
    /// in `txn`, the interruption's own writer: kept under `case_ref`, the
    /// group the consult's Finish reads, which only the engine names. As the
    /// engine's question to the owners it takes no ask ceiling and no launch
    /// hold. A replay of the same case answers the group it minted.
    pub(super) fn tasks_ask_for_case_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: &TaskAskSpec,
        case_ref: EntityId,
    ) -> MemoryResult<TaskAskReceipt> {
        let digest = ask_admission_digest(input)?;
        self.admit_ask_in_txn(
            txn,
            input,
            &digest,
            AskThen::<NoClosure>::Typed(None),
            None,
            Some(case_ref),
        )
    }

    /// One ask's admission in `txn`: replay (of a group, or of a held
    /// launch), the ask rules, the census, then either the launch hold or
    /// the member TASKs and the group, and the composed effect on a first
    /// admission. A consult case's ask (`case`) is kept under its case ref.
    fn admit_ask_in_txn<F>(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: &TaskAskSpec,
        digest: &str,
        then: AskThen<F>,
        auto: Option<&super::fanout_launch::AskAutoGate>,
        case: Option<EntityId>,
    ) -> MemoryResult<TaskAskReceipt>
    where
        F: FnOnce(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>,
    {
        let now = self.vault().store.clock.now_recorded_at();
        let group_ref = match case {
            Some(case_ref) => case_ref,
            None => ask_record::group_id(self.vault(), txn, self.actor(), &input.intent_key)?,
        };
        if let Some(group) = ask_record::read_group(self.vault(), txn, group_ref)? {
            return replay_receipt(group_ref, group, self.actor(), digest);
        }
        // A held ask replays its hold: the same intent never asks twice.
        if let Some(receipt) = super::fanout_launch::held_ask_receipt_in(
            self.vault(),
            txn,
            group_ref,
            self.actor(),
            digest,
        )? {
            return Ok(receipt);
        }
        if case.is_none() {
            self.require_ask_ceiling_in(txn, input)?;
        }
        // Revocation and admission observe the SAME snapshot.
        let census = self.ask_census_in(txn, input, group_ref, now)?;
        // One ask counts once on the asker's ask window, whatever its
        // recipients; a replay returned above never counts again.
        super::rate_limit::record_task_ask(
            self.vault(),
            txn,
            self.actor(),
            now,
            super::TaskCreateRateLimit::default(),
        )?;
        // Stated after the census and before any grant or member TASK. An
        // ask from an agent's run the host bound states its count, expected
        // spend and cap under that agent's spend tree (OF-393), the lease
        // re-proved here; over the cap is stated, never refused. Any other
        // ask states no cap.
        let caller = FanoutCaller {
            parent_attempt: super::create_origin::task_create_origin_in_txn(
                self,
                txn,
                self.task_host(),
            )?
            .and_then(|origin| origin.parent_attempt()),
            ..FanoutCaller::default()
        };
        let mut statement = AgentDispatcher::new(self.vault()).plan_fanout_in_txn(
            txn,
            &caller,
            &census.work,
            now,
        )?;
        let question = census.effective.what.reference.short_ref();
        let (check_scope, check_row) =
            super::fanout_launch::ask_check_keys(self.actor(), group_ref, &question);
        let question_digest =
            super::ask_settlement::question_digest(self.vault(), txn, &census.effective.what)?
                .ok_or(crate::Error::EntityNotFound)?;
        // The project whose lead and board may release a hold, bound now
        // from the asked TASK or the project effect; none leaves the owner.
        let approval_project = match &then {
            AskThen::Typed(effect) => self.ask_launch_project_in(txn, input, effect.as_ref())?,
            AskThen::Now(_) => self.ask_launch_project_in(txn, input, None)?,
        };
        // A comm widen ask (proved above) asks the approver itself, and a
        // code consent ask (proved above) and a consult case's ask are the
        // engine's questions to the owner, so none waits on a launch
        // approval.
        // An Auto ask's learned ruling, taken before the writer, holds it
        // through the same launch hold when it surfaced the ask to a person
        // or its policy or recipients moved since (FIX 10181).
        if case.is_none()
            && !super::comm_widen::is_comm_widen_ask_intent(&input.intent_key)
            && !super::code_consent_word::is_code_consent_ask_intent(&input.intent_key)
            && (super::fanout_launch::ask_launch_needs_approval(
                self.vault(),
                txn,
                &census.holders,
                approval_project,
            )? || match auto {
                Some(auto) => {
                    auto.holds_in(self.vault(), txn, &census.holders, approval_project)?
                }
                None => false,
            })
        {
            // Held: no guest grant, no member TASK and no group exist until
            // an approver releases it; a typed effect waits on the hold, and
            // a closure runs now.
            let effect = match then {
                AskThen::Now(effect) => {
                    effect(txn, group_ref)?;
                    None
                }
                AskThen::Typed(effect) => effect,
            };
            return super::fanout_launch::hold_ask_in(
                self.vault(),
                txn,
                super::fanout_launch::AskHold {
                    group_ref,
                    approval_project,
                    actor: self.actor(),
                    actor_class: self.actor_class(),
                    requested: input,
                    effective: census.effective,
                    holders: census.holders,
                    context_class: census.context_class,
                    question_digest,
                    request_digest: digest,
                    statement,
                    scope: check_scope,
                    effect,
                    now,
                },
            );
        }
        // Width is a check on an ask that goes out, never a hold.
        let width_asked = super::fanout_check::raise_unheld_width_check(
            self.vault(),
            txn,
            &mut statement,
            &check_scope,
            check_row,
        )?;
        let holders = census.holders.clone();
        let group = self.mint_ask_in(
            txn,
            AskMint {
                group_ref,
                request_digest: digest,
                requested: input.clone(),
                census,
                question_digest,
                statement,
                now,
            },
        )?;
        // An asked width check names a durable row the owner acknowledges;
        // it holds nothing and touches no member TASK.
        if width_asked {
            super::fanout_launch::record_ask_check_in(
                self.vault(),
                txn,
                super::fanout_launch::AskCheck {
                    group_ref,
                    actor: self.actor(),
                    actor_class: self.actor_class(),
                    request_digest: digest,
                    question,
                    recipients: &holders,
                    task_refs: group
                        .members
                        .iter()
                        .map(|member| ask_record::entity(&member.task))
                        .collect::<crate::Result<_>>()?,
                    statement: &group.statement,
                    scope: check_scope,
                    now,
                },
            )?;
        }
        let mut receipt = replay_receipt(group_ref, group, self.actor(), digest)?;
        match then {
            AskThen::Now(effect) => effect(txn, group_ref)?,
            AskThen::Typed(Some(effect)) => self.apply_ask_effect_in(txn, group_ref, &effect)?,
            AskThen::Typed(None) => {}
        }
        receipt.idempotent_replay = false;
        Ok(receipt)
    }

    /// The project a held launch of this ask binds its approvers to: the
    /// asked TASK's served project, else a project effect's project, read
    /// again here, else none. A TASK placed in two projects refuses, as its
    /// project route does.
    fn ask_launch_project_in(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &TaskAskSpec,
        effect: Option<&AskEffect>,
    ) -> MemoryResult<Option<EntityId>> {
        if let Some(task) = input.task_ref
            && let Some(project) = self.vault().task_served_project_in_txn(txn, task)?
        {
            return Ok(Some(project));
        }
        if let Some(AskEffect::Project { project, task, .. }) = effect {
            let (current, _) = self.vault().project_ask_route_in_txn(txn, *task)?;
            if current != *project {
                return Err(MemoryError::bad_request(
                    "project ask placement changed; ask again",
                ));
            }
            return Ok(Some(*project));
        }
        Ok(None)
    }

    /// Releases an ask the owner approved, in the approval's transaction, as
    /// its asker: the census runs again from the frozen request, and a
    /// recipient set or class that changed while it was held, a question
    /// that changed, an expired deadline or a lost ask authority refuses the
    /// approval rather than silently retargeting it. The ask is not counted
    /// again, and its statement is the one frozen at the hold. Returns the
    /// member TASKs it minted.
    pub(super) fn release_held_ask_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        group_ref: EntityId,
        held: super::fanout_launch::ReleasedAsk<'_>,
    ) -> MemoryResult<Vec<EntityId>> {
        let changed = || {
            consult_refusal(
                crate::memory::MEMORY_CODE_INVALID_STATE,
                "the held ask changed while it waited for approval",
                "Deny this launch and ask again.",
            )
        };
        if ask_record::read_group(self.vault(), txn, group_ref)?.is_some() {
            return Err(
                crate::Error::InvariantViolation("a held ask already has its group").into(),
            );
        }
        self.require_ask_ceiling_in(txn, held.requested)?;
        let now = self.vault().store.clock.now_recorded_at();
        let census = self.ask_census_in(txn, held.requested, group_ref, now)?;
        let mut current = census.holders.clone();
        current.sort_unstable();
        let mut frozen = held.holders.to_vec();
        frozen.sort_unstable();
        if current != frozen || &census.context_class != held.context_class {
            return Err(changed());
        }
        let question_digest =
            super::ask_settlement::question_digest(self.vault(), txn, &census.effective.what)?
                .ok_or(crate::Error::EntityNotFound)?;
        if question_digest != held.question_digest {
            return Err(changed());
        }
        let group = self.mint_ask_in(
            txn,
            AskMint {
                group_ref,
                request_digest: held.request_digest,
                requested: held.requested.clone(),
                census,
                question_digest,
                statement: held.statement.clone(),
                now,
            },
        )?;
        Ok(group
            .members
            .iter()
            .map(|member| ask_record::entity(&member.task))
            .collect::<crate::Result<_>>()?)
    }

    pub(super) fn ask_holders_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &TaskAskSpec,
    ) -> MemoryResult<Vec<EntityId>> {
        Ok(match &input.who {
            Some(TaskAskTarget::Authority(scope)) => {
                self.vault()
                    .ask_authority_holders_in_txn(txn, &scope.class, &scope.envelope)?
            }
            Some(TaskAskTarget::Responder(assignee)) => {
                vec![assignee.entity_ref().unwrap_or(self.actor())]
            }
            Some(TaskAskTarget::People(people)) => people.iter().copied().collect(),
            Some(TaskAskTarget::Guests(guests)) => guests.keys().copied().collect(),
            None => vec![self.short_ask_principal_in_txn(txn)?],
        })
    }

    /// A human can ask themselves. For an agent, an omitted target is the
    /// unique verified human owner of its live assigned TASK, not the agent's
    /// own actor id. The Owner fact is the binding; a caller-writable TASK
    /// body by itself cannot nominate the principal.
    fn short_ask_principal_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<EntityId> {
        if self.actor_class() == crate::EdgeActorClass::Human {
            crate::memory::verify_owner_actor_binding_in_txn(self.vault(), txn, self.actor())?;
            return Ok(self.actor());
        }
        let tasks = super::presence_pages::all_admitted_tasks_in(
            self.vault(),
            txn,
            self.destination(),
            self.actor().as_bytes(),
        )?;
        // Before an authority root exists, only the seeded vault owner has
        // an independently established human identity. A free-form PERSON
        // owner fact cannot classify its writer as human rather than agent.
        let rooted = self
            .vault()
            .authority_fold_readonly_in_txn(txn)?
            .vault_id
            .is_some();
        let mut principal = None;
        for task in tasks {
            let Some(body) = super::wire_decode::task_verb_body_in(self.vault(), txn, task)? else {
                continue;
            };
            if body.task_kind() != TaskKind::Standard
                || body.terminal().is_some()
                || body.assignee.and_then(TaskAssignee::entity_ref) != Some(self.actor())
            {
                continue;
            }
            let Some(proof) = self.vault().task_authority_state_in(txn, task)? else {
                continue;
            };
            if proof.cancelled || proof.owner_ref.to_hex() != body.owner_ref {
                continue;
            }
            let owner = proof.owner_ref;
            // The Owner fact may be nominated by the creating agent. Only
            // this independent human-authored witness can establish the
            // principal relationship for an omitted recipient.
            if self.vault().task_human_assigner_in(txn, task)? != Some((owner, self.actor())) {
                continue;
            }
            if !rooted && owner != crate::vault::embedded_owner_actor_id()? {
                continue;
            }
            if self.vault().get_entity_type_in_txn(txn, &owner)?
                != Some(crate::registry::ENTITY_TYPE_PERSON)
                || crate::memory::verify_owner_actor_binding_in_txn(self.vault(), txn, owner)
                    .is_err()
            {
                continue;
            }
            // The principal is derived from this TASK, a refusal from two.
            self.produced_from([task]);
            if principal.is_some_and(|found| found != owner) {
                return Err(MemoryError::bad_request(
                    "agent has more than one human principal",
                ));
            }
            principal = Some(owner);
        }
        principal.ok_or_else(|| MemoryError::bad_request("agent has no verified human principal"))
    }

    /// The class an ask naming `task` binds, with the TASK it came from:
    /// `task`, or this actor's governed TASK when the ask omits it.
    pub(super) fn ask_class_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        task: Option<EntityId>,
    ) -> MemoryResult<Option<(EntityId, TaskAskClass)>> {
        let task = match task {
            Some(task) => task,
            None => match self.governed_task_in_txn(txn)? {
                Some(task) => task,
                None => return Ok(None),
            },
        };
        // The ask answers from this TASK's class.
        self.ask_read_producer_in(txn, task)?;
        let body = super::create_validation::task_body_in_txn(self.vault(), txn, task)?;
        let authority = self
            .vault()
            .task_authority_state_in(txn, task)?
            .ok_or_else(|| MemoryError::bad_request("ask task has no owner proof"))?;
        if authority.cancelled
            || authority.owner_ref.to_hex() != body.owner_ref
            || (authority.owner_ref != self.actor()
                && body.assignee.and_then(TaskAssignee::entity_ref) != Some(self.actor()))
        {
            return Err(MemoryError::bad_request(
                "ask task context is not owned or addressed to this actor",
            ));
        }
        let Some(fields) = body.spec.as_map() else {
            return Ok(None);
        };
        let mut rows = fields
            .iter()
            .filter(|(key, _)| key.as_str() == Some("ask_class"));
        let Some((_, value)) = rows.next() else {
            return Ok(None);
        };
        if rows.next().is_some() {
            return Err(MemoryError::bad_request("duplicate ask class binding"));
        }
        let bytes = rmp_serde::to_vec_named(value)
            .map_err(|_| MemoryError::bad_request("invalid task ask class binding"))?;
        rmp_serde::from_slice(&bytes)
            .map(|class| Some((task, class)))
            .map_err(|_| MemoryError::bad_request("invalid task ask class binding"))
    }

    /// The task context of an ask that omits `task_ref`: the one live TASK
    /// assigned to this actor whose spec binds an `ask_class`.
    ///
    /// The walk reads every TASK, so "none" is a complete answer.
    fn governed_task_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<Option<EntityId>> {
        let name_the_task = |message: &str| {
            MemoryError::bad_request_with(message, &["Name the governing task in task_ref."])
        };
        let tasks = super::presence_pages::all_admitted_tasks_in(
            self.vault(),
            txn,
            self.destination(),
            self.actor().as_bytes(),
        )?;
        let mut found = None;
        for task in tasks {
            let Ok(Some(body)) = super::wire_decode::task_verb_body_in(self.vault(), txn, task)
            else {
                continue;
            };
            if body.assignee.and_then(TaskAssignee::entity_ref) != Some(self.actor())
                || body.terminal().is_some()
                || !body.spec.as_map().is_some_and(|fields| {
                    fields
                        .iter()
                        .any(|(key, _)| key.as_str() == Some("ask_class"))
                })
                || self
                    .vault()
                    .task_authority_state_in(txn, task)?
                    .is_some_and(|authority| authority.cancelled)
            {
                continue;
            }
            if let Some(first) = found.replace(task) {
                // Both TASKs decide this refusal.
                self.produced_from([first, task]);
                return Err(name_the_task(
                    "more than one governed task could bind this ask",
                ));
            }
        }
        Ok(found)
    }
}

fn replay_receipt(
    id: EntityId,
    group: AskGroup,
    actor: EntityId,
    digest: &str,
) -> MemoryResult<TaskAskReceipt> {
    if group.owner != actor.to_hex() || group.request_digest != digest {
        return Err(MemoryError::bad_request(
            "ask intent key was used for different arguments",
        ));
    }
    let task_refs = group
        .members
        .iter()
        .map(|m| ask_record::entity(&m.task))
        .collect::<crate::Result<Vec<_>>>()?;
    Ok(TaskAskReceipt::new(
        TaskAskHandle { group_ref: id },
        task_refs,
        group
            .no_live_route
            .then_some(TaskAskHoldReason::NoLiveRoute),
        true,
        Some(group.statement),
    ))
}

/// Owner and admitted responders read an ask; anyone else is refused.
fn require_ask_audience(group: &AskGroup, actor: EntityId) -> MemoryResult<()> {
    if group.owner != actor.to_hex() && !group.members.iter().any(|m| m.actor == actor.to_hex()) {
        return Err(consult_refusal(
            crate::memory::MEMORY_CODE_FORBIDDEN,
            "ask handle is not addressed to this actor",
            "Read an ask you own or answer.",
        ));
    }
    Ok(())
}

/// The intent-key check every admission runs first, and the request digest
/// a replay is held to.
fn ask_admission_digest(input: &TaskAskSpec) -> MemoryResult<String> {
    if input.intent_key.trim().is_empty() {
        return Err(MemoryError::bad_request("ask intent key must not be blank"));
    }
    ask_request_digest(input)
}

fn ask_request_digest(input: &TaskAskSpec) -> MemoryResult<String> {
    let bytes = rmp_serde::to_vec_named(input)
        .map_err(|_| MemoryError::bad_request("ask request encoding"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// Both `tasks_ask` and `can(ask)` preserve an explicitly addressed
/// non-human responder, even when that actor is stored as a PERSON.
pub(super) fn ask_assignee(
    who: &Option<TaskAskTarget>,
    actor: EntityId,
    kind: Option<u8>,
) -> TaskAssignee {
    match who {
        Some(TaskAskTarget::Responder(assignee)) => *assignee,
        _ if kind == Some(crate::registry::ENTITY_TYPE_PERSON) => {
            TaskAssignee::Human { actor_ref: actor }
        }
        _ => TaskAssignee::Peer { actor_ref: actor },
    }
}
