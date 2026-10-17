//! Async scope-authority asks over existing consult TASKs.
use super::ask_effect::AskEffect;
use super::ask_record::{self, AskGroup, AskMember};
use super::ask_types::*;
use super::create_validation::{ValidatedTaskCreate, consult_refusal, validate_task_create_in};
use super::{ConsultPayload, TaskAssignee, TaskCreateSpec, TaskKind, TaskTtl};
use crate::agent_dispatch::{AgentDispatcher, FanoutCaller, FanoutWork};
use crate::code_run::peer_result_wait;
use crate::entity_id::EntityId;
use crate::gate::PolicyApprovalCeiling;
use crate::memory::{Memory, MemoryError, MemoryResult, facade_provenance, verify_actor_binding};
use crate::side_table::{self, Named, SideTable};

/// What an ask's admission composes with the asker's own write.
enum AskThen<F> {
    /// A closure run in the admission's transaction. The closure cannot
    /// wait, so this ask is never held for launch approval.
    Now(F),
    /// A typed effect, or none. In `manual` mode the ask may be held for the
    /// owner's launch approval (ASK-3); the effect is kept on its hold and
    /// runs as the approval releases the ask.
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
    /// (ASK-3): its receipt names the hold and no member TASK exists yet.
    pub fn tasks_ask(&self, input: &TaskAskSpec) -> MemoryResult<TaskAskReceipt> {
        self.tasks_ask_composed(input, None)
    }

    /// Compose a closure into the same ask admission transaction. A replay
    /// has already committed its effect and does not execute it twice. A
    /// closure cannot wait for a launch approval, so this ask is never held.
    pub(crate) fn tasks_ask_with_txn_effect(
        &self,
        input: &TaskAskSpec,
        effect: impl FnOnce(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>,
    ) -> MemoryResult<TaskAskReceipt> {
        let digest = ask_admission_digest(input)?;
        self.with_verified_actor_write_txn(|txn| {
            self.admit_ask_in_txn(txn, input, &digest, AskThen::Now(effect))
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
        let digest = ask_admission_digest(input)?;
        self.with_verified_actor_write_txn(|txn| {
            self.admit_ask_in_txn(txn, input, &digest, AskThen::<NoClosure>::Typed(effect))
        })
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
        self.admit_ask_in_txn(txn, input, &digest, AskThen::<NoClosure>::Typed(effect))
    }

    /// One ask's admission in `txn`: replay (of a group, or of a held
    /// launch), the ask rules, the census, then either the launch hold or
    /// the member TASKs and the group, and the composed effect on a first
    /// admission.
    fn admit_ask_in_txn<F>(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: &TaskAskSpec,
        digest: &str,
        then: AskThen<F>,
    ) -> MemoryResult<TaskAskReceipt>
    where
        F: FnOnce(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>,
    {
        let now = self.vault().store.clock.now_recorded_at();
        let group_ref = ask_record::group_id(self.vault(), txn, self.actor(), &input.intent_key)?;
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
        self.require_ask_ceiling_in(txn)?;
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
        // Stated after the census and before any grant or member TASK.
        // An ask holds no spend context, so it states no cap.
        let mut statement = AgentDispatcher::new(self.vault()).plan_fanout_in_txn(
            txn,
            &FanoutCaller::default(),
            &census.work,
            now,
        )?;
        let question = census.effective.what.reference.short_ref();
        let (check_scope, check_row) =
            super::fanout_launch::ask_check_keys(self.actor(), group_ref, &question);
        let question_digest =
            super::ask_settlement::question_digest(self.vault(), txn, &census.effective.what)?
                .ok_or(crate::Error::EntityNotFound)?;
        let then = match then {
            AskThen::Typed(effect)
                if super::fanout_launch::ask_launch_needs_approval(
                    self.vault(),
                    txn,
                    &census.holders,
                )? =>
            {
                // Held: no guest grant, no member TASK and no group exist
                // until the owner approves; the effect waits on the hold.
                return super::fanout_launch::hold_ask_in(
                    self.vault(),
                    txn,
                    super::fanout_launch::AskHold {
                        group_ref,
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
            then => then,
        };
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

    /// An actor that may not ask is refused before any census runs.
    fn require_ask_ceiling_in(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        if super::rate_limit::task_actor_ceiling(
            self.vault(),
            txn,
            self.actor(),
            self.actor_class(),
        )? != PolicyApprovalCeiling::Auto
        {
            return Err(consult_refusal(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "scope ask requires an own auto-ceiling actor",
                "Propose the ask through the authority surface.",
            ));
        }
        Ok(())
    }

    /// The census of `input` for the group `group_ref`: its recipients and
    /// class, its effective spec, its rules, and one validated member TASK
    /// per recipient. It writes nothing but the route vetoes it reads.
    fn ask_census_in(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &TaskAskSpec,
        group_ref: EntityId,
        now: u64,
    ) -> MemoryResult<AskCensus> {
        let holders = self.ask_holders_in_txn(txn, input)?;
        let bound = self.ask_class_in_txn(txn, input.task_ref)?;
        let context_class = bound.as_ref().map(|(_, class)| class.clone());
        let effective = input.effective(
            &holders.iter().copied().collect(),
            now,
            context_class.clone(),
        )?;
        // Its rows are measured where the group is kept, once.
        super::ask_limits::check_ask_keys(&self.vault().store, input, &effective)?;
        self.ask_question_in(txn, &effective.what)?;
        let mut no_live_route = true;
        let mut validated = Vec::with_capacity(holders.len());
        let mut work = Vec::with_capacity(holders.len());
        for actor in &holders {
            let kind = self.vault().get_entity_type_in_txn(txn, actor)?;
            if !matches!(
                kind,
                Some(
                    crate::registry::ENTITY_TYPE_PERSON
                        | crate::registry::ENTITY_TYPE_AGENT_DEF
                        | crate::registry::ENTITY_TYPE_MACHINE
                )
            ) {
                return Err(MemoryError::bad_request("ask recipient is not an actor"));
            }
            let assignee = ask_assignee(&effective.who, *actor, kind);
            work.push(match assignee {
                TaskAssignee::Peer { actor_ref } => FanoutWork::PeerConsult { peer: actor_ref },
                other => FanoutWork::Task {
                    assignee: other.entity_ref(),
                },
            });
            // No contact route is required to QUEUE a question. Human followup
            // is registered only where the native route actually resolves.
            let reachable = match assignee {
                TaskAssignee::Human { actor_ref } => {
                    let mut vetoes = Vec::new();
                    let route = crate::human_task::resolve_native_human_route_for_actor_in(
                        self.vault(),
                        txn,
                        actor_ref,
                        self.actor(),
                        &mut vetoes,
                    );
                    // A standing veto that took the route decides the hold.
                    self.produced_from(vetoes);
                    route.is_ok()
                }
                TaskAssignee::Dreamer | TaskAssignee::Child { .. } => true,
                TaskAssignee::Peer { .. } | TaskAssignee::AgentDef { .. } => false,
            };
            no_live_route &= !reachable;
            for reference in std::iter::once(effective.what.reference)
                .chain(effective.what.context_refs.iter().copied())
            {
                crate::llm::decision::questions::validate_task_answer_unit(
                    self.vault(),
                    txn,
                    self.actor(),
                    *actor,
                    reference.entity_ref(),
                )?;
            }
            let spec = TaskCreateSpec::new(
                rmpv::Value::Nil,
                effective.what.label.clone(),
                None,
                Some(now),
            )
            .with_kind(TaskKind::Consult)
            .with_consult(ConsultPayload::question(
                effective.what.reference,
                effective.what.context_refs.clone(),
                group_ref,
            ))
            .with_assignee(assignee)
            .with_ttl(TaskTtl::at(
                effective
                    .until
                    .ok_or_else(|| MemoryError::bad_request("missing effective ask deadline"))?,
            ));
            validated.push((
                validate_task_create_in(self.vault(), txn, &spec, now)?,
                reachable,
            ));
        }
        Ok(AskCensus {
            holders,
            governed_task: bound
                .filter(|_| input.task_ref.is_none())
                .map(|(task, _)| task),
            context_class,
            effective,
            validated,
            work,
            no_live_route,
        })
    }

    /// Mints an ask's guest grants, member TASKs and group, and registers
    /// its human followups, in `txn`.
    fn mint_ask_in(&self, txn: &mut heed::RwTxn<'_>, mint: AskMint<'_>) -> MemoryResult<AskGroup> {
        let AskMint {
            group_ref,
            request_digest,
            requested,
            census,
            question_digest,
            statement,
            now,
        } = mint;
        let guest_grants = super::ask_guest::mint_guest_grants(
            self.vault(),
            txn,
            group_ref,
            self.actor(),
            &census.effective,
            now,
        )?;
        let mut members = Vec::with_capacity(census.holders.len());
        for (actor, (entry, reachable)) in census.holders.iter().zip(&census.validated) {
            let task_ref = self.mint_task_at_in_txn(
                txn,
                (ask_record::member_id(group_ref, *actor)?, self.actor()),
                entry,
                census.effective.what.label.clone(),
                &facade_provenance("ask"),
                now,
            )?;
            // Local executors use the SAME exhaustive TASK route; remote
            // mailboxes do not create a local worker. Unknown human routes
            // stay queued on the asks list rather than aborting the run.
            if !matches!(entry.assignee, Some(TaskAssignee::Human { .. })) && *reachable {
                self.route_created_task_in_txn(txn, task_ref, entry, now)?;
            }
            members.push(AskMember {
                task: task_ref.to_hex(),
                actor: actor.to_hex(),
            });
        }
        let policy_surface = super::ask_policy::confirmation_surface(
            self.vault(),
            txn,
            &census.effective,
            &census.holders,
        )?;
        let group = AskGroup {
            base_policy_version: 1,
            owner: self.actor().to_hex(),
            request_digest: request_digest.to_owned(),
            requested,
            effective: census.effective,
            context_class: census.context_class,
            governed_task: census.governed_task,
            question_digest,
            link_verify_key: ask_record::mint_link_key(self.vault(), txn, group_ref)?,
            members,
            no_live_route: census.no_live_route,
            created_at: now,
            guest_grants,
            policy_surface,
            statement,
        };
        ask_record::put_group(self.vault(), txn, group_ref, &group)?;
        for (member, (entry, _)) in group.members.iter().zip(&census.validated) {
            if matches!(entry.assignee, Some(TaskAssignee::Human { .. })) {
                crate::human_task::register_human_followup_in_txn(
                    self.vault(),
                    txn,
                    ask_record::entity(&member.task)?,
                    ask_record::entity(&member.actor)?,
                    now,
                )?;
            }
        }
        Ok(group)
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
        self.require_ask_ceiling_in(txn)?;
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
            self.locality(),
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
        self.read_producer_in(txn, task)?;
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
            self.locality(),
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

    /// Owner and admitted responders see the same winner, including its actor.
    /// An ask held for launch approval reads, to its asker, as pending on
    /// that approval.
    pub fn tasks_ask_status(&self, handle: TaskAskHandle) -> MemoryResult<TaskAskStatus> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let Some(group) = self.ask_group_in(&txn, handle.group_ref)? else {
            return self.held_ask_status_in(&txn, handle);
        };
        require_ask_audience(&group, self.actor())?;
        drop(txn);
        self.with_verified_actor_write_txn(|txn| self.tasks_ask_status_in_txn(txn, handle))
    }

    /// The status of an ask still held for launch approval, for its asker;
    /// any other handle with no group is unknown.
    fn held_ask_status_in(
        &self,
        txn: &heed::RoTxn<'_>,
        handle: TaskAskHandle,
    ) -> MemoryResult<TaskAskStatus> {
        match super::fanout_launch::held_ask_owner_in(self.vault(), txn, handle.group_ref)? {
            Some(owner) if owner == self.actor() => Ok(TaskAskStatus::Pending {
                hold: Some(TaskAskHoldReason::ApprovalRequired),
            }),
            Some(_) => Err(consult_refusal(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "ask handle is not addressed to this actor",
                "Read an ask you own or answer.",
            )),
            None => Err(MemoryError::bad_request("unknown ask handle")),
        }
    }

    /// [`Self::tasks_ask_status`] inside a write transaction the caller
    /// holds and verified: the same audience check, cut and status read.
    pub(super) fn tasks_ask_status_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        handle: TaskAskHandle,
    ) -> MemoryResult<TaskAskStatus> {
        let Some(group) = self.ask_group_in(txn, handle.group_ref)? else {
            return self.held_ask_status_in(txn, handle);
        };
        require_ask_audience(&group, self.actor())?;
        super::ask_settlement::settle_in(
            self.vault(),
            txn,
            handle.group_ref,
            self.vault().store.clock.now_recorded_at(),
        )?;
        Ok(ask_record::status_in(
            self.vault(),
            txn,
            handle.group_ref,
            &group,
        )?)
    }

    /// Projects a sibling's group winner without replacing that sibling's
    /// terminal evidence. An arbitrary matching correlation is not membership.
    pub fn tasks_ask_status_for_task(
        &self,
        task_ref: EntityId,
    ) -> MemoryResult<Option<TaskAskStatus>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let body = super::create_validation::task_body_in_txn(self.vault(), &txn, task_ref)?;
        let Some(consult) = body.consult else {
            return Ok(None);
        };
        let Some(group) = self.ask_group_in(&txn, consult.correlation_ref)? else {
            return Ok(None);
        };
        if !group
            .members
            .iter()
            .any(|member| member.task == task_ref.to_hex())
        {
            return Ok(None);
        }
        if group.owner != self.actor().to_hex()
            && !group
                .members
                .iter()
                .any(|member| member.actor == self.actor().to_hex())
        {
            return Err(consult_refusal(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "ask handle is not addressed to this actor",
                "Read an ask you own or answer.",
            ));
        }
        drop(txn);
        self.with_verified_actor_write_txn(|txn| {
            super::ask_settlement::settle_in(
                self.vault(),
                txn,
                consult.correlation_ref,
                self.vault().store.clock.now_recorded_at(),
            )?;
            Ok(Some(ask_record::status_in(
                self.vault(),
                txn,
                consult.correlation_ref,
                &group,
            )?))
        })
    }

    /// Call only when this step has no other work. A host without an engine
    /// step supplies its stable key; code mode consumes the returned C9 park.
    pub fn tasks_wait(
        &self,
        handle: TaskAskHandle,
        step_key: Option<&str>,
    ) -> MemoryResult<TaskAskWait> {
        self.tasks_wait_observing(handle, step_key, 0)
    }

    /// Code mode supplies only a generation proved by its durable bridge
    /// replay. An unrecorded Changed result cannot suppress a future wake.
    pub(crate) fn tasks_wait_observing(
        &self,
        handle: TaskAskHandle,
        step_key: Option<&str>,
        observed_generation: u64,
    ) -> MemoryResult<TaskAskWait> {
        if step_key.is_some_and(str::is_empty) {
            return Err(MemoryError::bad_request("invalid wait step key"));
        }
        self.with_verified_actor_write_txn(|txn| {
            let Some(group) = self.ask_group_in(txn, handle.group_ref)? else {
                // A held ask waits on its approval like any pending ask: the
                // park or the bound wait wakes once it goes out and settles.
                let status = self.held_ask_status_in(txn, handle).map_err(|error| {
                    if error.code == crate::memory::MEMORY_CODE_FORBIDDEN {
                        MemoryError::bad_request("only the asking actor may wait")
                    } else {
                        error
                    }
                })?;
                return match step_key {
                    None => {
                        let mut wait = peer_result_wait(handle.group_ref);
                        wait.effect = crate::code_run::SelfEffect::TasksWait;
                        Ok(TaskAskWait::Park(wait))
                    }
                    Some(step_key) => self.bind_external_wait(txn, handle, step_key, status),
                };
            };
            if group.owner != self.actor().to_hex() {
                return Err(MemoryError::bad_request("only the asking actor may wait"));
            }
            super::ask_settlement::settle_in(
                self.vault(),
                txn,
                handle.group_ref,
                self.vault().store.clock.now_recorded_at(),
            )?;
            let status = ask_record::status_in(self.vault(), txn, handle.group_ref, &group)?;
            let Some(step_key) = step_key else {
                return Ok(match status {
                    TaskAskStatus::Pending { .. } => {
                        let voided = super::ask_option_link::voided_friends_in_txn(
                            self.vault(),
                            txn,
                            handle.group_ref,
                            &group,
                        )?;
                        let generation = super::ask_option_link::option_void_generation_in(
                            self.vault(),
                            txn,
                            handle.group_ref,
                        )?;
                        if generation > observed_generation && !voided.is_empty() {
                            TaskAskWait::Changed { voided, generation }
                        } else {
                            let mut wait = peer_result_wait(handle.group_ref);
                            wait.effect = crate::code_run::SelfEffect::TasksWait;
                            TaskAskWait::Park(wait)
                        }
                    }
                    TaskAskStatus::Settled(result) => TaskAskWait::Ready(result),
                    TaskAskStatus::Changed { voided, generation } => {
                        TaskAskWait::Changed { voided, generation }
                    }
                });
            };
            self.bind_external_wait(txn, handle, step_key, status)
        })
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

impl Memory<'_> {
    /// Owner-scoped calibration pairs. The outcome reader rechecks current
    /// fact fields, lifecycle and privacy; the ask id is never a read grant.
    pub fn tasks_ask_outcomes(
        &self,
        handle: &TaskAskHandle,
    ) -> MemoryResult<Vec<crate::llm::decision::questions::CalibrationPair>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let group = self
            .ask_group_in(&txn, handle.group_ref)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
        if group.owner != self.actor().to_hex() {
            return Err(MemoryError::bad_request(
                "only the asking actor may read outcomes",
            ));
        }
        drop(txn);
        Ok(crate::llm::decision::questions::calibration_pairs(
            self.vault(),
            self.actor(),
            handle.group_ref,
            self.locality(),
        )?)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WaitRow {
    trap_ref: Option<EntityId>,
    step_hash: [u8; 32],
    actor: EntityId,
    consumed: bool,
}

/// Registered external ask wait: `(group id, step hash) -> WaitRow`.
const TASK_ASK_WAITS: SideTable<(EntityId, [u8; 32]), WaitRow, Named> =
    SideTable::new(&side_table::TASK_ASK_WAIT);

pub(super) fn signal_waiters(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    group: EntityId,
    now: u64,
) -> MemoryResult<()> {
    let rows = TASK_ASK_WAITS.scan_from(&vault.store, txn, group.as_bytes())?;
    for (_, row) in rows {
        if !row.consumed {
            let trap = crate::llm::TrapRef {
                trap_claim_id: row
                    .trap_ref
                    .ok_or_else(|| MemoryError::bad_request("pending wait has no trap"))?,
                kind: crate::llm::DreamerTrapKind::HumanResponse,
                step_hash: row.step_hash,
            };
            crate::llm::signal_step_wait_in_txn(vault, txn, &trap, now)?;
        }
    }
    Ok(())
}

impl Memory<'_> {
    fn bind_external_wait(
        &self,
        txn: &mut heed::RwTxn<'_>,
        handle: TaskAskHandle,
        step_key: &str,
        status: TaskAskStatus,
    ) -> MemoryResult<TaskAskWait> {
        let mut hash = blake3::Hasher::new();
        hash.update(TASK_ASK_WAITS.decl().prefix);
        hash.update(self.actor().as_bytes());
        hash.update(handle.group_ref.as_bytes());
        hash.update(step_key.as_bytes());
        let step_hash = *hash.finalize().as_bytes();
        let key = (handle.group_ref, step_hash);
        let now_ms = self
            .vault()
            .store
            .clock
            .now_recorded_at()
            .saturating_mul(1000);
        let mut row = if let Some(row) = TASK_ASK_WAITS.get(&self.vault().store, txn, &key)? {
            row
        } else {
            // Every identity the ask holds counts, consumed ones too; past
            // its row the wait asks and is bound anyway.
            let held = TASK_ASK_WAITS
                .iter_from(&self.vault().store, txn, handle.group_ref.as_bytes())?
                .try_fold(0u64, |count, row| row.map(|_| count.saturating_add(1)))?;
            self.vault().limit_watch().measure(
                crate::limit_ask::EngineLimit::AskWaitIdentities,
                held.saturating_add(1),
            );
            // Answer-before-wait needs only bounded exactly-once bookkeeping.
            // Do not mint a detached step or a trap for a completed answer.
            let trap_ref = if matches!(status, TaskAskStatus::Pending { .. }) {
                let ctx = crate::llm::DurableStepContext {
                    vault: self.vault(),
                    attempt_id: crate::attempt_queue::AttemptId::from_bytes(
                        step_hash
                            .get(..16)
                            .ok_or_else(|| MemoryError::bad_request("wait identity"))?,
                    )?,
                    run_id: None,
                    envelope_actor: crate::WriteActor::new(self.actor(), self.actor_class()),
                    subject: self.actor(),
                    deadline: None,
                    now_ms,
                };
                crate::llm::register_detached_step_in_txn(self.vault(), txn, &ctx, step_hash)?;
                Some(
                    crate::llm::open_step_wait_in_txn(self.vault(), txn, &ctx, step_hash)?
                        .trap_claim_id,
                )
            } else {
                None
            };
            WaitRow {
                trap_ref,
                step_hash,
                actor: self.actor(),
                consumed: false,
            }
        };
        if row.actor != self.actor() || row.step_hash != step_hash {
            return Err(MemoryError::bad_request("wait binding changed"));
        }
        let outcome = match status {
            TaskAskStatus::Pending { .. } => TaskAskWait::Pending {
                trap_ref: row
                    .trap_ref
                    .ok_or_else(|| MemoryError::bad_request("pending wait has no trap"))?
                    .to_hex(),
            },
            TaskAskStatus::Changed { voided, generation } => {
                TaskAskWait::Changed { voided, generation }
            }
            TaskAskStatus::Settled(result) => {
                if let Some(trap_claim_id) = row.trap_ref
                    && !row.consumed
                {
                    let trap = crate::llm::TrapRef {
                        trap_claim_id,
                        kind: crate::llm::DreamerTrapKind::HumanResponse,
                        step_hash,
                    };
                    crate::llm::signal_step_wait_in_txn(self.vault(), txn, &trap, now_ms)?;
                    if !crate::llm::consume_step_wait_in_txn(self.vault(), txn, &trap, now_ms)? {
                        return Err(MemoryError::bad_request("wait signal was not consumable"));
                    }
                }
                row.consumed = true;
                TaskAskWait::Ready(result)
            }
        };
        TASK_ASK_WAITS
            .put(&self.vault().store, txn, &key, &row)
            .map_err(MemoryError::from)?;
        Ok(outcome)
    }
}

impl Memory<'_> {
    /// `peek(ask)`: attributed partial words, then explicit unknowns at cutoff.
    /// Reading this view never mints a TASK or settles an ask.
    pub fn tasks_ask_peek(
        &self,
        handle: TaskAskHandle,
    ) -> MemoryResult<Vec<TaskAskPersonEvidence>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let group = self
            .ask_group_in(&txn, handle.group_ref)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
        if group.owner != self.actor().to_hex()
            && !group
                .members
                .iter()
                .any(|member| member.actor == self.actor().to_hex())
        {
            return Err(consult_refusal(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "ask handle is not addressed to this actor",
                "Read an ask you own or answer.",
            ));
        }
        Ok(ask_record::person_evidence_in(
            self.vault(),
            &txn,
            handle.group_ref,
            &group,
            self.vault().store.clock.now_recorded_at(),
        )?)
    }

    /// Live evidence includes late words, without rewriting the cutoff receipt.
    pub fn tasks_ask_evidence(&self, handle: TaskAskHandle) -> MemoryResult<Vec<TaskAskEvidence>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let group = self
            .ask_group_in(&txn, handle.group_ref)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
        if group.owner != self.actor().to_hex()
            && !group
                .members
                .iter()
                .any(|member| member.actor == self.actor().to_hex())
        {
            return Err(MemoryError::bad_request(
                "ask evidence is not addressed to this actor",
            ));
        }
        Ok(super::ask_settlement::evidence(
            self.vault(),
            &txn,
            handle.group_ref,
            &group,
        )?)
    }
}

pub(crate) fn settle_waiting_asks(vault: &crate::Vault) -> crate::Result<()> {
    let txn = vault.store.env.read_txn()?;
    let mut groups = std::collections::BTreeSet::new();
    for ((group, _), row) in TASK_ASK_WAITS.scan(&vault.store, &txn)? {
        if !row.consumed {
            groups.insert(group);
        }
    }
    // OF-533: a canonical code run parked on an ask (a pumped `tasks.wait`) waits too.
    groups.extend(crate::code_run::canonical_wait_ids(vault, &txn)?);
    drop(txn);
    for group in groups {
        super::ask_settlement::settle_ask_if_due(vault, group)?;
    }
    vault.retry_pending_ask_soft_confirms(usize::MAX)?;
    Ok(())
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
