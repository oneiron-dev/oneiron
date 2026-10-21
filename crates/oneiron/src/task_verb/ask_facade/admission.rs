//! Ask ceiling, census and minting.
//! Entry: `Memory::ask_census_in`.
//! Ask admission state stays in `ask_facade`; records belong to `ask_record`.

use super::*;

impl Memory<'_> {
    /// An actor that may not ask is refused before any census runs. A
    /// training offer or training swap intent takes the Coach's scoped
    /// offer-ask reach and nothing else (`gate::coach_offer_ask_ceiling_in_txn`),
    /// never the generic ceiling; a comm widen intent asks only as the run
    /// that reserved it (FIX 1380); every other ask needs the actor's own Auto
    /// ceiling.
    pub(in crate::task_verb) fn require_ask_ceiling_in(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &TaskAskSpec,
    ) -> MemoryResult<()> {
        let coach_ask = super::training_offer_ask::is_training_offer_ask_intent(&input.intent_key)
            || super::training_swap_ask::is_training_swap_ask_intent(&input.intent_key);
        let auto = if coach_ask {
            crate::gate::coach_offer_ask_ceiling_in_txn(
                self.vault(),
                txn,
                self.actor(),
                self.actor_class(),
                input,
            )?
        } else if super::comm_widen::is_comm_widen_ask_intent(&input.intent_key) {
            super::comm_widen::reserved_ask_in(self, txn, input)?
        } else if super::code_consent_word::is_code_consent_ask_intent(&input.intent_key) {
            // DOOR-079 1a: only the held call's caller asks, and only the
            // question its code consent wait reserved.
            super::code_consent_word::reserved_ask_in(self, txn, input)?
        } else {
            super::rate_limit::task_actor_ceiling(
                self.vault(),
                txn,
                self.actor(),
                self.actor_class(),
            )? == PolicyApprovalCeiling::Auto
        };
        if !auto {
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
    pub(super) fn ask_census_in(
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
    pub(super) fn mint_ask_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        mint: AskMint<'_>,
    ) -> MemoryResult<AskGroup> {
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
}
