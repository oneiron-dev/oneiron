//! Who an ask reaches: the holders of its target, the role a role ask
//! reached, and the principal of an ask that omits its target.
//! Entry: `Memory::ask_route_in_txn`.
//! Ask census and minting live in `admission`; records belong to `ask_record`.

use super::*;
use crate::task_verb::{presence_pages, wire_decode};

impl Memory<'_> {
    pub(in super::super) fn ask_holders_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &TaskAskSpec,
    ) -> MemoryResult<Vec<EntityId>> {
        Ok(self.ask_route_in_txn(txn, input)?.0)
    }

    /// `input`'s holders, and for a role ask the role it reached, read in
    /// the same snapshot as its holders (ROLES-EVERYWHERE = A); `None` for
    /// every other target.
    pub(in super::super) fn ask_route_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &TaskAskSpec,
    ) -> MemoryResult<(Vec<EntityId>, Option<crate::llm::decision::AskRole>)> {
        let holders = match &input.who {
            Some(TaskAskTarget::Authority(scope)) => {
                self.vault()
                    .ask_authority_holders_in_txn(txn, &scope.class, &scope.envelope)?
            }
            Some(TaskAskTarget::Responder(assignee)) => {
                vec![assignee.entity_ref().unwrap_or(self.actor())]
            }
            Some(TaskAskTarget::People(people)) => people.iter().copied().collect(),
            Some(TaskAskTarget::Guests(guests)) => guests.keys().copied().collect(),
            Some(TaskAskTarget::Role(to)) => {
                let reached = self.vault().ask_role_in_txn(txn, to)?;
                let holders = reached.holders.iter().map(|holder| holder.actor).collect();
                return Ok((holders, Some(reached.role)));
            }
            None => vec![self.short_ask_principal_in_txn(txn)?],
        };
        Ok((holders, None))
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
        let tasks = presence_pages::all_admitted_tasks_in(
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
            let Some(body) = wire_decode::task_verb_body_in(self.vault(), txn, task)? else {
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
}

impl crate::Vault {
    /// The role a role ask reaches in `txn` (ROLES-EVERYWHERE = A), through
    /// the decision ladders' own resolver: the first role on `to`'s chain, up
    /// to its ceiling, with a live holder who may answer for its act. With
    /// none up to the ceiling the ask is refused: it never goes wider.
    pub(in super::super) fn ask_role_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        to: &crate::llm::decision::AskTo,
    ) -> MemoryResult<crate::llm::decision::ResolvedRole> {
        if to.validate().is_err() {
            return Err(MemoryError::bad_request(
                "an ask's role is above its ceiling",
            ));
        }
        // A task ask's answer is a word, checked by who wrote it and not by
        // what kind of actor wrote it: a judgment. An e-signature or a payment
        // a person must authorise asks through its own door.
        if to.act.person_only() {
            return Err(MemoryError::bad_request(
                "a task ask by role carries a judgment, not a person-only act",
            ));
        }
        self.next_ask_role_in_txn(txn, to, None)?.ok_or_else(|| {
            MemoryError::bad_request("no role up to the ask's ceiling has a live holder")
        })
    }
}
