//! Read-only ask preflight over the exact admission holder and route facts.
use super::ask_types::*;
use super::create_validation::consult_refusal;
use crate::gate::PolicyApprovalCeiling;
use crate::memory::{Memory, MemoryError, MemoryResult, verify_actor_binding};

impl Memory<'_> {
    /// Read-only `can(ask)` preflight. Uses the live authority holders, class,
    /// disclosure and native route that `tasks_ask` resolves at admission. It
    /// neither mints a TASK nor schedules an outbound notice or effect.
    pub fn tasks_can_ask(&self, input: &TaskAskSpec) -> MemoryResult<TaskAskPreflight> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let now = self.vault().store.clock.now_recorded_at();
        let holders = self.ask_holders_in_txn(&txn, input)?;
        let effective = input.effective(
            &holders.iter().copied().collect(),
            now,
            self.ask_class_in_txn(&txn, input.task_ref)?,
        )?;
        if super::rate_limit::task_actor_ceiling(
            self.vault(),
            &txn,
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
        let seats = effective
            .need
            .of
            .seats(&holders.iter().copied().collect())?;
        let mut recipients = Vec::with_capacity(holders.len());
        for actor in holders {
            let kind = self.vault().get_entity_type_in_txn(&txn, &actor)?;
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
            for reference in std::iter::once(effective.what.reference)
                .chain(effective.what.context_refs.iter().copied())
            {
                crate::llm::decision::questions::validate_task_answer_unit(
                    self.vault(),
                    &txn,
                    self.actor(),
                    actor,
                    reference.entity_ref(),
                )?;
            }
            let route = if kind == Some(crate::registry::ENTITY_TYPE_PERSON) {
                crate::human_task::resolve_native_human_route_in(self.vault(), &txn, actor).ok()
            } else {
                None
            };
            let face = match &route {
                Some(route) => self
                    .vault()
                    .get_channel_identity_in_txn(&txn, &route.channel_identity_ref)?
                    .map(|identity| identity.address_or_handle),
                None => None,
            };
            recipients.push(TaskAskPreflightRecipient {
                who: actor,
                face,
                channel: route.map(|route| route.channel),
                word_required: (seats.contains(&actor)
                    && usize::from(effective.need.count) == seats.len())
                    || effective
                        .class
                        .as_ref()
                        .is_some_and(|class| class.required_people.contains(&actor)),
            });
        }
        Ok(TaskAskPreflight { recipients })
    }
}
