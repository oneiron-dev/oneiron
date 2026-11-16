//! Current phone-call consent, conjoined with every entity row admission.

use super::*;
use crate::ports::EntityStoreRead;

impl ScopedRead<'_> {
    /// The call's current consent ceiling, for invalidating prepared context
    /// and output when that ceiling changes. This is not a read grant or a
    /// substitute for checking every source row under this same read key.
    /// Ordinary readers have no phone ceiling and return `None`.
    pub fn phone_line_scope(&self) -> Result<Option<crate::federation::Scope>> {
        if self.actor_key.phone_lines.is_empty() {
            return Ok(None);
        }
        self.persist_grant_clock()?;
        let txn = self.vault.store.env.read_txn()?;
        let _policy = self.live_policy_manifest_in(&txn)?;
        if !self.proof_live_in(&txn)? {
            return Err(crate::phone_line::invalid());
        }
        self.phone_line_scope_in(&txn)
    }

    /// The actual receiving agent's admitted definition and a reader held to
    /// its world scope. Credential, line consent, row and dispatchability share
    /// one snapshot before the definition supplies instructions or models.
    pub fn phone_line_agent_read(
        &self,
    ) -> Result<(ScopedReadActorKey, crate::agent_def::AgentDefinition)> {
        if self.actor_key.phone_lines.is_empty() {
            return Err(crate::phone_line::invalid());
        }
        self.persist_grant_clock()?;
        let txn = self.vault.store.env.read_txn()?;
        let _policy = self.live_policy_manifest_in(&txn)?;
        if !self.proof_live_in(&txn)? || self.phone_line_scope_in(&txn)?.is_none() {
            return Err(crate::phone_line::invalid());
        }
        let id = EntityId::from_hex(self.actor_key.actor_ref())?;
        let Some((kind, _, body)) = self.graph_ask_parts_in_txn(&txn, &id)? else {
            return Err(crate::phone_line::invalid());
        };
        if kind != crate::registry::ENTITY_TYPE_AGENT_DEF {
            return Err(crate::phone_line::invalid());
        }
        let definition = crate::agent_def::decode_agent_definition(&body)?;
        crate::agent_dispatch::AgentDispatcher::ensure_dispatchable_definition(id, &definition)?;
        let key = match &definition.scope {
            crate::agent_def::AgentScope::All => self.actor_key.clone(),
            crate::agent_def::AgentScope::Base => self.actor_key.clone().within_worlds(
                crate::claim::world_access::WorldAuthoritySet::new(true, [])?,
            ),
            crate::agent_def::AgentScope::World(world) => self.actor_key.clone().within_worlds(
                crate::claim::world_access::WorldAuthoritySet::new(true, [*world])?,
            ),
        };
        Ok((key, definition))
    }

    /// The actual anonymous phone audience under this reader's current
    /// line consent. Ordinary readers cannot supply a phone disclosure.
    pub fn phone_line_disclosure(
        &self,
        interlocutors: crate::interlocutor::InterlocutorSet,
    ) -> Result<crate::DisclosureContext> {
        let scope = self
            .phone_line_scope()?
            .ok_or_else(crate::phone_line::invalid)?;
        crate::DisclosureContext::phone_line(interlocutors, scope)
    }

    /// Revalidates prepared output's source rows, native disclosure closure
    /// and current call consent in one snapshot. `None` means no phone call,
    /// never permission to send an anonymous answer.
    pub fn phone_line_output_scope(
        &self,
        sources: &[EntityId],
        interlocutors: &crate::interlocutor::InterlocutorSet,
    ) -> Result<Option<crate::federation::Scope>> {
        if self.actor_key.phone_lines.is_empty() {
            return Ok(None);
        }
        self.persist_grant_clock()?;
        let txn = self.vault.store.env.read_txn()?;
        let scope = self.phone_line_scope_in(&txn)?;
        let _policy = self.live_policy_manifest_in(&txn)?;
        if !self.proof_live_in(&txn)?
            || self
                .entities_readable_in_txn(&txn, sources)?
                .into_iter()
                .any(|readable| !readable)
        {
            return Err(crate::phone_line::invalid());
        }
        let scope = scope.ok_or_else(crate::phone_line::invalid)?;
        let disclosure =
            crate::DisclosureContext::phone_line(interlocutors.clone(), scope.clone())?;
        for source in sources {
            let Some(row) = self.vault.store.port_entity_record(&txn, source)? else {
                return Err(crate::phone_line::invalid());
            };
            if !disclosure.admits_in(self.vault, &txn, source, row.entity_type, None)? {
                return Err(crate::phone_line::invalid());
            }
        }
        Ok(Some(scope))
    }

    fn phone_line_scope_in(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<crate::federation::Scope>> {
        let mut scope: Option<crate::federation::Scope> = None;
        for ceiling in &self.actor_key.phone_lines {
            let current = ceiling
                .current_scope_in(self.vault, txn, self.actor_key.actor_ref())?
                .ok_or_else(crate::phone_line::invalid)?;
            scope = Some(match scope {
                Some(prior) => prior.meet(&current),
                None => current,
            });
        }
        Ok(scope)
    }

    pub(super) fn phone_lines_allow_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        if self.actor_key.phone_lines.is_empty() {
            return Ok(true);
        }
        let record = match self.session_view {
            Some(view) => crate::federation::record_scope::scope_for_blob(view, txn, *id, raw)?,
            None => {
                crate::federation::record_scope::scope_for_blob(&self.vault.store, txn, *id, raw)?
            }
        };
        let Some(record) = record else {
            return Ok(false);
        };
        for ceiling in &self.actor_key.phone_lines {
            let Some(scope) =
                ceiling.current_scope_in(self.vault, txn, self.actor_key.actor_ref())?
            else {
                return Ok(false);
            };
            let scope = ScopedReadActorKey::read_authority(&scope);
            if !scope.admits("read", &record, &crate::federation::Scope::top()) {
                return Ok(false);
            }
            // Facets use the native placement rule, not Scope::admits, and
            // explicit line consent has no owner-facet exemption.
            let facets = match self.session_view {
                Some(view) => crate::federation::facet_read::facets_admit_in(
                    self.vault,
                    view,
                    txn,
                    *id,
                    raw,
                    &scope.facets,
                )?,
                None => crate::federation::facet_read::facets_admit_in(
                    self.vault,
                    &self.vault.store,
                    txn,
                    *id,
                    raw,
                    &scope.facets,
                )?,
            };
            if !facets {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
