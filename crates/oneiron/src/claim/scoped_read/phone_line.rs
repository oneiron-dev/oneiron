//! Current phone-call consent, conjoined with every entity row admission.

use std::collections::BTreeSet;

use super::*;
use crate::edge::EdgeKind;
use crate::ports::EntityStoreRead;

/// How deep a confined reach walks `DerivedFrom` sources past the row itself.
const CONFINED_DEPTH: usize = 4;

/// How many walked rows one confined row's visit may touch, shared across its sources.
const CONFINED_BUDGET: usize = 64;

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

    /// The number the call's arrival names as its caller, as the line's
    /// provider gave it: untrusted text, never a recognised person or an
    /// instruction. Read under the same live credential and line consent as
    /// [`Self::phone_line_agent_read`], for the call's transcript (UNBUILT-02
    /// PR 3), which keeps it only normalised. `None` when the arrival names
    /// none; refused for a reader with no phone call, or with more than one.
    pub fn phone_line_caller(&self) -> Result<Option<String>> {
        let [ceiling] = self.actor_key.phone_lines.as_slice() else {
            return Err(crate::phone_line::invalid());
        };
        self.persist_grant_clock()?;
        let txn = self.vault.store.env.read_txn()?;
        let _policy = self.live_policy_manifest_in(&txn)?;
        if !self.proof_live_in(&txn)? || self.phone_line_scope_in(&txn)?.is_none() {
            return Err(crate::phone_line::invalid());
        }
        ceiling.caller_in(self.vault, &txn)
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
                .current_reach_in(self.vault, txn, self.actor_key.actor_ref())?
                .ok_or_else(crate::phone_line::invalid)?;
            let current = current.scope().clone();
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
        // The line's reach, one per ceiling: the frozen call met with the
        // live Setting (VOICE-PHONE-AGENT-REACH R2). A ceiling whose call no
        // longer stands refuses every row. The three presets meet here: the
        // default holds the call to its caller's thread plus the picked
        // documents, a custom holds its scope to the current caller's thread,
        // and the whole vault holds nothing back.
        let mut reaches = Vec::with_capacity(self.actor_key.phone_lines.len());
        for ceiling in &self.actor_key.phone_lines {
            let Some(reach) =
                ceiling.current_reach_in(self.vault, txn, self.actor_key.actor_ref())?
            else {
                return Ok(false);
            };
            reaches.push(reach);
        }
        let caller_rule = reaches.iter().any(|reach| reach.caller_rule());
        let mut confined: Option<BTreeSet<EntityId>> = None;
        for reach in &reaches {
            confined = match (confined, reach.confined()) {
                (Some(own), Some(other)) => Some(own.intersection(other).copied().collect()),
                (Some(own), None) => Some(own),
                (None, Some(other)) => Some(other.clone()),
                (None, None) => None,
            };
        }
        let header = crate::batch::EntityMetadataHeader::parse(raw)
            .ok_or(crate::error::Error::CorruptedIndex("entity header"))?;
        // Under the current-caller rule, a marked phone-thread row reads only
        // in its current caller's call (VOICE-PHONE-AGENT-REACH R1): each phone
        // ceiling must name the row's thread as its current caller's thread.
        // A withheld number names no stored thread, so every marked row is
        // refused. Only marked rows are affected; every other row is judged
        // as today.
        if caller_rule
            && matches!(
                header.entity_type,
                crate::registry::ENTITY_TYPE_CONVERSATION
                    | crate::registry::ENTITY_TYPE_TURN
                    | crate::registry::ENTITY_TYPE_MESSAGE
                    | crate::registry::ENTITY_TYPE_SESSION
            )
        {
            let threads = self.phone_threads_of_row_in(txn, id)?;
            if !threads.is_empty() {
                let Some(currents) = self.current_caller_threads_in(txn)? else {
                    return Ok(false);
                };
                if threads
                    .iter()
                    .any(|thread| currents.iter().any(|current| thread != current))
                {
                    return Ok(false);
                }
            }
        }
        // Under a confined reach, a row reads only when it is itself picked,
        // sits in the current caller's thread, or derives from rows that do --
        // except the line agent's own definition, which the call reads to answer.
        if let Some(documents) = confined.as_ref() {
            let own = self
                .actor_key
                .phone_lines
                .iter()
                .any(|ceiling| ceiling.agent_ref() == *id);
            if !own {
                let mut budget = CONFINED_BUDGET;
                if !self.confined_admits_in(
                    txn,
                    id,
                    header.entity_type,
                    documents,
                    0,
                    &mut budget,
                )? {
                    return Ok(false);
                }
            }
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
        for reach in &reaches {
            let scope = ScopedReadActorKey::read_authority(reach.scope());
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

    /// The current caller thread of each phone ceiling: the line agent's
    /// thread with the call's caller number. `None` when any ceiling's caller
    /// is withheld or unreadable, so every marked row is refused.
    fn current_caller_threads_in(&self, txn: &heed::RoTxn<'_>) -> Result<Option<Vec<EntityId>>> {
        let mut currents = Vec::with_capacity(self.actor_key.phone_lines.len());
        for ceiling in &self.actor_key.phone_lines {
            let caller = match ceiling.caller_in(self.vault, txn) {
                Ok(caller) => caller,
                Err(_) => return Ok(None),
            };
            let Some(number) = crate::voice_call::caller_number(caller.as_deref()) else {
                return Ok(None);
            };
            let Ok(current) = crate::voice_call::voice_phone_conversation_id(
                ceiling.agent_ref(),
                Some(&number),
                "",
            ) else {
                return Ok(None);
            };
            currents.push(current);
        }
        Ok(Some(currents))
    }

    /// Whether the row `id` of `entity_type` sits in the current caller's
    /// thread: true only for a conversation, turn, message or thread session
    /// whose marked threads are non-empty and every one equals the current
    /// thread of every ceiling. A withheld or unreadable caller reads as no
    /// thread.
    fn in_current_caller_thread_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        entity_type: u8,
    ) -> Result<bool> {
        if !matches!(
            entity_type,
            crate::registry::ENTITY_TYPE_CONVERSATION
                | crate::registry::ENTITY_TYPE_TURN
                | crate::registry::ENTITY_TYPE_MESSAGE
                | crate::registry::ENTITY_TYPE_SESSION
        ) {
            return Ok(false);
        }
        let threads = self.phone_threads_of_row_in(txn, id)?;
        if threads.is_empty() {
            return Ok(false);
        }
        let Some(currents) = self.current_caller_threads_in(txn)? else {
            return Ok(false);
        };
        Ok(threads
            .iter()
            .all(|thread| currents.iter().all(|current| thread == current)))
    }

    /// Whether the row `id` passes a confined reach: it is itself picked, it
    /// sits in the current caller's thread, or every row it derives from
    /// passes too (a picked document's chunks and their summaries read; an
    /// unpicked row does not). Fail closed: an edge that does not read is an
    /// error, a derived-from target with no entity record refuses, and past
    /// [`CONFINED_DEPTH`] or the shared [`CONFINED_BUDGET`] the row refuses.
    fn confined_admits_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        entity_type: u8,
        documents: &BTreeSet<EntityId>,
        depth: usize,
        budget: &mut usize,
    ) -> Result<bool> {
        if documents.contains(id) {
            return Ok(true);
        }
        if self.in_current_caller_thread_in(txn, id, entity_type)? {
            return Ok(true);
        }
        if depth >= CONFINED_DEPTH {
            return Ok(false);
        }
        if *budget == 0 {
            return Ok(false);
        }
        *budget -= 1;
        let mut sources = Vec::new();
        for edge in self.out_edges_in(txn, id, Some(EdgeKind::DerivedFrom))? {
            let target = edge?.target;
            let Some(row) = self.entity_record_in(txn, &target)? else {
                return Ok(false);
            };
            sources.push((target, row.entity_type));
        }
        if sources.is_empty() {
            return Ok(false);
        }
        for (source, entity_type) in &sources {
            if !self.confined_admits_in(txn, source, *entity_type, documents, depth + 1, budget)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
