//! Vault CRUD doors over the generic entity/batch machinery.

use super::codec::{
    decode_agent_definition, encode_agent_definition, legacy_logical_id_row,
    validate_agent_definition_update,
};
use super::types::{AgentDefinition, AgentScope};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::temporal::TimeRange;

/// Host-captured attempt generation. Guest input cannot construct this lease.
#[derive(Debug, Clone)]
pub(crate) struct AgentAuthorLease {
    pub(crate) attempt: AttemptId,
    pub(crate) owner: String,
    pub(crate) generation: u32,
}

impl AgentAuthorLease {
    pub(crate) fn from_leased(record: &AttemptRecord) -> Result<Self> {
        if record.state != AttemptState::Leased {
            return Err(Error::Artifact(ArtifactError::AgentNotDispatchable(
                "agent authoring requires a leased attempt",
            )));
        }
        Ok(Self {
            attempt: record.id,
            owner: record.lease_owner.clone().ok_or(Error::Artifact(
                ArtifactError::AgentNotDispatchable("leased author needs a lease owner"),
            ))?,
            generation: record.attempt_count,
        })
    }
}

/// The result of authoring a saved definition. Neither arm launches an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentDefinitionPutDisposition {
    Active,
    Proposed,
}

impl AgentDefinitionPutDisposition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Proposed => "proposed",
        }
    }
}

fn within_author_slice(request: &AgentDefinition, author: &AgentDefinition) -> bool {
    let scope_within = match (&request.scope, &author.scope) {
        (_, AgentScope::All) | (AgentScope::Base, AgentScope::Base | AgentScope::World(_)) => true,
        (AgentScope::World(child), AgentScope::World(parent)) => child == parent,
        _ => false,
    };
    scope_within
        && !request.ceiling.widens_beyond(author.ceiling)
        && request
            .skills
            .iter()
            .all(|skill| author.skills.iter().any(|allowed| allowed == skill))
        && request
            .connectors
            .iter()
            .all(|connector| author.connectors.contains(connector))
        && request
            .code_mode_mcps
            .iter()
            .all(|mcp| author.code_mode_mcps.contains(mcp))
        && (request.model_tier.is_none() || request.model_tier == author.model_tier)
}

impl Vault {
    /// Authors a reusable definition, without dispatching an agent. `author` is
    /// a host-bound stored agent row, never a guest-supplied ceiling or body.
    /// An in-slice definition is active at exactly the author's ceiling; a
    /// wider request is held as a non-dispatchable proposal. The author read
    /// and the create share one transaction so an edit cannot race this check.
    #[cfg(test)]
    pub(crate) fn put_agent_definition_for_author(
        &self,
        author: &EntityId,
        id: &EntityId,
        requested: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AgentDefinitionPutDisposition> {
        self.put_agent_definition_for_author_with_scope(
            author, id, requested, false, None, occurred, learned_at,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the authoring door binds author, target, request, scope, lease generation and time in one transaction"
    )]
    pub(crate) fn put_agent_definition_for_author_with_scope(
        &self,
        author: &EntityId,
        id: &EntityId,
        requested: &AgentDefinition,
        scope_widens: bool,
        lease: Option<&AgentAuthorLease>,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AgentDefinitionPutDisposition> {
        if author == id {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "author cannot replace its own definition through agents.put",
            )));
        }
        let mut wtxn = self.store.env.write_txn()?;
        if let Some(lease) = lease {
            let current = AttemptQueue::new(self)
                .get_in_txn(&wtxn, lease.attempt)?
                .ok_or(Error::EntityNotFound)?;
            if current.state != AttemptState::Leased
                || current.lease_owner.as_deref() != Some(lease.owner.as_str())
                || current.attempt_count != lease.generation
            {
                return Err(Error::Artifact(ArtifactError::AgentNotDispatchable(
                    "authoring lease is no longer held by this worker",
                )));
            }
        }
        let author_def = self.read_agent_definition_in_txn(&wtxn, author)?;
        if author_def.lifecycle_status != ClaimLifecycleStatus::Active
            || !author_def.enabled
            || !matches!(
                author_def.approval_status,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
        {
            return Err(Error::Artifact(ArtifactError::AgentNotDispatchable(
                "author definition is not active and approved",
            )));
        }
        if self.store.port_entity_record(&wtxn, id)?.is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "agents.put creates a new definition; use the update door for an existing row",
            )));
        }
        if requested.forked_from.is_some() || requested.logical_id.is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "agent-authored definitions cannot assert fork lineage or a reserved logical id",
            )));
        }
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        let effective = match policy.actor_ceiling("agent", Some(&author.to_hex())) {
            crate::gate::PolicyApprovalCeiling::Auto => author_def.ceiling,
            crate::gate::PolicyApprovalCeiling::Proposed => super::types::AgentCeiling::Proposed,
        };
        let mut bounded_author = author_def.clone();
        bounded_author.ceiling = effective;
        let within = !scope_widens && within_author_slice(requested, &bounded_author);
        let mut definition = requested.clone();
        definition.source = crate::claim::ClaimSource::Generated;
        definition.generated = true;
        definition.human_authored = false;
        definition.provenance = rmpv::Value::Map(vec![
            (
                rmpv::Value::from("author"),
                rmpv::Value::from(author.to_hex()),
            ),
            (
                rmpv::Value::from("definedVia"),
                rmpv::Value::from("vault.agents.put"),
            ),
        ]);
        definition.lifecycle_status = ClaimLifecycleStatus::Active;
        let disposition = if within {
            definition.ceiling = effective;
            definition.approval_status = author_def.approval_status;
            AgentDefinitionPutDisposition::Active
        } else {
            definition.approval_status = ClaimApprovalStatus::Proposed;
            AgentDefinitionPutDisposition::Proposed
        };
        let data = encode_agent_definition(&definition)?;
        self.apply_agent_definition_body(&mut wtxn, id, occurred, learned_at, data)?;
        wtxn.commit()?;
        crate::context_board::ensure_agent_person(
            self,
            *id,
            definition
                .display_name
                .as_deref()
                .unwrap_or(&definition.agent_id),
            learned_at,
        )?;
        Ok(disposition)
    }

    /// Encodes (validating) and writes an `AgentDefinition` through the generic
    /// entity door.
    pub fn put_agent_definition(
        &self,
        id: &EntityId,
        def: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_agent_definition(def)?;
        self.put_entity(id, ENTITY_TYPE_AGENT_DEF, occurred, learned_at, &data)?;
        // PEOPLE (ARCH-0067): every agent is a person with a `pr` handle.
        crate::context_board::ensure_agent_person(
            self,
            *id,
            def.display_name.as_deref().unwrap_or(&def.agent_id),
            learned_at,
        )
    }

    /// Transaction-composable [`Self::put_agent_definition`]: the definition
    /// and its person land in the caller's writer, which owns commit.
    pub(crate) fn put_agent_definition_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        def: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_agent_definition(def)?;
        crate::ports::EntityStore::port_entity_put(
            self,
            wtxn,
            id,
            &crate::ports::EntityRecord {
                entity_type: ENTITY_TYPE_AGENT_DEF,
                occurred,
                learned_at,
                body: data,
            },
        )?;
        crate::context_board::ensure_agent_person_in_txn(
            self,
            wtxn,
            *id,
            def.display_name.as_deref().unwrap_or(&def.agent_id),
            learned_at,
        )
    }

    /// Discoverability alias for `put_agent_definition` so the registry verb
    /// name `define_agent` greps to the vault surface. The house
    /// `put_/get_/update_` naming stays canonical.
    #[inline]
    pub fn define_agent(
        &self,
        id: &EntityId,
        def: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.put_agent_definition(id, def, occurred, learned_at)
    }

    /// Reads the prior record, enforces the immutability gate, and writes the
    /// new body in a single write transaction.
    pub fn update_agent_definition(
        &self,
        id: &EntityId,
        def: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_agent_definition(def)?;
        let mut wtxn = self.store.env.write_txn()?;
        let existing = self.read_agent_definition_in_txn(&wtxn, id)?;
        validate_agent_definition_update(&existing, def)?;
        self.apply_agent_definition_body(&mut wtxn, id, occurred, learned_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// [`Self::update_agent_definition`], as `owner`, and the one door that
    /// may widen an agent's ceiling (H215). Every other put at an agent id, on
    /// every road, is no wider than the ceiling the id is pinned at; this door
    /// moves that pin to `def`'s ceiling in the transaction that writes the
    /// row, so later puts answer to the owner's ceiling. It rechecks the proof
    /// there, and the actor must own this vault.
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds or its actor does not own this vault;
    /// otherwise as [`Self::update_agent_definition`].
    pub fn update_agent_definition_as(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        def: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_agent_definition(def)?;
        self.with_write_txn(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let existing = self.read_agent_definition_in_txn(txn, id)?;
            validate_agent_definition_update(&existing, def)?;
            super::id_pin::move_pin_for_owner_in_txn(&self.store, txn, id, def)?;
            self.apply_agent_definition_body(txn, id, occurred, learned_at, data)
        })
    }

    /// Applies an accepted acting revision of agent `id`'s charter (OF-379),
    /// as `owner`, in one write transaction: the revision's stored text is
    /// appended to the definition's instructions, the version moves, and the
    /// revision is marked Applied with that version. Every other field and
    /// the ceiling pin stay. A revision already applied returns the live
    /// definition and writes nothing. Only a charter revision whose actor is
    /// `id` applies here; a brief revision keeps its scope and waits for its
    /// brief's own door.
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds or its actor does not own this vault;
    /// [`Error::EntityNotFound`] for an unknown revision or definition;
    /// [`Error::InvalidClaimBody`] for a revision of another target, or one
    /// not accepted; an encoding refusal when the grown instructions no
    /// longer fit, which writes nothing.
    pub fn apply_agent_acting_revision(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        revision_id: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AgentDefinition> {
        use crate::edit_distance::compile::{
            ActingTarget, RevisionStatus, acting_revision_in_txn,
            mark_acting_revision_applied_in_txn,
        };
        self.with_write_txn(|txn| {
            let by = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let revision =
                acting_revision_in_txn(self, txn, revision_id)?.ok_or(Error::EntityNotFound)?;
            if revision.target != (ActingTarget::Charter { actor: *id }) {
                return Err(Error::InvalidClaimBody(
                    "an agent definition applies only a charter revision for that agent",
                ));
            }
            let existing = self.read_agent_definition_in_txn(txn, id)?;
            match revision.status {
                RevisionStatus::Accepted { .. } => {}
                RevisionStatus::Applied { .. } => return Ok(existing),
                _ => {
                    return Err(Error::InvalidClaimBody(
                        "only an accepted acting revision is applied",
                    ));
                }
            }
            let mut updated = existing.clone();
            updated.instructions = Some(match existing.instructions.as_deref() {
                Some(prior) if !prior.trim().is_empty() => format!("{prior}\n\n{}", revision.text),
                _ => revision.text.clone(),
            });
            let seed = serde_json::to_vec(&(&existing.version, &revision.id))
                .map_err(|_| Error::InvariantViolation("acting revision version encode"))?;
            updated.version = format!("acting-{}", blake3::hash(&seed).to_hex());
            validate_agent_definition_update(&existing, &updated)?;
            let data = encode_agent_definition(&updated)?;
            self.apply_agent_definition_body(txn, id, occurred, learned_at, data)?;
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            mark_acting_revision_applied_in_txn(self, txn, &revision.id, by, &updated.version, at)?;
            Ok(updated)
        })
    }

    /// Returns the decoded `AgentDefinition` for `id`, or `None` if absent.
    pub fn get_agent_definition(&self, id: &EntityId) -> Result<Option<AgentDefinition>> {
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AGENT_DEF {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "entity is not a type-17 AGENT_DEF",
            )));
        }
        decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Resolves a seeded row by its stable `sys.*` logical id: the canonical
    /// manifest pins the id, the live STORED row supplies the data. User
    /// edits, the runtime-editable `display_name`, and `enabled` therefore
    /// stay authoritative. An unknown logical id or an absent row is
    /// `Ok(None)`; a stored-row decode failure propagates.
    pub fn get_seeded_agent_definition_by_logical_id(
        &self,
        logical_id: &str,
    ) -> Result<Option<(EntityId, AgentDefinition)>> {
        let Some(id) = legacy_logical_id_row(logical_id)? else {
            return Ok(None);
        };
        Ok(self
            .get_agent_definition(&id)?
            .map(|definition| (id, definition)))
    }

    pub(crate) fn read_agent_definition_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<AgentDefinition> {
        let raw = self
            .store
            .port_entity_record(txn, id)?
            .map(|row| row.encode())
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AGENT_DEF {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "entity is not a type-17 AGENT_DEF",
            )));
        }
        decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..])
    }

    fn apply_agent_definition_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_AGENT_DEF,
                occurred,
                learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }
}
