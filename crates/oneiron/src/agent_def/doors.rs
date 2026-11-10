//! Vault CRUD doors over the generic entity/batch machinery.

use super::codec::{
    decode_agent_definition, encode_agent_definition, legacy_logical_id_row,
    validate_agent_definition_update,
};
use super::types::{AgentDefinition, AgentScope, DreamingMode};
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
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The verb name the authoring door's definitions record as their door.
const AGENTS_PUT_DOOR: &str = "vault.agents.put";

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

/// The agent a generic row door writes for, and that door's verb name. A
/// batch that carries one holds each definition it creates to that agent's
/// slice (ARCH-0053:20).
#[derive(Debug, Clone, Copy)]
pub(crate) struct AgentAuthoring {
    author: EntityId,
    door: &'static str,
}

impl AgentAuthoring {
    /// `actor` writing through `door`; `None` when `actor` is no agent.
    pub(crate) fn of(actor: &crate::WriteActor, door: &'static str) -> Option<Self> {
        (actor.actor_class() == crate::edge::EdgeActorClass::Agent).then(|| Self {
            author: actor.entity_ref(),
            door,
        })
    }
}

/// Marks `definition` as authored by the agent `author` through `door`: a
/// generated record, live at rest, whose provenance names both. Its approval
/// is the caller's to set.
fn mark_agent_authored(definition: &mut AgentDefinition, author: &EntityId, door: &'static str) {
    definition.source = crate::claim::ClaimSource::Generated;
    definition.generated = true;
    definition.human_authored = false;
    definition.provenance = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("author"),
            rmpv::Value::from(author.to_hex()),
        ),
        (rmpv::Value::from("definedVia"), rmpv::Value::from(door)),
    ]);
    definition.lifecycle_status = ClaimLifecycleStatus::Active;
}

/// Whether every grant `request` names is one `holder` holds: its scope, its
/// skills, its connectors and its code-mode MCPs.
fn grants_within(request: &AgentDefinition, holder: &AgentDefinition) -> bool {
    let scope_within = match (&request.scope, &holder.scope) {
        (_, AgentScope::All) | (AgentScope::Base, AgentScope::Base | AgentScope::World(_)) => true,
        (AgentScope::World(child), AgentScope::World(parent)) => child == parent,
        _ => false,
    };
    scope_within
        && request
            .skills
            .iter()
            .all(|skill| holder.skills.iter().any(|allowed| allowed == skill))
        && request
            .connectors
            .iter()
            .all(|connector| holder.connectors.contains(connector))
        && request
            .code_mode_mcps
            .iter()
            .all(|mcp| holder.code_mode_mcps.contains(mcp))
}

/// Whether a definition is one its agent runs under: active, approved and
/// switched on.
fn stands(definition: &AgentDefinition) -> bool {
    definition.lifecycle_status == ClaimLifecycleStatus::Active
        && definition.enabled
        && matches!(
            definition.approval_status,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
}

fn within_author_slice(request: &AgentDefinition, author: &AgentDefinition) -> bool {
    grants_within(request, author)
        && !request.ceiling.widens_beyond(author.ceiling)
        // The owner's model choices hold as they are (FIX 4472): an authored
        // put cannot change them. `request` has already taken every choice it
        // left out from the author (FIX 9557), so each resolved choice is
        // checked, the dreaming ones included; turning its own dreaming off
        // is the one narrowing a model choice allows.
        && request.model_tier == author.model_tier
        && request.models == author.models
        && request.compaction_model == author.compaction_model
        && request.dreaming_model == author.dreaming_model
        && (request.dreaming_mode() == author.dreaming_mode()
            || request.dreaming_mode() == DreamingMode::Off)
}

/// `requested` with every model choice it leaves out taken from `author`
/// (FIX 9557): an omitted model list, tier, compaction model, dreaming mode
/// or dreaming model inherits the author's live bound, so an omission never
/// lifts it. A choice the request names is kept whole.
fn inherit_model_choices(requested: &AgentDefinition, author: &AgentDefinition) -> AgentDefinition {
    let mut filled = requested.clone();
    if filled.models.is_empty() {
        filled.models.clone_from(&author.models);
    }
    if filled.model_tier.is_none() {
        filled.model_tier.clone_from(&author.model_tier);
    }
    if filled.compaction_model.is_none() {
        filled.compaction_model.clone_from(&author.compaction_model);
    }
    if filled.dreaming.is_none() {
        filled.dreaming = author.dreaming;
    }
    if filled.dreaming_model.is_none() {
        filled.dreaming_model.clone_from(&author.dreaming_model);
    }
    filled
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

    /// Keeps an admitted child's requested ceiling; the live author's bound
    /// decides whether it is active or an inert proposal.
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
        let (definition, disposition) = self.prepare_agent_definition_for_author_in_txn(
            &wtxn,
            author,
            id,
            requested,
            scope_widens,
            AGENTS_PUT_DOOR,
        )?;
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

    /// Creates only after credential admission and an Allow setup receipt in
    /// the same writer. `None` leaves the shape item resting without storing a
    /// proposed definition. A non-Allow result stores its Gate receipt only.
    /// The caller holds the credential's spend turn and commits this writer,
    /// including its item journal, only after the result has been recorded.
    ///
    /// `channel_scope`, `channel_ref` and `effect` are the native adapter's
    /// observed context, never fields taken from a shape request. This door
    /// supplies no default channel scope, effect facts or host signer.
    #[expect(
        clippy::too_many_arguments,
        reason = "setup binds the actual credential, channel, target, native effect and optional consuming signer in one writer"
    )]
    pub(crate) fn create_agent_definition_for_actor_credential_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        author: &EntityId,
        credential: &crate::authority::VerifiedSlip,
        issuer: Option<&crate::authority::HostSlipIssuer>,
        id: &EntityId,
        requested: &AgentDefinition,
        channel_scope: &crate::federation::Scope,
        channel_ref: Option<&str>,
        effect: &crate::consent::ComposedEffect,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<Option<(crate::gate::GateOutcome, crate::store::GateDecisionId)>> {
        if author == id {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "author cannot replace its own definition through agents.put",
            )));
        }
        let claims = credential.claims();
        if claims.holder_ref != author.to_hex()
            || !self.capability_slip_is_live_in_txn(txn, credential)?
        {
            return Err(Error::Artifact(ArtifactError::AgentNotDispatchable(
                "setup requires the author's live credential",
            )));
        }
        // Without the real consuming signer this call retains the old
        // resting state; an explicitly supplied signer supports one-shots.
        if claims.single_use && issuer.is_none() {
            return Ok(None);
        }
        let (definition, disposition) = self.prepare_agent_definition_for_author_in_txn(
            txn,
            author,
            id,
            requested,
            false,
            AGENTS_PUT_DOOR,
        )?;
        if disposition != AgentDefinitionPutDisposition::Active {
            return Ok(None);
        }
        let data = encode_agent_definition(&definition)?;
        let Some(position) = crate::federation::record_scope::candidate_put_position(
            &self.store,
            txn,
            *id,
            ENTITY_TYPE_AGENT_DEF,
            &data,
        )?
        else {
            return Ok(None);
        };
        let current = self.current_view_scope_in_txn(txn, claims);
        let admitted = ["core:write", "write"]
            .into_iter()
            .any(|verb| current.admits(verb, &position, channel_scope))
            && (claims.records.is_empty() || claims.records.contains(&id.to_hex()))
            && (claims.channels.is_empty()
                || channel_ref.is_some_and(|channel| claims.channels.contains(channel)));
        if !admitted {
            return Ok(None);
        }
        let actor = crate::WriteActor::new(*author, crate::edge::EdgeActorClass::Agent);
        let (decision, receipt) = crate::gate::record_agent_definition_setup_in_txn(
            self, txn, actor, *id, &data, &position, effect,
        )?;
        let outcome = decision.outcome();
        if outcome != crate::gate::GateOutcome::Allow {
            return Ok(Some((outcome, receipt)));
        }
        if let Some(issuer) = issuer {
            self.consume_verified_capability_slip_in_txn(txn, issuer, credential)?;
        }
        self.apply_agent_definition_body(txn, id, occurred, learned_at, data)?;
        crate::context_board::ensure_agent_person_in_txn(
            self,
            txn,
            *id,
            definition
                .display_name
                .as_deref()
                .unwrap_or(&definition.agent_id),
            learned_at,
        )?;
        Ok(Some((outcome, receipt)))
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
                row_version: 0,
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
        self.update_agent_definition_as_checked(owner, id, None, def, occurred, learned_at)
    }

    /// The owner's edit of exactly the revision they read. The version check
    /// and the existing immutable-field and ceiling gates share the writer.
    #[expect(
        clippy::too_many_arguments,
        reason = "owner, target, revision, body and event time are one edit"
    )]
    pub fn update_agent_definition_at_version_as(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        expected_version: &str,
        def: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.update_agent_definition_as_checked(
            owner,
            id,
            Some(expected_version),
            def,
            occurred,
            learned_at,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the revision fence is optional only for existing native callers"
    )]
    fn update_agent_definition_as_checked(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        expected_version: Option<&str>,
        def: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_agent_definition(def)?;
        self.with_write_txn(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let existing = self.read_agent_definition_in_txn(txn, id)?;
            if expected_version.is_some_and(|version| version != existing.version) {
                return Err(Error::ConcurrentWrite("agent definition revision changed"));
            }
            validate_agent_definition_update(&existing, def)?;
            super::id_pin::move_pin_for_owner_in_txn(&self.store, txn, id, def)?;
            self.apply_agent_definition_body(txn, id, occurred, learned_at, data)
        })
    }

    /// [`Self::update_agent_definition_at_version_as`] in the caller's
    /// writer, for a patch of the ceiling alone (FIX 1786): the definition
    /// standing at `expected_version` is cloned and only its ceiling and its
    /// version change; grants, scopes, connectors, instructions and manifest
    /// stay as they are. The proof is rechecked here and the id pin moves to
    /// the new ceiling, as the owner's edit does, so the caller's receipt
    /// commits with the effect. Returns the definition as written.
    ///
    /// # Errors
    ///
    /// As [`Self::update_agent_definition_at_version_as`].
    pub(crate) fn patch_agent_ceiling_at_version_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        expected_version: &str,
        ceiling: super::types::AgentCeiling,
        learned_at: u64,
    ) -> Result<AgentDefinition> {
        owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let existing = self.read_agent_definition_in_txn(txn, id)?;
        if expected_version != existing.version {
            return Err(Error::ConcurrentWrite("agent definition revision changed"));
        }
        let mut patched = existing.clone();
        patched.ceiling = ceiling;
        let seed = serde_json::to_vec(&(&existing.version, ceiling.as_str()))
            .map_err(|_| Error::InvariantViolation("ceiling patch version encode"))?;
        patched.version = format!("ceiling-{}", blake3::hash(&seed).to_hex());
        validate_agent_definition_update(&existing, &patched)?;
        super::id_pin::move_pin_for_owner_in_txn(&self.store, txn, id, &patched)?;
        let data = encode_agent_definition(&patched)?;
        let occurred = TimeRange {
            start: learned_at,
            end: learned_at,
        };
        self.apply_agent_definition_body(txn, id, occurred, learned_at, data)?;
        Ok(patched)
    }

    /// Creates an inert custom definition as the authenticated owner. An
    /// occupied id is never an implicit edit, including another entity kind.
    pub fn create_agent_definition_as(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        def: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            if self.store.port_entity_record(txn, id)?.is_some() {
                return Err(Error::ConcurrentWrite(
                    "agent definition id is already occupied",
                ));
            }
            self.put_agent_definition_in_txn(txn, id, def, occurred, learned_at)
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
        txn: &heed::RoTxn<'_>,
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

    /// The body an agent's generic put of a definition stores (ARCH-0053:20):
    /// the one the author writer gives it, so every door an agent's own handle
    /// writes rows through lands what `vault.agents.put` lands. A new
    /// definition inside the author's slice is active at the author's
    /// approval; wider, it is a proposal no dispatch runs. An agent that holds
    /// no definition of its own (a PERSON bound as an agent) has no slice to
    /// lend, so what it authors is a proposal. A put over a stored definition
    /// answers to [`Self::agent_authored_update_body_in_txn`]. `None` leaves
    /// the put as written.
    ///
    /// # Errors
    ///
    /// A body that does not decode, and the author writer's refusals: an
    /// author that is switched off, a body that names fork lineage or a
    /// logical id, and an id that holds a deleted row.
    fn agent_authored_definition_body_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        authoring: AgentAuthoring,
        id: &EntityId,
        body: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        match live_entity_row_in_txn(&self.store, txn, id)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_AGENT_DEF,
                body: stored,
            } => {
                return self.agent_authored_update_body_in_txn(txn, authoring, id, &stored, body);
            }
            // Another entity type at the id is the put arm's to refuse.
            LiveEntityRow::Live { .. } => return Ok(None),
            LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {}
        }
        let requested = decode_agent_definition(body)?;
        let author = &authoring.author;
        let author_holds_definition = matches!(
            live_entity_row_in_txn(&self.store, txn, author)?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_AGENT_DEF,
                ..
            }
        );
        let definition = if author_holds_definition {
            self.prepare_agent_definition_for_author_in_txn(
                txn,
                author,
                id,
                &requested,
                false,
                authoring.door,
            )?
            .0
        } else {
            self.ensure_new_authored_definition_in_txn(txn, id, &requested)?;
            let mut definition = requested;
            mark_agent_authored(&mut definition, author, authoring.door);
            definition.approval_status = ClaimApprovalStatus::Proposed;
            definition
        };
        encode_agent_definition(&definition).map(Some)
    }

    /// The body an agent's generic put over the stored definition `stored`
    /// stores at `id`. A put that names no grant the row does not hold (its
    /// scope, skills, connectors and code-mode MCPs) stays as written, for
    /// the update rules to judge: the id pin holds its ceiling, and the
    /// owner-only widening rule its three switches and its models. A put that
    /// grants the row more answers to the author's slice, as a new definition
    /// does (ARCH-0053:20): inside the slice of an author other than the row
    /// itself it stays as written; beyond it, the row is held as a proposal
    /// no dispatch runs until the owner approves it. A put that already
    /// stands below approved stays as written.
    ///
    /// # Errors
    ///
    /// A body, or a stored row, that does not decode.
    fn agent_authored_update_body_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        authoring: AgentAuthoring,
        id: &EntityId,
        stored: &[u8],
        body: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let requested = decode_agent_definition(body)?;
        if grants_within(&requested, &decode_agent_definition(stored)?)
            || !matches!(
                requested.approval_status,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
        {
            return Ok(None);
        }
        let author = &authoring.author;
        if author != id
            && let LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_AGENT_DEF,
                body: author_body,
            } = live_entity_row_in_txn(&self.store, txn, author)?
        {
            let author_def = decode_agent_definition(&author_body)?;
            if stands(&author_def) {
                let slice = self.policy_bounded_author_in_txn(txn, author, &author_def)?;
                if grants_within(&requested, &slice)
                    && !requested.ceiling.widens_beyond(slice.ceiling)
                {
                    return Ok(None);
                }
            }
        }
        let mut proposal = requested;
        proposal.approval_status = ClaimApprovalStatus::Proposed;
        encode_agent_definition(&proposal).map(Some)
    }

    /// `author_def` at the ceiling policy leaves the agent `author`: the
    /// slice it lends what it authors.
    fn policy_bounded_author_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        author: &EntityId,
        author_def: &AgentDefinition,
    ) -> Result<AgentDefinition> {
        let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        let mut bounded = author_def.clone();
        bounded.ceiling = match policy.actor_ceiling("agent", Some(&author.to_hex())) {
            crate::gate::PolicyApprovalCeiling::Auto => author_def.ceiling,
            crate::gate::PolicyApprovalCeiling::Proposed => super::types::AgentCeiling::Proposed,
        };
        Ok(bounded)
    }

    /// What every agent-authored create answers to before its slice is read:
    /// `id` holds no row, and the request asserts no lineage.
    fn ensure_new_authored_definition_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        requested: &AgentDefinition,
    ) -> Result<()> {
        if self.store.port_entity_record(txn, id)?.is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "agents.put creates a new definition; use the update door for an existing row",
            )));
        }
        if requested.forked_from.is_some() || requested.logical_id.is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "agent-authored definitions cannot assert fork lineage or a reserved logical id",
            )));
        }
        Ok(())
    }

    /// Holds each definition `ops` put to `authoring`'s slice, read in the
    /// transaction that applies them: the generic put doors' share of the
    /// author writer ([`Self::agent_authored_definition_body_in_txn`]). With
    /// no `authoring`, `ops` stay as staged.
    ///
    /// # Errors
    ///
    /// As [`Self::agent_authored_definition_body_in_txn`].
    pub(crate) fn bound_agent_authored_puts_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        authoring: Option<AgentAuthoring>,
        ops: &mut [BatchOp],
    ) -> Result<()> {
        let Some(authoring) = authoring else {
            return Ok(());
        };
        for op in ops {
            if let BatchOp::Put {
                id,
                entity_type,
                data,
                ..
            } = op
                && *entity_type == ENTITY_TYPE_AGENT_DEF
                && let Some(bounded) =
                    self.agent_authored_definition_body_in_txn(txn, authoring, id, data)?
            {
                *data = bounded;
            }
        }
        Ok(())
    }

    /// Prepares the same author-bounded definition for a door that owns its
    /// writer. `door` is the verb name its provenance records.
    fn prepare_agent_definition_for_author_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        author: &EntityId,
        id: &EntityId,
        requested: &AgentDefinition,
        scope_widens: bool,
        door: &'static str,
    ) -> Result<(AgentDefinition, AgentDefinitionPutDisposition)> {
        let author_def = self.read_agent_definition_in_txn(txn, author)?;
        if !stands(&author_def) {
            return Err(Error::Artifact(ArtifactError::AgentNotDispatchable(
                "author definition is not active and approved",
            )));
        }
        self.ensure_new_authored_definition_in_txn(txn, id, requested)?;
        let bounded_author = self.policy_bounded_author_in_txn(txn, author, &author_def)?;
        let mut definition = inherit_model_choices(requested, &bounded_author);
        let within = !scope_widens && within_author_slice(&definition, &bounded_author);
        mark_agent_authored(&mut definition, author, door);
        let disposition = if within {
            definition.approval_status = author_def.approval_status;
            AgentDefinitionPutDisposition::Active
        } else {
            definition.approval_status = ClaimApprovalStatus::Proposed;
            AgentDefinitionPutDisposition::Proposed
        };
        Ok((definition, disposition))
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
                row_version: None,
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
