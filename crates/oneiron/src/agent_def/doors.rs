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

/// The agent a generic row door writes for, that door's verb name, and the
/// key of the read the door holds its caller to. A batch that carries one
/// holds each definition it creates to that agent's slice (ARCH-0053:20).
#[derive(Debug, Clone)]
pub(crate) struct AgentAuthoring {
    author: EntityId,
    door: &'static str,
    /// The door's write lane key: the credential an agent with no definition
    /// of its own takes its slice from. `None` for an unbound lane, which
    /// grants nothing by itself.
    read_key: Option<crate::claim::ScopedReadActorKey>,
}

impl AgentAuthoring {
    /// `actor` writing through `door` under the lane key `read_key`; `None`
    /// when `actor` is no agent.
    pub(crate) fn of(
        actor: &crate::WriteActor,
        door: &'static str,
        read_key: Option<&crate::claim::ScopedReadActorKey>,
    ) -> Option<Self> {
        (actor.actor_class() == crate::edge::EdgeActorClass::Agent).then(|| Self {
            author: actor.entity_ref(),
            door,
            read_key: read_key.cloned(),
        })
    }
}

/// The key the id of a proposed change to a stored definition is derived
/// under.
const PROPOSED_CHANGE_ID_CONTEXT: &str = "oneiron agent_def proposed change id v1";

/// The id of the record that holds version `version` of the definition at
/// `stored` as a proposal (ARCH-0053:20, r6). An agent's put that grants a
/// stored definition more than its author's slice holds is stored there,
/// beside the definition it would replace, which stays as it is. The id is
/// the first 16 bytes of the BLAKE3 hash, keyed by
/// [`PROPOSED_CHANGE_ID_CONTEXT`], of the stored id's bytes then the
/// version's: a caller that knows what it put reads the proposal back, and a
/// repeat of the same put lands on the same record.
///
/// # Errors
///
/// An invalid-key error when the derived bytes are a reserved id pattern.
pub(super) fn proposed_change_id(stored: &EntityId, version: &str) -> Result<EntityId> {
    let mut hasher = blake3::Hasher::new_derive_key(PROPOSED_CHANGE_ID_CONTEXT);
    hasher.update(stored.as_bytes());
    hasher.update(version.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    let id = EntityId::from_bytes(bytes)?;
    Ok(id)
}

/// What the author writer makes of one AGENT_DEF put an agent staged.
enum AuthoredPut {
    /// Stored as staged.
    AsStaged,
    /// Stored at the put's id, with this body.
    Bounded(Vec<u8>),
    /// Stored as a new proposal record at `id`, with `body`; the row the put
    /// named stays as it is.
    ProposedChange { id: EntityId, body: Vec<u8> },
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

/// Whether the scope `request` reads is inside the scope `holder` reads.
fn scope_within(request: &AgentScope, holder: &AgentScope) -> bool {
    match (request, holder) {
        (_, AgentScope::All) | (AgentScope::Base, AgentScope::Base | AgentScope::World(_)) => true,
        (AgentScope::World(child), AgentScope::World(parent)) => child == parent,
        _ => false,
    }
}

/// Whether every grant `request` names is one `holder` holds: its scope, its
/// skills, its connectors and its code-mode MCPs.
fn grants_within(request: &AgentDefinition, holder: &AgentDefinition) -> bool {
    scope_within(&request.scope, &holder.scope)
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
pub(crate) fn stands(definition: &AgentDefinition) -> bool {
    definition.lifecycle_status == ClaimLifecycleStatus::Active
        && definition.enabled
        && matches!(
            definition.approval_status,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
}

/// Whether `request` keeps the single model choices its author runs under:
/// its tier, its compaction model and its dreaming. The owner's choices on
/// the author's row hold as they are (FIX 4472): an authored put cannot
/// change them. `request` has already taken every choice it left out from
/// the author (FIX 9557), so each resolved choice is checked; turning its
/// own dreaming off is the one narrowing a model choice allows.
fn keeps_author_model_choices(request: &AgentDefinition, author: &AgentDefinition) -> bool {
    request.model_tier == author.model_tier
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
        // PEOPLE (ARCH-0067): the definition and its person land in this one
        // writer, so a person that cannot be built leaves no definition
        // behind for a retry of this create-only door to find occupied.
        crate::context_board::ensure_agent_person_in_txn(
            self,
            &mut wtxn,
            *id,
            definition
                .display_name
                .as_deref()
                .unwrap_or(&definition.agent_id),
            learned_at,
        )?;
        wtxn.commit()?;
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
    /// entity door, with its person, in one writer.
    pub fn put_agent_definition(
        &self,
        id: &EntityId,
        def: &AgentDefinition,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_agent_definition(def)?;
        self.with_write_txn(|txn| {
            self.batch_in()
                .put(id, ENTITY_TYPE_AGENT_DEF, occurred, learned_at, &data)
                .apply(txn)?;
            // PEOPLE (ARCH-0067): every agent is a person with a `pr` handle.
            // A person that cannot be built leaves no definition behind.
            crate::context_board::ensure_agent_person_in_txn(
                self,
                txn,
                *id,
                def.display_name.as_deref().unwrap_or(&def.agent_id),
                learned_at,
            )
        })
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

    /// What an agent's generic put of a definition stores (ARCH-0053:20): what
    /// the author writer makes of it, so every door an agent's own handle
    /// writes rows through lands what `vault.agents.put` lands. A new
    /// definition inside the author's slice is active at the author's
    /// approval; wider, it is a proposal no dispatch runs. An agent that holds
    /// no definition of its own (a PERSON bound as an agent) lends the slice
    /// its grant gives it ([`Self::within_granted_slice_in_txn`]): inside it
    /// the definition is approved, and with no grant at all it is a proposal.
    /// A put over a stored definition answers to
    /// [`Self::agent_authored_update_in_txn`].
    ///
    /// # Errors
    ///
    /// A body that does not decode, and the author writer's refusals: an
    /// author that is switched off, a body that names fork lineage or a
    /// logical id, and an id that holds a deleted row.
    fn agent_authored_put_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        authoring: &AgentAuthoring,
        id: &EntityId,
        body: &[u8],
    ) -> Result<AuthoredPut> {
        match live_entity_row_in_txn(&self.store, txn, id)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_AGENT_DEF,
                body: stored,
            } => {
                return self.agent_authored_update_in_txn(txn, authoring, id, &stored, body);
            }
            // Another entity type at the id is the put arm's to refuse.
            LiveEntityRow::Live { .. } => return Ok(AuthoredPut::AsStaged),
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
            let within = self.within_granted_slice_in_txn(txn, authoring, &requested)?;
            let mut definition = requested;
            mark_agent_authored(&mut definition, author, authoring.door);
            definition.approval_status = if within {
                ClaimApprovalStatus::Approved
            } else {
                ClaimApprovalStatus::Proposed
            };
            definition
        };
        encode_agent_definition(&definition).map(AuthoredPut::Bounded)
    }

    /// Whether `requested` is inside the slice of an agent that holds no
    /// definition of its own: the slice its grant gives it (the owner's
    /// ruling, 10 Nov 2026: a definition within the creating agent's own
    /// powers goes live). The grant is the credential in the door's lane key,
    /// or one standing owner-agent Grant that confers `read` on the agent;
    /// an identity key alone grants nothing. Inside the slice:
    ///
    /// - the worlds `requested` reads (all, base, or base and one world) lie
    ///   inside the grant's worlds, met with the lane key's asked worlds and
    ///   its room turn's;
    /// - its ceiling is no higher than the ceiling policy and the gate's
    ///   definition bound leave the agent;
    /// - each skill, connector and code-mode MCP it names is one the agent
    ///   can itself use ([`Self::named_tools_in_writer_use_in_txn`]).
    ///
    /// No definition lists the models such an agent may run on, so no model
    /// `requested` names is outside its slice.
    ///
    /// # Errors
    ///
    /// Storage errors.
    fn within_granted_slice_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        authoring: &AgentAuthoring,
        requested: &AgentDefinition,
    ) -> Result<bool> {
        use crate::claim::world_access::WorldAuthoritySet;
        use crate::federation::ScopeAxis;
        use crate::gate::PolicyApprovalCeiling;

        let author = authoring.author;
        let requested_worlds = match &requested.scope {
            AgentScope::All => ScopeAxis::All,
            AgentScope::Base => WorldAuthoritySet::new(true, [])?.scope_axis(),
            AgentScope::World(world) => WorldAuthoritySet::new(true, [*world])?.scope_axis(),
        };
        let key = authoring.read_key.as_ref();
        let mut reach = key.map_or(ScopeAxis::All, |key| key.world_ceiling().worlds);
        if let Some(turn) = key.and_then(|key| key.room_turn()) {
            reach = reach.meet(&turn.terms.with(|terms| terms.worlds.worlds.clone()));
        }
        let credential_grants =
            key.is_some_and(|key| key.reads_as_vault_owner() || key.authority_scope().is_some());
        let scope_within = if credential_grants {
            requested_worlds.is_narrowing_of(&reach)
        } else {
            let grants = self.agent_grants_in_txn(txn)?;
            let classes = crate::federation::AgentVerbClasses::for_grants_in_txn(
                &self.store,
                txn,
                grants
                    .iter()
                    .filter(|standing| standing.grant.member_ref == author)
                    .map(|standing| &standing.grant),
            )?;
            let now = self.instant_in_txn(txn)?.secs();
            let owners = crate::policy_model::owners_in_txn(self, txn)?;
            grants.iter().any(|standing| {
                standing.stands_in_txn(self, txn, author, "read", now, &owners, &classes)
                    && requested_worlds
                        .is_narrowing_of(&reach.meet(&standing.grant.authority_scope.worlds))
            })
        };
        if !scope_within {
            return Ok(false);
        }
        let writer = crate::WriteActor::new(author, crate::edge::EdgeActorClass::Agent);
        let ceiling = match crate::gate::resolve_policy_manifest(&self.store, txn)?
            .actor_ceiling("agent", Some(&author.to_hex()))
            .restrict(
                crate::gate::agent_definition_ceiling_for_actor(&self.store, txn, writer)
                    .unwrap_or(PolicyApprovalCeiling::Auto),
            ) {
            PolicyApprovalCeiling::Auto => super::types::AgentCeiling::Auto,
            PolicyApprovalCeiling::Proposed => super::types::AgentCeiling::Proposed,
        };
        Ok(!requested.ceiling.widens_beyond(ceiling)
            && self.named_tools_in_writer_use_in_txn(txn, &author, None, requested)?)
    }

    /// Whether the agent `writer` can itself use each skill, connector and
    /// code-mode MCP `requested` names (the lead's ruling, 10 Nov 2026: the
    /// slice is what the writer can itself use right now). `held` is the
    /// writer's own definition, when it has one: a name on its lists is one
    /// it holds. Any other name is held to the check the runtime makes when
    /// the writer uses it:
    ///
    /// - a skill, to the load door's rule for one resident
    ///   ([`Self::writer_loads_skill_in_txn`]);
    /// - a connector or a code-mode MCP, to the standing-grant lookup a
    ///   connector call starts with
    ///   ([`Self::writer_granted_servers_in_txn`]).
    ///
    /// A name the writer cannot use puts `requested` outside its slice.
    ///
    /// # Errors
    ///
    /// Storage errors.
    fn named_tools_in_writer_use_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        writer: &EntityId,
        held: Option<&AgentDefinition>,
        requested: &AgentDefinition,
    ) -> Result<bool> {
        for skill in &requested.skills {
            if held.is_some_and(|held| held.skills.contains(skill)) {
                continue;
            }
            if !self.writer_loads_skill_in_txn(txn, writer, &skill.skill_id)? {
                return Ok(false);
            }
        }
        let servers: Vec<&str> = requested
            .connectors
            .iter()
            .filter(|connector| !held.is_some_and(|held| held.connectors.contains(connector)))
            .map(String::as_str)
            .chain(
                requested
                    .code_mode_mcps
                    .iter()
                    .filter(|mcp| !held.is_some_and(|held| held.code_mode_mcps.contains(mcp)))
                    .map(|mcp| mcp.key.as_str()),
            )
            .collect();
        if servers.is_empty() {
            return Ok(true);
        }
        let granted = self.writer_granted_servers_in_txn(txn, writer)?;
        Ok(servers
            .iter()
            .all(|server| granted.iter().any(|granted| granted.as_str() == *server)))
    }

    /// Whether the agent `writer` can load a skill named `skill_id`: the
    /// vault holds a live SKILL record of that name that the load door would
    /// load for it (`skill::pack_load`, `load_skill_pack_bound`), that is, an
    /// active, approved record that is shared or the writer's own fork. A
    /// record whose body does not decode is no skill here. The dependency's
    /// minimum version is not judged: no load reads it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    fn writer_loads_skill_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        writer: &EntityId,
        skill_id: &str,
    ) -> Result<bool> {
        let skills = self.entities_by_type_page_in_txn(
            txn,
            crate::registry::ENTITY_TYPE_SKILL,
            None,
            usize::MAX,
        )?;
        for id in skills {
            let record = match self.get_skill_record_in_txn(txn, &id) {
                Ok(Some(record)) => record,
                Ok(None) | Err(Error::Artifact(_)) => continue,
                Err(error) => return Err(error),
            };
            if record.skill_id == skill_id
                && crate::skill::skill_loadable(&record)
                && crate::skill::resident_of(&record)
                    .is_ok_and(|resident| resident.is_none_or(|resident| resident == *writer))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The servers the agent `writer` holds a live scoped outbound grant on:
    /// the lookup a connector call starts with
    /// (`outbound_consent::connector_call_driver::governance`,
    /// `connector_call_grant`), for any tool. The call's own checks of the
    /// tool, its key and its arguments stay with the call.
    ///
    /// # Errors
    ///
    /// Storage errors.
    fn writer_granted_servers_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        writer: &EntityId,
    ) -> Result<Vec<String>> {
        let frontier =
            crate::gate::resolve_policy_manifest(&self.store, txn)?.read_frontier_hash()?;
        Ok(
            crate::outbound_grant::standing_outbound_grants_for_principal_in_txn(
                &self.store,
                txn,
                &writer.to_hex(),
            )?
            .iter()
            .filter(|grant| grant.is_active_under_policy(&frontier))
            .filter_map(|grant| grant.scope.scoped_mcp_grant())
            .map(|scoped| scoped.server.to_owned())
            .collect(),
        )
    }

    /// What an agent's generic put over the stored definition `stored` at
    /// `id` stores. A put that names no grant the row does not hold (its
    /// scope, skills, connectors and code-mode MCPs) stays as staged, for the
    /// update rules to judge: the id pin holds its ceiling, and the
    /// owner-only widening rule its three switches and its models. A put that
    /// grants the row more answers to the author's slice, as a new definition
    /// does (ARCH-0053:20). An author other than the row itself, whose own
    /// slice holds everything the put names
    /// ([`Self::author_holds_wider_grant_in_txn`]), holds the wider power:
    /// its put stays as staged. Any other is a proposed change (ARCH-0053
    /// r6): the stored definition stays as it is, and keeps working, and the
    /// wider version is stored as a new proposal record that names it
    /// ([`proposed_change_id`]; `replaces` in its provenance), for whoever
    /// holds the wider power to approve.
    ///
    /// # Errors
    ///
    /// A body, or a stored row, that does not decode, and for a proposed
    /// change the refusals the same body would meet as an update of the
    /// stored row (`validate_agent_definition_update`).
    fn agent_authored_update_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        authoring: &AgentAuthoring,
        id: &EntityId,
        stored: &[u8],
        body: &[u8],
    ) -> Result<AuthoredPut> {
        let requested = decode_agent_definition(body)?;
        let stored = decode_agent_definition(stored)?;
        if grants_within(&requested, &stored) {
            return Ok(AuthoredPut::AsStaged);
        }
        let author = &authoring.author;
        if author != id && self.author_holds_wider_grant_in_txn(txn, authoring, &requested)? {
            return Ok(AuthoredPut::AsStaged);
        }
        // The proposal is the next version of the stored definition: it meets
        // what that update would meet, and keeps the lineage the row has.
        validate_agent_definition_update(&stored, &requested)?;
        let proposal_id = proposed_change_id(id, &requested.version)?;
        let mut proposal = requested;
        mark_agent_authored(&mut proposal, author, authoring.door);
        if let rmpv::Value::Map(entries) = &mut proposal.provenance {
            entries.push((
                rmpv::Value::from("replaces"),
                rmpv::Value::from(id.to_hex()),
            ));
        }
        proposal.approval_status = ClaimApprovalStatus::Proposed;
        // A reserved logical id names its one seeded row.
        proposal.logical_id = None;
        let body = encode_agent_definition(&proposal)?;
        // The proposal lands on its own id, past the below-owner widening
        // check, which judged the put at the stored row's id. A proposal the
        // owner rejected stays rejected: bringing it back to waiting moves
        // its approval up, which is the owner's (`widening`).
        if super::widening::agent_definition_put_widens_in_txn(
            &self.store,
            txn,
            &proposal_id,
            &body,
        )? {
            return Err(Error::Gate(
                crate::error::GateError::ConsentOwnerNotAuthenticated(
                    "only the vault owner brings back a proposed change it answered",
                ),
            ));
        }
        Ok(AuthoredPut::ProposedChange {
            id: proposal_id,
            body,
        })
    }

    /// Whether the slice of `authoring`'s agent holds every grant `requested`
    /// names: its scope, its ceiling, and each skill, connector and code-mode
    /// MCP. An agent with a standing definition lends that definition's scope
    /// and policy-bounded ceiling; one with no definition lends the slice its
    /// grant gives it ([`Self::within_granted_slice_in_txn`]). An agent whose
    /// definition does not stand lends nothing.
    ///
    /// # Errors
    ///
    /// Storage errors, and an author definition that does not decode.
    fn author_holds_wider_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        authoring: &AgentAuthoring,
        requested: &AgentDefinition,
    ) -> Result<bool> {
        let author = &authoring.author;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_AGENT_DEF,
            body: author_body,
        } = live_entity_row_in_txn(&self.store, txn, author)?
        else {
            return self.within_granted_slice_in_txn(txn, authoring, requested);
        };
        let author_def = decode_agent_definition(&author_body)?;
        if !stands(&author_def) {
            return Ok(false);
        }
        let slice = self.policy_bounded_author_in_txn(txn, author, &author_def)?;
        Ok(scope_within(&requested.scope, &slice.scope)
            && !requested.ceiling.widens_beyond(slice.ceiling)
            && self.named_tools_in_writer_use_in_txn(txn, author, Some(&slice), requested)?)
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
    /// author writer ([`Self::agent_authored_put_in_txn`]). A put it makes a
    /// proposed change moves to the proposal's own id, so the row it named is
    /// not written. With no `authoring`, `ops` stay as staged.
    ///
    /// # Errors
    ///
    /// As [`Self::agent_authored_put_in_txn`].
    pub(crate) fn bound_agent_authored_puts_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        authoring: Option<&AgentAuthoring>,
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
            {
                match self.agent_authored_put_in_txn(txn, authoring, id, data)? {
                    AuthoredPut::AsStaged => {}
                    AuthoredPut::Bounded(body) => *data = body,
                    AuthoredPut::ProposedChange { id: proposal, body } => {
                        *id = proposal;
                        *data = body;
                    }
                }
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
        // Inside the author's slice: its scope and ceiling, the single model
        // choices it runs under, each listed model its own list admits (the
        // check a seat on that model makes, `models::list_admits`), and each
        // skill, connector and code-mode MCP it holds or can itself use.
        let within = !scope_widens
            && scope_within(&definition.scope, &bounded_author.scope)
            && !definition.ceiling.widens_beyond(bounded_author.ceiling)
            && keeps_author_model_choices(&definition, &bounded_author)
            && definition
                .models
                .iter()
                .all(|entry| super::models::list_admits(&bounded_author.models, &entry.model_ref))
            && self.named_tools_in_writer_use_in_txn(
                txn,
                author,
                Some(&bounded_author),
                &definition,
            )?;
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

    pub(super) fn apply_agent_definition_body(
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
