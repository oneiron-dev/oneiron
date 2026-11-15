//! Actor-bound authorship checks. Native lifecycle projectors do not use this door.

use crate::claim::ClaimBody;
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use crate::edge::EdgeActorClass;
use crate::error::{ClaimError, Error, Result};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

pub(crate) fn authority_denied(reason: &'static str) -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority { reason })
}

pub(crate) use crate::claim::claim_author;

pub(super) fn verify_live_actor(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
) -> Result<()> {
    let raw = vault
        .get_raw_in(txn, &actor.entity_ref())?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("actor header"))?;
    crate::provenance::validate_actor_class(header.entity_type, actor.actor_class())?;
    if vault.entity_lifecycle_state_in_txn(txn, &actor.entity_ref())?
        != crate::identity_topology::EntityLifecycleState::Active
    {
        return Err(authority_denied("inactive actors hold no self-Grant"));
    }
    Ok(())
}

pub(super) fn root_id(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<String> {
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if fold.vault_root_is_conflicted() {
        return Err(authority_denied("conflicting authority roots"));
    }
    let root = fold
        .vault_id
        .ok_or_else(|| authority_denied("explicit authority requires a rooted vault"))?;
    Ok(super::support::hex_string(&root))
}

/// Whether `actor` owns this vault now and holds an active human binding
/// under its root: the one actor whose review needs no named grant and whose
/// grants delegate. A human binding alone is no ownership; a shared vault's
/// Admin or Delegate can hold one.
pub(super) fn is_root_owner(vault: &Vault, txn: &heed::RoTxn<'_>, actor: EntityId) -> Result<bool> {
    verify_live_actor(vault, txn, WriteActor::new(actor, EdgeActorClass::Human))?;
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if fold.vault_root_is_conflicted() || fold.vault_id.is_none() {
        return Ok(false);
    }
    Ok(
        crate::authority::actor_binding_is_active(&fold, &actor, "human")
            && crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)?,
    )
}

pub(super) fn verify_owner(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> Result<EntityId> {
    let actor = owner.revalidate_in_txn(vault, txn)?;
    if !is_root_owner(vault, txn, actor)? {
        return Err(authority_denied("an active root owner binding is required"));
    }
    Ok(actor)
}

/// A named owner-delegated slice. Target and verb are never caller-selected
/// inside an enforcement check. No role name, title, mask or boolean grants it.
pub(super) fn action_bound(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    verb: &str,
    target: EntityId,
) -> Result<GrantBound> {
    GrantBound::action(
        ActorBound::new(actor.entity_ref().to_hex())?
            .with_actor_class(actor.actor_class().gate_actor_class())?,
        ActionClass::new(verb)?,
        ActionEnvelope::new([target.to_hex()])?.with_target(root_id(vault, txn)?)?,
    )
}

pub(super) fn delegated_grant(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    required: &GrantBound,
) -> Result<Option<String>> {
    for grant in vault.active_standing_consent_grants_in_txn(txn)? {
        if !grant.bound().contains(required) {
            continue;
        }
        let grant_ref = grant.bound().digest().to_hex();
        let row = vault
            .consent_grant_in_txn(txn, &grant_ref)?
            .ok_or(Error::CorruptedIndex("consent grant disappeared"))?;
        // A grant minted by an arbitrary PERSON is not an owner delegation.
        // The authority root and current owner binding are rechecked on use.
        if row.is_active() && is_root_owner(vault, txn, row.owner_stamp.actor)? {
            return Ok(Some(grant_ref));
        }
    }
    Ok(None)
}

pub(crate) fn require_claim_self_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    target: EntityId,
    body: &ClaimBody,
    verb: &str,
) -> Result<()> {
    let author = crate::batch::authenticated_claim_author_in_txn(&vault.store, txn, &target, body)?
        .map(crate::write_envelope::WriteActor::entity_ref);
    require_authorship_in_txn(vault, txn, actor, target, author, verb)
}

/// The supersede check of a memory claim write (`memory.claim.supersede`):
/// the prior's own author and a System actor's delegated grant pass, as
/// [`require_claim_self_grant_in_txn`] passes them, and so does the vault's
/// root owner writing in person over a claim of the owner's own agent
/// ([`owner_agent_author_in_txn`]; OWNER-SUPERSEDES-OWN-AGENT-CLAIM, the
/// lead's ruling B, 13 Nov: never gate the owner on their own vault). Every
/// other author's claim keeps the conflict review path (ARCH-0040, ARCH-0043:
/// no admin override by default). Only the memory claim write calls this;
/// edit, retract, demote and the skill verbs keep their own checks.
pub(crate) fn require_claim_supersede_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    target: EntityId,
    body: &ClaimBody,
) -> Result<()> {
    let author = crate::batch::authenticated_claim_author_in_txn(&vault.store, txn, &target, body)?;
    verify_live_actor(vault, txn, actor)?;
    if let Some(author) = author
        && owner_agent_author_in_txn(vault, txn, actor, author)?
    {
        return Ok(());
    }
    require_authorship_in_txn(
        vault,
        txn,
        actor,
        target,
        author.map(WriteActor::entity_ref),
        "memory.claim.supersede",
    )
}

/// Whether `author`, the authenticated author of a claim, is the own agent
/// of `writer`, a human writing in person who is this vault's root owner
/// (OWNER-SUPERSEDES-OWN-AGENT-CLAIM). Decided from stored facts only, and
/// closed: an author it cannot place is no one's agent here.
///
/// The author is an Agent-class write of a live PERSON or AGENT_DEF (a
/// MACHINE writes as System, so the Dreamer and the Coach are outside it),
/// neither an introduced foreign agent nor an identity a counterparty contact
/// names. Then the first fact that names a person decides:
/// - the workspace companion map of the author's person (for an AGENT_DEF,
///   the person its subject anchor names, its own model person included)
///   must name the owner;
/// - an AGENT_DEF anchored to a person other than its own model person is
///   that person's pen, and must be the owner's;
/// - otherwise every capability slip minted for the author as holder must be
///   an Agent-class slip whose pairing the owner approved (its signed
///   `minting_member`, FIX 11713). A slip bound to a guest grant, an
///   invitation, a share, a support delegation, a trusted contact or a seat
///   claim names a peer, so it refuses the author. At least one such slip
///   must exist, or the author is an AGENT_DEF the owner created through the
///   owner's create door (its creating-owner stamp names the owner,
///   OWNER-MADE-AGENT-DEF-UNPLACED).
pub(crate) fn owner_agent_author_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    writer: WriteActor,
    author: WriteActor,
) -> Result<bool> {
    let owner = writer.entity_ref();
    let agent = author.entity_ref();
    if writer.actor_class() != EdgeActorClass::Human
        || author.actor_class() != EdgeActorClass::Agent
        || agent == owner
        || !is_root_owner(vault, txn, owner)?
    {
        return Ok(false);
    }
    let definition = match crate::vault::live_entity_row_in_txn(&vault.store, txn, &agent)? {
        crate::vault::LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_AGENT_DEF,
            ..
        } => true,
        crate::vault::LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_PERSON,
            ..
        } => false,
        _ => return Ok(false),
    };
    if crate::gate::introduced_foreign_agents(&vault.store, txn)?.contains(&agent)
        || !vault
            .counterparty_contact_ids_for_identity_in_txn(txn, &agent)?
            .is_empty()
    {
        return Ok(false);
    }
    let person = if definition {
        let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
        crate::workspace_roster::subject_person_of_actor_in_txn(vault, txn, agent, at)?
    } else {
        Some(agent)
    };
    if let Some(person) = person {
        if let Some(principal) =
            crate::workspace_roster::companion_principal_in_txn(vault, txn, person)?
        {
            return Ok(principal == owner);
        }
        if definition && person != crate::context_board::agent_person_id(agent)? {
            return Ok(person == owner);
        }
    }
    Ok(match holder_slips_in_txn(vault, txn, agent, owner)? {
        HolderSlips::OwnerPaired => true,
        HolderSlips::Other => false,
        HolderSlips::Unminted => {
            definition
                && crate::agent_def::created_by_owner_in_txn(&vault.store, txn, &agent, &owner)?
        }
    })
}

/// What the capability slips minted for an author as holder say of its owner.
enum HolderSlips {
    /// No slip names the author as holder.
    Unminted,
    /// Every one is an Agent-class slip the owner approved the pairing of,
    /// with no peer binding.
    OwnerPaired,
    /// At least one names a peer, another class or another approving member.
    Other,
}

/// What the capability slips the authority fold keeps for `agent` as its
/// holder (revoked, consumed and expired ones included, as `self.actor`
/// reads them) say of `owner`.
fn holder_slips_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    owner: EntityId,
) -> Result<HolderSlips> {
    let holder = agent.to_hex();
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let mut minted = HolderSlips::Unminted;
    for mint in fold
        .slips
        .mints
        .values()
        .filter(|mint| mint.action.claims.holder_ref == holder)
    {
        let claims = &mint.action.claims;
        let peer_bound = claims.grant_ref.is_some()
            || claims.invitation_ref.is_some()
            || claims.share_ref.is_some()
            || claims.delegation.is_some()
            || claims.trusted_contact.is_some()
            || claims.seat_claim.is_some();
        if peer_bound
            || claims.actor_class.as_deref() != Some(EdgeActorClass::Agent.gate_actor_class())
            || mint.action.minting_member != Some(owner)
        {
            return Ok(HolderSlips::Other);
        }
        minted = HolderSlips::OwnerPaired;
    }
    Ok(minted)
}

pub(super) fn require_authorship_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    target: EntityId,
    author: Option<EntityId>,
    verb: &str,
) -> Result<()> {
    verify_live_actor(vault, txn, actor)?;
    // Store-compatible human/agent actors (PERSON or AGENT_DEF) hold their
    // own authorship. MACHINE/system is the daemon lane; the actor-class
    // matrix rejects a MACHINE presented as an agent to borrow self-Grant.
    if actor.actor_class() != EdgeActorClass::System && author == Some(actor.entity_ref()) {
        return Ok(());
    }
    if actor.actor_class() == EdgeActorClass::System {
        let required = action_bound(vault, txn, actor, verb, target)?;
        if delegated_grant(vault, txn, &required)?.is_some() {
            return Ok(());
        }
        return Err(authority_denied(
            "daemon writes need an explicit delegated target and verb",
        ));
    }
    Err(authority_denied(
        "self-Grant never replaces another author's claim; ask for conflict review",
    ))
}

pub(crate) fn guard_existing_claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    target: EntityId,
) -> Result<()> {
    if let Some(body) = vault.get_claim_in_txn(txn, &target)? {
        require_claim_self_grant_in_txn(vault, txn, actor, target, &body, "memory.claim.edit")?;
    } else if actor.actor_class() == EdgeActorClass::System {
        require_authorship_in_txn(vault, txn, actor, target, None, "memory.claim.create")?;
    }
    Ok(())
}

/// The exact action delegated for one claim's review and settlement.
pub(super) const CLAIM_REVIEW_GRANT_VERB: &str = "memory.claim.review";

/// Exact memory verbs an owner can delegate. No delete/erase bit exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAuthoringAction {
    CreateClaim,
    EditClaim,
    SupersedeClaim,
    RetractClaim,
    CreateSkill,
    EditSkill,
    ForkSkill,
    ReviewConflict,
    ReviewClaim,
}
impl MemoryAuthoringAction {
    fn verb(self) -> &'static str {
        match self {
            Self::CreateClaim => "memory.claim.create",
            Self::EditClaim => "memory.claim.edit",
            Self::SupersedeClaim => "memory.claim.supersede",
            Self::RetractClaim => "memory.claim.retract",
            Self::CreateSkill => "memory.skill.create",
            Self::EditSkill => "memory.skill.edit",
            Self::ForkSkill => "memory.skill.fork",
            Self::ReviewConflict => "memory.conflict_review",
            Self::ReviewClaim => CLAIM_REVIEW_GRANT_VERB,
        }
    }
}
impl super::Memory<'_> {
    /// Mints an exact target/verb slice in the existing consent registry.
    /// Root-owner authentication and the delegation share one transaction.
    pub fn delegate_memory_authoring(
        &self,
        owner: &AuthenticatedOwner,
        delegate: WriteActor,
        action: MemoryAuthoringAction,
        target: EntityId,
    ) -> super::MemoryResult<crate::consent::ConsentReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            if self.actor != verify_owner(self.vault, txn, owner)?
                || self.actor_class != EdgeActorClass::Human
            {
                return Err(authority_denied("owner proof must name the bound caller").into());
            }
            verify_live_actor(self.vault, txn, delegate)?;
            let bound = action_bound(self.vault, txn, delegate, action.verb(), target)?;
            Ok(self.vault.create_standing_grant_in_txn(txn, owner, bound)?)
        })
    }
}

pub(super) fn decision(
    actor: WriteActor,
    kind: &str,
    outcome: &str,
    reason: &str,
    target: Option<EntityId>,
    digest: Vec<u8>,
    now: u64,
) -> GateDecisionRecord {
    GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::now(),
        created_at: now,
        outcome: outcome.to_owned(),
        reason_codes: vec![reason.to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: actor.actor_class().gate_actor_class().to_owned(),
        actor_ref: Some(actor.entity_ref().to_hex()),
        content_kind: kind.to_owned(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: target.map(|id| *id.as_bytes()),
        grant_ref: None,
        diff_handle: digest,
        read_frontier_hash: [0; 32],
        context: Default::default(),
        redacted_at: None,
    }
}

// EntityId deliberately has no global serde implementation.
pub(super) mod entity_serde {
    use crate::EntityId;
    use serde::{Deserialize, Deserializer, Serializer};
    pub(in crate::memory) fn serialize<S: Serializer>(
        id: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&id.to_hex())
    }
    pub(in crate::memory) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let text = String::deserialize(deserializer)?;
        EntityId::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// Explicit owner replacement/withdrawal in a family-owned actor-facing door.
/// This is never used by auto-upsert. Only the vault owner overrides: the
/// embedded owner on an unrooted vault, the bound owner on a rooted one; a
/// conflicted root is fail-closed.
pub(crate) fn explicit_claim_override_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    target: EntityId,
    body: &ClaimBody,
    now: u64,
) -> Result<()> {
    verify_live_actor(vault, txn, actor)?;
    let owns = claim_author(body) == Some(actor.entity_ref())
        && crate::batch::authenticated_claim_author_in_txn(&vault.store, txn, &target, body)?
            .is_some_and(|author| author.entity_ref() == actor.entity_ref());
    if owns || actor.actor_class() != EdgeActorClass::Human {
        return require_claim_self_grant_in_txn(
            vault,
            txn,
            actor,
            target,
            body,
            "memory.claim.retract",
        );
    }
    // The owner check every owner verb takes, rooted or not (H149).
    if super::support::verify_owner_actor_binding_in_txn(vault, txn, actor.entity_ref()).is_err() {
        return Err(authority_denied(
            "explicit override requires active owner authority",
        ));
    }
    let bytes = crate::claim::encode_claim_body(body)?;
    let receipt = decision(
        actor,
        "memory_claim_override",
        "approved",
        "gate.memory.explicit_owner_override",
        Some(target),
        blake3::hash(&bytes).as_bytes().to_vec(),
        now,
    );
    vault.store.append_gate_decision_in_txn(txn, &receipt)
}
