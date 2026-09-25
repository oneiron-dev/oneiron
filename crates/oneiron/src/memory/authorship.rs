//! Actor-bound authorship checks. Native lifecycle projectors do not use this door.

use crate::claim::ClaimBody;
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use crate::edge::EdgeActorClass;
use crate::error::{ClaimError, Error, Result};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::write_envelope::{WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WriteActor};
use crate::{EntityId, Vault};
use rmpv::Value;

pub(crate) fn authority_denied(reason: &'static str) -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority { reason })
}

pub(crate) fn claim_author(body: &ClaimBody) -> Option<EntityId> {
    let Value::Map(entries) = body.evidence.as_ref()? else {
        return None;
    };
    let mut matches = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY));
    let (_, Value::Binary(bytes)) = matches.next()? else {
        return None;
    };
    if matches.next().is_some() {
        return None;
    }
    EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()
}

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

pub(super) fn is_root_owner(vault: &Vault, txn: &heed::RoTxn<'_>, actor: EntityId) -> Result<bool> {
    verify_live_actor(vault, txn, WriteActor::new(actor, EdgeActorClass::Human))?;
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if fold.vault_root_is_conflicted() || fold.vault_id.is_none() {
        return Ok(false);
    }
    Ok(crate::authority::actor_binding_is_active(
        &fold, &actor, "human",
    ))
}

pub(super) fn verify_owner(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> Result<()> {
    if !is_root_owner(vault, txn, owner.actor())? {
        return Err(authority_denied("an active root owner binding is required"));
    }
    Ok(())
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
            if self.actor != owner.actor() || self.actor_class != EdgeActorClass::Human {
                return Err(authority_denied("owner proof must name the bound caller").into());
            }
            verify_owner(self.vault, txn, owner)?;
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
/// This is never used by auto-upsert. Standalone unrooted vaults keep their
/// existing human-owner posture; a declared/conflicted root is fail-closed.
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
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if fold.vault_root_is_conflicted()
        || (fold.vault_id.is_some()
            && !crate::authority::actor_binding_is_active(&fold, &actor.entity_ref(), "human"))
    {
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
