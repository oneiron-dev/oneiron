//! Whose act a repo proposal records, and the erase that forgets it
//! (FIX 3520): its proposer, the critics whose evidence judged it (FIX 4477),
//! the journal claims it wrote (FIX 4479) and the owner who decided its
//! removed-name review, with each settlement receipt claim that names that
//! owner (FIX 4365).

use std::collections::BTreeSet;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{PROPOSAL, PROPOSAL_OP, RepoProposal, RepoProposalStatus, invalid};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::critic::CritiqueArtifact;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::registry::ENTITY_TYPE_CLAIM;

/// Who opened a repo proposal: an actor, or no one once that actor was
/// erased (FIX 3520). It reads and writes as the actor's hex id, or as
/// [`ERASED_CALL_IDENTITY`]. An erased one is never a live critic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalActor {
    Actor(EntityId),
    Erased,
}

impl ProposalActor {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }

    /// The actor, while it is not erased.
    #[must_use]
    pub const fn id(self) -> Option<EntityId> {
        match self {
            Self::Actor(id) => Some(id),
            Self::Erased => None,
        }
    }

    /// How a view spells it: the actor's hex id, or [`ERASED_CALL_IDENTITY`].
    #[must_use]
    pub fn to_hex(self) -> String {
        match self {
            Self::Actor(id) => id.to_hex(),
            Self::Erased => ERASED_CALL_IDENTITY.to_owned(),
        }
    }

    /// The actor a reviewed write lands under. An erased actor's proposal
    /// never runs again.
    pub(in crate::repo_mutation) fn live(self) -> Result<EntityId> {
        self.id()
            .ok_or_else(|| invalid("an erased actor's proposal cannot run"))
    }
}

impl Serialize for ProposalActor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ProposalActor {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == ERASED_CALL_IDENTITY {
            return Ok(Self::Erased);
        }
        EntityId::from_hex(&value)
            .map(Self::Actor)
            .map_err(serde::de::Error::custom)
    }
}

impl RepoProposal {
    /// Whether `critique`'s critic counts toward the distinct-critic quorum
    /// (FIX 4477). An erased critic's evidence stays, with its verdict and
    /// lens, but a proposal still open waits for a live critic in its place.
    /// An approval already settled stays as it was: each erased critic keeps
    /// an opaque ref of its own, so the settled count does not change.
    pub(super) fn counts_toward_quorum(&self, critique: &CritiqueArtifact) -> bool {
        self.status != RepoProposalStatus::Proposed || !critique.provenance.is_erased()
    }

    /// Names one fresh opaque ref in place of `critic` across every critique
    /// it wrote here (FIX 4477), on the vault policy's lenses too (FIX
    /// 8268); whether any named it.
    fn forget_critic(&mut self, vault: &Vault, critic: &str) -> Result<bool> {
        if !self
            .critiques
            .iter()
            .chain(self.policy_critiques.iter().map(|vote| &vote.critique))
            .any(|critique| critique.provenance.critic_ref == critic)
        {
            return Ok(false);
        }
        let opaque = crate::critic::erased_critic_ref(vault.store.clock.entity_id()?);
        for critique in self.critiques.iter_mut().chain(
            self.policy_critiques
                .iter_mut()
                .map(|vote| &mut vote.critique),
        ) {
            if critique.provenance.critic_ref == critic {
                critique.forget_critic(&opaque);
            }
        }
        Ok(true)
    }

    /// Names no one in place of `actor` on each removed-name review decision
    /// it made here (FIX 4365); the receipts of those decisions, each once.
    /// Each decision keeps its value, its verdict binding and its time.
    fn forget_contract_reviewer(&mut self, actor: EntityId) -> Vec<EntityId> {
        let mut receipts = Vec::new();
        for settled in self
            .contract_reviews
            .iter_mut()
            .filter_map(|request| request.decision.as_mut())
        {
            if settled.actor.is(actor) {
                settled.actor = ProposalActor::Erased;
                if !receipts.contains(&settled.receipt) {
                    receipts.push(settled.receipt);
                }
            }
        }
        receipts
    }
}

/// The session claim a proposal writes beside its proposed diff: one per
/// session and proposal, whose id hashes no actor (FIX 4479; a call).
pub(super) fn session_claim_id(session: EntityId, proposal: EntityId) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(
        b"oneiron:repo-session-claim:v2",
        &[session.as_bytes(), proposal.as_bytes()],
    )
}

/// Rewrites `proposal`'s journal claims, its proposed diff and its session
/// claim, naming no one once `actor` was erased (FIX 4479): the value's actor
/// reads [`ERASED_CALL_IDENTITY`] and the producer evidence goes. Each keeps
/// its id, status, outcome and times, and its revision ledger starts over
/// from the rewritten row, so no older revision keeps the actor.
fn erase_journal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    proposal: &RepoProposal,
    actor: &EntityId,
) -> Result<()> {
    let session = session_claim_id(proposal.session, proposal.id)?;
    for id in [proposal.id, session] {
        let Some(raw) = vault.get_raw_in(wtxn, &id)? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("repository journal header"))?;
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        if header.entity_type != ENTITY_TYPE_CLAIM || body.is_empty() {
            continue;
        }
        let mut claim = crate::claim::decode_claim_body(body, true)?;
        if crate::claim::session_claim_producer(&claim) != Some(*actor) {
            continue;
        }
        if let Value::Map(entries) = &mut claim.value {
            for (key, value) in entries.iter_mut() {
                if key.as_str() == Some("actor") {
                    *value = Value::from(ERASED_CALL_IDENTITY);
                }
            }
        }
        claim.evidence = None;
        super::put_journal_claim(vault, wtxn, id, None, &claim, header.learned_at)?;
        crate::vault::entity_revision::remove_entity_revisions(&vault.store, wtxn, &id)?;
        let raw = vault.get_raw_in(wtxn, &id)?.ok_or(Error::EntityNotFound)?;
        crate::vault::entity_revision::capture_entity_revision(&vault.store, wtxn, &id, &raw)?;
    }
    Ok(())
}

/// Rewrites a proposal's settlement receipt claim `receipt`, naming no one
/// once `actor`, who made that decision, was erased (FIX 4365): the value's
/// actor reads [`ERASED_CALL_IDENTITY`] and any evidence goes. It keeps its
/// id, proposal, decision, answered verdicts and times, and its revision
/// ledger starts over from the rewritten row, so no older revision keeps
/// the actor.
fn erase_settlement_receipt_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: EntityId,
    actor: &EntityId,
) -> Result<()> {
    let Some(raw) = vault.get_raw_in(wtxn, &receipt)? else {
        return Ok(());
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("repository settlement header"))?;
    let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    if header.entity_type != ENTITY_TYPE_CLAIM || body.is_empty() {
        return Ok(());
    }
    let mut claim = crate::claim::decode_claim_body(body, true)?;
    if claim.predicate != "repo.proposal_settlement" {
        return Ok(());
    }
    let named = actor.to_hex();
    let mut erased = false;
    if let Value::Map(entries) = &mut claim.value {
        for (key, value) in entries.iter_mut() {
            if key.as_str() == Some("actor") && value.as_str() == Some(named.as_str()) {
                *value = Value::from(ERASED_CALL_IDENTITY);
                erased = true;
            }
        }
    }
    if !erased {
        return Ok(());
    }
    claim.evidence = None;
    vault.put_reserved_claim_in_txn(
        wtxn,
        &receipt,
        &claim,
        crate::temporal::TimeRange {
            start: header.learned_at,
            end: header.learned_at,
        },
        header.learned_at,
    )?;
    crate::vault::entity_revision::remove_entity_revisions(&vault.store, wtxn, &receipt)?;
    let raw = vault
        .get_raw_in(wtxn, &receipt)?
        .ok_or(Error::EntityNotFound)?;
    crate::vault::entity_revision::capture_entity_revision(&vault.store, wtxn, &receipt, &raw)?;
    Ok(())
}

/// Rewrites each settlement receipt claim that still names `actor`, found by
/// the predicate's posting list (FIX 4365). A receipt outlives its proposal
/// row: an earlier erase of the proposer can delete the row that pointed at
/// it. Each keeps its decision, its answered verdicts and its times. The row
/// sweep already rewrote each receipt in `scrubbed`, so none is rewritten
/// twice.
fn erase_actor_settlement_receipts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
    scrubbed: &BTreeSet<EntityId>,
) -> Result<()> {
    let receipts = crate::claim::claim_ids_for_predicate_in_txn(
        &vault.store,
        wtxn,
        "repo.proposal_settlement",
    )?;
    for receipt in receipts {
        if !scrubbed.contains(&receipt) {
            erase_settlement_receipt_in_txn(vault, wtxn, receipt, actor)?;
        }
    }
    Ok(())
}

/// What an actor's erase does with a proposal it opened that has not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingRepoProposalErase {
    /// The proposal goes, with any operation pointer to it.
    Delete,
    /// The proposal stays and names no one; the queue refuses to run it.
    Keep,
}

/// A proposal that has not run, proposed or approved and never queued, is
/// still work the queue could land, so an erase of the actor who opened it
/// deletes it (FIX 3520).
pub const ACTOR_ERASE_PENDING_REPO_PROPOSAL: PendingRepoProposalErase =
    PendingRepoProposalErase::Delete;

/// Erasing `actor` from the proposals it opened (FIX 3520): one that ran,
/// applied or failed, keeps its row, critiques and outcome and names no one,
/// and the queue refuses to run it again. One that has not run goes, with any
/// operation pointer to it, when [`ACTOR_ERASE_PENDING_REPO_PROPOSAL`] says
/// so, and a reviewed stack that listed it is dropped (FIX 4478); a stack that
/// already ran a member keeps it as an erased slot and ends at its last landed
/// member instead (FIX 5219). Either way its journal claims name no one (FIX
/// 4479). Each proposal it judged as a critic keeps that evidence under an
/// opaque ref (FIX 4477). Each removed-name review it decided keeps its
/// decision and names no one, in its row and in its receipt claim (FIX
/// 4365). Each settlement receipt claim that names it names no one too, even
/// when no proposal row points at it any more (FIX 4365). One-way, in the
/// erase's own transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a proposal row that cannot be read.
pub(crate) fn erase_proposal_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if super::super::support::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let critic = actor.to_hex();
    let mut named = Vec::new();
    for row in PROPOSAL.iter_from(&vault.store, wtxn, &[])? {
        let (id, mut proposal) = row?;
        let proposer = proposal.actor.is(*actor);
        if proposer {
            proposal.actor = ProposalActor::Erased;
        }
        let receipts = proposal.forget_contract_reviewer(*actor);
        if proposal.forget_critic(vault, &critic)? || proposer || !receipts.is_empty() {
            named.push((id, proposal, proposer, receipts));
        }
    }
    let mut gone = BTreeSet::new();
    let mut scrubbed = BTreeSet::new();
    for (id, proposal, proposer, receipts) in named {
        if proposer {
            erase_journal_in_txn(vault, wtxn, &proposal, actor)?;
        }
        for receipt in receipts {
            erase_settlement_receipt_in_txn(vault, wtxn, receipt, actor)?;
            scrubbed.insert(receipt);
        }
        let pending = proposer
            && proposal.operation_seq.is_none()
            && matches!(
                proposal.status,
                RepoProposalStatus::Proposed | RepoProposalStatus::Approved
            );
        if pending && ACTOR_ERASE_PENDING_REPO_PROPOSAL == PendingRepoProposalErase::Delete {
            PROPOSAL.delete(&vault.store, wtxn, &id)?;
            gone.insert(id);
        } else {
            PROPOSAL.put(&vault.store, wtxn, &id, &proposal)?;
        }
    }
    erase_actor_settlement_receipts_in_txn(vault, wtxn, actor, &scrubbed)?;
    if gone.is_empty() {
        return Ok(());
    }
    super::super::reviewed_stack::drop_stacks_listing_in_txn(vault, wtxn, &gone)?;
    let mut pointers = Vec::new();
    for row in PROPOSAL_OP.iter_from(&vault.store, wtxn, &[])? {
        let (key, id) = row?;
        if gone.contains(&id) {
            pointers.push(key);
        }
    }
    for key in pointers {
        PROPOSAL_OP.delete(&vault.store, wtxn, &key)?;
    }
    Ok(())
}
