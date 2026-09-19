//! Content-bound conflict questions and owner/delegated-admin rulings.
//!
//! A namespaced Gate consent bundle, not a second decision ledger: immutable
//! packet refs/digests live in vault_meta; pending/ruling receipts live in GateDecision.
//! Context bytes are hydrated only for an authorized read, not copied into a
//! second plaintext store that could outlive an entity's lawful erasure.
//! Unlike a Dreamer bundle, the contested claim need not be a pending consent.

use super::authorship::*;
use super::{Memory, MemoryResult};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::{Error, GateError};
use crate::store::GateDecisionId;
use crate::temporal::TimeRange;
use crate::{EntityId, WriteActor, WriteEnvelope, WriteProvenance};
use rmpv::Value;
use serde::{Deserialize, Serialize};

const PACKET: &[u8] = b"consent_bundle.claim_conflict.v1:";
const RESOLUTION: &[u8] = b"consent_bundle.claim_conflict.resolved.v1:";
const KIND: &str = "consent_bundle:claim_conflict";

/// Typed question, not a prompt string or an instruction hidden in a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimConflictQuestion {
    ConflictOfInterest,
}

/// One immutable context member. Bytes include the entity metadata header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimConflictMember {
    #[serde(with = "super::authorship::entity_serde")]
    pub entity: EntityId,
    pub row_digest: [u8; 32],
    /// Read projection only. Persistence strips this field's bytes.
    pub raw: Vec<u8>,
}

/// One packet: disputed claim, proposed revision, author and subject context.
/// Only the parties and authenticated owner/delegated reviewer can read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimConflictBundle {
    pub bundle_id: [u8; 32],
    pub question: ClaimConflictQuestion,
    #[serde(with = "super::authorship::entity_serde")]
    pub raised_by: EntityId,
    #[serde(with = "super::authorship::entity_serde")]
    pub author: EntityId,
    #[serde(with = "super::authorship::entity_serde")]
    pub subject: EntityId,
    #[serde(with = "super::authorship::entity_serde")]
    pub disputed: EntityId,
    #[serde(with = "super::authorship::entity_serde")]
    pub proposal: EntityId,
    pub authority_root: String,
    pub policy_frontier: [u8; 32],
    pub members: Vec<ClaimConflictMember>,
}

/// A ruling joins the existing Gate ledger. Both old and new claims survive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimConflictReceipt {
    pub bundle_id: [u8; 32],
    pub receipt_ref: String,
    #[serde(with = "super::authorship::entity_serde")]
    pub superseded_claim: EntityId,
    #[serde(with = "super::authorship::entity_serde")]
    pub ruling_claim: EntityId,
}

fn key(prefix: &[u8], digest: &[u8; 32]) -> Vec<u8> {
    [prefix, digest.as_slice()].concat()
}
fn encode(bundle: &ClaimConflictBundle) -> Result<Vec<u8>, Error> {
    let mut stored = bundle.clone();
    for member in &mut stored.members {
        member.raw.clear();
    }
    serde_json::to_vec(&stored).map_err(|_| Error::CorruptedIndex("claim conflict packet"))
}
fn digest(bundle: &ClaimConflictBundle) -> Result<[u8; 32], Error> {
    let mut input = bundle.clone();
    input.bundle_id = [0; 32];
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.consent_bundle.claim_conflict.v1\0");
    hash.update(&encode(&input)?);
    Ok(*hash.finalize().as_bytes())
}
fn load(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 32],
) -> Result<ClaimConflictBundle, Error> {
    let bytes = vault
        .store
        .vault_meta
        .get(txn, &key(PACKET, id))?
        .ok_or(Error::EntityNotFound)?;
    let packet: ClaimConflictBundle = serde_json::from_slice(&bytes)
        .map_err(|_| Error::CorruptedIndex("claim conflict packet"))?;
    if packet.bundle_id != *id || digest(&packet)? != *id {
        return Err(Error::CorruptedIndex("claim conflict digest"));
    }
    Ok(packet)
}
fn stale(id: EntityId) -> Error {
    Error::Gate(GateError::GateConsentStale { claim_id: id })
}
fn hydrate(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    mut packet: ClaimConflictBundle,
) -> Result<ClaimConflictBundle, Error> {
    for member in &mut packet.members {
        let raw = vault
            .get_raw_in(txn, &member.entity)?
            .ok_or_else(|| stale(packet.disputed))?;
        if *blake3::hash(&raw).as_bytes() != member.row_digest {
            return Err(stale(packet.disputed));
        }
        member.raw = raw;
    }
    Ok(packet)
}

impl Memory<'_> {
    /// Raises one immutable, deduplicated conflict-of-interest review packet.
    /// Context is derived from stored rows, never caller-asserted author facts.
    pub fn question_claim_conflict(
        &self,
        question: ClaimConflictQuestion,
        disputed_ref: &str,
        proposal_ref: &str,
    ) -> MemoryResult<ClaimConflictBundle> {
        let disputed = self.resolve_ref(disputed_ref)?;
        let proposal = self.resolve_ref(proposal_ref)?;
        self.with_verified_actor_write_txn(|txn| {
            verify_live_actor(
                self.vault,
                txn,
                WriteActor::new(self.actor, self.actor_class),
            )?;
            if self.actor_class == EdgeActorClass::System {
                return Err(authority_denied("daemon has no resident dispute standing").into());
            }
            let old = self
                .vault
                .get_claim_in_txn(txn, &disputed)?
                .ok_or(Error::EntityNotFound)?;
            let next = self
                .vault
                .get_claim_in_txn(txn, &proposal)?
                .ok_or(Error::EntityNotFound)?;
            let author = claim_author(&old)
                .ok_or_else(|| authority_denied("contested claim lacks a proven author"))?;
            let ClaimSubject::Entity(subject) = old.subject else {
                return Err(authority_denied("resident dispute requires an entity subject").into());
            };
            if self.actor != author && self.actor != subject {
                return Err(authority_denied(
                    "only a claim's parties may raise its private dispute",
                )
                .into());
            }
            if !crate::batch::authenticated_claim_author_in_txn(
                &self.vault.store,
                txn,
                &proposal,
                &next,
            )?
            .is_some_and(|writer| writer.entity_ref() == self.actor)
            {
                return Err(authority_denied("proposal must be authored by the questioner").into());
            }
            if disputed == proposal
                || old.lifecycle != ClaimLifecycleStatus::Active
                || next.lifecycle != ClaimLifecycleStatus::Active
                || next.stale
                || next.approval != ClaimApprovalStatus::Proposed
            {
                return Err(stale(disputed).into());
            }
            if old.subject != next.subject
                || old.predicate != next.predicate
                || old.scope != next.scope
                || old.world != next.world
                || old.rel != next.rel
            {
                return Err(Error::InvalidClaimBody(
                    "conflict proposal must retain the disputed claim's subject and scope",
                )
                .into());
            }
            let mut ids = vec![disputed, proposal, author, subject];
            ids.sort_unstable();
            ids.dedup();
            let mut members = Vec::new();
            let mut bytes = 0usize;
            for entity in ids {
                let raw = self
                    .vault
                    .get_raw_in(txn, &entity)?
                    .ok_or(Error::EntityNotFound)?;
                bytes = bytes
                    .checked_add(raw.len())
                    .ok_or(Error::ArithmeticOverflow("conflict context bytes"))?;
                if bytes > 1_048_576 {
                    return Err(Error::InvalidClaimBody("conflict context exceeds one MiB").into());
                }
                members.push(ClaimConflictMember {
                    entity,
                    row_digest: *blake3::hash(&raw).as_bytes(),
                    raw,
                });
            }
            let mut packet = ClaimConflictBundle {
                bundle_id: [0; 32],
                question,
                raised_by: self.actor,
                author,
                subject,
                disputed,
                proposal,
                authority_root: root_id(self.vault, txn)?,
                policy_frontier: crate::gate::resolve_policy_manifest(&self.vault.store, txn)?
                    .read_frontier_hash()?,
                members,
            };
            packet.bundle_id = digest(&packet)?;
            let packet_key = key(PACKET, &packet.bundle_id);
            if self.vault.store.vault_meta.get(txn, &packet_key)?.is_some() {
                return Ok(hydrate(
                    self.vault,
                    txn,
                    load(self.vault, txn, &packet.bundle_id)?,
                )?);
            }
            let receipt = decision(
                WriteActor::new(self.actor, self.actor_class),
                KIND,
                "pending",
                "gate.memory.conflict_of_interest",
                Some(disputed),
                packet.bundle_id.to_vec(),
                crate::unix_seconds_now(),
            );
            self.vault
                .store
                .vault_meta
                .put(txn, &packet_key, &encode(&packet)?)?;
            self.vault
                .store
                .append_gate_decision_in_txn(txn, &receipt)?;
            Ok(packet)
        })
    }

    /// Reads a private packet as one of its parties. Admins use the review door.
    pub fn claim_conflict(&self, id: [u8; 32]) -> MemoryResult<ClaimConflictBundle> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        verify_live_actor(
            self.vault,
            &txn,
            WriteActor::new(self.actor, self.actor_class),
        )?;
        let packet = load(self.vault, &txn, &id)?;
        if self.actor_class == EdgeActorClass::System
            || (self.actor != packet.author && self.actor != packet.subject)
        {
            return Err(authority_denied(
                "private conflict is visible only to its parties and reviewers",
            )
            .into());
        }
        Ok(hydrate(self.vault, &txn, packet)?)
    }

    /// The admin review queue. A named review Grant, not a role/title claim,
    /// grants a delegated reviewer access; root owners can review explicitly.
    pub fn pending_claim_conflicts(
        &self,
        reviewer: &AuthenticatedOwner,
    ) -> MemoryResult<Vec<ClaimConflictBundle>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.verify_reviewer_identity(&txn, reviewer)?;
        let owner = is_root_owner(self.vault, &txn, self.actor)?;
        let mut packets = Vec::new();
        for entry in self.vault.store.vault_meta.prefix_iter(&txn, PACKET)? {
            let (_, bytes) = entry?;
            let packet: ClaimConflictBundle = serde_json::from_slice(&bytes)
                .map_err(|_| Error::CorruptedIndex("claim conflict packet"))?;
            if self
                .vault
                .store
                .vault_meta
                .get(&txn, &key(RESOLUTION, &packet.bundle_id))?
                .is_some()
            {
                continue;
            }
            if packet.authority_root != root_id(self.vault, &txn)? {
                continue;
            }
            let bound = action_bound(
                self.vault,
                &txn,
                WriteActor::new(self.actor, EdgeActorClass::Human),
                "memory.conflict_review",
                packet.disputed,
            )?;
            if owner || delegated_grant(self.vault, &txn, &bound)?.is_some() {
                match hydrate(self.vault, &txn, load(self.vault, &txn, &packet.bundle_id)?) {
                    Ok(packet) => packets.push(packet),
                    Err(Error::Gate(GateError::GateConsentStale { .. })) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(packets)
    }

    fn verify_reviewer_identity(
        &self,
        txn: &heed::RoTxn<'_>,
        reviewer: &AuthenticatedOwner,
    ) -> Result<(), Error> {
        if self.actor != reviewer.actor() || self.actor_class != EdgeActorClass::Human {
            return Err(authority_denied(
                "review authentication must name the bound human",
            ));
        }
        verify_live_actor(
            self.vault,
            txn,
            WriteActor::new(self.actor, EdgeActorClass::Human),
        )
    }

    /// Explicit admin ruling. Revalidates root, live reviewer authority, policy
    /// and every reviewed byte, then appends receipt + new ruling claim and
    /// supersedes the disputed head in ONE transaction. Exact replay returns
    /// the same durable receipt. The proposal is closed, not erased; all source
    /// and author history remains on its original row.
    pub fn rule_claim_conflict(
        &self,
        reviewer: &AuthenticatedOwner,
        id: [u8; 32],
        now: u64,
    ) -> MemoryResult<ClaimConflictReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            self.verify_reviewer_identity(txn, reviewer)?;
            let packet = load(self.vault, txn, &id)?;
            if packet.authority_root != root_id(self.vault, txn)? {
                return Err(stale(packet.disputed).into());
            }
            let required = action_bound(
                self.vault,
                txn,
                WriteActor::new(self.actor, EdgeActorClass::Human),
                "memory.conflict_review",
                packet.disputed,
            )?;
            let grant_ref = if is_root_owner(self.vault, txn, self.actor)? {
                None
            } else {
                Some(
                    delegated_grant(self.vault, txn, &required)?
                        .ok_or_else(|| authority_denied("no named admin review Grant"))?,
                )
            };
            let resolution_key = key(RESOLUTION, &id);
            if let Some(raw) = self.vault.store.vault_meta.get(txn, &resolution_key)? {
                let decision_id = GateDecisionId::from_bytes(
                    raw.as_ref()
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("conflict resolution marker"))?,
                );
                let receipt = self
                    .vault
                    .store
                    .gate_decision_in_txn(txn, decision_id)?
                    .ok_or(Error::CorruptedIndex("conflict ruling receipt"))?;
                if receipt.content_kind != KIND
                    || receipt.outcome != "approved"
                    || receipt.diff_handle.as_slice() != id.as_slice()
                    || receipt.redacted_at.is_some()
                {
                    return Err(Error::CorruptedIndex("conflict ruling receipt").into());
                }
                let ruling_claim = EntityId::from_bytes(
                    receipt
                        .claim_id
                        .ok_or(Error::CorruptedIndex("conflict ruling claim"))?,
                )?;
                return Ok(ClaimConflictReceipt {
                    bundle_id: id,
                    receipt_ref: format!("gate:{}", decision_id.to_hex()),
                    superseded_claim: packet.disputed,
                    ruling_claim,
                });
            }
            if packet.policy_frontier
                != crate::gate::resolve_policy_manifest(&self.vault.store, txn)?
                    .read_frontier_hash()?
            {
                return Err(stale(packet.disputed).into());
            }
            hydrate(self.vault, txn, packet.clone())?;
            let ruling = self
                .vault
                .get_claim_in_txn(txn, &packet.proposal)?
                .ok_or(Error::EntityNotFound)?;
            if ruling.lifecycle != ClaimLifecycleStatus::Active
                || ruling.stale
                || ruling.valid_from.is_some_and(|at| at > now)
                || ruling.valid_to.is_some_and(|at| at <= now)
            {
                return Err(stale(packet.proposal).into());
            }
            // This is an explicit human ruling ABOUT the proposal, not a
            // relabeling of the proposal itself. Its separate row keeps both
            // original source stamps intact and records the ruling evidence.
            let envelope = WriteEnvelope::new(
                WriteActor::new(self.actor, EdgeActorClass::Human),
                ClaimSource::UserStated,
                WriteProvenance::new(Value::Map(vec![
                    (Value::from("conflictBundle"), Value::Binary(id.to_vec())),
                    (
                        Value::from("proposal"),
                        Value::Binary(packet.proposal.as_bytes().to_vec()),
                    ),
                    (
                        Value::from("ownerAuthentication"),
                        Value::from(reviewer.decision_id().to_hex()),
                    ),
                ]))?,
                ClaimApprovalStatus::Approved,
            );
            if ruling.rel.is_some() || ruling.session_tag.is_some() {
                return Err(Error::InvalidClaimBody(
                    "conflict proposals must use the actor-bound claim_propose door",
                )
                .into());
            }
            let mut candidate = crate::write_envelope::ClaimCandidate::new(
                ruling.predicate,
                ruling.subject,
                ruling.value,
                ruling.confidence,
            )
            .with_validity(ruling.valid_from, ruling.valid_to)
            .with_stale(ruling.stale);
            if let Some(scope) = ruling.scope {
                candidate = candidate.with_scope(scope);
            }
            if let Some(world) = ruling.world {
                candidate = candidate.with_world(world);
            }
            if let Some(salience) = ruling.salience {
                candidate = candidate.with_salience(salience);
            }
            let ruling_id = EntityId::now();
            self.vault
                .batch_in()
                .claim_candidate(
                    &ruling_id,
                    candidate,
                    &envelope,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )
                .apply(txn)?;
            // Close a pending target's review tray in the same atomic ruling.
            self.vault.store.close_pending_gate_consent_in_txn(
                txn,
                &packet.disputed,
                now,
                "superseded",
                vec!["gate.memory.admin_conflict_ruling".to_owned()],
                None,
            )?;
            self.vault
                .supersede_claim_in_txn(txn, &ruling_id, &packet.disputed, now)?;
            // The generic lifecycle projector may re-evaluate a Proposed row
            // as pending. A terminal ruled head must not leave an actionable
            // consent behind, so close any such replay in this transaction.
            self.vault.store.close_pending_gate_consent_in_txn(
                txn,
                &packet.disputed,
                now,
                "superseded",
                vec!["gate.memory.admin_conflict_ruling".to_owned()],
                None,
            )?;
            // The selected proposal is consumed as part of the unit. Keep its
            // value/source/author history, but leave no separate approval that
            // could later create a second canonical head beside the ruling.
            self.vault
                .retract_claim_in_txn(txn, &packet.proposal, now)?;
            let mut receipt = decision(
                envelope.actor(),
                KIND,
                "approved",
                "gate.memory.admin_conflict_ruling",
                Some(ruling_id),
                id.to_vec(),
                now,
            );
            receipt.grant_ref = grant_ref;
            receipt.read_frontier_hash = packet.policy_frontier;
            self.vault
                .store
                .append_gate_decision_in_txn(txn, &receipt)?;
            self.vault.store.vault_meta.put(
                txn,
                &resolution_key,
                &receipt.decision_id.as_bytes(),
            )?;
            Ok(ClaimConflictReceipt {
                bundle_id: id,
                receipt_ref: format!("gate:{}", receipt.decision_id.to_hex()),
                superseded_claim: packet.disputed,
                ruling_claim: ruling_id,
            })
        })
    }
}
