//! FIX 8875 for the topology-audit section: its rows split into
//! content-free facts and each actor's content, which L03's carrier seals
//! under that actor's erasable key (`sync::home_handoff::actor_content`).
//!
//! Every actor-bearing field travels as a typed piece in the partition of
//! the actor it names, and the facts keep only its place: each subject of a
//! candidate and each record its review read that is a PERSON, MACHINE or
//! AGENT_DEF (or a record this node cannot read, which counts as one), a
//! result's reviewer, and a decision receipt's principal and each evidence
//! version naming an actor. A piece names no actor itself: the partition
//! holding it is that actor's. A receipt's other fields name no actor (its
//! question, provider pins, band, clock and rule row), so they stay facts;
//! the recipe asks with no image, so a receipt carrying one does not
//! travel. The scope's handle and the decider's class
//! stay facts: the handle is the opaque proposer-scope token (FIX 10189),
//! which names no one without the source's own handle map, a map that
//! never travels and that an erase empties, as the live scrub leaves it.
//!
//! Rejoining reads each row as the live actor scrub leaves it
//! ([`super::super::erase_topology_audit_actor_in_txn`]): a candidate a
//! subject or read record of which has no piece here is dropped whole, a
//! result whose reviewer has none keeps its outcome with no reviewer, and a
//! decision receipt missing its principal's piece or any version's is
//! dropped. A rejoined receipt is the stored one byte for byte: both are the
//! receipt's own encoding.

use std::collections::BTreeMap;

use heed::RoTxn;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::{TopologyAuditIntent, TopologyAuditResult, TopologyAuditSelection};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::decision::{DecisionReceipt, EvidenceVersion};
use crate::sync::home_handoff::ActorContent;
use crate::vault::Vault;

/// One place a fact keeps: its value, or the place of an actor's piece.
#[derive(Serialize, Deserialize)]
pub(super) enum Slot<T> {
    Fact(T),
    Actor,
}

/// Which row a decision receipt belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum ReceiptOf {
    Selection,
    Result,
}

/// A decision receipt's facts: its JSON body without its principal and its
/// evidence versions, the principal's place, and each version's place.
#[derive(Serialize, Deserialize)]
pub(super) struct ReceiptFacts {
    body: String,
    principal: Slot<EntityId>,
    versions: Vec<Slot<EvidenceVersion>>,
}

/// One candidate's intent, its subjects by place.
#[derive(Serialize, Deserialize)]
pub(super) struct IntentFacts {
    /// The intent with no subjects.
    row: TopologyAuditIntent,
    subjects: Vec<Slot<EntityId>>,
}

/// One selection, its decision receipt by its facts.
#[derive(Serialize, Deserialize)]
pub(super) struct SelectionFacts {
    /// The selection with no decision receipt.
    row: TopologyAuditSelection,
    receipt: Option<ReceiptFacts>,
}

/// One result, its reviewer, decision receipt and read records by place.
#[derive(Serialize, Deserialize)]
pub(super) struct ResultFacts {
    /// The result with no reviewer, decision receipt or read records.
    row: TopologyAuditResult,
    reviewer: Option<Slot<EntityId>>,
    receipt: Option<ReceiptFacts>,
    evidence_refs: Vec<Slot<EntityId>>,
}

/// One piece of an actor's content, on the candidate it belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum TopologyAuditActorPiece {
    /// The actor is the candidate's subject at `index`.
    Subject { audit_id: [u8; 32], index: u32 },
    /// The actor is the record at `index` its review read.
    Evidence { audit_id: [u8; 32], index: u32 },
    /// The actor reviewed the candidate.
    Reviewer { audit_id: [u8; 32] },
    /// The actor is the principal of a decision receipt.
    ReceiptPrincipal { audit_id: [u8; 32], of: ReceiptOf },
    /// The evidence version at `index` of a decision receipt is of the
    /// actor's body, at this hash.
    ReceiptVersion {
        audit_id: [u8; 32],
        of: ReceiptOf,
        index: u32,
        body_hash: [u8; 32],
    },
}

/// One actor's pieces of the section.
#[derive(Serialize, Deserialize)]
pub(crate) struct TopologyAuditActorContent {
    actor: EntityId,
    pieces: Vec<TopologyAuditActorPiece>,
}

impl ActorContent for TopologyAuditActorContent {
    fn actor(&self) -> EntityId {
        self.actor
    }
}

/// Each actor's pieces, as the export gathers them.
pub(super) type Parts = BTreeMap<EntityId, Vec<TopologyAuditActorPiece>>;

/// The pieces as one move carries them, one partition per actor.
pub(super) fn partitions(parts: Parts) -> Vec<TopologyAuditActorContent> {
    parts
        .into_iter()
        .map(|(actor, pieces)| TopologyAuditActorContent { actor, pieces })
        .collect()
}

/// Whether `id` is an actor whose erase must reach every copy: a PERSON,
/// MACHINE or AGENT_DEF, or a record this node cannot read.
fn is_actor(vault: &Vault, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(!crate::ports::names_no_actor_in_txn(&vault.store, txn, id)?)
}

/// A list place as a piece carries it.
fn place(index: usize) -> Result<u32> {
    u32::try_from(index)
        .map_err(|_| Error::InvariantViolation("a topology audit list outgrew its place"))
}

/// `ids` by place: a record that is no actor as a fact, an actor as the
/// piece `piece` makes for its place, in that actor's partition.
fn slots(
    vault: &Vault,
    txn: &RoTxn<'_>,
    ids: Vec<EntityId>,
    parts: &mut Parts,
    piece: impl Fn(u32) -> TopologyAuditActorPiece,
) -> Result<Vec<Slot<EntityId>>> {
    let mut slots = Vec::with_capacity(ids.len());
    for (index, id) in ids.into_iter().enumerate() {
        if is_actor(vault, txn, &id)? {
            parts.entry(id).or_default().push(piece(place(index)?));
            slots.push(Slot::Actor);
        } else {
            slots.push(Slot::Fact(id));
        }
    }
    Ok(slots)
}

/// A decision receipt split into its facts and its actors' pieces. A receipt
/// that does not read as one, or carries images, travels nowhere: its row
/// lands with no receipt, as an erase would leave it.
fn split_receipt(
    vault: &Vault,
    txn: &RoTxn<'_>,
    (audit_id, of): ([u8; 32], ReceiptOf),
    receipt: &str,
    parts: &mut Parts,
) -> Result<Option<ReceiptFacts>> {
    let Ok(mut receipt) = serde_json::from_str::<DecisionReceipt>(receipt) else {
        return Ok(None);
    };
    if !receipt.images.is_empty() {
        return Ok(None);
    }
    let versions = std::mem::take(&mut receipt.evidence_versions);
    let Ok(Value::Object(mut body)) = serde_json::to_value(&receipt) else {
        return Ok(None);
    };
    body.remove("principal");
    body.remove("evidence_versions");
    let principal = if is_actor(vault, txn, &receipt.principal)? {
        parts
            .entry(receipt.principal)
            .or_default()
            .push(TopologyAuditActorPiece::ReceiptPrincipal { audit_id, of });
        Slot::Actor
    } else {
        Slot::Fact(receipt.principal)
    };
    let mut slots = Vec::with_capacity(versions.len());
    for (index, version) in versions.into_iter().enumerate() {
        if is_actor(vault, txn, &version.id)? {
            parts
                .entry(version.id)
                .or_default()
                .push(TopologyAuditActorPiece::ReceiptVersion {
                    audit_id,
                    of,
                    index: place(index)?,
                    body_hash: version.body_hash,
                });
            slots.push(Slot::Actor);
        } else {
            slots.push(Slot::Fact(version));
        }
    }
    Ok(Some(ReceiptFacts {
        body: Value::Object(body).to_string(),
        principal,
        versions: slots,
    }))
}

/// An intent's facts, its actor subjects in their partitions.
pub(super) fn intent_facts(
    vault: &Vault,
    txn: &RoTxn<'_>,
    mut row: TopologyAuditIntent,
    parts: &mut Parts,
) -> Result<IntentFacts> {
    let audit_id = row.audit_id;
    let subjects = slots(
        vault,
        txn,
        std::mem::take(&mut row.subjects),
        parts,
        |index| TopologyAuditActorPiece::Subject { audit_id, index },
    )?;
    Ok(IntentFacts { row, subjects })
}

/// A selection's facts, its receipt's actors in their partitions.
pub(super) fn selection_facts(
    vault: &Vault,
    txn: &RoTxn<'_>,
    mut row: TopologyAuditSelection,
    parts: &mut Parts,
) -> Result<SelectionFacts> {
    let receipt = match row.decision_receipt.take() {
        Some(receipt) => split_receipt(
            vault,
            txn,
            (row.audit_id, ReceiptOf::Selection),
            &receipt,
            parts,
        )?,
        None => None,
    };
    Ok(SelectionFacts { row, receipt })
}

/// A result's facts, its reviewer, receipt's actors and actor records in
/// their partitions.
pub(super) fn result_facts(
    vault: &Vault,
    txn: &RoTxn<'_>,
    mut row: TopologyAuditResult,
    parts: &mut Parts,
) -> Result<ResultFacts> {
    let audit_id = row.audit_id;
    let reviewer = match row.reviewer.take() {
        Some(reviewer) if is_actor(vault, txn, &reviewer)? => {
            parts
                .entry(reviewer)
                .or_default()
                .push(TopologyAuditActorPiece::Reviewer { audit_id });
            Some(Slot::Actor)
        }
        Some(reviewer) => Some(Slot::Fact(reviewer)),
        None => None,
    };
    let receipt = match row.decision_receipt.take() {
        Some(receipt) => split_receipt(vault, txn, (audit_id, ReceiptOf::Result), &receipt, parts)?,
        None => None,
    };
    let evidence_refs = slots(
        vault,
        txn,
        std::mem::take(&mut row.evidence_refs),
        parts,
        |index| TopologyAuditActorPiece::Evidence { audit_id, index },
    )?;
    Ok(ResultFacts {
        row,
        reviewer,
        receipt,
        evidence_refs,
    })
}

/// The pieces of every actor whose content opened here and who is not
/// erased here, by what each fills.
#[derive(Default)]
pub(super) struct Opened {
    subjects: BTreeMap<([u8; 32], u32), EntityId>,
    evidence: BTreeMap<([u8; 32], u32), EntityId>,
    reviewers: BTreeMap<[u8; 32], EntityId>,
    principals: BTreeMap<([u8; 32], ReceiptOf), EntityId>,
    versions: BTreeMap<([u8; 32], ReceiptOf, u32), EvidenceVersion>,
}

impl Opened {
    /// The pieces `actors` carry.
    pub(super) fn of(actors: Vec<TopologyAuditActorContent>) -> Self {
        let mut opened = Self::default();
        for content in actors {
            let actor = content.actor;
            for piece in content.pieces {
                match piece {
                    TopologyAuditActorPiece::Subject { audit_id, index } => {
                        opened.subjects.insert((audit_id, index), actor);
                    }
                    TopologyAuditActorPiece::Evidence { audit_id, index } => {
                        opened.evidence.insert((audit_id, index), actor);
                    }
                    TopologyAuditActorPiece::Reviewer { audit_id } => {
                        opened.reviewers.insert(audit_id, actor);
                    }
                    TopologyAuditActorPiece::ReceiptPrincipal { audit_id, of } => {
                        opened.principals.insert((audit_id, of), actor);
                    }
                    TopologyAuditActorPiece::ReceiptVersion {
                        audit_id,
                        of,
                        index,
                        body_hash,
                    } => {
                        opened.versions.insert(
                            (audit_id, of, index),
                            EvidenceVersion {
                                id: actor,
                                body_hash,
                            },
                        );
                    }
                }
            }
        }
        opened
    }

    /// `slots` filled from the facts and the opened pieces `held` keeps for
    /// `audit_id`; `None` when an actor's piece is not here.
    fn fill(
        held: &BTreeMap<([u8; 32], u32), EntityId>,
        audit_id: [u8; 32],
        slots: Vec<Slot<EntityId>>,
    ) -> Option<Vec<EntityId>> {
        slots
            .into_iter()
            .enumerate()
            .map(|(index, slot)| match slot {
                Slot::Fact(id) => Some(id),
                Slot::Actor => u32::try_from(index)
                    .ok()
                    .and_then(|index| held.get(&(audit_id, index)).copied()),
            })
            .collect()
    }

    /// A decision receipt rejoined, or `None` when its principal's piece or
    /// any version's is not here.
    fn receipt(&self, audit_id: [u8; 32], of: ReceiptOf, facts: ReceiptFacts) -> Option<String> {
        let Ok(Value::Object(mut body)) = serde_json::from_str::<Value>(&facts.body) else {
            return None;
        };
        let principal = match facts.principal {
            Slot::Fact(id) => id,
            Slot::Actor => *self.principals.get(&(audit_id, of))?,
        };
        let mut versions = Vec::with_capacity(facts.versions.len());
        for (index, slot) in facts.versions.into_iter().enumerate() {
            versions.push(match slot {
                Slot::Fact(version) => version,
                Slot::Actor => self
                    .versions
                    .get(&(audit_id, of, u32::try_from(index).ok()?))?
                    .clone(),
            });
        }
        body.insert("principal".to_owned(), Value::String(principal.to_hex()));
        let mut receipt = serde_json::from_value::<DecisionReceipt>(Value::Object(body)).ok()?;
        receipt.evidence_versions = versions;
        serde_json::to_string(&receipt).ok()
    }

    /// The intent rejoined, or `None` when a subject's piece is not here.
    pub(super) fn intent(&self, facts: IntentFacts) -> Option<TopologyAuditIntent> {
        let mut row = facts.row;
        row.subjects = Self::fill(&self.subjects, row.audit_id, facts.subjects)?;
        Some(row)
    }

    /// The selection rejoined: its receipt only with every piece it needs.
    pub(super) fn selection(&self, facts: SelectionFacts) -> TopologyAuditSelection {
        let mut row = facts.row;
        row.decision_receipt = facts
            .receipt
            .and_then(|receipt| self.receipt(row.audit_id, ReceiptOf::Selection, receipt));
        row
    }

    /// The result rejoined, or `None` when a record its review read has no
    /// piece here; its reviewer and receipt only with their pieces.
    pub(super) fn result(&self, facts: ResultFacts) -> Option<TopologyAuditResult> {
        let mut row = facts.row;
        let audit_id = row.audit_id;
        row.evidence_refs = Self::fill(&self.evidence, audit_id, facts.evidence_refs)?;
        row.reviewer = match facts.reviewer {
            Some(Slot::Fact(reviewer)) => Some(reviewer),
            Some(Slot::Actor) => self.reviewers.get(&audit_id).copied(),
            None => None,
        };
        row.decision_receipt = facts
            .receipt
            .and_then(|receipt| self.receipt(audit_id, ReceiptOf::Result, receipt));
        Some(row)
    }
}

/// The audit a selection's facts belong to.
pub(super) const fn selection_audit(facts: &SelectionFacts) -> [u8; 32] {
    facts.row.audit_id
}

/// The audit a result's facts belong to.
pub(super) const fn result_audit(facts: &ResultFacts) -> [u8; 32] {
    facts.row.audit_id
}
