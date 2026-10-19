//! Root-owned reference pins. No source bytes or child trust enter the receipt store.
use std::collections::{BTreeMap, BTreeSet};

use super::conflict::{collapse_verified_evidence, verify_swarm_evidence_bytes};
use super::evidence::EvidenceLocator;
use super::provenance::{evidence_source_from_claim, source_meet};
use super::resources::stored_project;
use super::support::invalid_consolidation;
use super::turn_text;
use super::watermark::decode_turn_body;
use crate::claim::{ClaimSource, ScopedRead};
use crate::memory::consolidation::ConsolidationMessageEvidence;
use crate::memory::consolidation_frontier::*;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::provenance::EdgeRef;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeKind, EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

const ROOTS: SideTable<EntityId, Root, Named> =
    SideTable::new(&side_table::DREAMER_CONSOLIDATION_ROOT);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Root {
    owner: EntityId,
    accounting: ConsolidationRootAccounting,
}

pub(crate) fn reference(input: &ConsolidationReference) -> Result<super::SwarmEvidenceRef> {
    let source = EntityId::from_hex(&input.source_id)?;
    match (&input.claim_id, input.byte_range) {
        (Some(claim), None) => {
            Ok(EvidenceLocator::claim(source, EntityId::from_hex(claim)?)?.reference())
        }
        (None, Some((start, end))) => {
            Ok(EvidenceLocator::turn_range(source, start, end)?.reference())
        }
        _ => Err(invalid_consolidation("reference needs one claim id or byte range")),
    }
}

fn bucket_key(input: &ConsolidationRootBucket) -> Result<super::ConsolidationBucketKey> {
    crate::claim::validate_predicate(&format!("{}.value", input.predicate_root), false)?;
    let parse = |id: &Option<String>| id.as_deref().map(EntityId::from_hex).transpose();
    Ok(super::ConsolidationBucketKey {
        subject: EntityId::from_hex(&input.subject)?,
        predicate_root: input.predicate_root.clone(),
        world: parse(&input.world)?,
        facet: parse(&input.facet)?,
        rel: parse(&input.relationship)?,
        project: EntityId::from_hex(&input.project)?,
    })
}

fn require_readable(read: &ScopedRead<'_>, txn: &heed::RoTxn<'_>, ids: &[EntityId]) -> Result<()> {
    if read.entities_readable_in_txn(txn, ids)?.iter().any(|allowed| !allowed) {
        return Err(invalid_consolidation("root evidence is not readable"));
    }
    Ok(())
}

fn source_row(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<(u8, Vec<u8>)> {
    let row = read.get_entities_parts_in_txn(txn, &[id])?.pop().flatten()
        .ok_or_else(|| invalid_consolidation("root source is not readable"))?;
    Ok((row.0, row.2))
}

fn row_trust(vault: &Vault, kind: u8, body: &[u8]) -> Result<ClaimSource> {
    if kind == ENTITY_TYPE_CLAIM {
        return Ok(evidence_source_from_claim(&crate::claim::decode_claim_body(body, true)?));
    }
    if kind == ENTITY_TYPE_TURN {
        return super::resources::native_turn_source(vault, body);
    }
    Err(invalid_consolidation("root evidence must name a TURN or CLAIM"))
}

/// Follow actual lineage, including the wrappers on derived_from edges, in
/// the same scoped snapshot as the citation. Ancestors taint but never add
/// corroboration just because the child cited a derived summary.
fn ancestors(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
) -> Result<Vec<ConsolidationAncestor>> {
    let mut pending = vec![source];
    let mut seen = BTreeSet::new();
    let mut found = Vec::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        let (kind, body) = source_row(read, txn, id)?;
        let trust = row_trust(vault, kind, &body)?;
        if id != source {
            found.push(ConsolidationAncestor {
                source_ref: id.to_hex(),
                source_revision: *blake3::hash(&body).as_bytes(),
                trust_class: trust,
            });
        }
        if kind == ENTITY_TYPE_CLAIM {
            let claim = crate::claim::decode_claim_body(&body, true)?;
            if let Some(value) = claim.evidence.as_ref() {
                let stored = value.as_map().and_then(|fields| fields.iter()
                    .find(|(key, _)| key.as_str() == Some("candidate_evidence")))
                    .map_or(value, |(_, value)| value);
                if let Some(envelope) = super::decode_consolidation_evidence(stored)? {
                    pending.extend(envelope.refs);
                    pending.extend(envelope.chain.into_iter()
                        .filter(|hop| hop.kind == super::ConsolidationProvenanceHopKind::AnswerTurn)
                        .map(|hop| hop.entity_ref));
                }
            }
        }
        for edge in vault.store.port_edges(txn, &id, EdgeDirection::Out,
            Some(EdgeKind::DerivedFrom), None)?
        {
            let edge = edge?;
            pending.push(edge.target);
            pending.extend(vault.live_edge_provenance_ids_in_txn(
                txn, &EdgeRef::new(id, EdgeKind::DerivedFrom, edge.target),
            )?);
        }
    }
    found.sort_by(|left, right| left.source_ref.cmp(&right.source_ref));
    Ok(found)
}

fn pin_reference(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    bucket: &super::ConsolidationBucketKey,
    input: &ConsolidationReference,
) -> Result<ConsolidationRootEvidence> {
    let locator = reference(input)?;
    let (kind, body) = source_row(read, txn, locator.source_id)?;
    if stored_project(&vault.store, txn, locator.source_id, kind, &body)? != Some(bucket.project) {
        return Err(invalid_consolidation("root source crossed its bucket project"));
    }
    let (world, facet, relationship) = if kind == ENTITY_TYPE_CLAIM {
        let claim = crate::claim::decode_claim_body(&body, true)?;
        (claim.world, super::resources::claim_facet(claim.scope.as_ref())?, claim.rel)
    } else if kind == ENTITY_TYPE_TURN {
        let facts = decode_turn_body(&body);
        let parents = vault.filtered_edge_peers(txn, EdgeDirection::Out,
            &locator.source_id, EdgeKind::ChildOf, None)?;
        let [parent] = parents.as_slice() else {
            return Err(invalid_consolidation("root TURN needs its conversation"));
        };
        let (parent_kind, parent_body) = source_row(read, txn, *parent)?;
        if !matches!(parent_kind, crate::registry::ENTITY_TYPE_SESSION
            | crate::registry::ENTITY_TYPE_CONVERSATION)
        {
            return Err(invalid_consolidation("root TURN parent is not a conversation"));
        }
        let parent = decode_turn_body(&parent_body);
        (facts.world_ref.or(parent.world_ref), facts.facet_ref.or(parent.facet_ref), None)
    } else {
        return Err(invalid_consolidation("root evidence must name a TURN or CLAIM"));
    };
    if world != bucket.world || facet != bucket.facet
        || (kind == ENTITY_TYPE_CLAIM && relationship != bucket.rel)
    {
        return Err(invalid_consolidation("root source crossed its bucket axes"));
    }
    let trust = row_trust(vault, kind, &body)?;
    let ancestry = ancestors(vault, read, txn, locator.source_id)?;
    let meet = ancestry.iter().fold(trust, |meet, ancestor| source_meet(meet, ancestor.trust_class));
    let text = (kind == ENTITY_TYPE_TURN).then(|| {
        turn_text::collect_in(read, txn, &locator.source_id, &body, &mut 0)
    }).transpose()?;
    let verified = verify_swarm_evidence_bytes(locator, kind, &body,
        text.as_ref().and_then(turn_text::TurnText::text), meet)?;
    let refusal = crate::dreamer_promotion::evidence_ref_refusal_in_txn(vault, txn, &locator.source_id)?;
    let corroborates = refusal.is_none()
        && !(trust == ClaimSource::Generated && !ancestry.is_empty());
    let messages = text.as_ref().map(|text| text.spans(locator.byte_range))
        .transpose()?.unwrap_or_default().into_iter().map(|span| ConsolidationMessageEvidence {
            message_ref: span.message.to_hex(), start: span.start, end: span.end,
            revision: span.revision, frontier: span.frontier,
        }).collect();
    Ok(ConsolidationRootEvidence {
        reference: input.clone(),
        source_revision: *blake3::hash(&body).as_bytes(),
        content_hash: verified.content_hash,
        trust_class: verified.trust_class,
        corroborates, refusal, ancestors: ancestry, messages,
    })
}

pub(crate) fn pin_in_txn(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    input: &ConsolidationPinRequest,
) -> Result<ConsolidationRootAccounting> {
    if input.buckets.is_empty() {
        return Err(invalid_consolidation("root needs at least one bucket"));
    }
    let mut buckets = Vec::new();
    let mut keys = BTreeSet::new();
    for input in &input.buckets {
        let key = bucket_key(&input.bucket)?;
        let selectors: Vec<_> = [Some(key.subject), key.world, key.facet, key.rel, Some(key.project)]
            .into_iter().flatten().collect();
        require_readable(read, txn, &selectors)?;
        if !keys.insert(key.bucket_hash()) || input.evidence.is_empty() {
            return Err(invalid_consolidation("root needs distinct, nonempty buckets"));
        }
        let mut refs = input.evidence.clone();
        refs.sort();
        refs.dedup();
        let pinned = refs.iter().map(|entry| pin_reference(vault, read, txn, &key, entry))
            .collect::<Result<Vec<_>>>()?;
        buckets.push(ConsolidationBucketAccounting {
            bucket: input.bucket.clone(), bucket_hash: key.bucket_hash(), pinned,
            children: Vec::new(), independent: Vec::new(), duplicates_collapsed: 0,
            excluded_references: 0, source_meet: ClaimSource::Generated,
        });
    }
    let id = EntityId::now();
    let accounting = ConsolidationRootAccounting {
        root_ref: id.to_hex(),
        revision: vault.store.env.info().last_txn_id as u64,
        buckets,
    };
    ROOTS.put(&vault.store, txn, &id, &Root { owner, accounting: accounting.clone() })?;
    Ok(accounting)
}

fn held_root(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
    reference: &str,
) -> Result<(EntityId, Root)> {
    let id = EntityId::from_hex(reference)?;
    let root = ROOTS.get(&vault.store, txn, &id)?
        .ok_or_else(|| invalid_consolidation("no evidence root has that ref"))?;
    if root.owner != owner {
        return Err(invalid_consolidation("evidence root belongs to another owner"));
    }
    require_readable(read, txn, &source_ids(&root.accounting)?)?;
    Ok((id, root))
}

pub(crate) fn source_ids(accounting: &ConsolidationRootAccounting) -> Result<Vec<EntityId>> {
    let mut ids = BTreeSet::new();
    for bucket in &accounting.buckets {
        let key = bucket_key(&bucket.bucket)?;
        ids.extend([Some(key.subject), key.world, key.facet, key.rel, Some(key.project)]
            .into_iter().flatten());
        for row in &bucket.pinned {
            ids.insert(reference(&row.reference)?.source_id);
            for ancestor in &row.ancestors {
                ids.insert(EntityId::from_hex(&ancestor.source_ref)?);
            }
            for message in &row.messages {
                ids.insert(EntityId::from_hex(&message.message_ref)?);
            }
        }
    }
    Ok(ids.into_iter().collect())
}

pub(crate) fn accounting_in_txn(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
    reference: &str,
) -> Result<ConsolidationRootAccounting> {
    Ok(held_root(vault, read, txn, owner, reference)?.1.accounting)
}

/// Children may finish in any order. Each identity is immutable, and no
/// newly introduced source or changed quote is substituted after the pin.
pub(crate) fn frontier_in_txn(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    input: &ConsolidationFrontierRequest,
) -> Result<ConsolidationRootAccounting> {
    let (id, mut root) = held_root(vault, read, txn, owner, &input.root_ref)?;
    for child in &input.children {
        EntityId::from_hex(&child.child_ref)?;
        if !child.judgement.confidence.is_finite()
            || !(0.0..=1.0).contains(&child.judgement.confidence)
            || child.evidence.is_empty()
        {
            return Err(invalid_consolidation("invalid child judgement or empty frontier"));
        }
        if root.accounting.buckets.iter().any(|bucket| bucket.bucket_hash != child.bucket_hash
            && bucket.children.iter().any(|row| row.child_ref == child.child_ref))
        {
            return Err(invalid_consolidation("child identity crossed its bucket"));
        }
        let bucket = root.accounting.buckets.iter_mut()
            .find(|bucket| bucket.bucket_hash == child.bucket_hash)
            .ok_or_else(|| invalid_consolidation("child names an unpinned bucket"))?;
        crate::claim::validate_predicate(&child.judgement.predicate, false)?;
        if crate::claim::predicate_root(&child.judgement.predicate) != bucket.bucket.predicate_root {
            return Err(invalid_consolidation("child judgement crossed its bucket"));
        }
        let mut evidence = child.evidence.clone();
        evidence.sort();
        evidence.dedup();
        for entry in &evidence {
            reference(entry)?;
            if !bucket.pinned.iter().any(|row| row.reference == *entry) {
                return Err(invalid_consolidation("child citation was not pinned by the root"));
            }
        }
        let encoded = serde_json::to_vec(&child.judgement)
            .map_err(|_| invalid_consolidation("child judgement does not encode"))?;
        let receipt = ConsolidationChildReceipt {
            child_ref: child.child_ref.clone(),
            judgement_hash: *blake3::hash(&encoded).as_bytes(), evidence,
        };
        if let Some(old) = bucket.children.iter().find(|old| old.child_ref == receipt.child_ref) {
            if old.judgement_hash != receipt.judgement_hash || old.evidence != receipt.evidence {
                return Err(invalid_consolidation("child frontier changed after submission"));
            }
        } else {
            bucket.children.push(receipt);
        }
        bucket.children.sort_by(|left, right| left.child_ref.cmp(&right.child_ref));
        account_bucket(bucket)?;
    }
    ROOTS.put(&vault.store, txn, &id, &root)?;
    Ok(root.accounting)
}

fn account_bucket(bucket: &mut ConsolidationBucketAccounting) -> Result<()> {
    let mut verified = Vec::new();
    let mut rows = BTreeMap::new();
    let mut excluded = 0_u32;
    let mut meet = ClaimSource::Generated;
    for entry in bucket.children.iter().flat_map(|child| &child.evidence) {
        let row = bucket.pinned.iter().find(|row| row.reference == *entry)
            .ok_or_else(|| invalid_consolidation("child citation is not pinned"))?;
        meet = source_meet(meet, row.trust_class);
        if !row.corroborates {
            excluded = excluded.saturating_add(1);
            continue;
        }
        let source_id = reference(entry)?.source_id;
        verified.push(super::VerifiedSwarmEvidence {
            source_id, content_hash: row.content_hash, trust_class: row.trust_class,
        });
        rows.entry((source_id, row.content_hash)).or_insert_with(|| row.clone());
    }
    let collapsed = collapse_verified_evidence(verified);
    bucket.independent = collapsed.independent.iter().map(|entry| {
        let mut row = rows[&(entry.source_id, entry.content_hash)].clone();
        row.trust_class = entry.trust_class;
        row
    }).collect();
    bucket.duplicates_collapsed = collapsed.duplicates_collapsed;
    bucket.excluded_references = excluded;
    bucket.source_meet = meet;
    Ok(())
}

/// No root survives erasure of its author. Source facts contain only ids and
/// hashes; every read also requires the current source rows to remain readable.
pub(crate) fn erase_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (id, root) in ROOTS.scan(&vault.store, txn)? {
        if root.owner == *actor {
            ROOTS.delete(&vault.store, txn, &id)?;
        }
    }
    Ok(())
}
