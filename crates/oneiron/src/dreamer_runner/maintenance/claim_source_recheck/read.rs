//! The re-check's read (FIX 15414): in one snapshot, each live claim the
//! deleted message's TURN or MESSAGE revisions support, by its logical head,
//! with every record it and its live support assertions cite as they stand
//! now, read as the judge reads them. A claim the Dreamer's own read
//! withholds is never sent to its judge.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use super::super::{CuratorRubric, curator, invalid};
use super::ClaimSourceRecheckDeclaration;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimDemotionRung, claim_demotion_rung};
use crate::edge::EdgeKind;
use crate::ports::EntityStoreRead;
use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, Result, Vault,
};

/// The scope key a support assertion's derived evidence sits under.
const DERIVED_EVIDENCE_KEY: &str = "derived_evidence";

/// The evidence key a verified citation's locators sit under.
const LOCATORS_KEY: &str = "locators";

/// One claim the re-check judges: its logical head, the revision read, its
/// rung and class, and what the judge reads.
pub(super) struct Ask {
    pub(super) head: EntityId,
    /// The hex BLAKE3 of the head's body as read: a rung applies to it alone.
    pub(super) source_hash: String,
    pub(super) rung: Option<ClaimDemotionRung>,
    pub(super) confidence: f32,
    /// Whether a rung on it waits for the owner: a critical class, or a
    /// critical confirm not settled yet.
    pub(super) critical: bool,
    pub(super) input: serde_json::Value,
}

/// What one pass reads before it judges: the claims still to judge, the
/// curator's owner-set rubric, whose factors their rungs take, and whether
/// a claim was withheld from the Dreamer's own read.
pub(super) struct Read {
    pub(super) asks: Vec<Ask>,
    pub(super) rubric: CuratorRubric,
    pub(super) withheld: bool,
}

/// Reads, in one snapshot, each claim the message's records support that
/// this generation's re-check has not settled, with what its judge reads.
/// `None` when the re-check is moot.
pub(super) fn read_asks(
    vault: &Vault,
    declaration: &ClaimSourceRecheckDeclaration,
) -> Result<Option<Read>> {
    // The grant clock is persisted first, so a grant's expiry is judged at a
    // real floor when the Dreamer reads a TURN's words below.
    vault.store.authorization_now()?;
    let txn = vault.store.env.read_txn()?;
    let Some(owed) = crate::mail_pack::claim_recheck::claim_recheck_owed_in(
        vault,
        &txn,
        declaration.source,
        declaration.occurrence,
        declaration.generation,
    )?
    else {
        return Ok(None);
    };
    let targets: BTreeSet<EntityId> = declaration.about().into_iter().collect();
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    let rubric = curator::rubric_in_txn(vault, &txn)?;
    let reader = dreamer_read(vault)?;
    let mut asks = Vec::new();
    let mut withheld = false;
    for (head, mut supports) in discover(vault, &txn, &targets)? {
        if owed.settled.contains(&head) {
            continue;
        }
        let Some(raw) = EntityStoreRead::port_entity_raw(&vault.store, &txn, &head)? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || raw.len() == ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let bytes = &raw[ENTITY_METADATA_HEADER_LEN..];
        let body = crate::claim::decode_claim_body(bytes, true)?;
        if !judged(&body) {
            continue;
        }
        if reader.entities_readable_in_txn(&txn, std::slice::from_ref(&head))? != [true] {
            withheld = true;
            continue;
        }
        if let Some(evidence) = &body.evidence {
            cited_by(evidence, &mut supports);
        }
        supports.remove(&head);
        let mut views = Vec::with_capacity(supports.len());
        for support in supports {
            views.push(support_view(vault, &txn, support)?);
        }
        let critical = policy.criticality_for_predicate(&body.predicate)
            == crate::gate::PolicyCriticality::Critical
            || !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, &txn, &head)?;
        asks.push(Ask {
            head,
            source_hash: blake3::hash(bytes).to_hex().to_string(),
            rung: claim_demotion_rung(&body)?,
            confidence: body.confidence,
            critical,
            input: judge_input(declaration, owed.deleted_at, &body, views),
        });
    }
    Ok(Some(Read {
        asks,
        rubric,
        withheld,
    }))
}

/// The Dreamer's own scoped read, the gate its other reads take: a claim it
/// may not read never reaches its judge.
fn dreamer_read(vault: &Vault) -> Result<crate::claim::ScopedRead<'_>> {
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?;
    let key = crate::claim::ScopedReadActorKey::with_actor_class(
        dreamer.to_hex(),
        crate::edge::EdgeActorClass::System.gate_actor_class(),
    )
    .ok_or_else(invalid)?;
    Ok(vault.scoped_read(key))
}

/// Whether the re-check judges `body`: a live belief, active and approved or
/// auto, and no maintenance finding of the Dreamer's or the Coach's own.
fn judged(body: &ClaimBody) -> bool {
    body.lifecycle == ClaimLifecycleStatus::Active
        && matches!(
            body.approval,
            ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
        )
        && !body.predicate.starts_with("dreamer.")
        && !body.predicate.starts_with("coach.")
}

/// Every live claim whose typed support cites one of `targets`, by its
/// logical head, with what each live support assertion on that head cites.
/// A head's own evidence is read with the head. One pass over the claims:
/// a support assertion's head is known only once its assertion is read.
fn discover(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    targets: &BTreeSet<EntityId>,
) -> Result<BTreeMap<EntityId, BTreeSet<EntityId>>> {
    let mut heads: BTreeMap<EntityId, BTreeSet<EntityId>> = BTreeMap::new();
    let mut assertions: Vec<(EntityId, BTreeSet<EntityId>)> = Vec::new();
    for row in EntityStoreRead::port_entity_raw_records(&vault.store, txn)? {
        let (id, bytes) = row?;
        let header = EntityMetadataHeader::parse(&bytes).ok_or_else(invalid)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || bytes.len() == ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let body = crate::claim::decode_claim_body(&bytes[ENTITY_METADATA_HEADER_LEN..], true)?;
        if body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let mut cited = BTreeSet::new();
        if let Some((source, head)) = supported_head(&body) {
            cited.insert(source);
            if let Some(evidence) = scope_field(&body, DERIVED_EVIDENCE_KEY) {
                cited_by(evidence, &mut cited);
            }
            assertions.push((head, cited));
        } else {
            if let Some(evidence) = &body.evidence {
                cited_by(evidence, &mut cited);
            }
            if !cited.is_disjoint(targets) {
                heads.entry(id).or_default();
            }
        }
    }
    for (head, cited) in &assertions {
        if !cited.is_disjoint(targets) {
            heads.entry(*head).or_default();
        }
    }
    for (head, cited) in assertions {
        if let Some(supports) = heads.get_mut(&head) {
            supports.extend(cited);
        }
    }
    Ok(heads)
}

/// The support assertion's source and the head it supports, for an
/// `edge.provenance` claim on a `Supports` edge; `None` for any other claim.
fn supported_head(body: &ClaimBody) -> Option<(EntityId, EntityId)> {
    match body.subject {
        ClaimSubject::Edge {
            source,
            kind: EdgeKind::Supports,
            target,
        } if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE => {
            Some((source, target))
        }
        _ => None,
    }
}

/// The value under `key` in `body`'s scope map.
fn scope_field<'a>(body: &'a ClaimBody, key: &str) -> Option<&'a Value> {
    body.scope
        .as_ref()?
        .as_map()?
        .iter()
        .find(|(field, _)| field.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// Adds the records `evidence` cites by type to `cited`: its refs, its
/// chain's hops, and its verified locators' sources and MESSAGE slices, as
/// the evidence decoders read them. A stamped successor's carried evidence
/// counts as its own. Evidence that does not decode cites nothing.
fn cited_by(evidence: &Value, cited: &mut BTreeSet<EntityId>) {
    let carried = crate::write_envelope::envelope_carried_evidence(evidence);
    for evidence in std::iter::once(evidence).chain(carried) {
        if let Ok(Some(envelope)) =
            crate::dreamer_consolidation::decode_consolidation_evidence(evidence)
        {
            cited.extend(envelope.refs);
            cited.extend(envelope.chain.iter().map(|hop| hop.entity_ref));
        }
        let located = evidence.as_map().is_some_and(|fields| {
            fields
                .iter()
                .any(|(key, _)| key.as_str() == Some(LOCATORS_KEY))
        });
        if located
            && let Ok(locators) = crate::dreamer_consolidation::decode_verified_citations(evidence)
        {
            for (locator, _, messages) in locators {
                cited.insert(locator.source_id);
                cited.extend(messages.iter().map(|span| span.message));
            }
        }
    }
}

/// One support as the judge reads it: its ref, its kind while it is live,
/// the provider's hold on it when it is an imported message's, and the
/// words of a live TURN the Dreamer may read. A TURN or a row the Dreamer
/// may not read keeps its words withheld.
fn support_view(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<serde_json::Value> {
    let entity_type = match crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)? {
        crate::vault::LiveEntityRow::Live { entity_type, .. } => Some(entity_type),
        _ => None,
    };
    let text = match entity_type {
        Some(crate::registry::ENTITY_TYPE_TURN) => {
            crate::dreamer_consolidation::projected_turn_text_in(vault, txn, &id)
                .ok()
                .flatten()
        }
        _ => None,
    };
    let provider = crate::mail_pack::claim_recheck::presence_of_row_in(vault, txn, &id)?;
    Ok(serde_json::json!({
        "ref": id.to_hex(),
        "kind": entity_type.map_or("gone", kind_name),
        "provider": provider,
        "text": text,
    }))
}

/// The judge's name for a live record's type.
const fn kind_name(entity_type: u8) -> &'static str {
    match entity_type {
        crate::registry::ENTITY_TYPE_TURN => "turn",
        crate::registry::ENTITY_TYPE_MESSAGE => "message",
        crate::registry::ENTITY_TYPE_CLAIM => "claim",
        crate::registry::ENTITY_TYPE_CONVERSATION => "conversation",
        _ => "record",
    }
}

/// What the judge reads about one claim: the claim as it stands, the
/// message the provider deleted, and every support as it stands now.
fn judge_input(
    declaration: &ClaimSourceRecheckDeclaration,
    deleted_at: u64,
    body: &ClaimBody,
    supports: Vec<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "claim": {
            "predicate": body.predicate,
            "value": serde_json::to_value(&body.value).unwrap_or(serde_json::Value::Null),
            "confidence": body.confidence,
            "stale": body.stale,
            "valid_from": body.valid_from,
            "valid_to": body.valid_to,
        },
        "deleted_at_provider": {
            "turn": declaration.turn.to_hex(),
            "messages": declaration.messages.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
            "deleted_at": deleted_at,
            "generation": declaration.generation,
        },
        "supports": supports,
    })
}
