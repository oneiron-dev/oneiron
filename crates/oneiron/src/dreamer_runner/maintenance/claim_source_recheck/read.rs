//! The re-check's read (FIX 15414): in one snapshot, each live claim the
//! deleted message's TURN or MESSAGE revisions support, by its logical head,
//! with every record it and its live support assertions cite as they stand
//! now, read as the judge reads them. A claim the Dreamer's own read
//! withholds is never sent to its judge, nor one not yet approved: each
//! stays owed until it can be judged.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use super::super::{CuratorRubric, curator, invalid};
use super::ClaimSourceRecheckDeclaration;
use crate::authority::consolidation_evidence::ConsolidationProvenanceHopKind;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimDemotionRung, ScopedRead, claim_demotion_rung};
use crate::edge::EdgeKind;
use crate::ports::EntityStoreRead;
use crate::write_envelope::{
    WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
    envelope_carried_evidence,
};
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
    /// The head's predicate as read, whose class its landing reads again.
    pub(super) predicate: String,
    pub(super) rung: Option<ClaimDemotionRung>,
    pub(super) confidence: f32,
    /// Whether a rung on it waits for the owner: a critical class, or a
    /// critical confirm not settled yet.
    pub(super) critical: bool,
    pub(super) input: serde_json::Value,
}

/// What one pass reads before it judges: the claims still to judge, the
/// curator's owner-set rubric, whose factors their rungs take, and whether
/// a claim it found cannot be judged yet: one still waiting for approval,
/// or one the Dreamer's own read withholds.
pub(super) struct Read {
    pub(super) asks: Vec<Ask>,
    pub(super) rubric: CuratorRubric,
    pub(super) deferred: bool,
}

/// Where a claim the re-check found stands.
enum Standing {
    /// A live belief, active and approved or auto: judged now.
    Live,
    /// Active and still proposed: owed, and judged once it is approved.
    Proposed,
    /// Rejected, closed, or a maintenance finding of the Dreamer's or the
    /// Coach's own: owed nothing.
    Out,
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
    let rubric = curator::rubric_in_txn(vault, &txn)?;
    let reader = dreamer_read(vault)?;
    let mut asks = Vec::new();
    let mut deferred = false;
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
        match standing(&body) {
            Standing::Live => {}
            Standing::Proposed => {
                deferred = true;
                continue;
            }
            Standing::Out => continue,
        }
        if reader.entities_readable_in_txn(&txn, std::slice::from_ref(&head))? != [true] {
            deferred = true;
            continue;
        }
        cited_by(&body, &mut supports);
        supports.remove(&head);
        let mut views = Vec::with_capacity(supports.len());
        for support in supports {
            views.push(support_view(vault, &txn, support)?);
        }
        let source_hash = blake3::hash(bytes).to_hex().to_string();
        let claim = ClaimView {
            head,
            revision: &source_hash,
            subject: subject_view(&reader, &txn, &body.subject)?,
            body: &body,
        };
        let input = judge_input(declaration, owed.deleted_at, claim, views);
        asks.push(Ask {
            head,
            critical: critical_in(vault, &txn, &head, &body.predicate)?,
            rung: claim_demotion_rung(&body)?,
            confidence: body.confidence,
            input,
            predicate: body.predicate,
            source_hash,
        });
    }
    Ok(Some(Read {
        asks,
        rubric,
        deferred,
    }))
}

/// Whether a rung on `head`, a claim of `predicate`, waits for the owner as
/// `txn` reads it: a critical class under the policy in force, or a
/// critical confirm on it not settled yet. The read asks it, and the
/// landing asks it again in its own write.
pub(super) fn critical_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    head: &EntityId,
    predicate: &str,
) -> Result<bool> {
    Ok(crate::gate::resolve_policy_manifest(&vault.store, txn)?
        .criticality_for_predicate(predicate)
        == crate::gate::PolicyCriticality::Critical
        || !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, head)?)
}

/// The Dreamer's own scoped read, the gate its other reads take: a claim it
/// may not read never reaches its judge.
fn dreamer_read(vault: &Vault) -> Result<ScopedRead<'_>> {
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?;
    let key = crate::claim::ScopedReadActorKey::with_actor_class(
        dreamer.to_hex(),
        crate::edge::EdgeActorClass::System.gate_actor_class(),
    )
    .ok_or_else(invalid)?;
    Ok(vault.scoped_read(key))
}

/// Where `body` stands for the re-check: a live belief is judged, one still
/// proposed waits for its approval, and anything else is owed nothing.
fn standing(body: &ClaimBody) -> Standing {
    if body.lifecycle != ClaimLifecycleStatus::Active
        || body.predicate.starts_with("dreamer.")
        || body.predicate.starts_with("coach.")
    {
        return Standing::Out;
    }
    match body.approval {
        ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto => Standing::Live,
        ClaimApprovalStatus::Proposed => Standing::Proposed,
        ClaimApprovalStatus::Rejected => Standing::Out,
    }
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
                cited_by_slot(evidence, &mut cited);
            }
            assertions.push((head, cited));
        } else {
            cited_by(&body, &mut cited);
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
    field(body.scope.as_ref()?, key)
}

/// The value under `key` in the map `value`.
fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// Adds the records `body` cites by type to `cited`, read from each slot a
/// stored claim's evidence holds: a raw body's own evidence, or a stamped
/// body's `candidate_evidence` and the raw predecessor's evidence it
/// carries; and an actor claim's CHAT turns, by the actor codec. Discovery
/// and the judge's supports read the same refs.
fn cited_by(body: &ClaimBody, cited: &mut BTreeSet<EntityId>) {
    if let Some(evidence) = &body.evidence {
        if field(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY).is_some() {
            let written = field(evidence, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY);
            for slot in written
                .into_iter()
                .chain(envelope_carried_evidence(evidence))
            {
                cited_by_slot(slot, cited);
            }
        } else {
            cited_by_slot(evidence, cited);
        }
    }
    if let Some(Some((_, turns))) =
        crate::actor_claims::actor_archive_references(body).map(|refs| refs.chat)
    {
        cited.extend(turns);
    }
}

/// Adds the records one evidence slot cites by type to `cited`, as the
/// evidence codecs read them: the consolidation envelope's refs and record
/// hops (a peer hop names an actor, not a record), its verified locators'
/// sources, claims and MESSAGE slices, and its typed document citations.
/// A slot that does not decode cites nothing.
fn cited_by_slot(slot: &Value, cited: &mut BTreeSet<EntityId>) {
    if let Ok(Some(envelope)) = crate::dreamer_consolidation::decode_consolidation_evidence(slot) {
        cited.extend(envelope.refs);
        cited.extend(
            envelope
                .chain
                .iter()
                .filter(|hop| hop.kind != ConsolidationProvenanceHopKind::PeerActor)
                .map(|hop| hop.entity_ref),
        );
    }
    if field(slot, LOCATORS_KEY).is_some()
        && let Ok(locators) = crate::dreamer_consolidation::decode_verified_citations(slot)
    {
        for (locator, _, messages) in locators {
            cited.insert(locator.source_id);
            cited.extend(locator.claim_id);
            cited.extend(messages.iter().map(|span| span.message));
        }
    }
    if let Ok(citations) = crate::claim::public_evidence_refs(Some(slot)) {
        cited.extend(
            citations
                .iter()
                .filter_map(|citation| EntityId::from_hex(&citation.entity).ok()),
        );
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

/// A claim's subject as the judge reads it: an entity by its ref, and its
/// kind and name as the Dreamer's own read gives them; an edge by its kind
/// and its two ends so. An entity the Dreamer may not read keeps its ref
/// alone.
fn subject_view(
    reader: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    subject: &ClaimSubject,
) -> Result<serde_json::Value> {
    Ok(match *subject {
        ClaimSubject::Entity(id) => entity_view(reader, txn, id)?,
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } => serde_json::json!({
            "edge": kind.name(),
            "source": entity_view(reader, txn, source)?,
            "target": entity_view(reader, txn, target)?,
        }),
    })
}

/// One entity as the Dreamer's own read gives it: its ref, kind and name.
fn entity_view(
    reader: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<serde_json::Value> {
    let row = reader
        .get_entities_parts_in_txn(txn, std::slice::from_ref(&id))?
        .pop()
        .flatten();
    let (kind, name) = match row {
        Some((entity_type, _, body)) => (Some(kind_name(entity_type)), entity_name(&body)),
        None => (None, None),
    };
    Ok(serde_json::json!({
        "ref": id.to_hex(),
        "kind": kind,
        "name": name,
    }))
}

/// An entity body's `name`, when it carries one.
fn entity_name(body: &[u8]) -> Option<String> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    let name = field(&value, "name")?.as_str()?.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

/// The claim one judge call is about: its logical head, the revision read,
/// its subject as the Dreamer reads it, and its body.
struct ClaimView<'a> {
    head: EntityId,
    revision: &'a str,
    subject: serde_json::Value,
    body: &'a ClaimBody,
}

/// What the judge reads about one claim: the claim as it stands, by its
/// head, revision and subject, so no two claims share a request; the
/// message the provider deleted; and every support as it stands now.
fn judge_input(
    declaration: &ClaimSourceRecheckDeclaration,
    deleted_at: u64,
    claim: ClaimView<'_>,
    supports: Vec<serde_json::Value>,
) -> serde_json::Value {
    let body = claim.body;
    serde_json::json!({
        "claim": {
            "ref": claim.head.to_hex(),
            "revision": claim.revision,
            "subject": claim.subject,
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
