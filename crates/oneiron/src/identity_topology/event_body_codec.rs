//! The low-level MessagePack field codec for the type-76 event body, plus the
//! stateless admission checks every door — local and replicated alike — runs
//! during decode.

use std::collections::BTreeMap;

use rmpv::Value;

use crate::claim::ClaimApprovalStatus;
use crate::edge::EdgeActorClass;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;

use super::ledger_fold::IdentityTopologyAction;
use super::op_apply::is_effective_approval;
use super::op_vocabulary::{IdentityOpEvidence, IdentityTopologyOp};
use super::proposal_resolution::{decode_amendable_kind, validate_resolution_scope_stateless};
use super::reassignment_map::{decode_reassignment_map, encode_reassignment_map};
use super::stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};
use super::transition_table::{ProposalOutcome, ProposalScope, evaluate_transition};
use super::wire_keys::{
    BODY_KEY_ACTOR, BODY_KEY_ACTOR_CLASS, BODY_KEY_AMENDED, BODY_KEY_APPLIED_ASSIGNED,
    BODY_KEY_APPLIED_RESIDUE, BODY_KEY_CLAIM, BODY_KEY_ENTITY, BODY_KEY_FACETS, BODY_KEY_HEADS,
    BODY_KEY_MAP, BODY_KEY_OUTCOME, BODY_KEY_PAIR_A, BODY_KEY_PAIR_B, BODY_KEY_PLAN,
    BODY_KEY_PROPOSAL, BODY_KEY_SCOPE_ACTOR, BODY_KEY_SCOPE_OP_KIND, BODY_KEY_SCOPE_TARGET_CLASS,
    BODY_KEY_SOURCES, BODY_KEY_SURVIVOR, BODY_KEY_TARGET, EVENT_KIND_ASSERT_DISTINCT,
    EVENT_KIND_FACET, EVENT_KIND_MERGE, EVENT_KIND_PROPOSAL_RESOLUTION, EVENT_KIND_SPLIT,
    EVENT_KIND_UNDO, EVIDENCE_KEY_RATIONALE, EVIDENCE_KEY_REFS,
    IDENTITY_TOPOLOGY_REPLICATED_SEQ_LIMIT, PLAN_READ_THROUGH,
};
use super::{
    IDENTITY_TOPOLOGY_REPLICATED_SEQ_CEILING, MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES,
    MAX_IDENTITY_TOPOLOGY_EVENT_FACETS, MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS,
};

/// Appends one action's pinned wire entries. Shared by the ledger event
/// body and the amendment codec so an amended op can only ever carry a
/// shape the ledger itself stores — ONE encoder, no second dialect.
pub(super) fn encode_action_entries(
    action: &StoredIdentityOpAction,
    entries: &mut Vec<(Value, Value)>,
) {
    match action {
        StoredIdentityOpAction::Merge { sources, survivor } => {
            entries.push((Value::from(BODY_KEY_SOURCES), ids_value(sources)));
            entries.push((Value::from(BODY_KEY_SURVIVOR), id_value(survivor)));
            entries.push((Value::from(BODY_KEY_PLAN), Value::from(PLAN_READ_THROUGH)));
        }
        StoredIdentityOpAction::Split {
            entity,
            heads,
            reassignment,
            applied_assigned,
            applied_residue,
        } => {
            entries.push((Value::from(BODY_KEY_ENTITY), id_value(entity)));
            entries.push((Value::from(BODY_KEY_HEADS), ids_value(heads)));
            entries.push((
                Value::from(BODY_KEY_MAP),
                encode_reassignment_map(reassignment),
            ));
            encode_applied_counts(*applied_assigned, *applied_residue, entries);
        }
        StoredIdentityOpAction::Facet {
            entity,
            facets,
            reassignment,
            applied_assigned,
            applied_residue,
        } => {
            entries.push((Value::from(BODY_KEY_ENTITY), id_value(entity)));
            entries.push((Value::from(BODY_KEY_FACETS), ids_value(facets)));
            entries.push((
                Value::from(BODY_KEY_MAP),
                encode_reassignment_map(reassignment),
            ));
            encode_applied_counts(*applied_assigned, *applied_residue, entries);
        }
        StoredIdentityOpAction::AssertDistinct { a, b, claim } => {
            entries.push((Value::from(BODY_KEY_PAIR_A), id_value(a)));
            entries.push((Value::from(BODY_KEY_PAIR_B), id_value(b)));
            entries.push((Value::from(BODY_KEY_CLAIM), id_value(claim)));
        }
        StoredIdentityOpAction::Undo { target } => {
            entries.push((Value::from(BODY_KEY_TARGET), id_value(target)));
        }
        StoredIdentityOpAction::ProposalResolution {
            proposal,
            outcome,
            scope,
            amended_body,
        } => {
            entries.push((Value::from(BODY_KEY_PROPOSAL), id_value(proposal)));
            entries.push((Value::from(BODY_KEY_OUTCOME), Value::from(outcome.as_str())));
            entries.push((
                Value::from(BODY_KEY_SCOPE_OP_KIND),
                Value::from(scope.op_kind),
            ));
            entries.push((
                Value::from(BODY_KEY_SCOPE_TARGET_CLASS),
                Value::from(scope.target_class.as_str()),
            ));
            entries.push((
                Value::from(BODY_KEY_SCOPE_ACTOR),
                Value::from(scope.actor.as_str()),
            ));
            if let Some(amended_body) = amended_body {
                entries.push((
                    Value::from(BODY_KEY_AMENDED),
                    Value::Binary(amended_body.clone()),
                ));
            }
        }
    }
}

/// Appends the ONE-1745 applied-count entries, OMITTING zeros.
///
/// The omission is load-bearing, not cosmetic: [`decode_identity_op_amendment`](super::decode_identity_op_amendment)
/// and the replicated-body door both demand a byte-exact re-encode, so an
/// event carrying no applied rows — a parked split, an amendment body — must
/// encode to exactly the bytes those shapes encoded to before this ticket.
fn encode_applied_counts(assigned: u64, residue: u64, entries: &mut Vec<(Value, Value)>) {
    if assigned != 0 {
        entries.push((
            Value::from(BODY_KEY_APPLIED_ASSIGNED),
            Value::from(assigned),
        ));
    }
    if residue != 0 {
        entries.push((Value::from(BODY_KEY_APPLIED_RESIDUE), Value::from(residue)));
    }
}

/// The [`encode_applied_counts`] inverse: an absent key is zero, a present
/// key must be a `u64` (a malformed one is a body rejection, never a
/// silently-zeroed count).
fn decode_applied_counts(map: &[(Value, Value)]) -> Result<(u64, u64)> {
    let count = |key: &'static str| match map_field(map, key) {
        None => Ok(0),
        Some(value) => value
            .as_u64()
            .ok_or(Error::InvalidIdentityTopologyEventBody(
                "identity topology event applied count",
            )),
    };
    Ok((
        count(BODY_KEY_APPLIED_ASSIGNED)?,
        count(BODY_KEY_APPLIED_RESIDUE)?,
    ))
}

/// Decodes one action from its wire entries — the [`encode_action_entries`]
/// inverse, shared by the ledger event body and the amendment codec.
pub(super) fn decode_action(kind: &str, map: &[(Value, Value)]) -> Result<StoredIdentityOpAction> {
    match kind {
        EVENT_KIND_MERGE => {
            let plan = decode_str_field(map, BODY_KEY_PLAN, "identity topology event plan")?;
            if plan != PLAN_READ_THROUGH {
                return Err(Error::InvalidIdentityTopologyEventBody(
                    "identity topology event plan is unknown",
                ));
            }
            Ok(StoredIdentityOpAction::Merge {
                sources: decode_ids_field(
                    map,
                    BODY_KEY_SOURCES,
                    "identity topology event sources",
                )?,
                survivor: decode_id_field(
                    map,
                    BODY_KEY_SURVIVOR,
                    "identity topology event survivor",
                )?,
            })
        }
        EVENT_KIND_SPLIT => {
            let (applied_assigned, applied_residue) = decode_applied_counts(map)?;
            Ok(StoredIdentityOpAction::Split {
                entity: decode_id_field(map, BODY_KEY_ENTITY, "identity topology event entity")?,
                heads: decode_ids_field(map, BODY_KEY_HEADS, "identity topology event heads")?,
                reassignment: decode_reassignment_map(map_field(map, BODY_KEY_MAP).ok_or(
                    Error::InvalidIdentityTopologyEventBody("identity topology event map"),
                )?)?,
                applied_assigned,
                applied_residue,
            })
        }
        EVENT_KIND_FACET => {
            let (applied_assigned, applied_residue) = decode_applied_counts(map)?;
            Ok(StoredIdentityOpAction::Facet {
                entity: decode_id_field(map, BODY_KEY_ENTITY, "identity topology event entity")?,
                facets: decode_ids_field(map, BODY_KEY_FACETS, "identity topology event facets")?,
                reassignment: decode_reassignment_map(map_field(map, BODY_KEY_MAP).ok_or(
                    Error::InvalidIdentityTopologyEventBody("identity topology event map"),
                )?)?,
                applied_assigned,
                applied_residue,
            })
        }
        EVENT_KIND_ASSERT_DISTINCT => {
            const PAIR_CONTEXT: &str = "identity topology assert_distinct pair";
            let a = decode_id_field(map, BODY_KEY_PAIR_A, PAIR_CONTEXT)?;
            let b = decode_id_field(map, BODY_KEY_PAIR_B, PAIR_CONTEXT)?;
            // The stored pair is NORMALIZED, so a descending or self-paired
            // row is malformed rather than a second spelling of one pair.
            if a >= b {
                return Err(Error::InvalidIdentityTopologyEventBody(PAIR_CONTEXT));
            }
            Ok(StoredIdentityOpAction::AssertDistinct {
                a,
                b,
                claim: decode_id_field(
                    map,
                    BODY_KEY_CLAIM,
                    "identity topology assert_distinct claim",
                )?,
            })
        }
        EVENT_KIND_UNDO => Ok(StoredIdentityOpAction::Undo {
            target: decode_id_field(map, BODY_KEY_TARGET, "identity topology event target")?,
        }),
        EVENT_KIND_PROPOSAL_RESOLUTION => {
            const RESOLUTION_CONTEXT: &str = "identity topology proposal resolution";
            let outcome = ProposalOutcome::parse(decode_str_field(
                map,
                BODY_KEY_OUTCOME,
                "identity topology event outcome",
            )?)
            .ok_or(Error::InvalidIdentityTopologyEventBody(
                "identity topology event outcome",
            ))?;
            let amended_body = match map_field(map, BODY_KEY_AMENDED) {
                None => None,
                Some(value) => Some(
                    value
                        .as_slice()
                        .ok_or(Error::InvalidIdentityTopologyEventBody(RESOLUTION_CONTEXT))?
                        .to_vec(),
                ),
            };
            // The amended body is present EXACTLY on the amended outcome:
            // bytes under any other outcome would contradict the receipt
            // contract (payload iff `approved_amended`), and an amended
            // outcome without them would lose the producer artifact ED-01
            // reads.
            if amended_body.is_some() != (outcome == ProposalOutcome::ApprovedAmended) {
                return Err(Error::InvalidIdentityTopologyEventBody(
                    "identity topology proposal resolution amended body must accompany \
                     exactly the amended outcome",
                ));
            }
            Ok(StoredIdentityOpAction::ProposalResolution {
                proposal: decode_id_field(map, BODY_KEY_PROPOSAL, RESOLUTION_CONTEXT)?,
                outcome,
                scope: ProposalScope {
                    op_kind: decode_amendable_kind(decode_str_field(
                        map,
                        BODY_KEY_SCOPE_OP_KIND,
                        RESOLUTION_CONTEXT,
                    )?)?,
                    target_class: decode_str_field(
                        map,
                        BODY_KEY_SCOPE_TARGET_CLASS,
                        RESOLUTION_CONTEXT,
                    )?
                    .to_owned(),
                    actor: decode_str_field(map, BODY_KEY_SCOPE_ACTOR, RESOLUTION_CONTEXT)?
                        .to_owned(),
                },
                amended_body,
            })
        }
        _ => Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event kind is unknown",
        )),
    }
}

/// Encodes a type-76 record body to its pinned MessagePack bytes.
pub(crate) fn encode_identity_topology_event_body(
    record: &StoredIdentityOpEvent,
) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &record.encode_value()).map_err(|_| {
        Error::InvalidIdentityTopologyEventBody("identity topology event encode failed")
    })?;
    Ok(data)
}

/// Decodes a type-76 record body from its pinned MessagePack bytes,
/// fail-closed on trailing bytes or any malformed field.
pub(crate) fn decode_identity_topology_event_body(data: &[u8]) -> Result<StoredIdentityOpEvent> {
    if data.len() > MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event body exceeds the size limit",
        ));
    }
    let mut cursor = data;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::InvalidIdentityTopologyEventBody("identity topology event bytes are malformed")
    })?;
    if !cursor.is_empty() {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event carries trailing bytes",
        ));
    }
    let record = StoredIdentityOpEvent::decode_value(&value)?;
    if encode_identity_topology_event_body(&record)? != data {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event body is not canonical",
        ));
    }
    validate_identity_topology_event_stateless(&record)?;
    Ok(record)
}

/// Timeless replicated-record admission checks. These are exactly the
/// invariants a local door can enforce without consulting lifecycle state:
/// sequence/consent legality, bounded fan-out, and operation shape. They run
/// during body decode, before quota, storage, clock join, or reconciliation.
fn validate_identity_topology_event_stateless(record: &StoredIdentityOpEvent) -> Result<()> {
    if record.seq == 0 {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event seq must be nonzero",
        ));
    }
    if record.seq >= IDENTITY_TOPOLOGY_REPLICATED_SEQ_CEILING {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event seq is in the reserved terminal range",
        ));
    }
    if record.approval == ClaimApprovalStatus::Rejected {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "rejected identity topology decisions are not stored",
        ));
    }
    validate_resolution_scope_stateless(record)?;
    let effective = is_effective_approval(record.approval);

    // ONE-1745: the applied counts are an AUDIT record of what a door
    // recorded, and the receipt projects them verbatim — so they are BOUNDED
    // here, on the one path every admitting door runs, rather than trusted
    // from the wire. Two bounds, both derivable from the record alone:
    // a parked event applied nothing, and an applied row can only ever be a
    // SUBSET of the map's own declaration in its own class (a row naming an
    // item this vault holds no claim for records nothing, and the resolver
    // never reclassifies a row between assigned and residue).
    if let (Some(applied), Some(map)) = (
        record.action.applied_reassignment_stats(),
        record.action.reassignment_map(),
    ) {
        if !effective && (applied.assigned != 0 || applied.residue != 0) {
            return Err(Error::InvalidIdentityTopologyEventBody(
                "parked identity topology event declares applied reassignment rows",
            ));
        }
        let (declared_assigned, declared_residue) = map.assigned_and_residue_counts();
        if applied.assigned as u64 > declared_assigned || applied.residue as u64 > declared_residue
        {
            return Err(Error::InvalidIdentityTopologyEventBody(
                "identity topology event applied counts exceed its reassignment map",
            ));
        }
    }

    let IdentityTopologyAction::Apply(op) = record.action.to_fold_action() else {
        return Ok(());
    };
    if op.participants().len() > MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event has too many participants",
        ));
    }
    if let IdentityTopologyOp::Facet(facet) = &op {
        // A facet op names ONE participant however many masks it mints, so
        // the participant bound above does not reach its fan-out. Bound it
        // here, on the same stateless path every admitting door runs.
        if facet.facets.len() > MAX_IDENTITY_TOPOLOGY_EVENT_FACETS {
            return Err(Error::InvalidIdentityTopologyEventBody(
                "identity topology event mints too many facets",
            ));
        }
        // A facet op has NO propose lane, and the SAME rule has to hold at
        // both doors. The local door refuses to record a park
        // ([`Vault::apply_identity_topology_op_in_txn`]) because a parked
        // facet mints nothing yet must name its masks, and
        // [`proposal_scope_target`] has no scope target for a facet — so a
        // park that DID get written could never be ruled on. Admitting one
        // from a peer would persist exactly the unresolvable orphan the
        // local path calls corruption.
        if !effective {
            return Err(Error::InvalidIdentityTopologyEventBody(
                "facet identity topology decisions have no propose lane",
            ));
        }
    }
    evaluate_transition(&BTreeMap::new(), &op).map_err(|_| {
        Error::InvalidIdentityTopologyEventBody(
            "identity topology event operation shape is invalid",
        )
    })?;
    Ok(())
}

pub(super) fn validate_replicated_identity_topology_seq(seq: u64) -> Result<()> {
    if seq >= IDENTITY_TOPOLOGY_REPLICATED_SEQ_LIMIT {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event seq is in the reserved terminal range",
        ));
    }
    Ok(())
}

/// D18 body validator for the type-76 maintenance kind, run at the shared
/// write chokepoint on every path that can admit the byte (engine door and
/// sync replay alike).
pub(crate) fn validate_identity_topology_event_body_bytes(data: &[u8]) -> Result<()> {
    decode_identity_topology_event_body(data).map(|_| ())
}

/// Decodes the deterministic body predicate shared by every replicated
/// type-76 ingress decision. Local authoring may consume the retained
/// headroom; replicated bodies must additionally leave it intact.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn decode_replicated_identity_topology_event_body(
    data: &[u8],
) -> Result<StoredIdentityOpEvent> {
    let record = decode_identity_topology_event_body(data)?;
    validate_replicated_identity_topology_seq(record.seq)?;
    Ok(record)
}

pub(super) fn id_value(id: &EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

pub(super) fn ids_value(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().map(id_value).collect())
}

pub(super) fn decode_evidence(value: &Value) -> Result<IdentityOpEvidence> {
    const EVIDENCE_CONTEXT: &str = "identity topology event evidence";
    let map = value
        .as_map()
        .ok_or(Error::InvalidIdentityTopologyEventBody(EVIDENCE_CONTEXT))?;
    let refs = decode_ids_field(map, EVIDENCE_KEY_REFS, EVIDENCE_CONTEXT)?;
    let rationale = decode_str_field(map, EVIDENCE_KEY_RATIONALE, EVIDENCE_CONTEXT)?.to_owned();
    Ok(IdentityOpEvidence { refs, rationale })
}

pub(super) fn map_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .map(|(_, entry_value)| entry_value)
}

pub(super) fn decode_str_field<'a>(
    map: &'a [(Value, Value)],
    key: &str,
    context: &'static str,
) -> Result<&'a str> {
    map_field(map, key)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidIdentityTopologyEventBody(context))
}

pub(super) fn decode_u64_field(
    map: &[(Value, Value)],
    key: &str,
    context: &'static str,
) -> Result<u64> {
    map_field(map, key)
        .and_then(Value::as_u64)
        .ok_or(Error::InvalidIdentityTopologyEventBody(context))
}

pub(super) fn decode_id_bytes(bytes: &[u8], context: &'static str) -> Result<EntityId> {
    let arr: [u8; ENTITY_ID_LEN] = bytes
        .try_into()
        .map_err(|_| Error::InvalidIdentityTopologyEventBody(context))?;
    EntityId::from_bytes(arr).map_err(|_| Error::InvalidIdentityTopologyEventBody(context))
}

pub(super) fn decode_id_value(value: &Value, context: &'static str) -> Result<EntityId> {
    decode_id_bytes(
        value
            .as_slice()
            .ok_or(Error::InvalidIdentityTopologyEventBody(context))?,
        context,
    )
}

fn decode_id_field(map: &[(Value, Value)], key: &str, context: &'static str) -> Result<EntityId> {
    decode_id_value(
        map_field(map, key).ok_or(Error::InvalidIdentityTopologyEventBody(context))?,
        context,
    )
}

fn decode_ids_field(
    map: &[(Value, Value)],
    key: &str,
    context: &'static str,
) -> Result<Vec<EntityId>> {
    let Some(Value::Array(items)) = map_field(map, key) else {
        return Err(Error::InvalidIdentityTopologyEventBody(context));
    };
    items
        .iter()
        .map(|item| decode_id_value(item, context))
        .collect()
}

pub(super) fn decode_actor(map: &[(Value, Value)]) -> Result<Option<WriteActor>> {
    let entity = map_field(map, BODY_KEY_ACTOR);
    let class = map_field(map, BODY_KEY_ACTOR_CLASS);
    match (entity, class) {
        (None, None) => Ok(None),
        (Some(entity), Some(class)) => {
            let entity_ref = decode_id_value(entity, "identity topology event actor")?;
            let class = class.as_str().and_then(parse_actor_class).ok_or(
                Error::InvalidIdentityTopologyEventBody("identity topology event actor class"),
            )?;
            Ok(Some(WriteActor::new(entity_ref, class)))
        }
        _ => Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event actor requires both entity and class",
        )),
    }
}

fn parse_actor_class(value: &str) -> Option<EdgeActorClass> {
    match value {
        "human" => Some(EdgeActorClass::Human),
        "agent" => Some(EdgeActorClass::Agent),
        "system" => Some(EdgeActorClass::System),
        _ => None,
    }
}
