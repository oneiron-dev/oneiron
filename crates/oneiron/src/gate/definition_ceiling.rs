use crate::agent_def::decode_agent_definition;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::store::Store;
use crate::write_envelope::WriteActor;

use super::ceiling::PolicyApprovalCeiling;
use super::constants::FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID;

pub(crate) fn first_party_eiri_connector_actor_ref() -> String {
    bytes_to_hex_lower(&FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID)
}

/// Resolves the AGENT_DEF-authored ceiling bound for a write actor, live at
/// evaluation time (D11: authority is never read from dispatch snapshots).
///
/// * non-`Agent` actor class → `None` (no definition bound);
/// * entity ABSENT → `Some(Proposed)` — deletion fails closed (B3 resolution
///   2026-07-10: a deleted Herald fork's definition can no longer drop its
///   Proposed self-limit);
/// * present but not type-17 → `None` (live person-backed agent actors keep
///   today's semantics);
/// * decoded definition → its ceiling restricted by the fork parent ROW's
///   stored ceiling, fail-closed (an unresolvable parent row clamps to
///   Proposed);
/// * unreadable/undecodable body → `Some(Proposed)` with a `tracing::warn!`
///   naming the actor entity id — the fail-closed re-clamp of a believed-Auto
///   agent must not be silent.
pub(crate) fn agent_definition_ceiling_for_actor(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
) -> Option<PolicyApprovalCeiling> {
    if actor.actor_class() != EdgeActorClass::Agent {
        return None;
    }
    match agent_bearing_for_entity(store, txn, actor.entity_ref()) {
        AgentBearing::Bound(ceiling) => Some(ceiling),
        // B3: a deleted definition can no longer drop its self-limit.
        AgentBearing::Absent => Some(PolicyApprovalCeiling::Proposed),
        // Live person-backed agent actors keep today's semantics.
        AgentBearing::NonAgent => None,
    }
}

/// How a governing entity id relates to the AGENT_DEF authority lattice.
/// Derived from the STORED ENTITY, never from a caller-asserted actor class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentBearing {
    /// The id holds a stored type-17 AGENT_DEF (or a fail-closed variant of
    /// one): it carries a definition ceiling.
    Bound(PolicyApprovalCeiling),
    /// No entity is stored at the id.
    Absent,
    /// An entity is stored, but it is not agent-bearing (non-type-17).
    NonAgent,
}

/// Classifies a governing entity id from stored state — READ-ONLY, and from
/// the ROW alone: no compiled table confers authority on any id, so a pinned
/// system-agent actor id classifies exactly like any other id (no row →
/// `Absent`, which both consumers map to `Proposed`). Read failures resolve
/// fail-closed to `Bound(Proposed)`.
fn agent_bearing_for_entity(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity_ref: EntityId,
) -> AgentBearing {
    let raw = match store.entities.get(txn, entity_ref.as_bytes()) {
        Ok(Some(raw)) => raw,
        Ok(None) => return AgentBearing::Absent,
        Err(error) => {
            tracing::warn!(
                actor_entity_id = %entity_ref.to_hex(),
                %error,
                "agent definition ceiling read failed; failing closed to proposed",
            );
            return AgentBearing::Bound(PolicyApprovalCeiling::Proposed);
        }
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        tracing::warn!(
            actor_entity_id = %entity_ref.to_hex(),
            "agent definition entity header failed to parse; failing closed to proposed",
        );
        return AgentBearing::Bound(PolicyApprovalCeiling::Proposed);
    };
    if header.entity_type != ENTITY_TYPE_AGENT_DEF {
        return AgentBearing::NonAgent;
    }
    match decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..]) {
        Ok(def) => {
            let mut ceiling = PolicyApprovalCeiling::from_agent_ceiling(def.ceiling);
            if let Some(parent_ref) = &def.forked_from {
                let parent_id = crate::agent_def::forked_from_row_ref(parent_ref);
                // GATE-HALF: the clamp reads the PARENT ROW's stored ceiling,
                // never a compiled table. Absent/undecodable/non-AGENT_DEF
                // parent fails closed.
                ceiling = ceiling.restrict(parent_row_ceiling(store, txn, &parent_id));
            }
            AgentBearing::Bound(ceiling)
        }
        Err(error) => {
            tracing::warn!(
                actor_entity_id = %entity_ref.to_hex(),
                %error,
                "agent definition body failed to decode; failing closed to proposed",
            );
            AgentBearing::Bound(PolicyApprovalCeiling::Proposed)
        }
    }
}

/// The no-widen bound a forked definition inherits: the stored `ceiling` of
/// the PARENT's own AGENT_DEF row (GATE-HALF — data over rows, never a
/// compiled preset table). Every arm that cannot READ a parent ceiling —
/// unreadable store, missing row, unparsable header, non-type-17, undecodable
/// body — warns and clamps to `Proposed`, so an unresolvable lineage can never
/// leave a fork wider than its parent.
fn parent_row_ceiling(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    parent_id: &EntityId,
) -> PolicyApprovalCeiling {
    let raw = match store.entities.get(txn, parent_id.as_bytes()) {
        Ok(Some(raw)) => raw,
        Ok(None) => {
            tracing::warn!(
                parent_entity_id = %parent_id.to_hex(),
                "fork parent definition row is absent; failing closed to proposed",
            );
            return PolicyApprovalCeiling::Proposed;
        }
        Err(error) => {
            tracing::warn!(
                parent_entity_id = %parent_id.to_hex(),
                %error,
                "fork parent definition read failed; failing closed to proposed",
            );
            return PolicyApprovalCeiling::Proposed;
        }
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        tracing::warn!(
            parent_entity_id = %parent_id.to_hex(),
            "fork parent entity header failed to parse; failing closed to proposed",
        );
        return PolicyApprovalCeiling::Proposed;
    };
    if header.entity_type != ENTITY_TYPE_AGENT_DEF {
        tracing::warn!(
            parent_entity_id = %parent_id.to_hex(),
            entity_type = header.entity_type,
            "fork parent entity is not an agent definition; failing closed to proposed",
        );
        return PolicyApprovalCeiling::Proposed;
    }
    match decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..]) {
        Ok(parent) => PolicyApprovalCeiling::from_agent_ceiling(parent.ceiling),
        Err(error) => {
            tracing::warn!(
                parent_entity_id = %parent_id.to_hex(),
                %error,
                "fork parent definition body failed to decode; failing closed to proposed",
            );
            PolicyApprovalCeiling::Proposed
        }
    }
}

/// The actor classes the gate recognizes as NON-agent effect principals.
/// Anything outside this set (and outside `"agent"`) is an unrecognized
/// assertion and resolves fail-closed.
const NON_AGENT_EFFECT_ACTOR_CLASSES: [&str; 3] = ["human", "system", "first_party"];

/// Resolves the definition ceiling for an EXTERNAL-EFFECT actor.
///
/// Effect inputs are the one gate door whose actor identity is fully
/// caller-asserted — `actor_class` (a free string), `actor_ref` (what the
/// manifest rows and scoped grants key on) and `provenance.actor_entity_ref`
/// (the audited identity) are three independent fields. Three hardenings:
///
/// * IDENTITY BINDING (F1/F2): `actor_ref` and `actor_entity_ref` must name
///   ONE governing identity before any authority is derived — otherwise a
///   Proposed-ceiling agent could pair its own provenance with an Auto
///   identity's ref. Mismatched or unparsable pairs fail closed to Proposed.
/// * ENTITY-TYPE-WINS (class-spoof): the ceiling is derived from what the
///   governing entity IS, not from the class the caller asserts. A stored
///   AGENT_DEF is clamped under ANY class string.
/// * CLASS FAIL-CLOSED (class-spoof): a class that is neither `"agent"` nor a
///   recognized non-agent principal — unknown, empty, or absent — resolves to
///   Proposed rather than skipping the clamp. Comparison is case-normalized,
///   so `"Agent"`/`"AGENT"` cannot dodge the agent path.
///
/// (The claim and edge-provenance doors derive both identity fields from a
/// single `WriteActor`/record and validate the class against the actor
/// entity's kind, so they are bound by construction.)
pub(super) fn agent_definition_ceiling_for_effect_actor(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor_class: &str,
    actor_ref: Option<&str>,
    actor_entity_ref: Option<EntityId>,
) -> Option<PolicyApprovalCeiling> {
    let normalized_class = actor_class.trim().to_ascii_lowercase();
    let recognized_non_agent = NON_AGENT_EFFECT_ACTOR_CLASSES.contains(&normalized_class.as_str());
    let asserts_agent = normalized_class == "agent";

    // Without an audited identity the gate denies the effect outright
    // (DenyMissingActorProvenance). Resolve fail-closed anyway unless the
    // caller asserts a recognized non-agent principal, so no path derives
    // authority from an unaudited ref.
    let Some(governing) = actor_entity_ref else {
        return if recognized_non_agent {
            None
        } else {
            Some(PolicyApprovalCeiling::Proposed)
        };
    };
    if let Some(actor_ref) = actor_ref {
        match EntityId::from_hex(actor_ref) {
            // An entity-shaped ref MUST name the audited identity, whatever
            // class is asserted: the manifest keys Auto on `actor_ref` while
            // the clamp keys on the audited entity, so an unbound pair lets a
            // Proposed agent borrow an Auto identity's grant.
            Ok(ref_id) if ref_id != governing => {
                tracing::warn!(
                    actor_ref,
                    actor_entity_ref = %governing.to_hex(),
                    "effect actor_ref does not match actor_entity_ref; \
                     failing closed to proposed",
                );
                return Some(PolicyApprovalCeiling::Proposed);
            }
            Ok(_) => {}
            // An opaque principal name. Only recognized non-agent principals
            // key manifest rows by name; an agent's actor_ref is always the
            // hex entity id, so a non-hex ref under an agent (or unrecognized)
            // class is an unbindable assertion.
            Err(_) if !recognized_non_agent => {
                tracing::warn!(
                    actor_ref,
                    actor_entity_ref = %governing.to_hex(),
                    "effect actor_ref is not an entity id under a non-principal class; \
                     failing closed to proposed",
                );
                return Some(PolicyApprovalCeiling::Proposed);
            }
            Err(_) => {}
        }
    }

    match agent_bearing_for_entity(store, txn, governing) {
        // Entity-type-wins: an agent-bearing identity is clamped regardless of
        // the class the caller asserted.
        AgentBearing::Bound(ceiling) => Some(ceiling),
        AgentBearing::Absent => {
            if recognized_non_agent {
                // A connector/human/system principal whose entity is not
                // stored keeps today's semantics.
                None
            } else {
                // B3 for asserted agents; fail-closed for unrecognized classes.
                Some(PolicyApprovalCeiling::Proposed)
            }
        }
        AgentBearing::NonAgent => {
            if asserts_agent || recognized_non_agent {
                None
            } else {
                tracing::warn!(
                    actor_class,
                    actor_entity_ref = %governing.to_hex(),
                    "effect actor asserts an unrecognized class; \
                     failing closed to proposed",
                );
                Some(PolicyApprovalCeiling::Proposed)
            }
        }
    }
}
