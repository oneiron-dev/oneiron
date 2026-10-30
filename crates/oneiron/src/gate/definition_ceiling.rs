use std::collections::BTreeMap;

use crate::agent_def::{AgentDefinition, decode_agent_definition};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::store::Store;
use crate::write_envelope::WriteActor;

use super::ceiling::PolicyApprovalCeiling;
use super::constants::{FIRST_PARTY_CONNECTOR_ACTOR_ID, MAX_DELEGATION_DEPTH};

pub(crate) fn first_party_connector_actor_ref() -> String {
    bytes_to_hex_lower(&FIRST_PARTY_CONNECTOR_ACTOR_ID)
}

/// Resolves the AGENT_DEF-authored ceiling bound for a write actor, live at
/// evaluation time (D11: authority is never read from dispatch snapshots).
///
/// * non-`Agent` actor class → `None` (no definition bound);
/// * entity ABSENT → `Some(Proposed)` — deletion fails closed (B3 resolution
///   2026-07-10: a deleted Herald fork's definition can no longer drop its
///   Proposed self-limit);
/// * present but not type-17 → `None` (live person-backed agent actors keep
///   today's semantics), except at an agent id (H215: pinned, or a seeded
///   row's), whose bound no other row there lifts → `Some(Proposed)`;
/// * decoded definition → its ceiling restricted by the fork parent ROW's
///   stored ceiling, fail-closed (an unresolvable parent row clamps to
///   Proposed); a definition that is no longer Active, approved and enabled
///   holds its actor at Proposed (H147: dispatch admitted it once, but a
///   running job answers to the row as it stands now);
/// * unreadable/undecodable body → `Some(Proposed)` with a `tracing::warn!`
///   naming the actor entity id — the fail-closed re-clamp of a believed-Auto
///   agent must not be silent.
pub(crate) fn agent_definition_ceiling_for_actor(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
) -> Option<PolicyApprovalCeiling> {
    let definition = definition_only_ceiling_for_actor(store, txn, actor);
    let foreign = super::foreign_agent::resolve(store, txn, actor)
        .unwrap_or(Some(PolicyApprovalCeiling::Proposed));
    match (definition, foreign) {
        (Some(a), Some(b)) => Some(a.restrict(b)),
        (a, b) => a.or(b),
    }
}

/// The delegation ancestor whose live bound no longer allows a delegated
/// child's write (FIX 10537): its agent-dispatch attempt and its AGENT_DEF
/// row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DelegationNarrowing {
    /// The ancestor's agent-dispatch attempt.
    pub(crate) attempt: AttemptId,
    /// The ancestor's AGENT_DEF row, whose live bound narrowed the write.
    pub(crate) agent: EntityId,
}

/// The ancestor that narrows `actor`'s write, read live in `txn` (FIX 10537,
/// Engine 09:24 and 10:43). It reads only an agent bound to the attempt
/// whose run writes ([`WriteActor::run_attempt`]), where that attempt
/// dispatched the agent's own row unforked: up its delegation chain, with
/// the reads dispatch's own chain walk takes, it names the nearest ancestor
/// whose live bound ([`agent_definition_ceiling_for_actor`]) is `Proposed`.
/// A chain that comes back on itself proves no grant and narrows at the
/// attempt it came back to. `None`: no agent bound to a run; a child forked
/// at dispatch, which keeps its row's clamp; no agent parent, which keeps
/// today's Auto; or a chain every ancestor of which still allows the write.
/// The walk reads at most [`MAX_DELEGATION_DEPTH`] ancestors and past them
/// stops, never refusing on a count (rule 5). A read that fails narrows, as
/// every read of this resolver fails closed.
pub(crate) fn delegation_chain_narrowing(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
) -> Option<DelegationNarrowing> {
    if actor.actor_class() != EdgeActorClass::Agent {
        return None;
    }
    let child = AttemptId::from_bytes(&actor.run_attempt()?).ok()?;
    let queue = AttemptQueue::from_store(store);
    let mut row = match queue.get_in_txn(txn, child) {
        Ok(row) => row?,
        Err(error) => return chain_read_failed(child, actor.entity_ref(), &error),
    };
    // The attempt binds only the run that dispatched this actor's own row.
    if dispatch_target(&row) != Some(actor.entity_ref()) {
        return None;
    }
    match crate::agent_def::delegation_parent_in_txn(store, txn, &actor.entity_ref()) {
        Ok(None) => {}
        Ok(Some(_)) => return None,
        Err(error) => return chain_read_failed(child, actor.entity_ref(), &error),
    }
    let mut seen = BTreeMap::from([(child, actor.entity_ref())]);
    let mut target = actor.entity_ref();
    for _ in 0..MAX_DELEGATION_DEPTH {
        let parent =
            match crate::agent_dispatch::delegation_lineage_parent_in_txn(store, txn, &row, target)
            {
                Ok(parent) => parent?,
                Err(error) => return chain_read_failed(row.id, target, &error),
            };
        if let Some(&agent) = seen.get(&parent) {
            return Some(DelegationNarrowing {
                attempt: parent,
                agent,
            });
        }
        row = match queue.get_in_txn(txn, parent) {
            Ok(row) => row?,
            Err(error) => return chain_read_failed(parent, target, &error),
        };
        target = dispatch_target(&row)?;
        seen.insert(parent, target);
        let live = agent_definition_ceiling_for_actor(
            store,
            txn,
            WriteActor::new(target, EdgeActorClass::Agent),
        );
        if live == Some(PolicyApprovalCeiling::Proposed) {
            return Some(DelegationNarrowing {
                attempt: parent,
                agent: target,
            });
        }
    }
    tracing::info!(
        actor_entity_id = %actor.entity_ref().to_hex(),
        read = MAX_DELEGATION_DEPTH,
        "a delegated write's chain goes past the ancestors the gate reads; the rest are not read",
    );
    None
}

/// The AGENT_DEF row `row`'s agent dispatch targets, `None` for a row that
/// is no agent dispatch.
fn dispatch_target(row: &AttemptRecord) -> Option<EntityId> {
    crate::agent_dispatch::record_dispatch_input(row)
        .and_then(|input| input.target.agent_definition_ref().ok())
}

/// A delegation-chain read that failed narrows at the attempt it read.
fn chain_read_failed(
    attempt: AttemptId,
    agent: EntityId,
    error: &crate::error::Error,
) -> Option<DelegationNarrowing> {
    tracing::warn!(
        actor_entity_id = %agent.to_hex(),
        %error,
        "delegation chain read failed; failing closed to proposed",
    );
    Some(DelegationNarrowing { attempt, agent })
}

/// The bound an agent actor's own stored definition puts on its writes: its
/// ceiling, restricted by its fork parent row's; `Proposed` for a definition
/// that is absent or does not read; `None` for a non-agent actor or an entity
/// that is not a definition. The effect door reads this alone, and
/// [`agent_definition_ceiling_for_actor`] folds it with the foreign chain.
pub(crate) fn definition_only_ceiling_for_actor(
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

/// `Bound(Proposed)` when `entity_ref` is an agent id, or its pin does not
/// read; `None` for an id that never was an agent.
fn agent_id_held(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity_ref: EntityId,
) -> Option<AgentBearing> {
    match crate::agent_def::is_agent_id_in_txn(store, txn, &entity_ref) {
        Ok(false) => None,
        Ok(true) => Some(AgentBearing::Bound(PolicyApprovalCeiling::Proposed)),
        Err(_) => {
            tracing::warn!(
                actor_entity_id = %entity_ref.to_hex(),
                "agent id pin read failed; failing closed to proposed",
            );
            Some(AgentBearing::Bound(PolicyApprovalCeiling::Proposed))
        }
    }
}

/// Classifies a governing entity id from stored state — READ-ONLY, and from
/// the ROW alone: no compiled table confers authority on any id, so a pinned
/// system-agent actor id classifies exactly like any other id. The one
/// exception only narrows: an agent id (pinned, or a seed's) holding no
/// definition, nothing or a row of another type, holds the agent there at
/// `Proposed` under any class asserted for it, rather than lifting its bound
/// (H215). Read failures resolve fail-closed to `Bound(Proposed)`.
fn agent_bearing_for_entity(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity_ref: EntityId,
) -> AgentBearing {
    let raw = match store
        .port_entity_record(txn, &entity_ref)
        .map(|row| row.map(|row| row.encode()))
    {
        Ok(Some(raw)) => raw,
        Ok(None) => {
            return agent_id_held(store, txn, entity_ref).unwrap_or(AgentBearing::Absent);
        }
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
        return agent_id_held(store, txn, entity_ref).unwrap_or(AgentBearing::NonAgent);
    }
    match decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..]) {
        // H147: switched off, retracted or rejected after dispatch, the
        // definition grants its running job nothing past Proposed.
        Ok(def) if !(definition_in_force(&def) && def.enabled) => {
            AgentBearing::Bound(PolicyApprovalCeiling::Proposed)
        }
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
/// leave a fork wider than its parent. A retracted or rejected parent lends
/// no ceiling either (H147).
fn parent_row_ceiling(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    parent_id: &EntityId,
) -> PolicyApprovalCeiling {
    let raw = match store
        .port_entity_record(txn, parent_id)
        .map(|row| row.map(|row| row.encode()))
    {
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
        Ok(parent) if definition_in_force(&parent) => {
            PolicyApprovalCeiling::from_agent_ceiling(parent.ceiling)
        }
        Ok(_) => PolicyApprovalCeiling::Proposed,
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

/// Whether a definition is in force: Active and approved (Auto or Approved),
/// the states dispatch admits. Retraction or rejection withdraws its ceiling
/// from its own actor and from every fork that inherits its bound.
fn definition_in_force(def: &AgentDefinition) -> bool {
    def.lifecycle_status == ClaimLifecycleStatus::Active
        && matches!(
            def.approval_status,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
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
