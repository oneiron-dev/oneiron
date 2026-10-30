//! The WORLD ids a guest's rows name beyond InWorld and SetIn edges (FIX 3892).
//! `Routes::plan` reads them; the copy renames them.
//! Owned by `super`.
//!
//! A guest CLAIM whose subject is a WORLD, an AGENT_DEF scoped to a world
//! (`AgentScope::World`) and a saved query's declared worlds name the
//! sender's WORLD ids. Each lands naming the foreign id the guest's WORLD
//! lands under here ([`super::routing::Routes`], FIX 3657), under the proof
//! an InWorld or SetIn edge takes. An AGENT_DEF's world and a saved query's
//! worlds are typed WORLDs by their schemas, as an edge's kind types its
//! target, so each names the foreign id even before its WORLD row arrives,
//! unless the update carries that id as a row of another kind. A CLAIM's
//! entity subject is typed by nothing: it names the foreign id only once its
//! WORLD row is proven, carried in the update or stored here. The agent and
//! saved-query codecs are read, never changed: a renamed body differs from
//! the sender's only in those WORLD leaves.

use std::collections::BTreeMap;

use crate::Vault;
use crate::claim::ClaimSubject;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_AGENT_DEF;

/// The AGENT_DEF body key that holds a world-scoped definition's world.
#[cfg(feature = "sync")]
const AGENT_WORLD_KEY: &str = crate::agent_def::AGENT_DEF_BODY_KEYS[9];

/// The saved-query kind this vault registers, `None` when it registers none.
#[cfg(feature = "sync")]
pub(super) fn saved_query_kind(vault: &Vault) -> Option<u8> {
    vault
        .structural_kind_registrations()
        .into_iter()
        .find(|registration| {
            registration.short_id_prefix == crate::saved_query::SAVED_QUERY_SHORT_ID_PREFIX
                && registration.pack == crate::campaign::CRM_PACK_ID
        })
        .map(|registration| registration.type_byte)
}

/// The entity a CLAIM is about, when it is about an entity: a WORLD only
/// once proven one.
#[cfg(feature = "sync")]
pub(super) const fn entity_subject(subject: &ClaimSubject) -> Option<EntityId> {
    match *subject {
        ClaimSubject::Entity(id) => Some(id),
        ClaimSubject::Edge { .. } => None,
    }
}

/// The WORLD ids the body of a row of `kind` names by its schema: an
/// AGENT_DEF's world, a saved query's declared worlds (`saved_query`, this
/// vault's saved-query kind). A body that does not decode names none here;
/// the copy refuses it as before.
#[cfg(feature = "sync")]
pub(super) fn typed_world_refs(kind: u8, saved_query: Option<u8>, body: &[u8]) -> Vec<EntityId> {
    if kind == ENTITY_TYPE_AGENT_DEF {
        return match crate::agent_def::decode_agent_definition(body) {
            Ok(definition) => match definition.scope {
                crate::agent_def::AgentScope::World(world) => vec![world],
                crate::agent_def::AgentScope::All | crate::agent_def::AgentScope::Base => {
                    Vec::new()
                }
            },
            Err(_) => Vec::new(),
        };
    }
    if saved_query == Some(kind) {
        return serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .as_ref()
            .and_then(saved_query_worlds)
            .map(|worlds| {
                worlds
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter_map(canonical_id)
                    .collect()
            })
            .unwrap_or_default();
    }
    Vec::new()
}

/// A guest CLAIM about a WORLD names it by the id its copy lands under.
#[cfg(feature = "sync")]
pub(super) fn rename_entity_subject(
    subject: &mut ClaimSubject,
    worlds: &BTreeMap<EntityId, EntityId>,
) {
    if let ClaimSubject::Entity(id) = subject
        && let Some(here) = worlds.get(&*id)
    {
        *id = *here;
    }
}

/// The body of a guest's row of `kind` with each WORLD id its schema names
/// renamed to the id that WORLD lands under here; `None` when it names none
/// of them, so the row lands as it came.
#[cfg(feature = "sync")]
pub(super) fn rename_typed_world_refs(
    kind: u8,
    saved_query: Option<u8>,
    body: &[u8],
    worlds: &BTreeMap<EntityId, EntityId>,
) -> Result<Option<Vec<u8>>> {
    if worlds.is_empty() {
        return Ok(None);
    }
    if kind == ENTITY_TYPE_AGENT_DEF {
        return rename_agent_world(body, worlds);
    }
    if saved_query == Some(kind) {
        return rename_saved_query_worlds(body, worlds);
    }
    Ok(None)
}

/// An AGENT_DEF body whose world leaf names a renamed WORLD, with that leaf
/// alone rewritten.
#[cfg(feature = "sync")]
fn rename_agent_world(
    body: &[u8],
    worlds: &BTreeMap<EntityId, EntityId>,
) -> Result<Option<Vec<u8>>> {
    let Ok(rmpv::Value::Map(mut entries)) = rmpv::decode::read_value(&mut &body[..]) else {
        return Ok(None);
    };
    let mut renamed = false;
    for (key, value) in &mut entries {
        if key.as_str() != Some(AGENT_WORLD_KEY) {
            continue;
        }
        if let Some(here) = value.as_str().and_then(canonical_id).and_then(|id| worlds.get(&id)) {
            *value = rmpv::Value::from(here.to_hex());
            renamed = true;
        }
    }
    if !renamed {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(body.len());
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("renamed AGENT_DEF body does not encode"))?;
    Ok(Some(out))
}

/// A saved query body whose declared worlds name a renamed WORLD, with those
/// entries alone rewritten; the body's key order is kept.
#[cfg(feature = "sync")]
fn rename_saved_query_worlds(
    body: &[u8],
    worlds: &BTreeMap<EntityId, EntityId>,
) -> Result<Option<Vec<u8>>> {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Ok(None);
    };
    let mut renamed = false;
    if let Some(declared) = value
        .get_mut("definition")
        .and_then(|definition| definition.get_mut("scope"))
        .and_then(|scope| scope.get_mut("worlds"))
        .and_then(serde_json::Value::as_array_mut)
    {
        for world in declared {
            if let Some(here) = world.as_str().and_then(canonical_id).and_then(|id| worlds.get(&id)) {
                *world = serde_json::Value::String(here.to_hex());
                renamed = true;
            }
        }
    }
    if !renamed {
        return Ok(None);
    }
    serde_json::to_vec(&value)
        .map(Some)
        .map_err(|_| Error::InvariantViolation("renamed saved query body does not encode"))
}

/// The worlds a saved query body declares.
#[cfg(feature = "sync")]
fn saved_query_worlds(value: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    value
        .get("definition")?
        .get("scope")?
        .get("worlds")?
        .as_array()
}

/// The id `hex` names, when it is that id's canonical hex.
#[cfg(feature = "sync")]
fn canonical_id(hex: &str) -> Option<EntityId> {
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}
