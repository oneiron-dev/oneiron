//! The filters a fact passes in Rust before any sandbox starts (ARCH-0080 §4
//! Filters). They read the claim only as the hook's grant shows it.

use crate::claim::ClaimBody;
use crate::edge::EdgeActorClass;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::skill_hub::pack_catalog::{HookActorClass, HookSelector};
use crate::{EntityId, Result, Vault};

use super::source::FactKind;

/// Whether `selector` takes this fact, as seen under the hook's grant.
pub(super) fn fact_matches(
    selector: &HookSelector,
    kind: FactKind,
    claim: Option<&ClaimBody>,
    actor: HookActorClass,
) -> bool {
    verbs_match(
        &selector.verbs,
        kind,
        claim.map(|body| body.predicate.as_str()),
    ) && (selector.actors.is_empty() || selector.actors.contains(&actor))
        && scope_matches(selector.scope.as_deref(), claim)
}

/// Whether any selector entry could take a fact of `kind`, before anything
/// is read.
pub(super) fn verbs_admit_kind(verbs: &[String], kind: FactKind) -> bool {
    verbs
        .iter()
        .any(|verb| kind_admits(entry_parts(verb).0, kind))
}

/// A selector entry is `<fact kind>:<predicate glob>`, or a bare predicate
/// glob that takes landed and superseded claims.
fn verbs_match(verbs: &[String], kind: FactKind, predicate: Option<&str>) -> bool {
    verbs.iter().any(|verb| {
        let (kind_part, glob) = entry_parts(verb);
        kind_admits(kind_part, kind)
            && predicate.map_or(glob == "*", |predicate| glob_match(glob, predicate))
    })
}

fn entry_parts(verb: &str) -> (Option<&str>, &str) {
    match verb.split_once(':') {
        Some((kind, glob)) => (Some(kind), glob),
        None => (None, verb),
    }
}

fn kind_admits(kind_part: Option<&str>, kind: FactKind) -> bool {
    match kind_part {
        Some(named) => named == kind.as_str(),
        None => matches!(kind, FactKind::ClaimLanded | FactKind::ClaimSuperseded),
    }
}

/// A scope only narrows: `world:<hex32>`, `facet:<token>` or
/// `project:<token>`, matched against what the claim carries. A claim that
/// carries no such field, or a scope of another shape, does not match.
fn scope_matches(scope: Option<&str>, claim: Option<&ClaimBody>) -> bool {
    let Some(scope) = scope else {
        return true;
    };
    let (Some(body), Some((axis, wanted))) = (claim, scope.split_once(':')) else {
        return false;
    };
    match axis {
        "world" => EntityId::from_hex(wanted)
            .ok()
            .is_some_and(|world| body.world == Some(world)),
        "facet" | "project" => scope_value(body.scope.as_ref(), axis).as_deref() == Some(wanted),
        _ => false,
    }
}

/// The text a claim's scope map holds under `axis`: a string, or a 16-byte
/// id as lowercase hex.
fn scope_value(scope: Option<&rmpv::Value>, axis: &str) -> Option<String> {
    let rmpv::Value::Map(entries) = scope? else {
        return None;
    };
    let (_, value) = entries.iter().find(|(key, _)| key.as_str() == Some(axis))?;
    match value {
        rmpv::Value::String(text) => text.as_str().map(str::to_owned),
        rmpv::Value::Binary(bytes) if bytes.len() == 16 => Some(crate::receipt::hex_lower(bytes)),
        _ => None,
    }
}

/// A `*` glob: `*` matches any run of characters, every other byte itself.
pub(super) fn glob_match(pattern: &str, text: &str) -> bool {
    let (pattern, text) = (pattern.as_bytes(), text.as_bytes());
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if pattern.get(p) == Some(&b'*') {
            star = Some((p, t));
            p += 1;
        } else if pattern.get(p) == text.get(t) {
            p += 1;
            t += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    pattern
        .get(p..)
        .is_some_and(|rest| rest.iter().all(|byte| *byte == b'*'))
}

/// The class of the actor a changelog row or a settlement names: the vault
/// owner is human, a machine or the storage service is system, and any other
/// writer is an agent.
pub(super) fn actor_class(vault: &Vault, actor: EntityId) -> Result<HookActorClass> {
    if actor == storage_service_principal()? {
        return Ok(HookActorClass::System);
    }
    let txn = vault.store.env.read_txn()?;
    if crate::memory::actor_is_vault_owner_in_txn(vault, &txn, actor, EdgeActorClass::Human)
        .unwrap_or(false)
    {
        return Ok(HookActorClass::Human);
    }
    let entity_type = vault
        .store
        .port_entity_record(&txn, &actor)?
        .map(|row| row.entity_type);
    Ok(if entity_type == Some(ENTITY_TYPE_MACHINE) {
        HookActorClass::System
    } else {
        HookActorClass::Agent
    })
}

/// The principal the changelog stamps on writes no actor made (supersession
/// among them): the same digest `ports::mutation` uses.
fn storage_service_principal() -> Result<EntityId> {
    let digest = blake3::hash(b"oneiron:storage-service-principal:v1");
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_bytes(bytes)
}

/// The edge actor class a [`HookActorClass`] reads and writes as.
pub(super) const fn edge_class(class: HookActorClass) -> EdgeActorClass {
    match class {
        HookActorClass::Human => EdgeActorClass::Human,
        HookActorClass::Agent => EdgeActorClass::Agent,
        HookActorClass::System => EdgeActorClass::System,
    }
}

/// The class token a hook's input carries.
pub(super) const fn class_token(class: HookActorClass) -> &'static str {
    match class {
        HookActorClass::Human => "human",
        HookActorClass::Agent => "agent",
        HookActorClass::System => "system",
    }
}
