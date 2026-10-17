//! The filters a fact passes in Rust before any sandbox starts (ARCH-0080 §4
//! Filters). They read the claim only as the hook's grant shows it.

use crate::claim::ClaimBody;
use crate::edge::EdgeActorClass;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::skill_hub::pack_catalog::{HookActorClass, HookSelector};
use crate::{EntityId, Result, Vault};

use super::source::FactKind;

/// Whether `selector` takes the fact on `entity`, as seen under the hook's
/// grant. A scope is read last, and only when the selector names one.
pub(super) fn fact_matches(
    vault: &Vault,
    selector: &HookSelector,
    kind: FactKind,
    entity: EntityId,
    claim: Option<&ClaimBody>,
    actor: HookActorClass,
) -> Result<bool> {
    if !verbs_match(
        &selector.verbs,
        kind,
        claim.map(|body| body.predicate.as_str()),
    ) || !(selector.actors.is_empty() || selector.actors.contains(&actor))
    {
        return Ok(false);
    }
    scope_matches(vault, selector.scope.as_deref(), entity, claim)
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

/// A scope only narrows, read as a `HookScope`: the record's world, the
/// facets the one facet rule places it in, its claim's project or its room's,
/// or the room it was said in. A selector with no scope takes every fact.
fn scope_matches(
    vault: &Vault,
    scope: Option<&str>,
    entity: EntityId,
    claim: Option<&ClaimBody>,
) -> Result<bool> {
    match scope {
        None => Ok(true),
        Some(scope) => super::scope::fact_within(vault, scope, entity, claim),
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
