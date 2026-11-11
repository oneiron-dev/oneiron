//! The filters a fact passes in Rust before any sandbox starts (ARCH-0080 §4
//! Filters). They read the claim only as the hook's grant shows it; a tick or
//! an inbound surface event, which carries no claim, by its own key.

use crate::claim::ClaimBody;
use crate::edge::EdgeActorClass;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::skill_hub::pack_catalog::{HookActorClass, HookSelector};
use crate::{EntityId, Result, Vault};

use super::source::{FactEntry, FactKind};

/// Whether `selector` takes `entry`, its entity as seen under the hook's
/// grant. A claim fact's glob reads the claim's predicate; a tick's or an
/// inbound event's reads its own key ([`FactEntry::selector_key`]). A scope
/// is read last, and only when the selector names one.
pub(super) fn fact_matches(
    vault: &Vault,
    selector: &HookSelector,
    entry: &FactEntry,
    claim: Option<&ClaimBody>,
    actor: HookActorClass,
) -> Result<bool> {
    let own_key = entry.selector_key();
    let key = claim
        .map(|body| body.predicate.as_str())
        .or(own_key.as_deref());
    if !verbs_match(&selector.verbs, entry.kind, key)
        || !(selector.actors.is_empty() || selector.actors.contains(&actor))
    {
        return Ok(false);
    }
    scope_matches(vault, selector.scope.as_deref(), entry.entity, claim)
}

/// Filters a fact in the caller's existing snapshot.
pub(super) fn fact_matches_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    selector: &HookSelector,
    kind: FactKind,
    entity: EntityId,
    claim: Option<&ClaimBody>,
    actor: HookActorClass,
) -> Result<bool> {
    if !selector_matches(selector, kind, claim, actor) {
        return Ok(false);
    }
    let Some(scope) = selector.scope.as_deref() else {
        return Ok(true);
    };
    let Some(wanted) = super::scope::HookScope::parse(scope) else {
        return Ok(false);
    };
    super::scope::fact_within_in_txn(vault, txn, wanted, entity, claim)
}

fn selector_matches(
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
}

/// Whether any selector entry could take a fact of `kind`, before anything
/// is read.
pub(super) fn verbs_admit_kind(verbs: &[String], kind: FactKind) -> bool {
    verbs
        .iter()
        .any(|verb| kind_admits(entry_parts(verb).0, kind))
}

/// Whether the runner delivers `entry` to `binding`, whose selector names
/// `verbs`: [`verbs_admit_kind`], and for a tick, its TASK open at that due
/// time (FIX 4749): still open, or a watch TASK settled at or after it, as
/// the release of its tick settles it (FIX 22121), for a binding enabled
/// before that release alone. A binding fresh to the tick feed starts
/// before the earliest open TASK's tick, so this keeps it to the ticks of
/// TASKs open at them, and keeps it from a watch TASK's tick at or before
/// its enable-time tick head: that release did the watch's work before the
/// binding was bound (review #6784;
/// [`super::store::enabled_before_tick_in_txn`]). A TASK that settled
/// otherwise or moved its due time wants no run on its old tick, as its
/// release would have dropped it.
pub(super) fn admits_entry(
    vault: &Vault,
    binding: EntityId,
    verbs: &[String],
    entry: &FactEntry,
) -> Result<bool> {
    if !verbs_admit_kind(verbs, entry.kind) {
        return Ok(false);
    }
    let Some(tick) = entry.tick else {
        return Ok(true);
    };
    let txn = vault.store.env.read_txn()?;
    let bound = super::store::enabled_before_tick_in_txn(vault, &txn, binding, entry.position)?;
    let due_at = crate::task_verb::tick_due_at_in_txn(vault, &txn, entry.entity, bound)?;
    Ok(due_at == Some(tick.due_at))
}

/// A selector entry is `<fact kind>:<glob>`, or a bare predicate glob that
/// takes landed and superseded claims. The glob reads `key`: a claim's
/// predicate, a tick's TASK id as 32 hex (`schedule.tick:<id>` binds one
/// watcher TASK), or an inbound event's connector key
/// (`surface.inbound:slack`).
fn verbs_match(verbs: &[String], kind: FactKind, key: Option<&str>) -> bool {
    verbs.iter().any(|verb| {
        let (kind_part, glob) = entry_parts(verb);
        kind_admits(kind_part, kind) && key.map_or(glob == "*", |key| glob_match(glob, key))
    })
}

/// A watcher source named bare, `schedule.tick` or `surface.inbound`, takes
/// all of its facts (FIX 4749).
fn entry_parts(verb: &str) -> (Option<&str>, &str) {
    match verb.split_once(':') {
        Some((kind, glob)) => (Some(kind), glob),
        None if FactKind::from_token(verb).is_some_and(FactKind::is_watcher_source) => {
            (Some(verb), "*")
        }
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
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
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
    if actor == crate::ports::storage_service_principal()? {
        return Ok(HookActorClass::System);
    }
    let txn = vault.store.env.read_txn()?;
    stored_actor_class_in_txn(vault, &txn, actor)
}

/// Classifies a fact's actor without opening a second snapshot.
pub(super) fn actor_class_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<HookActorClass> {
    if actor == crate::ports::storage_service_principal()? {
        return Ok(HookActorClass::System);
    }
    stored_actor_class_in_txn(vault, txn, actor)
}

fn stored_actor_class_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<HookActorClass> {
    if crate::memory::actor_is_vault_owner_in_txn(vault, txn, actor, EdgeActorClass::Human)
        .unwrap_or(false)
    {
        return Ok(HookActorClass::Human);
    }
    let entity_type = vault
        .store
        .port_entity_record(txn, &actor)?
        .map(|row| row.entity_type);
    Ok(if entity_type == Some(ENTITY_TYPE_MACHINE) {
        HookActorClass::System
    } else {
        HookActorClass::Agent
    })
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
