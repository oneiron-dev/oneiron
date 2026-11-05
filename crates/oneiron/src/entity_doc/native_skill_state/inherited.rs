//! Native inheritance at the ordinary document persistence boundary.
//!
//! Only the real old Store source supplies inherited native operations. New
//! native operations need their own closed producer, not equal signed bytes.

use std::collections::BTreeSet;

use loro::CommitOptions;

use super::super::{EntityDoc, storage};
use super::inspect::{NativeMapWrite, inspect};
use super::register::{CURRENT, ROOT};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

fn invalid() -> Error {
    Error::CorruptedIndex("native SKILL state persistence source")
}

/// The caller has already run its real ordinary gates. This executes before
/// generation, export, HEAD publication or provenance/history capture. The
/// authoritative source invariant must be closed at every ingress before the
/// native doors are enabled; old raw storage is not retrospective permission.
pub(in crate::entity_doc) fn reconcile_for_persist(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    head: &storage::Head,
    document: &EntityDoc,
) -> Result<BTreeSet<EntityId>> {
    let incoming = inspect(document)?;
    let incoming_native = incoming.current.is_some()
        || incoming
            .floor
            .as_ref()
            .is_some_and(|floor| floor.fact.is_some())
        || !incoming.mutations.is_empty();
    let entity_type = vault.get_entity_type_in_txn(txn, entity)?;
    if !incoming_native && entity_type != Some(crate::registry::ENTITY_TYPE_SKILL) {
        return Ok(BTreeSet::new());
    }
    let stored_head = storage::record_head_bytes(&vault.store, txn, entity)?;
    let Some(stored_head) = stored_head else {
        return if incoming_native {
            Err(invalid())
        } else {
            Ok(BTreeSet::new())
        };
    };
    let stored_head: storage::Head = storage::decode(&stored_head)?;
    let stored = storage::load(&vault.store, txn, &stored_head)?;
    let inherited = inspect(&stored)?;
    let inherited_native = inherited.current.is_some()
        || inherited
            .floor
            .as_ref()
            .is_some_and(|floor| floor.fact.is_some())
        || !inherited.mutations.is_empty();
    if !incoming_native && !inherited_native {
        return Ok(BTreeSet::new());
    }
    if stored_head.entity != entity.to_hex()
        || stored_head.entity != head.entity
        || stored_head.document != head.document
        || stored_head.incarnation != head.incarnation
        || stored_head.field != head.field
        || stored_head.generation != head.generation
        || stored_head.pending != head.pending
        || stored_head.birth_frontier != head.birth_frontier
    {
        return Err(invalid());
    }
    if entity_type != Some(crate::registry::ENTITY_TYPE_SKILL)
        || document.birth().entity != entity.to_hex()
        || document.birth().at != stored.birth().at
        || incoming.floor != inherited.floor
        || incoming.mutations.len() != inherited.mutations.len()
        || incoming
            .mutations
            .iter()
            .any(|mutation| !inherited.mutations.contains(mutation))
    {
        return Err(invalid());
    }
    // The full raw mutation identity was checked above, not just membership
    // of each decoded value. A current/floor fact alone cannot admit writes
    // hidden by another LWW value or a delete.
    let known = |fact: &super::codec::SkillStateFact| {
        inherited.current.as_ref() == Some(fact)
            || inherited.floor.as_ref().and_then(|floor| floor.fact.as_ref()) == Some(fact)
            || inherited.mutations.iter().any(|mutation| {
                matches!(&mutation.write, NativeMapWrite::Insert(value) if value == fact)
            })
    };
    if incoming.current.as_ref().is_some_and(|fact| !known(fact)) {
        return Err(invalid());
    }
    for fact in inherited
        .current
        .iter()
        .chain(
            inherited
                .floor
                .iter()
                .filter_map(|floor| floor.fact.as_ref()),
        )
        .chain(
            inherited
                .mutations
                .iter()
                .filter_map(|mutation| match &mutation.write {
                    NativeMapWrite::Insert(fact) => Some(fact),
                    NativeMapWrite::Delete => None,
                }),
        )
    {
        if !fact.target_birth_is(*entity, stored.birth().at) {
            return Err(invalid());
        }
    }
    // Inheritance alone cannot select a different native state. In
    // particular, an original selected None is not a floor/history fallback.
    // A genuine new local or recipient operation uses its closed source path.
    if incoming.current != inherited.current {
        let map = document.doc.get_map(ROOT);
        match &inherited.current {
            Some(fact) => {
                map.insert(CURRENT, fact.encode()?.as_slice())
                    .map_err(|_| invalid())?;
            }
            None => {
                map.delete(CURRENT).map_err(|_| invalid())?;
            }
        }
        document
            .doc
            .commit_with(CommitOptions::new().commit_msg(super::ANONYMOUS_COMMIT));
        if super::register::read_fact(document)? != inherited.current {
            return Err(invalid());
        }
    }
    inherited.writer_tokens()
}
