//! A text-edit proposal's review bundle, split by its forks' entities
//! (KS7-2). Each entity's compartment holds a fragment: the bundle with only
//! the forks on that entity, naming no one, its path naming the entity and
//! every fork in the bundle's order. The author and each fork's opener are
//! actor parts.
//!
//! A restore merges each fragment into the bundle the owners restored before
//! it hold, in the bundle's order, so the bundle comes back whole when every
//! owner opens. A fork whose entity did not open is not in it; a pending fork
//! whose opener did not open leaves it, as the erase takes it out; and a
//! bundle left with no fork is not written.

use std::collections::BTreeMap;

use heed::RoTxn;

use super::super::doc_actor::DocActor;
use super::super::forks::{
    ACTOR_ERASE_PENDING_ENTITY_DOC_FORK, ENTITY_DOC_PROPOSAL_BUNDLE, ForkRecord, ForkStatus,
    PendingDocForkErase, ProposalBundle,
};
use super::{fill, hex_id};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::SideKey;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OwnerRef, RowLocator, RowPart, TypedRow, Unresolved,
};

/// The field the bundle's author fills.
const AUTHOR: &str = "author";

/// The field a fork's opener fills, before the fork's id.
const OPENER: &str = "opener ";

pub(super) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    for row in rows::typed_rows(dbs, txn, ENTITY_DOC_PROPOSAL_BUNDLE, out)? {
        split(out, row)?;
    }
    Ok(())
}

fn split(out: &mut Captured, row: TypedRow<String, ProposalBundle>) -> Result<()> {
    if !rows::spells_back(ENTITY_DOC_PROPOSAL_BUNDLE, &row) {
        let reason = Unresolved::ActorSplit(rows::NOT_SPELLED_BACK);
        out.unclassified(row.at, None, reason);
        return Ok(());
    }
    let mut members: BTreeMap<EntityId, Vec<ForkRecord>> = BTreeMap::new();
    for fork in &row.value.forks {
        let (Some(entity), Some(_)) = (hex_id(&fork.entity), hex_id(&fork.fork)) else {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            return Ok(());
        };
        members.entry(entity).or_default().push(fork.clone());
    }
    if members.is_empty() {
        out.unclassified(row.at, None, Unresolved::NoOwner);
        return Ok(());
    }
    let order = row
        .value
        .forks
        .iter()
        .map(|fork| fork.fork.as_str())
        .collect::<Vec<_>>()
        .join(",");
    for (entity, forks) in members {
        let mut fragment = ProposalBundle {
            proposal: row.value.proposal.clone(),
            author: row.value.author,
            forks,
            settled: row.value.settled,
        };
        let mut actors = Vec::new();
        if let DocActor::Actor(id) = std::mem::replace(&mut fragment.author, DocActor::Erased) {
            actors.push((AUTHOR.to_owned(), id));
        }
        for fork in &mut fragment.forks {
            if let DocActor::Actor(id) = std::mem::replace(&mut fork.actor, DocActor::Erased) {
                actors.push((format!("{OPENER}{}", fork.fork), id));
            }
        }
        let at = row.at.fragment(format!("{}:{order}", entity.to_hex()));
        let value = ENTITY_DOC_PROPOSAL_BUNDLE.encode_value(&fragment)?;
        let rows = out.owner(OwnerRef::entity(&entity));
        for (field, actor) in actors {
            rows.actor_parts.push(ActorPart {
                actor_entity: actor,
                content_locator: at.clone(),
                field,
                bytes: actor.as_bytes().to_vec(),
            });
        }
        rows.rows.push(RowPart::NoActor { at, value });
    }
    Ok(())
}

fn put_actor(bundle: &mut ProposalBundle, field: &str, actor: EntityId) -> Result<()> {
    if field == AUTHOR {
        return fill(&mut bundle.author, actor);
    }
    let id = field.strip_prefix(OPENER).ok_or_else(rows::bad_part)?;
    let fork = bundle
        .forks
        .iter_mut()
        .find(|fork| fork.fork == id)
        .ok_or_else(rows::bad_part)?;
    fill(&mut fork.actor, actor)
}

/// One fragment with its opened actors back, merged into the bundle `view`
/// holds at its key; `None` while the merge holds no fork.
pub(super) fn join(
    dbs: &impl ManifestDbs,
    view: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    let (_, order) = at.path.split_once(':').ok_or_else(rows::bad_part)?;
    let order: Vec<&str> = order.split(',').collect();
    let mut fragment = rows::join_actors(ENTITY_DOC_PROPOSAL_BUNDLE, value, parts, put_actor)?;
    if ACTOR_ERASE_PENDING_ENTITY_DOC_FORK == PendingDocForkErase::Delete {
        fragment
            .forks
            .retain(|fork| fork.status != ForkStatus::Pending || fork.actor != DocActor::Erased);
    }
    let key = at
        .key
        .strip_prefix(ENTITY_DOC_PROPOSAL_BUNDLE.decl().prefix)
        .and_then(String::decode_key)
        .ok_or_else(rows::bad_part)?;
    let mut merged = match ENTITY_DOC_PROPOSAL_BUNDLE.get(dbs, view, &key)? {
        Some(mut earlier) => {
            if earlier.proposal != fragment.proposal || earlier.settled != fragment.settled {
                return Err(rows::bad_part());
            }
            if earlier.author == DocActor::Erased {
                earlier.author = fragment.author;
            }
            earlier.forks.extend(fragment.forks);
            earlier
        }
        None => fragment,
    };
    let place = |fork: &ForkRecord| order.iter().position(|id| *id == fork.fork);
    if merged.forks.iter().any(|fork| place(fork).is_none()) {
        return Err(rows::bad_part());
    }
    merged.forks.sort_by_key(|fork| place(fork));
    if merged.forks.is_empty() {
        return Ok(None);
    }
    ENTITY_DOC_PROPOSAL_BUNDLE.encode_value(&merged).map(Some)
}
