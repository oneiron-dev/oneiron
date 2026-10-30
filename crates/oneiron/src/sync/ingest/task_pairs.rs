//! TASK rows one delta or pass changes together (FIX 5998).
//!
//! The ChildOf role matrix judges a pair by both endpoints as a batch leaves
//! them. Rows ingested one by one judge each new role against its partner's
//! stored one, so a valid pair change no single row makes valid alone, such
//! as a Goal over a Milestone becoming a Milestone over a Task, is refused.
//! The rows of such a component run their whole ladder in one savepoint and
//! their puts apply as one batch. A component that does not land whole
//! ingests row by row, as any other row does.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_TASK;
use crate::sync::quarantine::remote_rejection_reason;
use crate::temporal::TimeRange;
use crate::vault::Vault;

use super::entity::{EntityStep, IngestCtx, ingest_entity_in_savepoint, waits_for_sibling_row};

/// The TASK puts a component holds for its one batch; `None` outside one.
pub(super) type Staging = RefCell<Option<Vec<StagedPut>>>;

/// One TASK row's replicated put, held for its component's batch.
pub(super) struct StagedPut {
    id: EntityId,
    occurred: TimeRange,
    learned_at: u64,
    data: Vec<u8>,
}

/// The replicated put that ends a row's ladder: applied at once, or held for
/// the batch of the component a TASK row is staged in. `blob` is the row as
/// its window holds it; `data` is the body the put lands. An AUTHORITY_LOG
/// row is judged beside the window's other authority rows, as its ingest
/// door judged it (FIX 11764).
pub(super) fn put_or_stage(
    ctx: &IngestCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    header: &EntityMetadataHeader,
    blob: &[u8],
    data: &[u8],
) -> Result<()> {
    let occurred = TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    };
    if header.entity_type == ENTITY_TYPE_TASK
        && let Some(staged) = ctx.staged.borrow_mut().as_mut()
    {
        staged.push(StagedPut {
            id,
            occurred,
            learned_at: header.learned_at,
            data: data.to_vec(),
        });
        return Ok(());
    }
    // FIX 9600: a MESSAGE row an own machine's proven connection sent takes
    // its own-device lane as far as the put, and no further here: the batch
    // threads it to the witness gate.
    let _own_device = super::own_device::lane_in_txn(ctx, wtxn, &id, blob, data)?;
    let put = ctx.vault.batch_in().put_replicated(
        &id,
        header.entity_type,
        occurred,
        header.learned_at,
        data,
    );
    match &ctx.authority_beside {
        Some(authority) => put.apply_with_authority_beside(wtxn, &|| authority.rows()),
        None => put.apply(wtxn),
    }
}

/// The TASK components of one delta or pass: rows that change a stored TASK
/// row's role, joined by the stored ChildOf edges between them, two rows or
/// more each.
pub(in crate::sync) struct TaskComponents {
    by_key: HashMap<String, usize>,
    rows: Vec<Option<Vec<(String, Vec<u8>)>>>,
}

impl TaskComponents {
    /// The components among `rows` (key, entity blob), read in `rtxn`.
    pub(in crate::sync) fn find<'r>(
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        rows: impl IntoIterator<Item = (&'r str, &'r [u8])>,
    ) -> Result<Self> {
        let mut changed = Vec::new();
        let mut at = HashMap::new();
        for (key, blob) in rows {
            if let Ok(id) = EntityId::from_hex(key)
                && id.to_hex() == key
                && !waits_for_sibling_row(blob)
                && role_changes(vault, rtxn, &id, blob)?
            {
                at.insert(id, changed.len());
                changed.push((key, blob, id));
            }
        }
        let mut root: Vec<usize> = (0..changed.len()).collect();
        for (child, (_, _, id)) in changed.iter().enumerate() {
            let parents = EdgeStoreRead::port_edges(
                &vault.store,
                rtxn,
                id,
                EdgeDirection::Out,
                Some(EdgeKind::ChildOf),
                None,
            )?;
            for edge in parents {
                if let Some(&parent) = at.get(&edge?.target) {
                    let (from, to) = (root_of(&mut root, child), root_of(&mut root, parent));
                    root[from] = to;
                }
            }
        }
        let mut components = BTreeMap::<usize, Vec<usize>>::new();
        for index in 0..changed.len() {
            components
                .entry(root_of(&mut root, index))
                .or_default()
                .push(index);
        }
        let mut found = Self {
            by_key: HashMap::new(),
            rows: Vec::new(),
        };
        for members in components.into_values().filter(|members| members.len() > 1) {
            let rows = members
                .into_iter()
                .map(|index| (changed[index].0.to_owned(), changed[index].1.to_vec()))
                .collect::<Vec<_>>();
            for (key, _) in &rows {
                found.by_key.insert(key.clone(), found.rows.len());
            }
            found.rows.push(Some(rows));
        }
        Ok(found)
    }

    /// The rows of `key`'s component, the first time one of them is asked
    /// for; an empty list after that. `None` when `key` is in none.
    pub(in crate::sync) fn take(&mut self, key: &str) -> Option<Vec<(String, Vec<u8>)>> {
        let at = *self.by_key.get(key)?;
        Some(self.rows[at].take().unwrap_or_default())
    }
}

/// The root of `at`'s set.
fn root_of(root: &mut [usize], mut at: usize) -> usize {
    while root[at] != at {
        root[at] = root[root[at]];
        at = root[at];
    }
    at
}

/// Whether `blob` is a TASK row whose role differs from the stored TASK row's.
fn role_changes(vault: &Vault, rtxn: &heed::RoTxn<'_>, id: &EntityId, blob: &[u8]) -> Result<bool> {
    let role = |row: &[u8]| {
        EntityMetadataHeader::parse(row)
            .filter(|header| header.entity_type == ENTITY_TYPE_TASK)
            .and_then(|_| {
                crate::habit::task_role_from_body_bytes(&row[ENTITY_METADATA_HEADER_LEN..]).ok()
            })
    };
    let Some(new) = role(blob) else {
        return Ok(false);
    };
    Ok(EntityStoreRead::port_entity_raw(&vault.store, rtxn, id)?
        .is_some_and(|stored| role(&stored[..]).is_some_and(|old| old != new)))
}

/// [`ingest_entity_in_savepoint`] for each of `rows`, a component's
/// together: every row runs its ladder in one savepoint and their admitted
/// puts apply as one batch, so the role matrix judges each pair as the batch
/// leaves it. When a row or the batch is refused, the component rolls back
/// and its rows ingest one by one. Steps come back in `rows` order.
pub(in crate::sync) fn ingest_rows_in_savepoint(
    ctx: &IngestCtx<'_>,
    parent: &mut heed::RwTxn<'_>,
    rows: &[(&str, Option<&[u8]>)],
) -> Result<Vec<EntityStep>> {
    if rows.len() > 1 {
        let mut component = ctx.vault.store.env.nested_write_txn(parent)?;
        *ctx.staged.borrow_mut() = Some(Vec::new());
        let staged = stage_component(ctx, &mut component, rows);
        let puts = ctx.staged.take().unwrap_or_default();
        if let Some(steps) = staged? {
            let mut batch = ctx.vault.batch_in();
            for put in &puts {
                batch = batch.put_replicated(
                    &put.id,
                    ENTITY_TYPE_TASK,
                    put.occurred,
                    put.learned_at,
                    &put.data,
                );
            }
            let applied = if puts.is_empty() {
                Ok(())
            } else {
                batch.apply(&mut component)
            };
            match applied {
                Ok(()) => {
                    component.commit()?;
                    return Ok(steps);
                }
                Err(err) if remote_rejection_reason(&err).is_some() => {}
                Err(err) => return Err(err),
            }
        }
    }
    rows.iter()
        .map(|&(key, value)| ingest_entity_in_savepoint(ctx, parent, key, value))
        .collect()
}

/// Each row's step with its TASK put staged; `None` once a row is refused.
fn stage_component(
    ctx: &IngestCtx<'_>,
    component: &mut heed::RwTxn<'_>,
    rows: &[(&str, Option<&[u8]>)],
) -> Result<Option<Vec<EntityStep>>> {
    let mut steps = Vec::with_capacity(rows.len());
    for &(key, value) in rows {
        let step = ingest_entity_in_savepoint(ctx, component, key, value)?;
        if matches!(step, EntityStep::Quarantine(_)) {
            return Ok(None);
        }
        steps.push(step);
    }
    Ok(Some(steps))
}
