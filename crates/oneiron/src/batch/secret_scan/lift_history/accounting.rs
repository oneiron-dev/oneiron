//! Canonical per-source counters for historical lift runs (FIX 10493).

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{LiftCounts, LiftFamily, carriers, records};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

const COUNTS: SideTable<Vec<u8>, Contribution, Named> =
    SideTable::new(&side_table::SECRET_LIFT_CONTRIBUTION);

#[derive(Clone, Copy, Serialize, Deserialize)]
enum Source {
    Unmapped,
    Entity(EntityId),
}

#[derive(Serialize, Deserialize)]
struct Contribution {
    source: Source,
    counts: LiftCounts,
}

/// Only keys whose producer contract names the source entity are mapped.
pub(super) fn source(family: LiftFamily, key: &[u8]) -> Option<EntityId> {
    match family {
        LiftFamily::Records => records::record_id(key),
        LiftFamily::Carriers => carriers::source(key),
        LiftFamily::Attempts | LiftFamily::SideRows => None,
    }
}

pub(super) fn add(
    store: &Store,
    txn: &mut RwTxn<'_>,
    run: EntityId,
    source: Option<EntityId>,
    delta: LiftCounts,
) -> Result<()> {
    let mut key = run.as_bytes().to_vec();
    key.push(match delta.family {
        LiftFamily::Records => 0,
        LiftFamily::Attempts => 1,
        LiftFamily::SideRows => 2,
        LiftFamily::Carriers => 3,
    });
    match source {
        None => key.push(0),
        Some(id) => {
            key.push(1);
            key.extend_from_slice(id.as_bytes());
        }
    }
    let mut row = COUNTS
        .get_lenient(store, txn, &key)?
        .unwrap_or(Contribution {
            source: source.map_or(Source::Unmapped, Source::Entity),
            counts: LiftCounts::new(delta.family),
        });
    row.counts.read += delta.read;
    row.counts.masked += delta.masked;
    row.counts.proposals += delta.proposals;
    row.counts.failed += delta.failed;
    COUNTS.put(store, txn, &key, &row)
}

fn visit(
    store: &Store,
    txn: &RoTxn<'_>,
    run: EntityId,
    mut visit: impl FnMut(Contribution),
) -> Result<()> {
    for row in COUNTS.iter_from(store, txn, run.as_bytes())? {
        let (key, row) = row?;
        if !key.starts_with(run.as_bytes()) {
            break;
        }
        visit(row);
    }
    Ok(())
}

pub(super) fn sources(store: &Store, txn: &RoTxn<'_>, run: EntityId) -> Result<BTreeSet<EntityId>> {
    let mut sources = BTreeSet::new();
    visit(store, txn, run, |row| {
        if let Source::Entity(id) = row.source {
            sources.insert(id);
        }
    })?;
    Ok(sources)
}

pub(super) fn counts(
    store: &Store,
    txn: &RoTxn<'_>,
    run: EntityId,
    finished: bool,
    keep: &dyn Fn(EntityId) -> bool,
) -> Result<Vec<LiftCounts>> {
    let mut families = BTreeMap::new();
    if finished {
        for family in LiftFamily::ALL {
            families.insert(family, LiftCounts::new(family));
        }
    }
    visit(store, txn, run, |row| {
        let total = families
            .entry(row.counts.family)
            .or_insert_with(|| LiftCounts::new(row.counts.family));
        if let Source::Entity(id) = row.source
            && !keep(id)
        {
            return;
        }
        total.read += row.counts.read;
        total.masked += row.counts.masked;
        total.proposals += row.counts.proposals;
        total.failed += row.counts.failed;
    })?;
    Ok(families.into_values().collect())
}
