//! Canonical per-source counters for historical lift runs (FIX 10493).

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{LiftCounts, LiftFamily, carriers, records};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

const COUNTS: SideTable<Vec<u8>, Contribution, Named> =
    SideTable::new(&side_table::SECRET_LIFT_CONTRIBUTION);

#[derive(Clone, Serialize, Deserialize)]
pub(super) enum Source {
    Unmapped,
    Entity(EntityId),
    Multi(Vec<EntityId>),
}

impl Source {
    pub(super) fn of_set(mut ids: Vec<EntityId>) -> Self {
        ids.sort_unstable();
        ids.dedup();
        match ids.len() {
            0 => Self::Unmapped,
            1 => Self::Entity(ids[0]),
            _ => Self::Multi(ids),
        }
    }

    pub(super) fn entities(&self) -> &[EntityId] {
        match self {
            Self::Unmapped => &[],
            Self::Entity(id) => std::slice::from_ref(id),
            Self::Multi(ids) => ids,
        }
    }

    pub(super) fn kept_by(&self, keep: &dyn Fn(EntityId) -> bool) -> bool {
        self.entities().iter().all(|id| keep(*id))
    }
}

#[derive(Serialize, Deserialize)]
struct Contribution {
    source: Source,
    counts: LiftCounts,
}

/// Proven sources from the native key or its same-snapshot content binding.
pub(super) fn source_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    family: LiftFamily,
    key: &[u8],
) -> Result<Source> {
    match family {
        LiftFamily::Records => Ok(records::record_id(key).map_or(Source::Unmapped, Source::Entity)),
        LiftFamily::Carriers => carriers::source_in_txn(vault, txn, key),
        LiftFamily::Attempts | LiftFamily::SideRows => Ok(Source::Unmapped),
    }
}

pub(super) fn add(
    store: &Store,
    txn: &mut RwTxn<'_>,
    run: EntityId,
    source: &Source,
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
        Source::Unmapped => key.push(0),
        Source::Entity(id) => {
            key.push(1);
            key.extend_from_slice(id.as_bytes());
        }
        Source::Multi(ids) => {
            key.push(2);
            let mut group =
                blake3::Hasher::new_derive_key("oneiron/secret-lift/contribution-sources/v1");
            for id in ids {
                group.update(id.as_bytes());
            }
            key.extend_from_slice(group.finalize().as_bytes());
        }
    }
    let mut row = COUNTS
        .get_lenient(store, txn, &key)?
        .unwrap_or_else(|| Contribution {
            source: source.clone(),
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
        sources.extend(row.source.entities());
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
        if !row.source.kept_by(keep) {
            return;
        }
        total.read += row.counts.read;
        total.masked += row.counts.masked;
        total.proposals += row.counts.proposals;
        total.failed += row.counts.failed;
    })?;
    Ok(families.into_values().collect())
}
