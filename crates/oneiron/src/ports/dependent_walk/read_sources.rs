//! Original staleness walk reads with opt-in borrowed physical inputs.
//! Calendar-origin subcalls share the same observer. These events alone never
//! certify the complete staleness predicate or permission.
use super::{
    BTreeSet, CarriedWorlds, EntityId, EntityMetadataHeader, ManifestDbs, Result, RoTxn, SETTLED,
    SourceSpan, WALK, row_key,
};

pub(super) fn entity_type_in(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    observer: &mut Option<&mut crate::ports::StaleReadObserver<'_>>,
) -> Result<Option<u8>> {
    let raw = dbs.entities().get(txn, id.as_bytes())?;
    crate::ports::stale_reads::observe(
        observer,
        crate::ports::StaleRead::Row {
            table: crate::ports::StaleReadTable::Entities,
            key: id.as_bytes(),
            value: raw.as_deref(),
        },
    );
    Ok(raw
        .and_then(|raw| EntityMetadataHeader::parse(&raw))
        .map(|header| header.entity_type))
}

pub(super) fn pending_withdrawal_in(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    observer: &mut Option<&mut crate::ports::StaleReadObserver<'_>>,
) -> Result<Option<CarriedWorlds>> {
    if !any_pending_walk(dbs, txn, observer)? {
        return Ok(None);
    }
    let mut withdrawn: Option<CarriedWorlds> = None;
    let mut seen = BTreeSet::new();
    // A worklist up the epoch summaries' sources, not recursion.
    let mut pending = vec![*id];
    while let Some(node) = pending.pop() {
        if !seen.insert(node) {
            continue;
        }
        let sources = crate::ports::regeneration::sources_observed_in(dbs, txn, &node, observer)?;
        if sources.is_empty() {
            continue;
        }
        let entity_type = entity_type_in(dbs, txn, &node, observer)?;
        if let Some(worlds) =
            direct_withdrawal_in(dbs, txn, &node, &sources, entity_type, observer)?
        {
            withdrawn
                .get_or_insert_with(CarriedWorlds::default)
                .absorb(&worlds);
        }
        if entity_type == Some(crate::registry::ENTITY_TYPE_SUMMARY)
            && crate::ports::epoch_reads::epoch_summary_in(dbs, txn, &node, observer)?
        {
            pending.extend(sources.iter().map(|source| source.document));
        }
    }
    Ok(withdrawn)
}

pub(super) fn direct_withdrawal_in(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    node: &EntityId,
    sources: &[SourceSpan],
    entity_type: Option<u8>,
    observer: &mut Option<&mut crate::ports::StaleReadObserver<'_>>,
) -> Result<Option<CarriedWorlds>> {
    let mut withdrawn: Option<CarriedWorlds> = None;
    for SourceSpan { document, frontier } in sources {
        let row = row_key(*frontier, node);
        let Some(walk) = crate::ports::stale_reads::side_row(WALK, dbs, txn, document, observer)?
        else {
            continue;
        };
        if !walk.mark.covers(&row) {
            continue;
        }
        let settled =
            crate::ports::stale_reads::side_row(SETTLED, dbs, txn, &(*document, row), observer)?;
        if let Some(worlds) = walk.worlds_for(&row, settled)
            && !(entity_type == Some(crate::registry::ENTITY_TYPE_EVENT)
                && crate::calendar::origin::survives_source_deletion_observed(
                    dbs, txn, *node, observer,
                )?)
        {
            withdrawn
                .get_or_insert_with(CarriedWorlds::default)
                .absorb(&worlds);
        }
    }
    Ok(withdrawn)
}

pub(super) fn any_pending_walk(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    observer: &mut Option<&mut crate::ports::StaleReadObserver<'_>>,
) -> Result<bool> {
    use crate::ports::stale_reads::observe;
    use crate::ports::{StaleRead, StaleReadTable};

    if observer.is_none() {
        return Ok(WALK.iter_raw_from(dbs, txn, &[])?.next().is_some());
    }
    let next = WALK.iter_raw_from(dbs, txn, &[])?.next();
    let prefix = WALK.decl().prefix;
    let table = match WALK.decl().db {
        crate::side_table::SideDb::VaultMeta => StaleReadTable::VaultMeta,
        crate::side_table::SideDb::SyncState => StaleReadTable::SyncState,
    };
    match &next {
        Some(Ok((key, value))) => {
            let full = [prefix, key.as_slice()].concat();
            observe(
                observer,
                StaleRead::Row {
                    table,
                    key: &full,
                    value: Some(value),
                },
            );
        }
        Some(Err(_)) => observe(observer, StaleRead::ScanFailed { table, prefix }),
        None => observe(observer, StaleRead::ScanComplete { table, prefix }),
    }
    Ok(next.is_some())
}
