//! Borrowed physical inputs of the original calendar-origin survival read.
//! These observations do not grant retention or certify source completeness.
use super::*;
use crate::ports::stale_reads::{entity_record, observe};
use crate::ports::{StaleRead, StaleReadObserver, StaleReadTable};

pub(super) fn live_origin_observed(
    store: &impl ManifestDbs,
    authority: &impl crate::side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
    observer: &mut Option<&mut StaleReadObserver<'_>>,
) -> Result<Option<CalendarOrigin>> {
    let mut chosen = None;
    if observer.is_none() {
        for entry in store.port_edges(
            txn,
            &event,
            crate::ports::EdgeDirection::In,
            Some(EdgeKind::ClaimOf),
            None,
        )? {
            choose_origin(store, authority, txn, entry?.target, &mut chosen, observer)?;
        }
    } else {
        use std::ops::Bound;
        let mut prefix = event.as_bytes().to_vec();
        prefix.push(EdgeKind::ClaimOf as u8);
        let rows = store.edges_in().range(
            txn,
            &(
                Bound::Included(prefix.as_slice()),
                Bound::<&[u8]>::Unbounded,
            ),
        )?;
        for row in rows {
            let (key, value) = row?;
            observe(
                observer,
                StaleRead::Row {
                    table: StaleReadTable::EdgesIn,
                    key: &key,
                    value: Some(&value),
                },
            );
            if !key.starts_with(&prefix) {
                break;
            }
            let edge = crate::edge::parse_strict_edge_record(&key, &value)?;
            if edge.source != event || edge.kind != EdgeKind::ClaimOf {
                return Err(Error::CorruptedIndex("centered edge stream"));
            }
            choose_origin(
                store,
                authority,
                txn,
                edge.into_edge_info().target,
                &mut chosen,
                observer,
            )?;
        }
        observe(
            observer,
            StaleRead::ScanComplete {
                table: StaleReadTable::EdgesIn,
                prefix: &prefix,
            },
        );
    }
    Ok(chosen.map(|(_, origin)| origin))
}

fn choose_origin(
    store: &impl ManifestDbs,
    authority: &impl crate::side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    chosen: &mut Option<(EntityId, CalendarOrigin)>,
    observer: &mut Option<&mut StaleReadObserver<'_>>,
) -> Result<()> {
    let Some(raw) = entity_record(store, txn, &id, observer)?.map(|row| row.encode()) else {
        return Ok(());
    };
    let Some(bytes) = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .filter(|b| !b.is_empty())
    else {
        return Ok(());
    };
    let body = crate::claim::decode_claim_body(bytes, true)?;
    if body.predicate == PREDICATE_CALENDAR_ORIGIN
        && claim_surfaceable(&body)
        && crate::gate::claim_critical_confirm_settled_observed_in_txn(
            authority, txn, &id, observer,
        )?
    {
        let origin = body
            .value
            .as_str()
            .and_then(CalendarOrigin::parse)
            .ok_or(invalid("calendar origin value"))?;
        if chosen.is_some_and(|(_, existing)| existing != origin) {
            return Err(invalid("conflicting live calendar origins"));
        }
        if chosen.is_none_or(|(old, _)| id < old) {
            *chosen = Some((id, origin));
        }
    }
    Ok(())
}

pub(super) fn replay_origin_bound_observed(
    store: &impl ManifestDbs,
    authority: &impl crate::side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
    observer: &mut Option<&mut StaleReadObserver<'_>>,
) -> Result<bool> {
    let Some(row) = entity_record(store, txn, &event, observer)? else {
        return Ok(true);
    };
    if row.entity_type != ENTITY_TYPE_EVENT {
        return Ok(true);
    }
    let Some(origin) = declared_origin(&row.body)? else {
        return Ok(true);
    };
    Ok(live_origin_observed(store, authority, txn, event, observer)? == Some(origin))
}

pub(crate) fn survives_source_deletion_observed(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
    observer: &mut Option<&mut StaleReadObserver<'_>>,
) -> Result<bool> {
    if !replay_origin_bound_observed(store, store, txn, event, observer)?
        && let Some(row) = entity_record(store, txn, &event, observer)?
    {
        // Pending native/imported entries keep the original survival behavior.
        return Ok(declared_origin(&row.body)? != Some(CalendarOrigin::Dreamer));
    }
    Ok(live_origin_observed(store, store, txn, event, observer)? == Some(CalendarOrigin::Native))
}
