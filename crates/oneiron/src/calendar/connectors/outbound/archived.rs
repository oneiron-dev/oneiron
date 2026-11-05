//! The retained calendar carriers an archived vault's custody fork needs.
use std::collections::BTreeSet;

use super::*;
use crate::store::{
    CustodyForkRequirement as Requirement, CustodyPlan, Store, custody_binding_in_txn,
};

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

struct CarrierRow {
    row_key: Vec<u8>,
    carrier: LiteralCarrier,
    kind: LiteralKind,
    key: [u8; 32],
    digest: [u8; 32],
}

/// Only source-live rows require readback; an already unavailable row stays sealed.
pub(crate) struct PlannedCalendarRows {
    live: Vec<CarrierRow>,
}

fn carrier(row_key: &[u8], value: &[u8]) -> crate::Result<Option<CarrierRow>> {
    let Some(key) = row_key.strip_prefix(side_table::CALENDAR_CONNECTOR_WRITE.prefix) else {
        return Ok(None);
    };
    let row = if key.starts_with(OUTBOX_ROW_TAG) {
        let key = OutboxKey::decode_key(key).ok_or_else(literal::invalid)?;
        let stored = OUTBOX.decode_value(value)?;
        if stored.outbox_id != key.0 {
            return Err(literal::invalid());
        }
        let row = stored.into_row().map_err(|_| literal::invalid())?;
        CarrierRow {
            row_key: row_key.to_vec(),
            carrier: row.carrier.clone().ok_or_else(literal::invalid)?,
            kind: LiteralKind::Outbox,
            key: key.0,
            digest: outbox_digest(&row)?,
        }
    } else if key.starts_with(REMOTE_OBJECT_TAG) {
        let key = RemoteObjectKey::decode_key(key).ok_or_else(literal::invalid)?;
        let row = remote_projection(REMOTE_OBJECT.decode_value(value)?);
        CarrierRow {
            row_key: row_key.to_vec(),
            carrier: row.carrier.clone().ok_or_else(literal::invalid)?,
            kind: LiteralKind::Cursor,
            key: key.0,
            digest: cursor_digest(&row)?,
        }
    } else {
        return Ok(None);
    };
    Ok(Some(row))
}

/// Plans every current outbox and cursor, including closed outbox evidence.
/// Only a proved retirement drops its own row; absent or faulty custody stays unavailable.
pub(crate) fn plan_archived_calendar_rows(
    rows: &mut Rows,
    plan: &mut CustodyPlan,
) -> crate::Result<PlannedCalendarRows> {
    let mut retired = BTreeSet::new();
    let mut live = Vec::new();
    for (key, value) in rows.iter() {
        let row = match carrier(key, value) {
            Ok(Some(row)) => row,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "an unavailable archived calendar row remains sealed"
                );
                continue;
            }
        };
        match row.carrier.plan(plan, row.kind) {
            Ok(Some(Requirement::Live)) => live.push(row),
            Ok(Some(Requirement::Retired)) => {
                retired.insert(row.row_key);
            }
            Ok(None) => {
                tracing::warn!("an archived calendar carrier has no source key; it remains sealed")
            }
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "an archived calendar carrier could not be planned; it remains sealed"
            ),
        }
    }
    rows.retain(|(key, _)| !retired.contains(key));
    Ok(PlannedCalendarRows { live })
}

/// A source-live carrier must authenticate under the fork, never be demoted to pending.
/// Failure leaves the archive and its old binding unchanged through the caller's rollback.
pub(crate) fn read_back_archived_calendar_rows(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    planned: &PlannedCalendarRows,
) -> crate::Result<()> {
    if planned.live.is_empty() {
        return Ok(());
    }
    let binding = custody_binding_in_txn(store, txn)?.ok_or_else(literal::invalid)?;
    for row in &planned.live {
        row.carrier
            .read_back(&binding, row.kind, row.key, row.digest)?;
    }
    Ok(())
}
