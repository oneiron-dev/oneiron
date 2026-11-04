//! The retained calendar carriers an archived vault's custody fork needs.
use std::collections::BTreeSet;

use super::*;
use crate::store::Store;
use crate::store::key_custody::{self, CustodyPlan, Requirement};

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

struct CarrierRow {
    row_key: Vec<u8>,
    carrier: LiteralCarrier,
    kind: LiteralKind,
    key: [u8; 32],
    digest: [u8; 32],
}

fn carriers(rows: &Rows) -> crate::Result<Vec<CarrierRow>> {
    let mut carriers = Vec::new();
    for (row_key, value) in rows {
        let Some(key) = row_key.strip_prefix(side_table::CALENDAR_CONNECTOR_WRITE.prefix) else {
            continue;
        };
        if key.starts_with(OUTBOX_ROW_TAG) {
            let key = OutboxKey::decode_key(key).ok_or_else(literal::invalid)?;
            let stored = OUTBOX.decode_value(value)?;
            if stored.outbox_id != key.0 {
                return Err(literal::invalid());
            }
            let row = stored.into_row().map_err(|_| literal::invalid())?;
            carriers.push(CarrierRow {
                row_key: row_key.clone(),
                carrier: row.carrier.clone().ok_or_else(literal::invalid)?,
                kind: LiteralKind::Outbox,
                key: key.0,
                digest: outbox_digest(&row)?,
            });
        } else if key.starts_with(REMOTE_OBJECT_TAG) {
            let key = RemoteObjectKey::decode_key(key).ok_or_else(literal::invalid)?;
            let row = remote_projection(REMOTE_OBJECT.decode_value(value)?);
            carriers.push(CarrierRow {
                row_key: row_key.clone(),
                carrier: row.carrier.clone().ok_or_else(literal::invalid)?,
                kind: LiteralKind::Cursor,
                key: key.0,
                digest: cursor_digest(&row)?,
            });
        }
    }
    Ok(carriers)
}

/// Plans every current outbox and cursor, including closed outbox evidence.
/// A source-retired instance loses only its own row, as its removal did live.
pub(crate) fn plan_archived_calendar_rows(
    rows: &mut Rows,
    plan: &mut CustodyPlan,
) -> crate::Result<()> {
    let mut retired = BTreeSet::new();
    for row in carriers(rows)? {
        if row.carrier.plan(plan, row.kind)? == Requirement::Retired {
            retired.insert(row.row_key);
        }
    }
    rows.retain(|(key, _)| !retired.contains(key));
    Ok(())
}

/// Authenticates each kept carrier and its exact row geometry under the fork,
/// without returning literals or admitting transport work.
pub(crate) fn read_back_archived_calendar_rows(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    rows: &Rows,
) -> crate::Result<()> {
    let rows = carriers(rows)?;
    if rows.is_empty() {
        return Ok(());
    }
    let binding = key_custody::binding_in_txn(store, txn)?.ok_or_else(literal::invalid)?;
    for row in rows {
        row.carrier
            .read_back(&binding, row.kind, row.key, row.digest)?;
    }
    Ok(())
}
