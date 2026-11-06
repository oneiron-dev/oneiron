//! Original-input witnesses qualified under the receipt reader's own policy.

use serde::{Deserialize, Serialize};

use super::{ReceiptScan, SourcedTeamReceipt, stored_receipts_in_txn};
use crate::claim::{
    ClaimBody, ClaimLifecycleStatus, PointRead, ReadRow, ScopedRead, decode_claim_body,
};
use crate::skill_optimize::union_source_rows;
use crate::team::run::{INPUT_PREDICATE, TeamRecordInput};
use crate::write_envelope::claim_body::encode_claim_body;
use crate::{EntityId, Error, Result};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TeamInputSource {
    claim: EntityId,
    body_hash: [u8; 32],
}

impl TeamInputSource {
    pub(crate) fn captured(claim: EntityId, body: &ClaimBody) -> Result<Self> {
        Ok(Self {
            claim,
            body_hash: *blake3::hash(&encode_claim_body(body)?).as_bytes(),
        })
    }

    fn admitted(&self, row: Option<ReadRow>, team_ref: &str) -> Option<EntityId> {
        let row = row?;
        if row.id != self.claim || row.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return None;
        }
        let body = decode_claim_body(row.body.as_deref()?, true).ok()?;
        if body.predicate != INPUT_PREDICATE
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.stale
            || *blake3::hash(&encode_claim_body(&body).ok()?).as_bytes() != self.body_hash
        {
            return None;
        }
        let input: TeamRecordInput = serde_json::from_str(body.value.as_str()?).ok()?;
        (input.team_ref == team_ref).then_some(self.claim)
    }
}

/// Keeps the receipt's original-input witness only after this reader admits its
/// exact captured body. Other unknown receipt cohorts remain unknown.
pub(crate) fn team_receipts_sourced_for_reader(
    reader: &ScopedRead<'_>,
    type_ref: Option<&crate::receipt::task_type_ref::TypeRef>,
) -> Result<Vec<SourcedTeamReceipt>> {
    let vault = reader.vault();
    let _bodies = crate::store::ASSET_FILE_PLANE.then(|| vault.pin_all_result_bodies());
    let clock_ready = reader.persist_grant_clock().is_ok();
    let txn = vault.store.env.read_txn()?;
    let stored = stored_receipts_in_txn(vault, &txn, ReceiptScan::AllScopes(type_ref))?;
    let reads: Vec<_> = stored
        .iter()
        .flat_map(|row| {
            row.input_source
                .as_ref()
                .map(|source| PointRead::id(source.claim))
                .into_iter()
                .chain(
                    row.team_start_source
                        .as_ref()
                        .map(|source| PointRead::id(source.claim())),
                )
        })
        .collect();
    // Input capture is optional. Its qualification errors cannot reject a
    // receipt that the ordinary reader would have returned.
    let admitted = if clock_ready && !reads.is_empty() {
        reader
            .read_projected_in_txn(&txn, &reads, None, |_, rows| Ok::<_, Error>(rows))
            .ok()
            .map(|read| read.value)
    } else {
        None
    };
    let mut admitted = admitted.unwrap_or_default().into_iter();
    Ok(stored
        .into_iter()
        .map(|stored| {
            let input = stored.input_source.as_ref().map(|source| {
                source
                    .admitted(admitted.next().flatten(), &stored.receipt.team_ref)
                    .map(|id| vec![id])
            });
            let start = stored.team_start_source.as_ref().map(|source| {
                source
                    .admitted_in_txn(
                        vault,
                        &txn,
                        admitted.next().flatten(),
                        &stored.receipt.team_ref,
                    )
                    .map(|id| vec![id])
            });
            let (receipt, rows) = stored.sourced();
            let rows = match input {
                None => rows,
                Some(input) => union_source_rows([rows.as_deref(), input.as_deref()]),
            };
            let rows = match start {
                None => rows,
                Some(start) => union_source_rows([rows.as_deref(), start.as_deref()]),
            };
            (receipt, rows)
        })
        .collect())
}
