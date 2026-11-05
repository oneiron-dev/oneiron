//! User-selected Art18 restriction and truthful prior-external-notice
//! attestation. Only the answer's owner-revalidated writer writes markers.

use super::{
    CooperativeDeletionAnswer, CooperativeRestrictionLiftAttestation, IncomingCooperativeDeletion,
};
use crate::side_table::{self, Named, SideTable};
use crate::store::legal_hold::{CooperativeRestriction, CooperativeRestrictionKey};
use crate::{EntityId, Result, Vault};
use heed::{RoTxn, RwTxn};

const RESTRICTIONS: SideTable<CooperativeRestrictionKey, CooperativeRestriction, Named> =
    SideTable::new(&side_table::COOPERATIVE_RESTRICTION);

/// `restricted` is the distinct, present, pact-covered selection from this
/// SAME writer. Prior restrictions are not implicitly lifted by a new answer.
pub(super) fn apply_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    pact: &[u8; 32],
    nonce: &[u8; 16],
    filed: &mut IncomingCooperativeDeletion,
    actor: EntityId,
    answer: &CooperativeDeletionAnswer,
    restricted: &[EntityId],
    now: u64,
) -> Result<()> {
    let mut lifted = Vec::new();
    for record in &answer.restriction_notice_given {
        // Keeping the same copy restricted is not a lift and gets no receipt.
        if restricted.contains(record) || lifted.contains(record) {
            continue;
        }
        let key = (*record, *pact, *nonce);
        if RESTRICTIONS.get(&vault.store, txn, &key)?.is_some() {
            RESTRICTIONS.delete(&vault.store, txn, &key)?;
            lifted.push(*record);
        }
    }
    if !lifted.is_empty() {
        filed
            .restriction_lifts
            .push(CooperativeRestrictionLiftAttestation {
                records: lifted,
                attested_by: actor,
                attested_at: now,
            });
    }
    for record in restricted {
        let key = (*record, *pact, *nonce);
        let prior = RESTRICTIONS.get(&vault.store, txn, &key)?;
        if prior.is_none() {
            crate::dreamer_consolidation::mark_person_about_dropped_in_txn(
                &vault.store,
                txn,
                record,
            )?;
        }
        let marker = CooperativeRestriction {
            since: prior.map_or(now, |prior| prior.since),
            reason_code: answer
                .reason_code
                .clone()
                .expect("checked non-delete reason"),
            review_at: answer.review_at.expect("checked non-delete review date"),
        };
        RESTRICTIONS.put(&vault.store, txn, &key, &marker)?;
        if !filed.courtesy_restriction_records.contains(record) {
            filed.courtesy_restriction_records.push(*record);
        }
    }
    Ok(())
}

impl Vault {
    /// Active restrictions from this ask, for its existing owner projection.
    pub(crate) fn courtesy_restrictions(
        &self,
        pact: &[u8; 32],
        nonce: &[u8; 16],
        records: &[EntityId],
    ) -> Result<Vec<(EntityId, CooperativeRestriction)>> {
        let txn = self.store.env.read_txn()?;
        restrictions_in(self, &txn, pact, nonce, records)
    }
}

fn restrictions_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    pact: &[u8; 32],
    nonce: &[u8; 16],
    records: &[EntityId],
) -> Result<Vec<(EntityId, CooperativeRestriction)>> {
    let mut rows = Vec::new();
    for record in records {
        if let Some(marker) = RESTRICTIONS.get(&vault.store, txn, &(*record, *pact, *nonce))? {
            rows.push((*record, marker));
        }
    }
    Ok(rows)
}
