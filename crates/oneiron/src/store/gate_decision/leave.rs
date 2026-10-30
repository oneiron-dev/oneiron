//! The gate-decision rows a left environment's purge keeps (FIX 8851): the
//! decisions of the partitions a standing legal hold names, a bundle's when
//! it cites a held claim, and the side rows those decisions stand on. A hold
//! on one partition keeps no other partition's decisions. Planned in the
//! purge's transaction before its first deletion; nothing is written.

use std::collections::HashSet;

use heed::RoTxn;

use super::ledger::{LEDGER, decode_gate_decision};
use super::orcb;
use super::types::GateDecisionId;
use crate::error::Result;
use crate::side_table::{self, SideKey, SideTableDecl};
use crate::store::{Store, legal_hold};

/// One gate-decision key partition: a claim's, or (`None`) the claim-free
/// one.
type Partition = Option<[u8; 16]>;

/// The gate families whose key ends in its decision's id: the primary, its
/// retention context, bundle refs and preflight marker by the id alone; the
/// claim, claim-ref and grant-ref indexes and the pending scrub after their
/// other components.
static DECISION_KEYED: &[&SideTableDecl] = &[
    &side_table::GATE_DECISION_LEDGER,
    &side_table::GATE_DECISION_RETENTION_CONTEXT,
    &side_table::GATE_DECISION_CLAIM_REFS,
    &side_table::GATE_DECISION_UNAPPLIED_PREFLIGHT,
    &side_table::GATE_DECISION_CLAIM_INDEX,
    &side_table::GATE_DECISION_CLAIM_REF_INDEX,
    &side_table::GATE_DECISION_GRANT_REF_INDEX,
    &side_table::GATE_DECISION_PENDING_SCRUB,
];

/// The gate-decision rows a leave keeps.
#[derive(Default)]
pub(in crate::store) struct HeldGateRows {
    /// The partitions a standing hold names.
    partitions: HashSet<Partition>,
    /// The decisions kept: a held partition's, a bundle's that cites a held
    /// claim, and one whose row shows no partition (keeping is safe).
    decisions: HashSet<[u8; 16]>,
}

impl HeldGateRows {
    /// Whether the `vault_meta` row `key` is a gate-decision row this leave
    /// keeps: a kept decision's row, or a held partition's claim context or
    /// retain-until stamp. `false` for every other key.
    pub(in crate::store) fn keeps(&self, key: &[u8]) -> bool {
        if self.partitions.is_empty() {
            return false;
        }
        for decl in DECISION_KEYED {
            if let Some(rest) = key.strip_prefix(decl.prefix) {
                return rest
                    .len()
                    .checked_sub(16)
                    .and_then(|at| <[u8; 16]>::try_from(&rest[at..]).ok())
                    .is_some_and(|id| self.decisions.contains(&id));
            }
        }
        if let Some(claim) = key.strip_prefix(side_table::GATE_DECISION_CLAIM_CONTEXT.prefix) {
            return <[u8; 16]>::try_from(claim)
                .is_ok_and(|claim| self.partitions.contains(&Some(claim)));
        }
        if let Some(partition) =
            key.strip_prefix(side_table::GATE_DECISION_PARTITION_RETAIN_UNTIL.prefix)
        {
            return match partition.split_first() {
                Some((&0, [])) => self.partitions.contains(&None),
                Some((&1, claim)) => <[u8; 16]>::try_from(claim)
                    .is_ok_and(|claim| self.partitions.contains(&Some(claim))),
                _ => false,
            };
        }
        false
    }
}

impl Store {
    /// The gate-decision rows a left environment's purge keeps, read whole
    /// before it deletes a row. The partitions are those a standing customer
    /// or host-order hold names; a lifted hold names none. A decision is kept
    /// when its own partition is held, read from its row without a key (an
    /// encrypted row's header, a plain row's claim), or when its bundle refs
    /// cite a held claim. A row that shows no partition, or whose refs do
    /// not read, is kept too. A decision that names no claim is kept only
    /// while the claim-free partition is held.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(in crate::store) fn held_gate_rows_in_txn(&self, txn: &RoTxn<'_>) -> Result<HeldGateRows> {
        let mut held = HeldGateRows::default();
        for hold in legal_hold::holds_in_txn(self, txn)? {
            if hold.stands() {
                held.partitions.extend(
                    hold.targets
                        .iter()
                        .map(|target| target.id().map(|id| *id.as_bytes())),
                );
            }
        }
        if held.partitions.is_empty() {
            return Ok(held);
        }
        for row in LEDGER.iter_raw_from(self, txn, &[])? {
            let (key, raw) = row?;
            let Some(id) = GateDecisionId::decode_key(&key) else {
                continue;
            };
            let kept = match partition_of(&raw) {
                Some(partition) => {
                    held.partitions.contains(&partition)
                        || self.cites_held_claim(txn, id, &held.partitions)
                }
                None => true,
            };
            if kept {
                held.decisions.insert(id.as_bytes());
            }
        }
        Ok(held)
    }

    /// Whether `id`'s bundle refs cite a held claim; `true` when they do not
    /// read.
    fn cites_held_claim(
        &self,
        txn: &RoTxn<'_>,
        id: GateDecisionId,
        partitions: &HashSet<Partition>,
    ) -> bool {
        self.gate_decision_claim_refs_in_txn(txn, id)
            .map_or(true, |refs| {
                refs.into_iter()
                    .any(|claim| partitions.contains(&Some(claim)))
            })
    }
}

/// The partition a stored ledger value names, read without a key: an
/// encrypted row's header, a claim-free policy row's, or a plain row's
/// claim. `None` when the row shows none.
fn partition_of(raw: &[u8]) -> Option<Partition> {
    if orcb::is_policy_sealed(raw) {
        return Some(None);
    }
    if orcb::is_orcb(raw) {
        return orcb::raw_claim_generation(raw).map(|(claim, _)| Some(claim));
    }
    decode_gate_decision(raw).ok().map(|record| record.claim_id)
}
