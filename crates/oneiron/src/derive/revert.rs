//! Reverting a derivation batch (untangle 6.7c): each landed item is undone
//! only while every row it landed still stands at the revision the commit
//! recorded. An item changed since is left alone and listed, as every revert
//! of today leaves it. The committing actor may revert its own batch while
//! its derive verdict still stands; the owner may revert any batch
//! (decision C-2).

use serde::{Deserialize, Serialize};

use super::record::{ItemRecord, batch_record_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::error::{Error, GateError, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::store::{GateDecisionContext, GateDecisionId, GateDecisionRecord};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// The gate decision ledger's content kind for a batch revert's receipt.
pub const DERIVE_REVERT_CONTENT_KIND: &str = "vault.derive.revert";

/// Why an item was left alone: a row it landed changed since the commit.
pub const REVERT_CHANGED_SINCE: &str = "derive.revert.changed_since";

/// Why an item was left alone: its kind has no inverse in a batch revert
/// (a PsychProfile snapshot, a topology judgment: the profile's next
/// snapshot and the topology ledger's own undo answer those).
pub const REVERT_NO_INVERSE: &str = "derive.revert.no_inverse";

/// Why an item was left alone: its inverse refused, so it stands.
pub const REVERT_INVERSE_REFUSED: &str = "derive.revert.inverse_refused";

/// The refusal of a revert by an actor that is neither the batch's
/// committing actor, with its derive verdict standing, nor the owner.
pub const REVERT_NOT_YOURS: &str = "gate.deny.derive.revert_not_yours";

/// What one batch revert did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeriveRevertReceipt {
    /// The batch.
    pub batch: EntityId,
    /// The items undone, by local name, in the order they were undone.
    pub reverted: Vec<String>,
    /// The items left standing, by local name, each with why.
    pub left: Vec<(String, String)>,
    /// The revert's receipt in the gate decision ledger.
    pub receipt: [u8; 16],
}

/// The revision of `row`, as an item of `kind` landed it, in `txn`: a digest
/// of the stored row, or of the PERSON's `about` row for an `about` item.
/// All zeros for a row that is gone.
pub(super) fn row_revision_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kind: &str,
    row: EntityId,
) -> Result<[u8; 32]> {
    if kind == "person_about" {
        return crate::dreamer_consolidation::about_revision_in(vault, txn, row);
    }
    Ok(
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &row)?
            .map_or([0; 32], |raw| *blake3::hash(&raw).as_bytes()),
    )
}

impl Vault {
    /// Reverts the derivation batch `batch` as `reverter`, or as the owner
    /// `owner` proves (untangle 6.7c). Each landed item, last first, is undone
    /// in a savepoint of one write while every row it landed still stands at
    /// its recorded revision; an item changed since, one whose kind has no
    /// inverse here, or one whose inverse refuses is left standing and
    /// listed. The revert keeps its own receipt.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for a batch that is not recorded, the gate's
    /// refusal ([`REVERT_NOT_YOURS`]) for a reverter that may not revert it,
    /// an owner proof that no longer holds, and storage errors.
    pub fn derive_revert(
        &self,
        reverter: WriteActor,
        owner: Option<&AuthenticatedOwner>,
        batch: EntityId,
    ) -> Result<DeriveRevertReceipt> {
        self.with_write_txn_grouped(|txn| self.derive_revert_in_txn(txn, reverter, owner, batch))
    }

    fn derive_revert_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        reverter: WriteActor,
        owner: Option<&AuthenticatedOwner>,
        batch: EntityId,
    ) -> Result<DeriveRevertReceipt> {
        let record = batch_record_in_txn(self, txn, batch)?.ok_or(Error::EntityNotFound)?;
        let allowed = match owner {
            Some(owner) => owner.revalidate_in_txn(self, txn)? == reverter.entity_ref(),
            None => {
                reverter.entity_ref() == record.actor
                    && derive_verdict_in_txn(
                        &self.store,
                        txn,
                        reverter,
                        DeriveCapability::Derive,
                        None,
                    )?
                    .is_ok()
            }
        };
        if !allowed {
            return Err(Error::Gate(GateError::GateWriteRejected {
                outcome: "deny",
                reason_codes: vec![REVERT_NOT_YOURS],
            }));
        }
        let now_ms = crate::ports::recorded_at_in_txn(&self.store, txn)?.saturating_mul(1_000);
        let mut reverted = Vec::new();
        let mut left = Vec::new();
        for item in record.items.iter().rev().filter(|item| item.landed) {
            let read: &heed::RoTxn<'_> = txn;
            let mut current = Vec::with_capacity(item.rows.len());
            for row in &item.rows {
                current.push(row_revision_in(self, read, &item.kind, *row)?);
            }
            if current != item.revisions {
                left.push((item.local.clone(), REVERT_CHANGED_SINCE.to_owned()));
                continue;
            }
            let mut savepoint = self.store.env.nested_write_txn(txn)?;
            match self.undo_item_in_txn(&mut savepoint, &record.actor, reverter, item, now_ms) {
                Ok(true) => {
                    savepoint.commit()?;
                    reverted.push(item.local.clone());
                }
                Ok(false) => {
                    savepoint.abort();
                    left.push((item.local.clone(), REVERT_NO_INVERSE.to_owned()));
                }
                Err(error @ (Error::Storage(_) | Error::Io(_) | Error::MapFull)) => {
                    return Err(error);
                }
                Err(_) => {
                    savepoint.abort();
                    left.push((item.local.clone(), REVERT_INVERSE_REFUSED.to_owned()));
                }
            }
        }
        let receipt = revert_receipt(
            self,
            txn,
            reverter,
            batch,
            !reverted.is_empty(),
            now_ms / 1_000,
        )?;
        Ok(DeriveRevertReceipt {
            batch,
            reverted,
            left,
            receipt,
        })
    }

    /// Undoes one landed item in `txn`. `false` when its kind has no inverse
    /// here.
    fn undo_item_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        author: &EntityId,
        reverter: WriteActor,
        item: &ItemRecord,
        now_ms: u64,
    ) -> Result<bool> {
        let first = || {
            item.rows
                .first()
                .copied()
                .ok_or(Error::InvariantViolation("a landed item names no row"))
        };
        match item.kind.as_str() {
            // A claim, and a person's `about` landing: the Dreamer's own
            // per-row inverse, for this batch's author.
            "claim" | "person_about" => {
                crate::dreamer_consolidation::revert_authored_change_in_txn(
                    self,
                    txn,
                    first()?,
                    *author,
                    reverter,
                    now_ms,
                )?;
            }
            "evidence" => {
                for record in &item.rows {
                    self.retract_edge_provenance_in_txn(txn, record, now_ms, false)?;
                }
            }
            "supersede" => {
                let [new, old] = item.rows.as_slice() else {
                    return Err(Error::InvariantViolation("a supersession names two rows"));
                };
                if !self.restore_superseded_claim_in_txn(txn, new, old, now_ms / 1_000)? {
                    return Err(Error::InvalidClaimBody("the superseded claim stays closed"));
                }
            }
            "settle" => {
                crate::dreamer_consolidation::revert_settlement_in_txn(
                    self,
                    txn,
                    first()?,
                    reverter,
                    now_ms,
                )?;
            }
            "archive" => {
                self.restore_archived_in_txn(txn, &first()?)?;
            }
            "same_as" => {
                let status = first()?;
                let body = self
                    .get_claim_in_txn(txn, &status)?
                    .ok_or(Error::EntityNotFound)?;
                crate::dreamer_consolidation::revert_authored_change_in_txn(
                    self, txn, status, *author, reverter, now_ms,
                )?;
                if let crate::claim::ClaimSubject::Edge { source, target, .. } = body.subject {
                    unlink_same_as_in_txn(self, txn, source, target)?;
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

/// Removes the SameAs edge between `source` and `target`, both
/// orientations, when it stands.
fn unlink_same_as_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: EntityId,
    target: EntityId,
) -> Result<()> {
    use crate::ports::EdgeStoreRead;
    let mut ops = Vec::new();
    for (from, to) in [(source, target), (target, source)] {
        if vault
            .store
            .port_edge_get(txn, &from, EdgeKind::SameAs, &to)?
            .is_some()
        {
            ops.push(crate::batch::BatchOp::DeleteEdge {
                src: from,
                kind: EdgeKind::SameAs,
                tgt: to,
            });
        }
    }
    if ops.is_empty() {
        return Ok(());
    }
    crate::batch::apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        ops,
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    Ok(())
}

fn revert_receipt(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reverter: WriteActor,
    batch: EntityId,
    any: bool,
    now: u64,
) -> Result<[u8; 16]> {
    let frontier = crate::gate::resolve_policy_manifest(&vault.store, txn)?.read_frontier_hash()?;
    let record = GateDecisionRecord {
        version: crate::store::GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::now(),
        created_at: now,
        outcome: "approved".to_owned(),
        reason_codes: vec![
            if any {
                "gate.allow.derive.revert"
            } else {
                "gate.allow.derive.revert_left_all"
            }
            .to_owned(),
        ],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: reverter.actor_class().gate_actor_class().to_owned(),
        actor_ref: Some(reverter.entity_ref().to_hex()),
        content_kind: DERIVE_REVERT_CONTENT_KIND.to_owned(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: None,
        grant_ref: None,
        diff_handle: batch.as_bytes().to_vec(),
        read_frontier_hash: frontier,
        context: GateDecisionContext::default(),
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(txn, &record)?;
    Ok(record.decision_id.as_bytes())
}
