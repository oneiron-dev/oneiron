//! Reverting a derivation batch (untangle 6.7c): each landed item is undone
//! only while every row it landed still stands at the revision the commit
//! recorded. An item changed since is left alone and listed, as every revert
//! of today leaves it. The committing actor may revert its own batch while
//! its derive verdict still stands; the owner may revert any batch
//! (decision C-2).

use serde::{Deserialize, Serialize};

use super::record::{AppliedEdge, ItemRecord, batch_record_in_txn};
use crate::claim::PREDICATE_CONFLICT_RESOLVED;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_promotion::KeptConflictLink;
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
///
/// An archive changes no byte of its claim: it stands in the claim's
/// cleanup-archive marker. So an `archive` item's revision also covers that
/// marker as stored (its request id and time included), and a claim that was
/// restored, or restored and archived again by a later act, no longer stands
/// at the revision its first archive left.
pub(super) fn row_revision_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kind: &str,
    row: EntityId,
) -> Result<[u8; 32]> {
    if kind == "person_about" {
        return crate::dreamer_consolidation::about_revision_in(vault, txn, row);
    }
    let stored = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &row)?
        .map_or([0; 32], |raw| *blake3::hash(&raw).as_bytes());
    if kind != "archive" {
        return Ok(stored);
    }
    let marker = crate::ports::TombstoneStoreRead::port_deletion_marker(
        &vault.store,
        txn,
        crate::ports::DeletionMarker::Archive,
        &row,
    )?;
    let mut revision = blake3::Hasher::new();
    revision.update(b"oneiron:derive-archive-revision:v1");
    revision.update(&stored);
    match marker {
        Some(marker) => {
            revision.update(&[1]);
            revision.update(&marker);
        }
        None => {
            revision.update(&[0]);
        }
    }
    Ok(*revision.finalize().as_bytes())
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
        let mut reverted_rows = std::collections::BTreeSet::new();
        for item in record.items.iter().rev().filter(|item| item.landed) {
            let read: &heed::RoTxn<'_> = txn;
            let mut current = Vec::with_capacity(item.rows.len());
            for row in &item.rows {
                current.push(row_revision_in(self, read, &item.kind, *row)?);
            }
            // The revert is one write transaction, and an item is taken back
            // only while each of its rows stands as recorded or as an undo of
            // this revert left it. So a row of an item already taken back
            // differs from its record only by this revert's own undo.
            if current.len() != item.revisions.len()
                || current.iter().zip(&item.revisions).zip(&item.rows).any(
                    |((current, recorded), row)| {
                        current != recorded && !reverted_rows.contains(row)
                    },
                )
            {
                left.push((item.local.clone(), REVERT_CHANGED_SINCE.to_owned()));
                continue;
            }
            let mut savepoint = self.store.env.nested_write_txn(txn)?;
            match self.undo_item_in_txn(&mut savepoint, &record.actor, reverter, item, now_ms) {
                Ok(true) => {
                    savepoint.commit()?;
                    reverted_rows.extend(item.rows.iter().copied());
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
                // The provenance retract takes Unix seconds, as the other
                // inverses here do.
                for record in &item.rows {
                    self.retract_edge_provenance_in_txn(txn, record, now_ms / 1_000, false)?;
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
            // A settlement's first row is its answer or its staged Keep.
            // Only a staged Keep linked to this item's marker is retracted.
            "settle" => {
                let staged = first()?;
                let claim = self
                    .get_claim_in_txn(txn, &staged)?
                    .ok_or(Error::EntityNotFound)?;
                if claim.predicate == PREDICATE_CONFLICT_RESOLVED {
                    crate::dreamer_consolidation::revert_settlement_in_txn(
                        self, txn, staged, reverter, now_ms,
                    )?;
                } else {
                    if !KeptConflictLink::of_claim(&claim)
                        .is_some_and(|link| item.rows.get(1) == Some(&link.marker))
                    {
                        return Err(Error::InvalidClaimBody(
                            "the staged Keep does not name this item's marker",
                        ));
                    }
                    self.retract_claim_in_txn_as(txn, &staged, now_ms / 1_000, Some(reverter))?;
                }
            }
            "archive" => {
                self.restore_archived_in_txn(txn, &first()?)?;
            }
            "same_as" => {
                crate::dreamer_consolidation::revert_authored_change_in_txn(
                    self,
                    txn,
                    first()?,
                    *author,
                    reverter,
                    now_ms,
                )?;
                if let Some(edge) = &item.applied_edge {
                    unlink_applied_edge_in_txn(self, txn, edge)?;
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

/// The revision of the SameAs edge `source` to `target` in `txn`: a digest
/// of the edge as stored, `None` when no such edge stands.
pub(super) fn same_as_edge_revision_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    target: EntityId,
) -> Result<Option<[u8; 32]>> {
    use crate::ports::EdgeStoreStaging;
    Ok(vault
        .store
        .port_edge_encoded(txn, &source, EdgeKind::SameAs, &target)?
        .map(|raw| *blake3::hash(&raw).as_bytes()))
}

/// Removes the SameAs edge a `same_as` item created, while it stands as the
/// commit left it. An edge that is gone, or that another writer has put
/// again or changed since, is not this item's to remove and stays.
fn unlink_applied_edge_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    edge: &AppliedEdge,
) -> Result<()> {
    if same_as_edge_revision_in(vault, txn, edge.source, edge.target)? != Some(edge.revision) {
        return Ok(());
    }
    crate::batch::apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        vec![crate::batch::BatchOp::DeleteEdge {
            src: edge.source,
            kind: EdgeKind::SameAs,
            tgt: edge.target,
        }],
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
