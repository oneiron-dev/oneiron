//! The apply's run tree (ARCH-0070 `shape:plan-apply`): one run-tree root
//! per apply and one child row per item, opened in the writer that opens
//! the journal. The rows are inert: each is placed on the shape's own worker
//! and paused, so no worker runs one. A child settles in the writer that
//! records its item. A landed item completes its row with a receipt
//! reference that resolves to the item's journal entry, and an item that
//! closes without landing cancels its row with the reason. A child waiting
//! for the owner's word stays paused. The root completes once no item is
//! open. The journal stays the source of truth; the tree is how an apply
//! reads among the vault's other runs.
use super::apply::{ShapeApplyItem, ShapeApplyReceipt, ShapeItemState};
use super::invalid;
use super::plan::ShapePlanItem;
use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptPlacement, AttemptQueue, AttemptResultRef,
    AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt, EnqueueOutcome,
    InterveneAttempt, SetAttemptResult,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::ports::JobQueue;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The kind of an apply's root row.
pub const SHAPE_APPLY_ATTEMPT_KIND: &str = "vault_shape.apply";
/// The kind of an item's row.
pub const SHAPE_ITEM_ATTEMPT_KIND: &str = "vault_shape.item";
/// The worker the rows are placed on, the lease owner that settles them and
/// the actor of their interventions: the shape's own apply.
const SHAPE_RUN_WORKER: &str = "vault_shape";
/// Every run id and receipt reference an apply mints starts with it.
const SHAPE_RUN_PREFIX: &str = "vault_shape:";
/// An intervention note's bound in the queue.
const SHAPE_RUN_NOTE_MAX_BYTES: usize = 2048;

/// An apply's run tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeApplyRun {
    /// The run id every row carries; it names the apply's journal.
    pub run_id: String,
    /// The root row, hex: the apply's inbox group key.
    pub root: String,
    /// Each item's row, hex, in `seq` order.
    pub items: Vec<String>,
}

/// The run id of the apply landing the plan at `frontier`; its root row
/// completes with it as its receipt reference.
fn shape_run_id(frontier: &str) -> String {
    format!("{SHAPE_RUN_PREFIX}{frontier}")
}

/// The receipt reference a landed item's row completes with. It resolves
/// to the item's journal entry through [`Vault::shape_item_receipt`].
#[must_use]
pub fn shape_item_ref(frontier: &str, seq: u32) -> String {
    format!("{SHAPE_RUN_PREFIX}{frontier}#{seq}")
}

fn row_hex(id: AttemptId) -> String {
    bytes_to_hex_lower(id.as_bytes())
}

fn row_id(hex: &str) -> Result<AttemptId> {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|at| {
            hex.get(at..at + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| invalid("an apply's run row id is not hex"))?;
    AttemptId::from_bytes(&bytes)
}

fn bounded(note: &str) -> String {
    let mut cut = note.len().min(SHAPE_RUN_NOTE_MAX_BYTES);
    while !note.is_char_boundary(cut) {
        cut -= 1;
    }
    note[..cut].to_owned()
}

fn intervene(
    queue: &AttemptQueue<'_>,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
    kind: AttemptInterventionKind,
    note: Option<String>,
    now: u64,
) -> Result<()> {
    queue.intervene_in_txn(
        txn,
        InterveneAttempt {
            id,
            kind,
            actor: SHAPE_RUN_WORKER.to_owned(),
            note,
            now,
        },
    )?;
    Ok(())
}

/// Enqueues one inert row of the run, placed on the shape's worker under
/// `parent`, and pauses it.
fn open_row(
    queue: &AttemptQueue<'_>,
    txn: &mut heed::RwTxn<'_>,
    kind: &str,
    run_id: &str,
    parent: Option<AttemptId>,
    payload: String,
    now: u64,
) -> Result<AttemptId> {
    let record = match queue.port_job_enqueue(
        txn,
        EnqueueAttempt {
            kind: kind.to_owned(),
            payload: payload.into_bytes(),
            dedupe_key: None,
            run_id: Some(run_id.to_owned()),
            now,
        },
    )? {
        EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record) => record,
    };
    queue.place_in_txn(
        txn,
        record.id,
        AttemptPlacement {
            worker: Some(SHAPE_RUN_WORKER.to_owned()),
            parent,
        },
    )?;
    intervene(
        queue,
        txn,
        record.id,
        AttemptInterventionKind::Pause,
        None,
        now,
    )?;
    Ok(record.id)
}

/// Completes a row with `reference`. A row already settled, or pruned, is
/// left as it is; a row the claim does not hand over stays paused. Either
/// way the journal still says how its item landed.
fn complete_row(
    queue: &AttemptQueue<'_>,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
    reference: String,
    now: u64,
) -> Result<()> {
    let Some(record) = queue.get_in_write_txn(txn, id)? else {
        return Ok(());
    };
    match record.state {
        AttemptState::Paused => {
            intervene(queue, txn, id, AttemptInterventionKind::Resume, None, now)?;
        }
        AttemptState::Queued => {}
        _ => return Ok(()),
    }
    let claimed = match queue.claim_id_in_txn(
        txn,
        id,
        ClaimAttempt {
            lease_owner: SHAPE_RUN_WORKER.to_owned(),
            now: u64::MAX,
        },
    )? {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => {
            return intervene(queue, txn, id, AttemptInterventionKind::Pause, None, now);
        }
    };
    queue.set_result_in_txn(
        txn,
        SetAttemptResult {
            id,
            lease_owner: SHAPE_RUN_WORKER.to_owned(),
            attempt_count: claimed.attempt_count,
            result_ref: AttemptResultRef::new(reference)?,
            now,
        },
    )?;
    queue.complete_in_txn(
        txn,
        CompleteAttempt {
            id,
            lease_owner: SHAPE_RUN_WORKER.to_owned(),
            attempt_count: claimed.attempt_count,
            now,
        },
    )?;
    Ok(())
}

/// Cancels a row whose item closed without landing, noting why.
fn cancel_row(
    queue: &AttemptQueue<'_>,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
    note: &str,
    now: u64,
) -> Result<()> {
    let Some(record) = queue.get_in_write_txn(txn, id)? else {
        return Ok(());
    };
    if !matches!(
        record.state,
        AttemptState::Queued | AttemptState::Paused | AttemptState::Scheduled
    ) {
        return Ok(());
    }
    let note = Some(bounded(note)).filter(|note| !note.trim().is_empty());
    intervene(queue, txn, id, AttemptInterventionKind::Cancel, note, now)
}

impl Vault {
    /// Opens the run tree of the apply landing `items` at `frontier`, in
    /// the caller's writer: a root and one child per item, each inert.
    pub(super) fn open_shape_run_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        frontier: &str,
        items: &[ShapePlanItem],
        now: u64,
    ) -> Result<ShapeApplyRun> {
        let queue = AttemptQueue::new(self);
        let run_id = shape_run_id(frontier);
        let root = open_row(
            &queue,
            txn,
            SHAPE_APPLY_ATTEMPT_KIND,
            &run_id,
            None,
            run_id.clone(),
            now,
        )?;
        let mut rows = Vec::with_capacity(items.len());
        for item in items {
            let row = open_row(
                &queue,
                txn,
                SHAPE_ITEM_ATTEMPT_KIND,
                &run_id,
                Some(root),
                shape_item_ref(frontier, item.seq),
                now,
            )?;
            rows.push(row_hex(row));
        }
        Ok(ShapeApplyRun {
            run_id,
            root: row_hex(root),
            items: rows,
        })
    }

    /// Settles the rows of `journal`'s closed items, and its root once the
    /// apply is done, in the writer that records the journal. Settling a
    /// row twice changes nothing.
    pub(super) fn settle_shape_run_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        journal: &ShapeApplyReceipt,
        now: u64,
    ) -> Result<()> {
        let queue = AttemptQueue::new(self);
        for (entry, row) in journal.items.iter().zip(&journal.run.items) {
            let id = row_id(row)?;
            match &entry.state {
                ShapeItemState::Landed { .. } => complete_row(
                    &queue,
                    txn,
                    id,
                    shape_item_ref(&journal.frontier, entry.item.seq),
                    now,
                )?,
                ShapeItemState::Refused { reason } => cancel_row(&queue, txn, id, reason, now)?,
                ShapeItemState::Ceremony => cancel_row(
                    &queue,
                    txn,
                    id,
                    "an authority operation, for its AUTHORITY_LOG ceremony",
                    now,
                )?,
                ShapeItemState::NoDoor => {
                    cancel_row(&queue, txn, id, "the vault has no door for it yet", now)?;
                }
                ShapeItemState::Pending
                | ShapeItemState::Proposed
                | ShapeItemState::Filed { .. } => {}
            }
        }
        if journal.done {
            complete_row(
                &queue,
                txn,
                row_id(&journal.run.root)?,
                journal.run.run_id.clone(),
                now,
            )?;
        }
        Ok(())
    }

    /// The journal entry a shape receipt reference names, as a landed
    /// item's run row carries it. `None` for any other reference, or when
    /// the apply or the item is gone.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub fn shape_item_receipt(&self, reference: &str) -> Result<Option<ShapeApplyItem>> {
        let Some((frontier, seq)) = reference
            .strip_prefix(SHAPE_RUN_PREFIX)
            .and_then(|rest| rest.split_once('#'))
        else {
            return Ok(None);
        };
        let Ok(seq) = seq.parse::<u32>() else {
            return Ok(None);
        };
        Ok(self.shape_apply(frontier)?.and_then(|journal| {
            journal
                .items
                .into_iter()
                .find(|entry| entry.item.seq == seq)
        }))
    }
}
