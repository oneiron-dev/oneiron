//! Where a resident dreaming lands: its diary entry, every part of it,
//! its proposed craft notes, its landing marker and the progress it read,
//! in one grouped write.

use super::{DreamCut, LANDED, PADS, PROGRESS, READ, ResidentDreamRead, advance, invalid};
use crate::actor_claims::ResidentCraftCandidate;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::FreeTimeItemBinding;
use crate::dreamer_wake::WakeAttemptContext;
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::{EntityId, Vault, WriteActor};

/// What one dreaming's reply lands: its entry, its craft notes, and the
/// free-time item it ran as, if any.
pub(super) struct DreamWrite<'a> {
    pub(super) entry: &'a str,
    pub(super) craft: &'a [ResidentCraftCandidate],
    pub(super) free_time: &'a Option<FreeTimeItemBinding>,
}

/// Lands one dreaming in one grouped write; a replay after it landed
/// writes nothing.
pub(super) fn commit_dream(
    ctx: &WakeAttemptContext<'_>,
    attempt_id: AttemptId,
    resident: WriteActor,
    resident_id: EntityId,
    write: DreamWrite<'_>,
    cut: &DreamCut,
    now: u64,
) -> Result<()> {
    let DreamWrite {
        entry,
        craft,
        free_time,
    } = write;
    ctx.vault.with_write_txn_grouped(|txn| {
        if LANDED.contains(&ctx.vault.store, txn, &attempt_id)? {
            return Ok(());
        }
        let at = crate::ports::recorded_at_in_txn(&ctx.vault.store, txn)?;
        let entry_id = append_diary_entry_in_txn(ctx.vault, txn, resident, entry, at)
            .map_err(|error| invalid(&format!("diary entry: {error}")))?;
        propose_craft_notes_in_txn(ctx.vault, txn, resident_id, attempt_id, craft, at)?;
        LANDED.put(&ctx.vault.store, txn, &attempt_id, &entry_id)?;
        READ.put(
            &ctx.vault.store,
            txn,
            &entry_id,
            &ResidentDreamRead {
                attempt: attempt_id,
                sources: cut.read.clone(),
            },
        )?;
        if let Some(binding) = free_time {
            crate::dreamer_runner::record_own_time_landed_in_txn(ctx.vault, txn, binding, at)?;
        }
        for pad in &cut.pads {
            PADS.put(&ctx.vault.store, txn, &(resident_id, *pad), &[1])?;
        }
        let mut progress = PROGRESS
            .get(&ctx.vault.store, txn, &resident_id)?
            .unwrap_or_default();
        advance(
            &mut progress.receipts_after,
            &mut progress.receipt_after_id,
            cut.receipts_after.as_ref(),
        );
        advance(
            &mut progress.inbox_after,
            &mut progress.inbox_after_id,
            cut.inbox_after.as_ref(),
        );
        advance(
            &mut progress.health_after,
            &mut progress.health_after_id,
            cut.health_after.as_ref(),
        );
        advance(
            &mut progress.fork_health_after,
            &mut progress.fork_health_after_id,
            cut.fork_health_after.as_ref(),
        );
        // A part read moves its input's offset on; an input read to its end
        // (a pad marked read, a row the cursor passed) has none left.
        if let Some(partial) = &cut.pad_partial {
            progress.pad_partial = Some(partial.clone());
        } else if progress
            .pad_partial
            .as_ref()
            .is_some_and(|partial| cut.pads.iter().any(|pad| pad.to_hex() == partial.id))
        {
            progress.pad_partial = None;
        }
        if let Some(partial) = &cut.inbox_partial {
            progress.inbox_partial = Some(partial.clone());
        } else if progress.inbox_partial.as_ref().is_some_and(|partial| {
            (progress.inbox_after, progress.inbox_after_id.as_str())
                >= (partial.at, partial.id.as_str())
        }) {
            progress.inbox_partial = None;
        }
        progress.dreamed_at = now;
        progress.entries += 1;
        PROGRESS.put(&ctx.vault.store, txn, &resident_id, &progress)
    })?;
    Ok(())
}

/// Lands `entry` in `resident`'s diary in the caller's write. Past the NOTE
/// body bound it lands as ordered private parts, each continuation linked
/// `Mentions` to the first, as an imported note's parts are. Returns the
/// first part.
fn append_diary_entry_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    resident: WriteActor,
    entry: &str,
    at: u64,
) -> Result<EntityId> {
    let mut parts = Vec::new();
    for part in super::super::note_parts::parts(entry, crate::note::MAX_NOTE_BYTES) {
        parts.push(crate::memory::append_agent_diary_in_txn(
            vault,
            txn,
            resident,
            part.to_owned(),
            at,
        )?);
    }
    let (&first, continuations) = parts
        .split_first()
        .ok_or_else(|| invalid("the entry landed no note"))?;
    if !continuations.is_empty() {
        let mut batch = vault.batch_in();
        for part in continuations {
            batch = batch.edge(part, EdgeKind::Mentions, &first, 1.0);
        }
        let mut content = crate::federation::ActorContentTxn::new(vault, txn, resident)?;
        content.apply_batch(batch)?;
        content.finish()?;
    }
    Ok(first)
}

/// Lands a dreaming's craft notes as Proposed candidates on the resident
/// (OF-490), in the entry's write. The notes write in their own savepoint:
/// a refusal rolls back alone, is logged, and the entry still lands.
fn propose_craft_notes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    resident: EntityId,
    attempt: crate::attempt_queue::AttemptId,
    craft: &[ResidentCraftCandidate],
    at: u64,
) -> Result<()> {
    if craft.is_empty() {
        return Ok(());
    }
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match crate::actor_claims::write_resident_craft_candidates_in_txn(
        vault,
        &mut savepoint,
        resident,
        attempt,
        craft,
        at,
    ) {
        Ok(_) => savepoint.commit()?,
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            ?attempt,
            "a resident's dreaming craft notes were not proposed"
        ),
    }
    Ok(())
}
