//! The native fact-run completion, prepared before the writer and applied in it.

use std::borrow::Cow;

use crate::receipt::hex_lower;
use crate::runtime_hooks::apply;
use crate::runtime_hooks::block::{self, HookBlock};
use crate::runtime_hooks::lineage::{self, HookCheck, LineageLink};
use crate::runtime_hooks::outcome::HookOutcome;
use crate::runtime_hooks::store::{
    self, HookIntent, HookIntentState, HookRunRecord, HookRunRef, RunKey,
};
use crate::{EntityId, Result, Vault};

use super::body::receipt;
use super::{Pass, Run, Verdict, block_id};

/// The native completion's pre-writer values. Applying it owns no transaction
/// boundary; the caller keeps its admission through its actual commit.
pub(super) struct PreparedRunCommit<'run, 'binding> {
    run: &'run Run<'binding>,
    verdict: &'run Verdict,
    key: RunKey,
    queued: bool,
    proposal: Option<EntityId>,
    added: Option<(EntityId, HookBlock)>,
    rows_read: usize,
    duration_ms: u64,
    now: u64,
    link: LineageLink,
    memo: HookRunRecord,
    at: u64,
}

impl<'run, 'binding> PreparedRunCommit<'run, 'binding> {
    pub(super) fn prepare(
        run: &'run Run<'binding>,
        memo: HookRunRecord,
        verdict: &'run Verdict,
        at: u64,
    ) -> Result<Self> {
        let key = run.key;
        let queued = verdict.outcome.as_ref().is_some_and(HookOutcome::is_queued);
        let proposal = match &verdict.outcome {
            Some(HookOutcome::Propose { .. }) => Some(apply::proposal_id(&key)?),
            _ => None,
        };
        let added = match &verdict.outcome {
            Some(HookOutcome::AddBlock { block }) => Some((
                block_id(&key)?,
                HookBlock::from_request(
                    run.binding_id,
                    format!("{}/{}", run.binding.pack, run.binding.hook),
                    hex_lower(&key),
                    block,
                    at,
                    None,
                )?,
            )),
            _ => None,
        };
        let rows_read = memo.reads.iter().map(|pin| pin.rows.len()).sum::<usize>();
        let (duration_ms, now) = (memo.duration_ms, memo.now);
        let link = LineageLink {
            binding: run.binding_id,
            run_key: hex_lower(&key),
            entity: run.entry.entity,
            position: run.entry.position.hex(),
        };
        let memo = HookRunRecord {
            committed_at: at.saturating_mul(1_000),
            ..memo
        };
        Ok(Self {
            run,
            verdict,
            key,
            queued,
            proposal,
            added,
            rows_read,
            duration_ms,
            now,
            link,
            memo,
            at,
        })
    }

    /// Returns whether an intent waits and whether a lineage check was raised.
    /// Report those results only after the caller's writer commits.
    pub(super) fn apply_in_txn(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<(bool, bool)> {
        let Self {
            run,
            verdict,
            key,
            mut queued,
            proposal,
            added,
            rows_read,
            duration_ms,
            now,
            link,
            mut memo,
            at,
        } = self;
        // A body that ran across a permanent erase keeps its content-free
        // run identity, never erased bytes, an erased actor or a pending
        // effect; an input naming an erased row retires it too (FIX 22240).
        let erased = store::scrub_erased_memo_in_txn(vault, txn, &mut memo, run.entry.actor)?
            || store::dependencies_erased_in_txn(vault, txn, &memo.derivation.dependencies)?;
        if erased {
            store::scrub_memo_payload(&mut memo);
            queued = false;
            if let Some(mut intent) = store::INTENTS.get(&vault.store, txn, &key)? {
                store::scrub_intent_payload(&mut intent, at);
                store::INTENTS.put(vault, txn, &key, &intent)?;
            }
        }
        let due_at = run.entry.tick.as_ref().map(|tick| tick.due_at);
        let (chain, check) =
            lineage::run_chain_in_txn(vault, txn, &run.entry.entity, link, due_at)?;
        if let Some(reason) = check {
            let raised = HookCheck {
                binding: run.binding_id,
                run_key: hex_lower(&key),
                reason,
                chain: chain.clone(),
                raised_at: at,
            };
            lineage::raise_check_in_txn(vault, txn, &key, &raised)?;
        }
        if !erased {
            if let Some((id, added)) = &added {
                // A block naming a row a permanent erase fenced lands expired
                // and cleared, as the erase's scrub leaves one (FIX 22191).
                let mut added = Cow::Borrowed(added);
                if block::names_erased_in_txn(vault, txn, &added)? {
                    block::scrub_block_payload(added.to_mut(), at);
                }
                block::put_block_in_txn(vault, txn, *id, &added)?;
                lineage::put_in_txn(vault, txn, id.as_bytes(), &chain)?;
            }
            if let Some(id) = proposal {
                lineage::put_in_txn(vault, txn, id.as_bytes(), &chain)?;
            }
        }
        if queued {
            let intent = HookIntent {
                dependencies: memo.derivation.dependencies.clone(),
                binding: run.binding_id,
                author: run.binding.author_id(),
                outcome_json: verdict.outcome_json.clone().unwrap_or_default(),
                lineage: chain,
                state: HookIntentState::Pending,
                landed: None,
                reason: None,
                created_at: at,
                settled_at: None,
            };
            store::INTENTS.put(vault, txn, &key, &intent)?;
        }
        let previous = store::MEMOS
            .get(&vault.store, txn, &key)?
            .map(|old| old.committed_at);
        store::MEMOS.put(vault, txn, &key, &memo)?;
        store::index_run_in_txn(
            vault,
            txn,
            run.binding_id,
            previous,
            memo.committed_at,
            HookRunRef::Fact(key),
        )?;
        let mut hook_receipt = receipt(run, verdict, check, rows_read, duration_ms, now);
        if erased {
            store::scrub_receipt_payload(&mut hook_receipt);
        }
        store::RECEIPTS.put(vault, txn, &key, &hook_receipt)?;
        store::advance_cursor_in_txn(vault, txn, run.binding_id, run.entry.position, at)?;
        Ok((queued, check.is_some()))
    }
}

impl Pass<'_, '_> {
    /// The run's one write: lineage and any owner check, local outcomes,
    /// saved intents, memo and its run index row, receipt and the cursor.
    /// Returns whether an intent waits.
    pub(super) fn commit(
        &mut self,
        run: &Run<'_>,
        memo: HookRunRecord,
        verdict: &Verdict,
    ) -> Result<bool> {
        let vault = self.vault;
        let at = vault.store.clock.now_recorded_at();
        let prepared = PreparedRunCommit::prepare(run, memo, verdict, at)?;
        let (queued, raised_check) =
            vault.with_write_txn_grouped(|txn| prepared.apply_in_txn(vault, txn))?;
        if raised_check {
            self.report.checks += 1;
        }
        Ok(queued)
    }
}
