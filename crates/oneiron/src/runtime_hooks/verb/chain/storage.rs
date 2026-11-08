//! A chain's records (ARCH-0080 §6): the one vault write that commits its
//! receipts, saved runs, blocks and intents, or, for a session-only call, its
//! receipts and saved runs held for the call to keep in the session's own
//! store (WILL L11-01 S01-2c); and the queued outcomes the vault lands once
//! its write committed.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use crate::Result;
use crate::receipt::{ReceiptKind, ReceiptRecord, hex_lower};
use crate::runtime_hooks::runner::{MAX_PINNED_INPUT, bounded};
use crate::runtime_hooks::{HookPassReport, apply, block, filter, lineage, store};

use super::super::ask;
use super::super::record::{self, HookVerbRunRecord};
use super::super::storage::VerbHookStorage;
use super::{Chain, RunRecord, hook_name, phase_token};

/// One run as a write lands it ([`Chain::landed_in_txn`]): its receipt, its
/// saved copy, and whether its payload retired.
pub(super) type Landed = (ReceiptRecord, HookVerbRunRecord, bool);

impl Chain<'_> {
    /// Commits the chain's rows. A resumed chain commits even with no run
    /// after the asking hook: its write uses the answer up. A session-only
    /// call's chain holds them for the call to keep once its read is done
    /// ([`Self::hold_in_session`]), a resumed one after using its answer up
    /// in the keep ([`Self::take_session_answer`], L13 PR-D); a call with no
    /// room overlay writes its blocks and intents in the vault
    /// ([`Self::write_consequences`]), and a room has none. The runs are
    /// held as that write landed them, so the hold reads none again.
    pub(super) fn commit(&self) -> Result<()> {
        if self.runs.is_empty() && self.token.is_none() {
            return Ok(());
        }
        match self.storage {
            VerbHookStorage::Canonical => self
                .vault
                .with_write_txn_grouped(|txn| self.write_in_txn(txn)),
            VerbHookStorage::Session(hooks) => {
                self.take_session_answer(hooks)?;
                let (landed, written) = match self.write_consequences() {
                    Ok(landed) => (landed, Ok(())),
                    Err(error) => (None, Err(error)),
                };
                self.hold_in_session(hooks, landed);
                written
            }
        }
    }

    /// A session-only call's hook consequences with no room overlay, while
    /// `KEPT_CALL_HOOK_CONSEQUENCES_RUN` holds (L13 PR-D, FIX 5525): its
    /// blocks with their lineage and its intents, each written once in the
    /// vault as [`Self::write_in_txn`] writes them. Its receipts and saved
    /// runs stay in the keep. A room's chain, and a call whose consequences
    /// do not run, holds none. Each run as this write lands it, in run
    /// order, for the hold ([`Self::hold_in_session`]); `None` when there
    /// was nothing to write.
    pub(super) fn consequences_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<Option<Vec<Landed>>> {
        if self.blocks.is_empty() && self.intents.is_empty() {
            return Ok(None);
        }
        let at = self.vault.store.clock.now_recorded_at();
        let mut landed = Vec::with_capacity(self.runs.len());
        let mut retired = BTreeSet::new();
        for run in &self.runs {
            let run_landed = self.landed_in_txn(txn, run, at.saturating_mul(1_000))?;
            if run_landed.2 {
                retired.insert(run.key);
            }
            landed.push(run_landed);
        }
        self.consequences_at_in_txn(txn, at, &retired)?;
        Ok(Some(landed))
    }

    /// The chain's blocks with their lineage and its intents, each written
    /// once; `at` (Unix seconds) stamps when a block or intent of a run in
    /// `retired` ([`Self::landed_in_txn`]), or a block naming a row a
    /// permanent erase fenced before this write, expires or is refused, as
    /// that erase's own scrub would have left it had the chain committed
    /// first (FIX 22191). An erased caller leaves the lineage of each
    /// ([`lineage::erase_entity`]; FIX 22184).
    fn consequences_at_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        at: u64,
        retired: &BTreeSet<store::RunKey>,
    ) -> Result<()> {
        if self.blocks.is_empty() && self.intents.is_empty() {
            return Ok(());
        }
        let vault = self.vault;
        let retired_refs: BTreeSet<String> = retired.iter().map(|key| hex_lower(key)).collect();
        let caller =
            store::source_erased_in_txn(vault, txn, &self.call.actor)?.then_some(self.call.actor);
        for (id, row, chain) in &self.blocks {
            let chain = lineage::without_erased(chain, caller.as_ref());
            if retired_refs.contains(&row.run_key) || block::names_erased_in_txn(vault, txn, row)? {
                let mut row = row.clone();
                block::scrub_block_payload(&mut row, at);
                block::put_block_in_txn(vault, txn, *id, &row)?;
                lineage::put_in_txn(vault, txn, id.as_bytes(), &chain)?;
                continue;
            }
            if block::put_new_block_in_txn(vault, txn, *id, row)? {
                lineage::put_in_txn(vault, txn, id.as_bytes(), &chain)?;
            }
        }
        for (key, intent, proposal) in &self.intents {
            let mut intent = Cow::Borrowed(intent);
            if let Some(caller) = &caller {
                lineage::erase_entity(&mut intent.to_mut().lineage, caller);
            }
            if retired.contains(key)
                || store::dependencies_erased_in_txn(vault, txn, &intent.dependencies)?
            {
                let intent = intent.to_mut();
                store::scrub_intent_payload(intent, at);
                store::INTENTS.put(vault, txn, key, intent)?;
                continue;
            }
            if store::INTENTS.get(&vault.store, txn, key)?.is_some() {
                continue;
            }
            if let Some(id) = proposal {
                lineage::put_in_txn(vault, txn, id.as_bytes(), &intent.lineage)?;
            }
            store::INTENTS.put(vault, txn, key, &intent)?;
        }
        Ok(())
    }

    /// [`Self::consequences_in_txn`] in a vault write of its own, when the
    /// chain holds any.
    fn write_consequences(&self) -> Result<Option<Vec<Landed>>> {
        if self.blocks.is_empty() && self.intents.is_empty() {
            return Ok(None);
        }
        self.vault
            .with_write_txn_grouped(|txn| self.consequences_in_txn(txn))
    }

    /// The chain's receipts, saved runs, blocks and intents. A retried call
    /// writes each block and intent once, and each saved run over its last.
    /// A resumed chain uses its answer up first; one another try used fails
    /// the write, so none of it commits.
    pub(super) fn write_in_txn(&self, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        let vault = self.vault;
        if let Some(token) = &self.token
            && !ask::consume_in_txn(vault, txn, token)?
        {
            self.used.set(true);
            return Err(ask::used_error());
        }
        if self.call.verb == "host.turn.generate"
            && let (Some(token), Some(turn)) = (&self.token, &self.call.turn)
        {
            crate::code_run::clear_parked_wait_in_txn(vault, txn, turn.run, token.ask())?;
        }
        let at = vault.store.clock.now_recorded_at().saturating_mul(1_000);
        let mut retired = BTreeSet::new();
        for run in &self.runs {
            let (receipt, saved, gone) = self.landed_in_txn(txn, run, at)?;
            if gone {
                retired.insert(run.key);
            }
            store::RECEIPTS.put(vault, txn, &run.key, &receipt)?;
            record::put_in_txn(vault, vault, txn, &run.key, &saved)?;
        }
        self.consequences_at_in_txn(txn, at / 1_000, &retired)
    }

    /// `run`'s receipt and saved copy as a write at `at` (Unix ms) lands
    /// them, read in that write's snapshot, and whether its payload retired.
    /// A caller or tail actor a permanent erase fenced names the erased
    /// marker (FIX 22178); a run across a source's erase keeps none of its
    /// bytes, nor one whose caller's own args or result name an erased row
    /// (FIX 22191). So each lands as the erase's own scrub would have left it
    /// had the chain committed first, and no later sweep scrubs it again
    /// ([`store::scrub_erased_verb_run_in_txn`]).
    pub(super) fn landed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        run: &RunRecord<'_>,
        at: u64,
    ) -> Result<Landed> {
        let mut receipt = self.receipt(run);
        let mut saved = self.saved(run, at);
        let retired =
            store::scrub_erased_verb_run_in_txn(self.vault, txn, &mut saved, &mut receipt)?;
        Ok((receipt, saved, retired))
    }

    /// Lands the post chain's queued outcomes, each once, as its hook's
    /// author with source Generated. One that does not land now stays
    /// pending for the runner's start-up drain: the verb's result stands.
    pub(super) fn apply(&self) {
        if self.intents.is_empty() {
            return;
        }
        let bindings = match self.vault.pack_hook_bindings() {
            Ok(bindings) => bindings,
            Err(error) => {
                tracing::warn!(%error, "verb hook outcomes wait for the hook runner");
                return;
            }
        };
        let mut report = HookPassReport::default();
        for (key, _, _) in &self.intents {
            if let Err(error) = apply::drain_one(self.vault, &bindings, key, &mut report) {
                tracing::warn!(%error, "a verb hook outcome waits for the hook runner");
            }
        }
    }

    /// The run's Hook receipt: the hook, its content hash, the call, the
    /// duration, the outcome, `now` and the rows read, and the overrun of a
    /// run past its budget.
    pub(super) fn receipt(&self, run: &RunRecord<'_>) -> ReceiptRecord {
        let binding = run.binding;
        let mut fields: BTreeMap<String, String> = [
            ("binding", run.id.to_hex()),
            ("code", binding.code.to_hex()),
            ("body_hash", binding.body_hash.clone()),
            ("hook", hook_name(binding)),
            ("hook_version", binding.hook_version.clone()),
            ("invocation", self.call.invocation.to_hex()),
            ("verb", bounded(&self.call.verb)),
            ("phase", phase_token(self.phase).to_owned()),
            ("class", filter::class_token(self.call.class).to_owned()),
            ("duration_ms", run.duration_ms.to_string()),
            ("now", self.now.to_string()),
            ("rows_read", run.rows_read.to_string()),
            ("run_key", hex_lower(&run.key)),
        ]
        .into_iter()
        .chain(run.usage.receipt_fields())
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        let scope_text = self.call.scope.as_ref().map(|scope| scope.receipt_text());
        for (name, value) in [
            ("reason", run.reason.as_deref()),
            ("note", run.note.as_deref()),
            ("fail_safe", run.fail_safe),
            ("scope", scope_text.as_deref()),
            (
                "retry",
                self.expired
                    .then_some(ask::session::PRUNED_RECORDED_ASK_NOTE),
            ),
        ] {
            if let Some(value) = value {
                fields.insert(name.to_owned(), bounded(value));
            }
        }
        if let Some(overrun) = &run.budget_overrun {
            for (name, value) in overrun.receipt_fields() {
                fields.insert(name.to_owned(), value);
            }
        }
        ReceiptRecord {
            receipt_id: store::receipt_id(&run.key),
            receipt_kind: ReceiptKind::Hook,
            occurred_at: self.now / 1_000,
            actor: Some(binding.author_id().to_hex()),
            on_behalf_of: Some(self.call.actor.to_hex()),
            outcome: run.token.clone(),
            job_ref: None,
            trigger_ref: Some(self.call.invocation.to_hex()),
            policy_trace: Vec::new(),
            fields,
        }
    }

    /// The run's saved copy, written at `at` (Unix ms): what replay runs the
    /// body on again.
    pub(super) fn saved(&self, run: &RunRecord<'_>, at: u64) -> HookVerbRunRecord {
        HookVerbRunRecord {
            binding: run.id,
            code: run.binding.code,
            body_hash: run.binding.body_hash.clone(),
            invocation: self.call.invocation,
            phase: self.phase,
            verb: self.call.verb.clone(),
            input_json: (run.input.len() <= MAX_PINNED_INPUT).then(|| run.input.clone()),
            landing_original: run
                .landing_original
                .as_ref()
                .filter(|original| original.len() <= MAX_PINNED_INPUT)
                .cloned(),
            had_landing: run.had_landing,
            args_withheld: run.args_withheld,
            history_erased: false,
            input_hash: blake3::hash(run.input.as_bytes()).to_hex().to_string(),
            dependencies: run.dependencies.clone(),
            named_rows: store::rows_named_by_call(&run.input, run.landing_original.as_deref()),
            unattributed: run.unattributed,
            grant: run.grant.clone(),
            preparation: run.preparation.clone(),
            reads: run.reads.clone(),
            outcome_json: run.outcome_json.clone(),
            outcome: run.token.clone(),
            reason: run.reason.clone(),
            receipt_id: store::receipt_id(&run.key),
            duration_ms: run.duration_ms,
            budget_overrun: run.budget_overrun,
            now: self.now,
            committed_at: at,
        }
    }
}
