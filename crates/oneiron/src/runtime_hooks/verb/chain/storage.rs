//! A chain's records (ARCH-0080 §6): the one vault write that commits its
//! receipts, saved runs, blocks and intents, or, for a session-only call, its
//! receipts and saved runs held for the call to keep in the session's own
//! store (WILL L11-01 S01-2c); and the queued outcomes the vault lands once
//! its write committed.

use std::collections::BTreeMap;

use crate::Result;
use crate::receipt::{ReceiptKind, ReceiptRecord, hex_lower};
use crate::runtime_hooks::runner::{MAX_PINNED_INPUT, bounded};
use crate::runtime_hooks::{HookPassReport, apply, block, filter, lineage, store};

use super::super::ask;
use super::super::record::{self, HookVerbRunRecord};
use super::super::storage::VerbHookStorage;
use super::{Chain, RunRecord, hook_name, phase_token};

impl Chain<'_> {
    /// Commits the chain's rows. A resumed chain commits even with no run
    /// after the asking hook: its write uses the answer up. A session-only
    /// call's chain holds them for the call to keep once its read is done
    /// ([`Self::hold_in_session`]).
    pub(super) fn commit(&self) -> Result<()> {
        if self.runs.is_empty() && self.token.is_none() {
            return Ok(());
        }
        match self.storage {
            VerbHookStorage::Canonical => self
                .vault
                .with_write_txn_grouped(|txn| self.write_in_txn(txn)),
            VerbHookStorage::Session(hooks) => {
                self.hold_in_session(hooks);
                Ok(())
            }
        }
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
        let at = vault.store.clock.now_recorded_at().saturating_mul(1_000);
        for run in &self.runs {
            store::RECEIPTS.put(vault, txn, &run.key, &self.receipt(run))?;
            record::put_in_txn(vault, vault, txn, &run.key, &self.saved(run, at))?;
        }
        for (id, row, chain) in &self.blocks {
            if block::put_new_block_in_txn(vault, txn, *id, row)? {
                lineage::put_in_txn(vault, txn, id.as_bytes(), chain)?;
            }
        }
        for (key, intent, proposal) in &self.intents {
            if store::INTENTS.get(&vault.store, txn, key)?.is_some() {
                continue;
            }
            if let Some(id) = proposal {
                lineage::put_in_txn(vault, txn, id.as_bytes(), &intent.lineage)?;
            }
            store::INTENTS.put(vault, txn, key, intent)?;
        }
        Ok(())
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
    /// duration, the outcome, `now` and the rows read.
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
            ("fuel_used", run.fuel_used.to_string()),
            ("host_calls", run.host_calls.to_string()),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        for (name, value) in [
            ("reason", run.reason.as_deref()),
            ("note", run.note.as_deref()),
            ("fail_safe", run.fail_safe),
            ("scope", self.call.scope.as_deref()),
        ] {
            if let Some(value) = value {
                fields.insert(name.to_owned(), bounded(value));
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
            input_hash: blake3::hash(run.input.as_bytes()).to_hex().to_string(),
            reads: run.reads.clone(),
            outcome_json: run.outcome_json.clone(),
            outcome: run.token.clone(),
            reason: run.reason.clone(),
            receipt_id: store::receipt_id(&run.key),
            duration_ms: run.duration_ms,
            now: self.now,
            committed_at: at,
        }
    }
}
