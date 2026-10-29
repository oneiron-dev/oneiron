//! A chain's records (ARCH-0080 §6): the one vault write that commits its
//! receipts, saved runs, blocks and intents, or, for a session-only call, its
//! receipts and saved runs held for the call to keep in the session's own
//! store (WILL L11-01 S01-2c); and the queued outcomes the vault lands once
//! its write committed.

use std::collections::BTreeMap;

use crate::receipt::{ReceiptKind, ReceiptRecord, hex_lower};
use crate::runtime_hooks::runner::{MAX_PINNED_INPUT, bounded};
use crate::runtime_hooks::{HookPassReport, apply, block, filter, lineage, store};
use crate::{EntityId, Result};

use super::super::ask;
use super::super::record::{self, HookVerbRunRecord};
use super::super::storage::VerbHookStorage;
use super::{Chain, RunRecord, hook_name, phase_token};

impl Chain<'_> {
    /// Commits the chain's rows. A resumed chain commits even with no run
    /// after the asking hook: its write uses the answer up. A session-only
    /// call's chain holds them for the call to keep once its read is done
    /// ([`Self::hold_in_session`]), a resumed one after using its answer up
    /// in the keep ([`Self::take_session_answer`], L13 PR-D); a call with no
    /// room overlay writes its blocks and intents in the vault
    /// ([`Self::write_consequences`]), and a room has none.
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
                self.hold_in_session(hooks);
                self.write_consequences()
            }
        }
    }

    /// A session-only call's hook consequences with no room overlay, while
    /// `KEPT_CALL_HOOK_CONSEQUENCES_RUN` holds (L13 PR-D, FIX 5525): its
    /// blocks with their lineage and its intents, each written once in the
    /// vault as [`Self::write_in_txn`] writes them. Its receipts and saved
    /// runs stay in the keep. A room's chain, and a call whose consequences
    /// do not run, holds none.
    pub(super) fn consequences_in_txn(&self, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        let vault = self.vault;
        let at = vault.store.clock.now_recorded_at();
        let erased = self.erased_sources(txn)?;
        for (id, row, chain) in &self.blocks {
            if row.refs.iter().any(|id| erased.contains(id)) {
                let mut row = row.clone();
                block::scrub_block_payload(&mut row, at);
                block::put_block_in_txn(vault, txn, *id, &row)?;
                lineage::put_in_txn(vault, txn, id.as_bytes(), chain)?;
                continue;
            }
            if block::put_new_block_in_txn(vault, txn, *id, row)? {
                lineage::put_in_txn(vault, txn, id.as_bytes(), chain)?;
            }
        }
        for (key, intent, proposal) in &self.intents {
            if store::dependencies_erased_in_txn(vault, txn, &intent.dependencies)? {
                let mut intent = intent.clone();
                store::scrub_intent_payload(&mut intent, at);
                store::INTENTS.put(vault, txn, key, &intent)?;
                continue;
            }
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

    /// The permanently erased sources this chain carries, checked in its
    /// own write snapshot before any original payload can be committed.
    fn erased_sources(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<std::collections::BTreeSet<EntityId>> {
        let vault = self.vault;
        let mut erased = std::collections::BTreeSet::new();
        for run in &self.runs {
            erased.extend(store::erased_dependency_ids_in_txn(
                vault,
                txn,
                &run.hook_dependencies(),
            )?);
        }
        for (_, intent, _) in &self.intents {
            erased.extend(store::erased_dependency_ids_in_txn(
                vault,
                txn,
                &intent.dependencies,
            )?);
        }
        Ok(erased)
    }

    /// [`Self::consequences_in_txn`] in a vault write of its own, when the
    /// chain holds any.
    fn write_consequences(&self) -> Result<()> {
        if self.blocks.is_empty() && self.intents.is_empty() {
            return Ok(());
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
        let at = vault.store.clock.now_recorded_at().saturating_mul(1_000);
        for run in &self.runs {
            let mut receipt = self.receipt(run);
            let mut saved = self.saved(run, at);
            if !store::erased_dependency_ids_in_txn(vault, txn, &run.hook_dependencies())?
                .is_empty()
            {
                store::scrub_receipt_payload(&mut receipt);
                store::scrub_verb_payload(&mut saved);
            }
            store::RECEIPTS.put(vault, txn, &run.key, &receipt)?;
            record::put_in_txn(vault, vault, txn, &run.key, &saved)?;
        }
        let erased = self.erased_sources(txn)?;
        for (id, row, chain) in &self.blocks {
            if row.refs.iter().any(|id| erased.contains(id)) {
                let mut row = row.clone();
                block::scrub_block_payload(&mut row, at / 1_000);
                block::put_block_in_txn(vault, txn, *id, &row)?;
                lineage::put_in_txn(vault, txn, id.as_bytes(), chain)?;
                continue;
            }
            if block::put_new_block_in_txn(vault, txn, *id, row)? {
                lineage::put_in_txn(vault, txn, id.as_bytes(), chain)?;
            }
        }
        for (key, intent, proposal) in &self.intents {
            if store::dependencies_erased_in_txn(vault, txn, &intent.dependencies)? {
                let mut intent = intent.clone();
                store::scrub_intent_payload(&mut intent, at / 1_000);
                store::INTENTS.put(vault, txn, key, &intent)?;
                continue;
            }
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
        for (name, value) in [
            ("reason", run.reason.as_deref()),
            ("note", run.note.as_deref()),
            ("fail_safe", run.fail_safe),
            ("scope", self.call.scope.as_deref()),
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
            history_erased: false,
            input_hash: blake3::hash(run.input.as_bytes()).to_hex().to_string(),
            dependencies: run.dependencies.clone(),
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
