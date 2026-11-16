//! UC-09 K pins (PLAN-UC-09 "The K-proof", PRs C, D1 and D2): what the queue
//! stores for each job kind a UC-09 PR moves.
//!
//! Each fixture enqueues one job, then the same job again, and renders one
//! line per call: the outcome, then the stored row (its kind, payload bytes,
//! state, dedupe key, run id, task ref and the rest of its fields), its
//! private run-tree row, and its authority stamps with the Gate receipt each
//! names. A refused call renders its error text.
//!
//! Attempt and entity ids are random and the queue stamps instants from the
//! vault clock, so the table names each attempt by its order of first
//! appearance (`A1`, `A2`, ...; also inside the payload hex), each other entity
//! the same way (`E1`, ...), and says only whether an instant equals the row's
//! own `created_at`. The same table at a PR's base and at its
//! head shows that the PR kept every stored byte (M-1 keep path).

use crate::attempt_queue::AttemptId;
use crate::attempt_queue::AttemptQueue;
use crate::attempt_queue::AttemptRecord;
use crate::attempt_queue::dispatch_payload::AGENT_DISPATCH_ATTEMPT_TYPE;
use crate::dreamer_runner::{
    DreamerConsolidationScope, DreamerRunnerStore, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
};
use crate::error::Result;
use crate::store::GateDecisionId;
use crate::{EntityId, Vault};

/// The rendered lines, and the attempts named so far.
struct Table<'a> {
    vault: &'a Vault,
    ids: Vec<AttemptId>,
    entities: Vec<EntityId>,
    lines: Vec<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Table<'_> {
    /// `A<n>`: the order in which `id` first appeared in this table.
    fn name(&mut self, id: AttemptId) -> String {
        let at = if let Some(at) = self.ids.iter().position(|known| *known == id) {
            at
        } else {
            self.ids.push(id);
            self.ids.len() - 1
        };
        format!("A{}", at + 1)
    }

    fn named(&mut self, id: Option<AttemptId>) -> String {
        id.map_or_else(|| "none".to_owned(), |id| self.name(id))
    }

    /// `E<n>`: the order in which entity `id` first appeared in this table.
    fn entity(&mut self, id: EntityId) -> String {
        let at = if let Some(at) = self.entities.iter().position(|known| *known == id) {
            at
        } else {
            self.entities.push(id);
            self.entities.len() - 1
        };
        format!("E{}", at + 1)
    }

    /// The Gate receipt `receipt_id` names, as stamped for `row` by `actor`:
    /// its fixed fields, and whether its actor, instant and diff handle are
    /// the stamp's actor, the row's `created_at` and the row's id.
    fn receipt(
        &self,
        receipt_id: [u8; 16],
        row: &AttemptRecord,
        actor: EntityId,
    ) -> Result<String> {
        let txn = self.vault.store.env.read_txn()?;
        let Some(receipt) = self
            .vault
            .store
            .gate_decision_in_txn(&txn, GateDecisionId::from_bytes(receipt_id))?
        else {
            return Ok("none".to_owned());
        };
        Ok(format!(
            "{}/{:?}/{}/{}/actor_eq={}/created_eq={}/diff_eq={}/claim={:?}/grant={:?}/redacted={}",
            receipt.outcome,
            receipt.reason_codes,
            receipt.content_kind,
            receipt.actor_class,
            receipt.actor_ref == Some(actor.to_hex()),
            receipt.created_at == row.created_at,
            receipt.diff_handle == row.id.as_bytes(),
            receipt.claim_id,
            receipt.grant_ref,
            receipt.redacted_at.is_some(),
        ))
    }

    /// `row`'s base-agent and resident authority stamps, each with its receipt.
    fn stamps(&mut self, row: &AttemptRecord) -> Result<String> {
        let (stamp, resident) =
            crate::dreamer_runner::authority::attempt_stamps(self.vault, row.id)?;
        let stamp = match stamp {
            Some(stamp) => format!(
                "facet={},attempt_eq={},actor={},receipt={}",
                stamp.facet,
                stamp.attempt_id == *row.id.as_bytes(),
                self.entity(stamp.actor),
                self.receipt(stamp.receipt_id, row, stamp.actor)?,
            ),
            None => "none".to_owned(),
        };
        let resident = match resident {
            Some(resident) => format!(
                "attempt_eq={},resident={},receipt={}",
                resident.attempt_id == *row.id.as_bytes(),
                self.entity(resident.resident),
                self.receipt(resident.receipt_id, row, resident.resident)?,
            ),
            None => "none".to_owned(),
        };
        Ok(format!("stamp={stamp}|resident_stamp={resident}"))
    }

    /// `bytes` as lowercase hex, with every named attempt id as `<A<n>>`.
    fn payload_hex(&self, bytes: &[u8]) -> String {
        let mut text = hex(bytes);
        for (at, id) in self.ids.iter().enumerate() {
            text = text.replace(&hex(id.as_bytes()), &format!("<A{}>", at + 1));
        }
        text
    }

    /// One line for call `call` of fixture `label`.
    fn record(
        &mut self,
        label: &str,
        call: u32,
        outcome: Result<EnqueueDreamerAttemptOutcome>,
    ) -> Result<()> {
        let (word, status) = match outcome {
            Ok(EnqueueDreamerAttemptOutcome::Enqueued(status)) => ("Enqueued", status),
            Ok(EnqueueDreamerAttemptOutcome::Existing(status)) => ("Existing", status),
            Err(error) => {
                self.lines.push(format!("{label}|{call}|Err|{error}"));
                return Ok(());
            }
        };
        let returned = status.attempt;
        let id = self.name(returned.id);
        let Some(row) = AttemptQueue::new(self.vault).get(returned.id)? else {
            self.lines
                .push(format!("{label}|{call}|{word}|{id}|stored=none"));
            return Ok(());
        };
        let tree = DreamerRunnerStore::new(self.vault).run_tree(returned.id)?;
        let run_tree = match tree {
            Some(tree) => format!(
                "id_eq={},parent={},created_eq={}",
                tree.attempt_id == returned.id,
                self.named(tree.parent_attempt),
                tree.created_at == row.created_at
            ),
            None => "none".to_owned(),
        };
        let stamps = self.stamps(&row)?;
        let tail = format!(
            "manifest={},executor_model={:?},executor_seat={:?},executor_role={:?}\
             ,planned_binding={},read_set={},cancel_default={},result_ref={},signals={}\
             ,asks={},placement={},history={},budget_refusal={}",
            row.manifest.len(),
            row.executor_model,
            row.executor_seat,
            row.executor_role,
            row.planned_binding.is_some(),
            row.read_set.is_some(),
            row.cancel_state == Default::default(),
            row.result_ref.is_some(),
            row.signals.len(),
            row.asks.len(),
            row.placement.is_some(),
            row.history.len(),
            row.budget_refusal.is_some(),
        );
        let retry_of = self.named(row.retry_of);
        let payload = self.payload_hex(&row.payload);
        let at_created = |instant: Option<u64>| instant.map(|instant| instant == row.created_at);
        self.lines.push(format!(
            "{label}|{call}|{word}|{id}|returned_eq_stored={}|kind={}|payload={payload}\
             |state={:?}|attempt_count={}|lease_owner={:?}|lease_expirations={}\
             |claimed_at_eq_created={:?}|scheduled_at_eq_created={:?}|retry_of={retry_of}\
             |folded_retries={}|backoff_until_eq_created={:?}|last_error={:?}|task_ref={:?}\
             |run_id={:?}|dedupe_key={:?}|dedupe_actor_ref={:?}|updated_eq_created={}\
             |settled_at_eq_created={:?}|events={}|run_tree={run_tree}|{stamps}|tail={tail}",
            returned == row,
            row.kind,
            row.state,
            row.attempt_count,
            row.lease_owner,
            row.lease_expirations.len(),
            at_created(row.claimed_at),
            at_created(row.scheduled_at),
            row.folded_retries,
            at_created(row.backoff_until),
            row.last_error,
            row.task_ref,
            row.run_id,
            row.dedupe_key,
            row.dedupe_actor_ref,
            row.updated_at == row.created_at,
            at_created(row.settled_at),
            row.events.len(),
        ));
        Ok(())
    }
}

/// A generic runner job of `attempt_type`.
fn runner_job(attempt_type: &str, dedupe_key: Option<&str>) -> EnqueueDreamerAttempt {
    EnqueueDreamerAttempt {
        attempt_type: attempt_type.to_owned(),
        input: rmpv::Value::from("uc09-pin-runner-input"),
        parent_attempt: None,
        dedupe_key: dedupe_key.map(str::to_owned),
        run_id: Some("uc09-pin-run".to_owned()),
        now: 1_000,
    }
}

/// UC-09 PR C's kinds, through every Dreamer enqueue door the PR moves: the
/// generic runner through its public door (keyed, then unkeyed), the task-ref
/// door that agent dispatch uses (with a parent), one kind-scoped lane (MICRO
/// consolidation), and the refusal of an empty job type.
///
/// # Errors
///
/// Storage errors from the reads after each call.
pub fn dreamer_core_rows(vault: &Vault) -> Result<Vec<String>> {
    let store = DreamerRunnerStore::new(vault);
    let mut table = Table {
        vault,
        ids: Vec::new(),
        entities: Vec::new(),
        lines: Vec::new(),
    };
    for call in 1..=2 {
        let outcome = store.enqueue(runner_job("uc09.pin.runner", Some("uc09-pin-runner")));
        table.record("runner", call, outcome)?;
    }
    let parent = table.ids.first().copied();
    for call in 1..=2 {
        let mut wtxn = vault.store.env.write_txn()?;
        let outcome = store.enqueue_with_task_ref_in_txn(
            &mut wtxn,
            EnqueueDreamerAttempt {
                attempt_type: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
                input: rmpv::Value::from("uc09-pin-task-input"),
                parent_attempt: parent,
                dedupe_key: Some("uc09-pin-task".to_owned()),
                run_id: None,
                now: 1_000,
            },
            Some("uc09-pin-task-ref".to_owned()),
        );
        if outcome.is_ok() {
            wtxn.commit()?;
        } else {
            drop(wtxn);
        }
        table.record("runner-task-ref", call, outcome)?;
    }
    for call in 1..=2 {
        let outcome = store.enqueue(runner_job("uc09.pin.runner", None));
        table.record("runner-unkeyed", call, outcome)?;
    }
    for call in 1..=2 {
        let outcome = store.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input: rmpv::Value::from("uc09-pin-micro-input"),
            parent_attempt: None,
            dedupe_key: Some("uc09-pin-micro".to_owned()),
            run_id: Some("uc09-pin-micro-run".to_owned()),
            now: 1_000,
        });
        table.record("consolidation-micro", call, outcome)?;
    }
    let outcome = store.enqueue(runner_job("", Some("uc09-pin-empty")));
    table.record("runner-empty-type", 1, outcome)?;
    Ok(table.lines)
}
