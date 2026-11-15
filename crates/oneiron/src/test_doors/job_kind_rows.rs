//! UC-09 K pins (PLAN-UC-09 "The K-proof", PRs C, D1 and D2): what the queue
//! stores for each job kind a UC-09 PR moves.
//!
//! Each fixture enqueues one job, then the same job again, and renders one
//! line per call: the outcome, then the stored row (its kind, payload bytes,
//! state, dedupe key, run id, task ref and the rest of its fields), its
//! private run-tree row, and its authority stamps with the Gate receipt each
//! names. A refused call renders its error text. A door that answers only
//! the attempt id renders the stored row under the word `Id`.
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
use crate::claim::WeaveDigestReader;
use crate::dreamer_runner::{
    DreamerConsolidationScope, DreamerRunnerStore, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
    EnqueueDreamerSkillOptimizeAttempt, EnqueueDreamerVaultCleanupAttempt,
};
use crate::dreamer_wake::{WakePolicyTrigger, WakeTrigger};
use crate::error::{Error, Result};
use crate::failure_ladder::{FailureClass, FailureScope, HealerCase};
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
        self.render(label, call, word, status.attempt)
    }

    /// One line for call `call` of fixture `label`, for a door that answers
    /// only the attempt id: the stored row as `returned`, so
    /// `returned_eq_stored` reads it twice.
    fn record_id(&mut self, label: &str, call: u32, outcome: Result<AttemptId>) -> Result<()> {
        let id = match outcome {
            Ok(id) => id,
            Err(error) => {
                self.lines.push(format!("{label}|{call}|Err|{error}"));
                return Ok(());
            }
        };
        let Some(returned) = AttemptQueue::new(self.vault).get(id)? else {
            let id = self.name(id);
            self.lines
                .push(format!("{label}|{call}|Id|{id}|stored=none"));
            return Ok(());
        };
        self.render(label, call, "Id", returned)
    }

    /// The line for one answered call: `returned` is the row the door
    /// answered, read again from the queue.
    fn render(
        &mut self,
        label: &str,
        call: u32,
        word: &str,
        returned: AttemptRecord,
    ) -> Result<()> {
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

/// A table with nothing named yet.
fn table(vault: &Vault) -> Table<'_> {
    Table {
        vault,
        ids: Vec::new(),
        entities: Vec::new(),
        lines: Vec::new(),
    }
}

/// Runs a caller-owned-transaction door in a write transaction of its own:
/// commits it when the door answers, rolls it back when the door refuses.
/// The outer error is storage; the inner one is the door's answer.
fn in_write_txn<T>(
    vault: &Vault,
    door: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
) -> Result<Result<T>> {
    let mut wtxn = vault.store.env.write_txn()?;
    let outcome = door(&mut wtxn);
    if outcome.is_ok() {
        wtxn.commit()?;
    } else {
        drop(wtxn);
    }
    Ok(outcome)
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
    let mut table = table(vault);
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

/// A vault-cleanup job registered on `trigger`.
fn vault_cleanup_job(
    trigger: WakeTrigger,
    parent_attempt: Option<AttemptId>,
) -> EnqueueDreamerVaultCleanupAttempt {
    EnqueueDreamerVaultCleanupAttempt {
        trigger,
        input: rmpv::Value::from("uc09-pin-cleanup-input"),
        parent_attempt,
        dedupe_key: Some("uc09-pin-cleanup".to_owned()),
        run_id: Some("uc09-pin-cleanup-run".to_owned()),
        now: 1_000,
    }
}

/// A failure-ladder case on `failing_attempt_id`, its refs fixed hex.
fn healer_case(failing_attempt_id: AttemptId) -> HealerCase {
    HealerCase {
        case_ref: "0123456789abcdef0123456789abcdef".to_owned(),
        scope: FailureScope {
            agent_ref: "5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b".to_owned(),
            skill_ref: None,
        },
        failure_class: FailureClass::Permanent,
        failing_attempt_id,
        task_ref: None,
        evidence_ref: "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c".to_owned(),
        blocked_reports: Vec::new(),
        pre_fail_checkpoint_ref: "5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d".to_owned(),
        qa_thread_ref: "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e".to_owned(),
        consecutive_transients: 0,
    }
}

/// A Nightly wake-policy trigger with fixed counts and cursors. Built from
/// its serde form: its snapshot fields are private to the wake policy.
fn nightly_trigger() -> Result<WakePolicyTrigger> {
    let through = [0x60_u8; 16];
    let after = [0x61_u8; 16];
    serde_json::from_value(serde_json::json!({
        "recipe": "nightly",
        "turn_count": 3,
        "record_count": 5,
        "nightly_count": 1,
        "after_nightly": null,
        "after_turn": after,
        "after_record": null,
        "through": through,
        "observed_at": 1_000,
        "latest_after_turn": after,
        "latest_after_record": null,
        "latest_after_nightly": null,
        "latest_turn_count": 3,
        "latest_record_count": 5,
        "latest_nightly_count": 1,
    }))
    .map_err(|error| Error::InvalidConfig(format!("uc09 pin wake trigger: {error}")))
}

/// UC-09 PR D1's kinds: every kind-scoped door whose job type is its own
/// lane's kind (SKILL-OPT, coach heal, recipe wake, vault cleanup, NOTE
/// review, resident dream, weave lens), each called twice, and the refusals
/// those doors keep (a non-timer vault cleanup; a resident with no agent
/// definition). SKILL-OPT and vault cleanup go through their own-commit
/// doors; the generic runner and consolidation own-commit doors are in
/// [`dreamer_core_rows`]. A first runner job is the parent the child doors
/// name. The resident is the seeded system agent `sys.scout`, enabled with
/// dreaming inherited (on).
///
/// # Errors
///
/// Storage errors from the transactions and the reads after each call.
pub fn dreamer_kind_rows(vault: &Vault) -> Result<Vec<String>> {
    let store = DreamerRunnerStore::new(vault);
    let mut table = table(vault);
    let outcome = store.enqueue(runner_job("uc09.pin.parent", Some("uc09-pin-parent")));
    table.record("parent", 1, outcome)?;
    let parent_id = table
        .ids
        .first()
        .copied()
        .ok_or_else(|| Error::InvalidConfig("uc09 pin parent did not enqueue".into()))?;
    let parent = Some(parent_id);
    for call in 1..=2 {
        let outcome = store.enqueue_skill_optimize(EnqueueDreamerSkillOptimizeAttempt {
            input: rmpv::Value::from("uc09-pin-skill-input"),
            parent_attempt: parent,
            dedupe_key: Some("uc09-pin-skill".to_owned()),
            run_id: Some("uc09-pin-skill-run".to_owned()),
            now: 1_000,
        });
        table.record("skill-optimize", call, outcome)?;
    }
    for call in 1..=2 {
        let outcome = store.enqueue_vault_cleanup(vault_cleanup_job(WakeTrigger::Timer, parent));
        table.record("vault-cleanup", call, outcome)?;
    }
    let outcome = store.enqueue_vault_cleanup(vault_cleanup_job(WakeTrigger::Event, parent));
    table.record("vault-cleanup-event", 1, outcome)?;
    let case = healer_case(parent_id);
    for call in 1..=2 {
        let outcome = in_write_txn(vault, |wtxn| {
            store.enqueue_coach_heal_in_txn(
                wtxn,
                &case,
                Some("uc09-pin-heal-run".to_owned()),
                1_000,
            )
        })?;
        table.record_id("coach-heal", call, outcome)?;
    }
    let trigger = nightly_trigger()?;
    for call in 1..=2 {
        let outcome = in_write_txn(vault, |wtxn| {
            store.enqueue_recipe_wake_in_txn(wtxn, &trigger, 1_000)
        })?;
        table.record("recipe-wake", call, outcome)?;
    }
    for call in 1..=2 {
        let outcome = in_write_txn(vault, |wtxn| {
            store.enqueue_note_review_in_txn(
                wtxn,
                parent,
                Some("uc09-pin-wake"),
                Some("uc09-pin-note-run".to_owned()),
                1_000,
            )
        })?;
        table.record("note-review", call, outcome)?;
    }
    let scout = EntityId::from_bytes_unchecked([0xA1; 16]);
    let stranger = EntityId::from_bytes_unchecked([0x5F; 16]);
    for (label, resident, calls) in [
        ("resident-dream", scout, 2),
        ("resident-dream-unknown", stranger, 1),
    ] {
        for call in 1..=calls {
            let outcome = in_write_txn(vault, |wtxn| {
                store.enqueue_resident_dream_in_txn(
                    wtxn,
                    resident,
                    parent,
                    Some("uc09-pin-wake"),
                    Some("uc09-pin-dream-run".to_owned()),
                    1_000,
                )
            })?;
            table.record(label, call, outcome)?;
        }
    }
    let reader = WeaveDigestReader::Person(EntityId::from_bytes_unchecked([0x62; 16]));
    let revision = EntityId::from_bytes_unchecked([0x63; 16]);
    for call in 1..=2 {
        let outcome = in_write_txn(vault, |wtxn| {
            store.enqueue_weave_lens_in_txn(wtxn, reader, 2_000, 2_500, revision, 1_000)
        })?;
        table.record("weave-lens", call, outcome)?;
    }
    Ok(table.lines)
}
