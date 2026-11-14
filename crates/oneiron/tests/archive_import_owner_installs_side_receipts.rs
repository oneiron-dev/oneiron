#![cfg(oneiron_test_support)]
//! The owner's restore installs receipt and owner-act history live (SIDE-2c).
//!
//! Public doors only; neutral fixtures; vaults in tempdirs. Each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as
//! in `archive_import_retained_side_rows.rs`.
//!
//! * `the_owner_restore_installs_owner_act_history_and_the_actorless_import_does_not`:
//!   the owner import installs one POLICY_SETTING_ACT row, one
//!   OWNER_POLICY_SECRET_SCAN_RECEIPT row and one OWNER_POLICY_CHANGE_EVENT
//!   row live and reports one installed row for each; a repeat owner import
//!   reports one unchanged live row for each; the actorless import of the
//!   same archive lists none.
//! * `the_next_owner_act_after_a_restore_follows_the_restored_sequence`:
//!   a restored secret-scan receipt keeps revision one, and the next switch
//!   the destination owner makes takes revision two, with both in the log.
//! * `a_destination_act_at_the_same_sequence_stays_live_and_the_source_act_stays_retained`:
//!   a destination that already holds its own policy-setting act keeps it,
//!   the report counts one kept-live row, and its next archive holds both
//!   tuples.
//! * `a_delivered_send_summary_without_its_idempotency_support_is_held_back`:
//!   a source Delivered send receipt, made through the public outbound
//!   schedule and executor, restores its attempt audit live but holds back
//!   its summary as missing_companion, with no installed summary and the
//!   source tuple retained.
//! * `restored_free_time_and_team_receipts_install_as_history`:
//!   source free-time receipts, made through the public Timer pass and
//!   free-time host with a Failed receipt for the resident's human, and a
//!   source team Solo receipt, made through the public team record door,
//!   restore live; the team reports one installed row and the free-time
//!   table reports one installed row per source receipt.
//! * `a_consumed_check_in_receipt_restores_as_history`: a check-in the
//!   holder approved and the act then spent writes the receipts opened,
//!   answered and consumed; the owner's restore installs all three with none
//!   held back (REVIEW-7799 round 1: main's `consumed` outcome).
//! * `rotation_receipts_of_either_body_form_restore_as_history`: a rotation
//!   receipt body with its cause (`provider_refresh`) and one written before
//!   causes were recorded (no `cause` key) both install, with none held back
//!   (REVIEW-7799 round 1: main's six-key receipt body).
//!
//! New report counts are read through `serde_json::to_value` of the SIDE-1
//! summary, so this file compiles on 7b24852131b3; an absent field fails its
//! assertion as a missing outcome, never as a setup panic.
//! `cargo test --locked -p oneiron --all-features --test
//! archive_import_owner_installs_side_receipts`.

#[path = "check_in/fixture.rs"]
mod check_in_fixture;
#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::Cursor;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::AttemptId;
use oneiron::authority::ActSurface;
use oneiron::connector_key::{
    CalendarPeriod, ConnectorKeyRecord, EffectorBudget, EffectorBudgetOnExhaust,
    EffectorBudgetWindow,
};
use oneiron::dreamer_consolidation::{ResidentDreamModel, run_free_time_for_human};
use oneiron::dreamer_runner::{
    DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND, DREAMER_SERVER_PARK_OWNER, DreamerConsolidationScope,
    DreamerRunnerStore, FreeTimeCadence, FreeTimeItemBinding, FreeTimeItemOutcome, FreeTimeKind,
    FreeTimePolicyInput, FreeTimeSchedule, FreeTimeSplit,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::outbound::{
    ConnectorSendTaskOutcome, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink,
};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyGrantMapEntry, PolicyGrantValue, PolicyManifestPut,
    PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::policy_model::SecretScanMode;
use oneiron::receipt::{ReceiptKind, ReceiptQuery};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::settings::undo_send::UndoSendSetting;
use oneiron::store::ports::ManualClock;
use oneiron::task_type::type_tree;
use oneiron::team::{
    DecidedBy, TeamAxis, TeamPattern, TeamReceipt, TeamShape, record_team_receipt, team_receipt,
};
use oneiron::test_doors::coach::define_agent;
use oneiron::test_doors::spend::set_scope_ceiling;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::test_doors::wake_d1_park_release as release_doors;
use oneiron::{
    CallPurpose, DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerWakeDriver, EdgeActorClass, EntityId, ModelLocality, OutboundDraftInput, RunWakePass,
    TimeRange, Vault, VaultConfig, WakeAttemptContext, WakeCancellation, WakePassDeadline,
    WakePassReport, WakeTrigger,
};
use retained_side_rows::{
    export_whole, open_later_vault, open_source_vault, owner_proof, retained_rows, rows_for,
};

/// The `field` count for `table` in a `retained_side_rows` JSON summary, when
/// the table entry and the field are both present.
fn table_count(summary: &serde_json::Value, table: &str, field: &str) -> Option<u64> {
    summary
        .get("tables")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("source_table").and_then(|name| name.as_str()) == Some(table))?
        .get(field)?
        .as_u64()
}

/// The held-back list for `table` in a `retained_side_rows` JSON summary,
/// when the table entry and the list are both present.
fn held_back_for_table(summary: &serde_json::Value, table: &str) -> Option<serde_json::Value> {
    summary
        .get("tables")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("source_table").and_then(|name| name.as_str()) == Some(table))?
        .get("held_back")
        .cloned()
}

/// A fixed entity id from one repeated byte. The banned bytes (00, 11, 42,
/// 47, A1..A6, D7, E1, FF) belong to other fixtures.
fn fixed_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("a non-reserved repeated byte is a valid entity id")
}

/// The three history tables the first test carries through the archive.
const HISTORY_TABLES: [&str; 3] = [
    "POLICY_SETTING_ACT",
    "OWNER_POLICY_SECRET_SCAN_RECEIPT",
    "OWNER_POLICY_CHANGE_EVENT",
];

/// The reserve every spent free-time step guard asks.
const STEP_RESERVE: u64 = 500;
/// The free-time policy's total: the cycle root's cap.
const FREE_TIME_TOTAL: u64 = 10_000;
/// A pass time well past the policy's first boundary, never the wall.
const PASS_NOW: u64 = 4_000_000_000;

/// Polls a free-time future to readiness on a no-op waker, panicking when it stays
/// pending past its attempt-boundary yields.
fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("a free-time future pending on something other than an attempt-boundary yield");
}

/// A backend a spent or refused step must never reach: any call panics, and the count stays
/// readable.
struct NeverBackend {
    calls: AtomicUsize,
}

impl NeverBackend {
    /// A backend that has answered no call yet.
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }

    /// How many calls reached the backend; a refused step leaves zero.
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl llm::LlmBackend for NeverBackend {
    fn generate<'a>(
        &'a self,
        _request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("a spent step must not call its backend");
    }

    fn stream<'a>(
        &'a self,
        _request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmStreamResult<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("a spent step must not call its backend");
    }
}

/// The host egress an own-server call runs under: every fixture call permitted.
fn allow_egress(_: &llm::LlmRequest) -> bool {
    true
}

/// A frozen pass deadline, as the WAKE-D1 fixture builds one.
fn frozen_deadline() -> WakePassDeadline {
    let elapsed = Arc::new(AtomicU64::new(0));
    WakePassDeadline::with_clock(180_000, Arc::new(move || elapsed.load(Ordering::SeqCst)))
}

/// Widens the vault's inference defaults so an own-server call of a free-time item is admitted:
/// its call is gated as an extraction.
fn widen_inference(vault: &Vault) {
    let mut table = vault.purpose_default_table().expect("default table");
    table.extraction_max_locality = ModelLocality::OwnServer;
    for purpose in [CallPurpose::Extraction, CallPurpose::AutonomyForHuman] {
        if let Some(row) = table.purposes.get_mut(&purpose) {
            row.locality = ModelLocality::OwnServer;
        }
    }
    vault
        .set_purpose_default_table(&table)
        .expect("widened table");
}

/// One resident with a free-time policy on an owner-carrier vault, its vault's node the elected
/// home of its cycles.
struct FreeTime {
    _dir: tempfile::TempDir,
    vault: Vault,
    agent: EntityId,
    node: u64,
}

/// One open cycle's item for the resident's human: its cycle and its binding.
struct ForHumanItem {
    cycle: EntityId,
    binding: FreeTimeItemBinding,
}

impl FreeTime {
    /// Opens an owner-carrier vault with a free-time policy for one fresh resident agent,
    /// its own node elected home.
    fn open(pinned_split: Option<FreeTimeSplit>) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let vault = open_owner_carrier_vault(dir.path())?;
        let owner = owner(&vault)?;
        let agent = define_agent(&vault)?;
        widen_inference(&vault);
        let _policy = vault.set_free_time_policy(
            &owner,
            None,
            agent,
            0,
            FreeTimePolicyInput {
                total_units: FREE_TIME_TOTAL,
                schedule: FreeTimeSchedule {
                    cadence: FreeTimeCadence::Nightly,
                    hour: 2,
                    minute: 0,
                    zone: "Asia/Tokyo".to_owned(),
                },
                pinned_split,
                cap_shown_at_ms: 1_000,
            },
        )?;
        let node = release_doors::load_or_mint_client_id(&vault)?;
        let store = DreamerRunnerStore::new(&vault);
        let candidate = store.local_home_node_candidate(true, true, true)?;
        let home = store
            .elect_home_node(&[candidate], PASS_NOW)?
            .expect("the vault's node is elected home");
        assert_eq!(home.node_id, node, "the vault's own node is its home");
        Ok(Self {
            _dir: dir,
            vault,
            agent,
            node,
        })
    }

    /// Opens the policy's first cycle at the pass time and returns its item for the resident's
    /// human, its try queued and its scope reserved under the cycle's root.
    fn open_cycle(&self) -> Result<ForHumanItem, Box<dyn std::error::Error>> {
        let opened = self
            .vault
            .enqueue_due_free_time_cycles(PASS_NOW, self.node)?;
        assert_eq!(opened, 1, "the policy's first boundary opens one cycle");
        let sheets = self.vault.free_time_cycles(self.agent, None, 1)?;
        let sheet = sheets.first().expect("the open cycle's sheet");
        let item = sheet
            .cycle
            .items
            .iter()
            .find(|item| item.kind == FreeTimeKind::ForHuman)
            .expect("the cycle's item for the resident's human");
        let attempt = AttemptId::from_bytes(&item.attempt.expect("the item's try"))?;
        let binding = self
            .vault
            .free_time_item_binding(attempt)?
            .expect("the item's binding");
        Ok(ForHumanItem {
            cycle: sheet.cycle.cycle,
            binding,
        })
    }

    /// Runs one Timer pass of the server's Dreamer on the home node, at the pass time.
    fn run_timer_pass(
        &self,
        host: &mut ItemHost<'_>,
    ) -> Result<WakePassReport, Box<dyn std::error::Error>> {
        let guard = llm::BudgetGuard::with_reserve_units(
            "side-receipts:p1",
            FREE_TIME_TOTAL,
            100,
            llm::BudgetExhaustionPolicy::Suspend,
        );
        let mut driver =
            DreamerWakeDriver::new(&self.vault, "wake", frozen_deadline()).with_budget_guard(guard);
        Ok(block_on_ready(driver.run_wake_pass(
            RunWakePass {
                trigger: WakeTrigger::Timer,
                scope: DreamerConsolidationScope::Macro,
                local_node_id: self.node,
                lease_owner: DREAMER_SERVER_PARK_OWNER.to_owned(),
                budget_total_units: FREE_TIME_TOTAL,
                reserve_units: 100,
                now: PASS_NOW,
                host_scope: None,
                destination_bound: None,
            },
            host,
            &WakeCancellation::new(),
        ))?)
    }
}

/// The host of a free-time item, as the server's free-time host lends its model: it reads the
/// item's scope before it builds the step's guard, and lends a step guard that is spent, so the
/// item's one step meets its budget. Every other try the pass admits ends without work.
struct ItemHost<'b> {
    backend: &'b NeverBackend,
    ran: usize,
}

impl<'b> ItemHost<'b> {
    /// A host that has run no item yet on the given never-reached backend.
    fn new(backend: &'b NeverBackend) -> Self {
        Self { backend, ran: 0 }
    }
}

impl DreamerAttemptExecutor for ItemHost<'_> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        if attempt.status.payload.attempt_type != DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND {
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_bindings: Vec::new(),
            });
        }
        self.ran += 1;
        let binding = ctx
            .vault
            .free_time_item_binding(attempt.status.attempt.id)?
            .expect("the admitted item's binding");
        let spend_scope = llm::StepSpendScope::read_before_guards(ctx.vault, binding.spend_scope)?;
        let guard = llm::BudgetGuard::with_reserve_units(
            "side-receipts:item-step",
            0,
            STEP_RESERVE,
            llm::BudgetExhaustionPolicy::Suspend,
        );
        let model = llm::ModelId::new("test/model@r1").expect("model id");
        let lent = ResidentDreamModel {
            backend: self.backend,
            guard: &guard,
            model: model.clone(),
            inference: HostInferenceContext {
                binding: HostInferenceBinding::Advertised {
                    model,
                    locality: ModelLocality::OwnServer,
                    keyless: false,
                },
                extraction_egress: Some(&allow_egress),
            },
            role: None,
            instruction: "Suggest one small thing for your human.",
            window_tokens: None,
            sourced: None,
            spend_scope: Some(spend_scope),
        };
        run_free_time_for_human(attempt, ctx, lent).await
    }
}

/// An outbound sink that delivers every send to one provider ref, counting calls.
struct DeliveredSink {
    calls: usize,
}

impl OutboundExecutionSink for DeliveredSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls += 1;
        OutboundExecutionOutcome::delivered_to_channel("provider:message:one")
    }
}

/// The owner restore installs the three histories live; the actorless import
/// lists none.
#[test]
fn the_owner_restore_installs_owner_act_history_and_the_actorless_import_does_not() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let undo = UndoSendSetting {
        all_channels_secs: 30,
        channels: Vec::new(),
    };
    source
        .set_undo_send(&source_owner, Some(ActSurface::ThisInstall), &undo)
        .expect("the owner stores the source undo-send window");
    let source_acts = source
        .policy_setting_acts()
        .expect("read the source policy-setting acts");
    assert_eq!(
        source_acts.len(),
        1,
        "the source holds one policy-setting act"
    );
    let off = source
        .set_secret_scan_mode(&source_owner, SecretScanMode::Off, 20)
        .expect("the owner switches the source secret scan off");
    assert_eq!(
        off.revision, 1,
        "the first switch lands at revision one: {off:?}"
    );
    assert_eq!(
        off.mode,
        SecretScanMode::Off,
        "the first switch turns the scan off: {off:?}"
    );
    assert_eq!(
        off.previous,
        SecretScanMode::On,
        "the first switch replaces the default on mode: {off:?}"
    );
    let source_scans = source
        .secret_scan_change_log()
        .expect("read the source switch log");
    assert_eq!(source_scans.len(), 1, "the source holds one switch receipt");
    assert_eq!(
        source_scans[0], off,
        "the source log holds the switch receipt"
    );
    let source_events = source
        .policy_changed_events()
        .expect("read the source policy events");
    assert_eq!(
        source_events.len(),
        1,
        "the source holds one policy-change event"
    );
    assert_eq!(
        source_events[0].kind, "policy.secret_scan.changed",
        "the source event names the switch change: {:?}",
        source_events[0]
    );
    assert_eq!(
        source_events[0].receipt_id, off.receipt_id,
        "the source event names the switch receipt: {:?}",
        source_events[0]
    );
    assert_eq!(
        source
            .secret_scan_mode()
            .expect("read the source scan mode"),
        SecretScanMode::Off,
        "the source scan mode is off"
    );
    let archive = export_whole(&source);
    let source_rows = retained_rows(&archive);
    for table in HISTORY_TABLES {
        assert_eq!(
            rows_for(&source_rows, table).len(),
            1,
            "the source archive holds one {table} tuple"
        );
    }

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.policy_setting_acts()
            .expect("read the restored policy-setting acts"),
        source_acts,
        "the owner import installs the policy-setting act live"
    );
    assert_eq!(
        dest.secret_scan_change_log()
            .expect("read the restored switch log"),
        source_scans,
        "the owner import installs the switch receipt live"
    );
    assert_eq!(
        dest.policy_changed_events()
            .expect("read the restored policy events"),
        source_events,
        "the owner import installs the policy-change event live"
    );
    assert_eq!(
        dest.secret_scan_mode()
            .expect("read the restored scan mode"),
        SecretScanMode::On,
        "the owner import leaves the scan mode at its default"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for table in HISTORY_TABLES {
        assert_eq!(
            table_count(&summary, table, "installed_rows"),
            Some(1),
            "the owner import reports one installed {table} row; an absent field means it installed nothing: {summary}"
        );
    }

    let repeat = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the repeat owner import succeeds");
    let repeat_summary =
        serde_json::to_value(&repeat.retained_side_rows).expect("the repeat summary serializes");
    for table in HISTORY_TABLES {
        assert_eq!(
            table_count(&repeat_summary, table, "unchanged_live_rows"),
            Some(1),
            "the repeat owner import reports one unchanged live {table} row; an absent field means it counted no live outcome: {repeat_summary}"
        );
        assert_eq!(
            table_count(&repeat_summary, table, "installed_rows"),
            Some(0),
            "the repeat owner import installs no {table} row; an absent field means it counted no live outcome: {repeat_summary}"
        );
    }

    let (_bare_dir, bare) = open_later_vault();
    let bare_receipt = bare
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    assert!(
        bare.policy_setting_acts()
            .expect("read the actorless policy-setting acts")
            .is_empty(),
        "the actorless import lists no policy-setting act"
    );
    assert!(
        bare.secret_scan_change_log()
            .expect("read the actorless switch log")
            .is_empty(),
        "the actorless import lists no switch receipt"
    );
    assert!(
        bare.policy_changed_events()
            .expect("read the actorless policy events")
            .is_empty(),
        "the actorless import lists no policy-change event"
    );
    let bare_summary =
        serde_json::to_value(&bare_receipt.retained_side_rows).expect("the summary serializes");
    for table in HISTORY_TABLES {
        assert!(
            matches!(
                table_count(&bare_summary, table, "installed_rows"),
                None | Some(0)
            ),
            "the actorless import installs no {table} row: {bare_summary}"
        );
    }
}

/// The next switch after a restore takes the revision after the restored one.
#[test]
fn the_next_owner_act_after_a_restore_follows_the_restored_sequence() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let off = source
        .set_secret_scan_mode(&source_owner, SecretScanMode::Off, 20)
        .expect("the owner switches the source secret scan off");
    assert_eq!(
        off.revision, 1,
        "the source switch lands at revision one: {off:?}"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let restored = dest
        .secret_scan_change_log()
        .expect("read the restored switch log");
    assert_eq!(
        restored.len(),
        1,
        "the owner import installs the one switch receipt"
    );
    assert_eq!(
        restored[0], off,
        "the restored receipt equals the source receipt"
    );
    let next = dest
        .set_secret_scan_mode(&dest_owner, SecretScanMode::Off, 30)
        .expect("the destination owner switches the scan off again");
    assert_eq!(
        next.revision, 2,
        "the next switch after a restore takes revision two: {next:?}"
    );
    let log = dest
        .secret_scan_change_log()
        .expect("read the destination switch log");
    assert_eq!(
        log.len(),
        2,
        "the history lists the restored receipt and the new one"
    );
    assert_eq!(
        log[0], off,
        "the first log entry stays the restored receipt"
    );
    assert_eq!(
        log[1], next,
        "the second log entry is the new switch receipt"
    );
}

/// A destination act at the same sequence stays live and the source act stays
/// retained.
#[test]
fn a_destination_act_at_the_same_sequence_stays_live_and_the_source_act_stays_retained() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let source_setting = UndoSendSetting {
        all_channels_secs: 30,
        channels: Vec::new(),
    };
    source
        .set_undo_send(
            &source_owner,
            Some(ActSurface::ThisInstall),
            &source_setting,
        )
        .expect("the owner stores the source undo-send window");
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "POLICY_SETTING_ACT");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one policy-setting tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let dest_setting = UndoSendSetting {
        all_channels_secs: 60,
        channels: Vec::new(),
    };
    assert_ne!(
        dest_setting, source_setting,
        "the two undo-send windows differ before the import"
    );
    dest.set_undo_send(&dest_owner, Some(ActSurface::ThisInstall), &dest_setting)
        .expect("the destination owner stores its own undo-send window");
    let dest_acts_before = dest
        .policy_setting_acts()
        .expect("read the destination acts before the import");
    assert_eq!(
        dest_acts_before.len(),
        1,
        "the destination holds its own act before the import"
    );
    let pre_tuple = rows_for(&retained_rows(&export_whole(&dest)), "POLICY_SETTING_ACT");
    assert_eq!(
        pre_tuple.len(),
        1,
        "the destination archive holds its live tuple before the import"
    );
    assert_ne!(
        pre_tuple, source_tuple,
        "the two act tuples differ before the import"
    );

    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.policy_setting_acts()
            .expect("read the destination acts after the import"),
        dest_acts_before,
        "the owner import keeps the different destination act live"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "POLICY_SETTING_ACT", "kept_live_rows"),
        Some(1),
        "the owner import reports one kept-live POLICY_SETTING_ACT row; an absent field means it counted no live outcome: {summary}"
    );
    let post = rows_for(&retained_rows(&export_whole(&dest)), "POLICY_SETTING_ACT");
    assert_eq!(
        post.len(),
        2,
        "the destination keeps both acts after a kept-live import"
    );
    assert!(
        post.contains(&source_tuple[0]) && post.contains(&pre_tuple[0]),
        "the destination archive holds its live tuple and the retained source tuple byte for byte: {post:?}"
    );
}

/// A Delivered send summary without its idempotency support is held back.
#[test]
fn a_delivered_send_summary_without_its_idempotency_support_is_held_back() {
    // A provider channel that no built-in pack names: the seeded vault holds
    // its built-in email packs only as candidates, and a channel one of them
    // serves sends only through an installed, checked pack.
    const SEND_CHANNEL: &str = "email_resend";
    let source_dir = tempfile::tempdir().expect("temp dir for the source vault");
    let source_clock = ManualClock::new(90);
    let mut source_config = VaultConfig::default();
    source_config.store_clock = source_clock.bundle();
    let source =
        Vault::open_owned(source_dir.path(), source_config).expect("open the source vault");
    // The send pipeline signs its binding with this install's device key
    // (`OutboundBindingAuthority::for_vault`), as a host's would.
    source.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    let source_owner = owner_proof(&source);
    let actor = fixed_id(0x4A);
    source
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 90, end: 90 },
            90,
            b"send actor",
        )
        .expect("the source holds the send actor");
    let view = policy_manifests_as_owner(
        &source,
        &source_owner,
        &PolicyManifestRead { manifest_ref: None },
    )
    .expect("read the source policy manifests");
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .expect("the default policy manifest");
    let mut manifest = default.manifest.clone();
    manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "agent".to_owned(),
        actor_ref: Some(actor.to_hex()),
        ceiling: PolicyCeiling::Auto,
    });
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["effect".to_owned()]));
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    rows.push(PolicyScopedGrantRow {
        actor_class: None,
        actor_ref: Some(actor.to_hex()),
        effector: "external:send".to_owned(),
        scope,
        selectors: Some(PolicyGrantValue::Map(vec![PolicyGrantMapEntry {
            key: PolicyGrantValue::String("channel".to_owned()),
            value: PolicyGrantValue::String(SEND_CHANNEL.to_owned()),
        }])),
        budget: None,
        receipt_required: false,
    });
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        &source,
        &source_owner,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )
    .expect("the owner grants the agent sends on the channel");
    source
        .register_connector_key(
            &fixed_id(0x4E),
            ConnectorKeyRecord::active(
                SEND_CHANNEL,
                None,
                vec![EffectorBudget::sends(
                    5,
                    EffectorBudgetWindow::Calendar {
                        period: CalendarPeriod::Day,
                        tz: None,
                    },
                    EffectorBudgetOnExhaust::Suspend,
                )],
                1_000,
            ),
        )
        .expect("the source registers the channel's sends key");
    let draft = OutboundDraftInput {
        verb: "send".to_owned(),
        channel: SEND_CHANNEL.to_owned(),
        target: "transport:shared-inbox".to_owned(),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: Some("durable-idempotency:test".to_owned()),
        dedupe_key: None,
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:durable-idempotency".to_owned(),
        job_ref: None,
        occurred_at: Some(90),
        mention: None,
    };
    let first = source
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound_for_counterparty(&draft, "counterparty:durable-idempotency")
        .expect("the first schedule lands");
    assert!(
        !first.deduped,
        "the first schedule is not a dedupe: {first:?}"
    );
    let unsettled = source
        .connector_send_tasks()
        .expect("read the unsettled send tasks");
    assert_eq!(
        unsettled.len(),
        1,
        "the source holds one unsettled send task"
    );
    let task_ref = unsettled[0].task_ref;
    assert_eq!(
        unsettled[0].outcome, None,
        "the unsettled task has no outcome yet: {:?}",
        unsettled[0]
    );
    source_clock.set(91);
    let mut sink = DeliveredSink { calls: 0 };
    let executed = source
        .run_connector_task_executor(&mut sink, 91)
        .expect("the executor runs");
    assert_eq!(executed, 1, "the executor delivers one send");
    assert_eq!(sink.calls, 1, "the sink delivers once");
    let settled = source
        .connector_send_task(&task_ref)
        .expect("read the settled send task")
        .expect("the settled send task");
    assert_eq!(
        settled.outcome,
        Some(ConnectorSendTaskOutcome::Delivered),
        "the settled task is Delivered: {settled:?}"
    );
    let outbound = source
        .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))
        .expect("read the source outbound receipts");
    assert_eq!(outbound.len(), 1, "the source holds one outbound receipt");
    let archive = export_whole(&source);
    let source_summary = rows_for(&retained_rows(&archive), "SEND_RECEIPT_SUMMARY");
    assert_eq!(
        source_summary.len(),
        1,
        "the source archive holds one send-summary tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let dest_outbound = dest
        .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))
        .expect("read the destination outbound receipts");
    assert_eq!(
        dest_outbound, outbound,
        "the owner import installs the send attempt audit live"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "SEND_RECEIPT_ATTEMPT_AUDIT", "installed_rows"),
        Some(1),
        "the owner import reports one installed SEND_RECEIPT_ATTEMPT_AUDIT row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        held_back_for_table(&summary, "SEND_RECEIPT_SUMMARY"),
        Some(serde_json::json!([{"reason": "missing_companion", "rows": 1}])),
        "the owner import holds back one send summary as missing_companion; an absent field means it counted no held-back outcome: {summary}"
    );
    assert!(
        matches!(
            table_count(&summary, "SEND_RECEIPT_SUMMARY", "installed_rows"),
            None | Some(0)
        ),
        "the owner import installs no send summary: {summary}"
    );
    assert_eq!(
        rows_for(&retained_rows(&export_whole(&dest)), "SEND_RECEIPT_SUMMARY"),
        source_summary,
        "the destination retains the held-back summary tuple byte for byte"
    );
}

/// Restored free-time and team receipts install as history.
#[test]
fn restored_free_time_and_team_receipts_install_as_history()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FreeTime::open(Some(FreeTimeSplit {
        for_human_units: FREE_TIME_TOTAL / 2,
        own_time_units: FREE_TIME_TOTAL / 2,
    }))?;
    let item = fixture.open_cycle()?;
    let ceiling = STEP_RESERVE / 5;
    set_scope_ceiling(&fixture.vault, &item.binding.spend_scope, ceiling)?;
    let backend = NeverBackend::new();
    let mut host = ItemHost::new(&backend);
    let report = fixture.run_timer_pass(&mut host)?;
    assert_eq!(host.ran, 1, "the pass runs the item once: {report:?}");
    let source_sheet = fixture
        .vault
        .free_time_cycle(fixture.agent, item.cycle)?
        .expect("the source cycle sheet");
    let source_receipts = source_sheet.receipts;
    assert!(
        !source_receipts.is_empty(),
        "the source pass writes at least one free-time receipt"
    );
    let failed = source_receipts
        .iter()
        .find(|receipt| receipt.kind == FreeTimeKind::ForHuman)
        .expect("the source free-time receipt for the resident's human");
    assert_eq!(
        failed.outcome,
        FreeTimeItemOutcome::Failed,
        "the source item receipt says it failed: {failed:?}"
    );
    assert_eq!(backend.calls(), 0, "a refused step never calls its backend");
    let source_cycle = item.cycle;
    let source_agent = fixture.agent;

    let tree = type_tree(&fixture.vault, None)?;
    let team = TeamReceipt {
        team_ref: "team-archive-1".to_owned(),
        project: None,
        type_ref: tree.root(),
        pattern: TeamPattern::Solo,
        pattern_skill: None,
        axis: TeamAxis::Converge,
        models: vec!["model-a@1".to_owned()],
        shape: TeamShape {
            width: 1,
            roles: BTreeMap::from([("solo".to_owned(), 1)]),
        },
        decided_by: DecidedBy::Leader {
            actor: fixed_id(0x2D),
        },
        coverage: None,
        confessions: None,
        spend: None,
        spend_cap: None,
        elapsed_secs: 10,
        calls: None,
        outcome: None,
        at: 1_700_000_010,
    };
    record_team_receipt(&fixture.vault, &team)?;
    assert_eq!(
        team_receipt(&fixture.vault, "team-archive-1")?,
        Some(team.clone()),
        "the source holds the team receipt"
    );
    let archive = export_whole(&fixture.vault);
    let source_rows = retained_rows(&archive);
    let free_time_tuples = rows_for(&source_rows, "DREAMER_FREE_TIME_RECEIPT");
    assert_eq!(
        free_time_tuples.len(),
        source_receipts.len(),
        "the source archive holds one free-time tuple per source receipt"
    );
    assert_eq!(
        rows_for(&source_rows, "TEAM_RECEIPT").len(),
        1,
        "the source archive holds one team tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "DREAMER_FREE_TIME_RECEIPT", "installed_rows"),
        Some(source_receipts.len() as u64),
        "the owner import reports one installed row per source free-time receipt; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        table_count(&summary, "TEAM_RECEIPT", "installed_rows"),
        Some(1),
        "the owner import reports one installed TEAM_RECEIPT row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        team_receipt(&dest, "team-archive-1")?,
        Some(team.clone()),
        "the owner import installs the team receipt live"
    );
    // A restored agent definition comes back switched off and proposed, and
    // an agent that is off opens no free-time cycle. The owner turns it back
    // on, as after any restore.
    let mut restored = dest
        .get_agent_definition(&source_agent)?
        .expect("the destination holds the restored agent");
    assert!(
        !restored.enabled,
        "an owner import restores an agent definition switched off"
    );
    restored.enabled = true;
    restored.approval_status = oneiron::ClaimApprovalStatus::Approved;
    restored.version = "2".to_owned();
    dest.update_agent_definition_as(
        &dest_owner,
        &source_agent,
        &restored,
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    dest.set_free_time_policy(
        &dest_owner,
        None,
        source_agent,
        0,
        FreeTimePolicyInput {
            total_units: FREE_TIME_TOTAL,
            schedule: FreeTimeSchedule {
                cadence: FreeTimeCadence::Nightly,
                hour: 2,
                minute: 0,
                zone: "Asia/Tokyo".to_owned(),
            },
            pinned_split: Some(FreeTimeSplit {
                for_human_units: FREE_TIME_TOTAL / 2,
                own_time_units: FREE_TIME_TOTAL / 2,
            }),
            cap_shown_at_ms: 1_000,
        },
    )?;
    let dest_node = release_doors::load_or_mint_client_id(&dest)?;
    let dest_store = DreamerRunnerStore::new(&dest);
    let dest_candidate = dest_store.local_home_node_candidate(true, true, true)?;
    dest_store.elect_home_node(&[dest_candidate], PASS_NOW)?;
    let opened = dest.enqueue_due_free_time_cycles(PASS_NOW, dest_node)?;
    assert_eq!(opened, 1, "the destination opens its matching cycle");
    let dest_sheet = dest
        .free_time_cycle(source_agent, source_cycle)?
        .expect("the destination cycle sheet");
    assert_eq!(
        dest_sheet.receipts.len(),
        source_receipts.len(),
        "the destination holds as many free-time receipts as the source: {:?}",
        dest_sheet.receipts
    );
    assert!(
        source_receipts
            .iter()
            .all(|receipt| dest_sheet.receipts.contains(receipt)),
        "the owner import installs every source free-time receipt live: {:?}",
        dest_sheet.receipts
    );
    Ok(())
}

#[test]
fn a_consumed_check_in_receipt_restores_as_history() {
    use check_in_fixture::{DIGEST, Fixture, people, request};
    use oneiron::check_in::{ActClass, EligibleBasis, HolderAnswer, Rung};
    use oneiron::test_doors::check_in::{FixedChain, answer, consume, open};

    let fx = Fixture::open();
    let (holder, holder_proof) = fx.person();
    let chain = FixedChain::default().with(Rung::Owner, people(&[holder]));
    let id = open(&fx.vault, request(EntityId::now(), ActClass::Spawn), &chain)
        .expect("the check-in opens")
        .id;
    answer(
        &fx.vault,
        &holder_proof,
        &id,
        &DIGEST,
        HolderAnswer::Approve,
    )
    .expect("the holder approves");
    assert_eq!(
        consume(&fx.vault, &id, &DIGEST).expect("the approved act runs"),
        EligibleBasis::Approved
    );
    let source_outcomes = fx.outcomes(&id);
    assert_eq!(
        source_outcomes.last().map(String::as_str),
        Some("consumed"),
        "the spent check-in's last receipt is consumed: {source_outcomes:?}"
    );
    let archive = export_whole(&fx.vault);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        held_back_for_table(&summary, "CHECK_IN_RECEIPT"),
        None,
        "the owner import holds back no check-in receipt: {summary}"
    );
    assert_eq!(
        table_count(&summary, "CHECK_IN_RECEIPT", "installed_rows"),
        Some(source_outcomes.len() as u64),
        "the owner import installs every check-in receipt: {summary}"
    );
    let mut query = ReceiptQuery::new(100);
    query.kinds = [ReceiptKind::CheckIn].into();
    query.job_ref = Some(id.to_hex());
    let mut restored = dest.receipts(query).expect("read the restored receipts");
    restored.sort_by_key(|receipt| receipt.receipt_id.clone());
    assert_eq!(
        restored
            .into_iter()
            .map(|receipt| receipt.outcome)
            .collect::<Vec<_>>(),
        source_outcomes,
        "the destination holds the source check-in history, consumed included"
    );
}

/// A rotation receipt body as a writer stores it: the canonical keys in
/// order, with `cause` last when the writer recorded one.
fn rotation_receipt_body(rotated_at: u64, cause: Option<&str>) -> Vec<u8> {
    let mut entries = vec![
        (
            rmpv::Value::from("secret_ref"),
            rmpv::Value::from("mail-relay"),
        ),
        (
            rmpv::Value::from("from_generation"),
            rmpv::Value::from(1_u64),
        ),
        (rmpv::Value::from("to_generation"), rmpv::Value::from(2_u64)),
        (
            rmpv::Value::from("rotated_at"),
            rmpv::Value::from(rotated_at),
        ),
        (rmpv::Value::from("kind"), rmpv::Value::from("rotated")),
    ];
    if let Some(cause) = cause {
        entries.push((rmpv::Value::from("cause"), rmpv::Value::from(cause)));
    }
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &rmpv::Value::Map(entries)).expect("encode the body");
    body
}

#[test]
fn rotation_receipts_of_either_body_form_restore_as_history() {
    use oneiron::test_doors::archive_side_catalogue::put_secret_rotation_receipt_body;

    let (_source_dir, source) = open_source_vault();
    for (rotated_at, cause) in [(100, None), (200, Some("provider_refresh"))] {
        put_secret_rotation_receipt_body(
            &source,
            EntityId::now(),
            &rotation_receipt_body(rotated_at, cause),
        )
        .expect("the source stores the rotation receipt");
    }
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        held_back_for_table(&summary, "SECRET_ROTATION_RECEIPT"),
        None,
        "the owner import holds back neither rotation receipt: {summary}"
    );
    assert_eq!(
        table_count(&summary, "SECRET_ROTATION_RECEIPT", "installed_rows"),
        Some(2),
        "the owner import installs both rotation receipts: {summary}"
    );
}
