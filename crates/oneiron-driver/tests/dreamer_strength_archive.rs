//! The production strength facet (untangle 6.9c PR 4, MAP-6.9 row 6.9c): a
//! wake pass through the production factory's executor and the core
//! dispatch archives an old, weak Dreamer claim as ONE derive batch by the
//! Dreamer actor, with an Archive item and its strength snapshot; the
//! owner's `vault.derive.revert` restores it; with the Dreamer's grant
//! narrowed to drop `derive`, nothing is archived and the refusal names the
//! grant.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver
//! --all-features --test dreamer_strength_archive` (the driver's dev
//! dependency turns on the engine's `test-support` feature).
#![cfg(oneiron_test_support)]
// The layout of `run_wake_pass`'s future (the wake driver, the dispatch and
// the job adapter, all async) needs a query depth of about 130, past
// rustc's default limit of 128.
#![recursion_limit = "256"]

use std::sync::Arc;

use oneiron::attempt_queue::{AttemptQueue, AttemptState};
use oneiron::dreamer_promotion::AttemptPromotionSink;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{derive_item_receipts, row_live};
use oneiron::test_doors::derive_verbs::revert_as_owner;
use oneiron::test_doors::dreamer_attempt_binding::{
    ObservedStrengthClaim, STRENGTH_RUN, enqueue_unadmitted_strength_attempt,
    observe_strength_claim,
};
use oneiron::test_doors::run_lifecycle::defer_enqueued;
use oneiron::test_doors::steward::{
    STEWARD_ARCHIVE_VERB, STEWARD_READ_VERB, STEWARD_VERBS, archive_every_quiet_claim, dreamer,
    stand_steward_grant,
};
use oneiron::test_doors::wake_d1_park_release::load_or_mint_client_id;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, DreamerClaimAuthoringStrategy, DreamerConsolidationScope,
    DreamerWakeDriver, EntityId, RunWakePass, Vault, VaultConfig, WakeCancellation,
    WakePassDeadline, WakeTrigger,
};
use oneiron_driver::{ConsolidationExecutorFactory, PassExecutorFactory};

type StrengthTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The strength facet calls no model: a call reaching this backend is the
/// defect.
struct NoModelBackend;

impl oneiron::LlmBackend for NoModelBackend {
    fn generate<'a>(
        &'a self,
        _request: oneiron::LlmRequest,
        _lease: &'a oneiron::BudgetLease,
    ) -> oneiron::LlmGenerateFuture<'a> {
        Box::pin(async { panic!("the strength facet must never call a model") })
    }

    fn stream<'a>(
        &'a self,
        _request: oneiron::LlmRequest,
        _lease: &'a oneiron::BudgetLease,
    ) -> oneiron::LlmStreamResult<'a> {
        panic!("the strength facet must never stream")
    }
}

/// A Dreamer with a Steward grant of `verbs`, one observed claim that is
/// quiet and weak under the policy, and its strength attempt queued for the
/// next wake pass, at the vault's clock in seconds.
struct QueuedStrength {
    vault: Arc<Vault>,
    dreamer: EntityId,
    observed: ObservedStrengthClaim,
    grant: EntityId,
    now: u64,
}

fn queued_strength(dir: &tempfile::TempDir, verbs: &[&str]) -> StrengthTestResult<QueuedStrength> {
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    let dreamer = dreamer(&vault)?;
    stand_steward_grant(&vault, dreamer, &STEWARD_VERBS)?;
    let observed = observe_strength_claim(&vault)?;
    archive_every_quiet_claim(&vault)?;
    let grant = stand_steward_grant(&vault, dreamer, verbs)?;
    // The observation is recorded one second ahead of the clock; it is
    // quiet once the clock passes it.
    std::thread::sleep(std::time::Duration::from_millis(2_100));
    let now = vault.now_recorded_at();
    // Only the strength attempt is due in the pass: anything the fixture's
    // consolidation left queued (a PERSON `about` line, say) would call a
    // model, and the pass ends at the first executor panic.
    for record in AttemptQueue::new(&vault).list()? {
        if matches!(record.state, AttemptState::Queued) {
            defer_enqueued(&vault, record.id, now + 86_400)?;
        }
    }
    enqueue_unadmitted_strength_attempt(&vault, observed.seed, now)?;
    Ok(QueuedStrength {
        vault,
        dreamer,
        observed,
        grant,
        now,
    })
}

/// The factory a served host builds for a pass, with the vault lent to the
/// Dreamer's jobs.
fn production_factory(vault: &Arc<Vault>) -> StrengthTestResult<ConsolidationExecutorFactory> {
    let model = oneiron::ModelId::new("test/model@v1").expect("a model id");
    Ok(ConsolidationExecutorFactory::new(
        Arc::new(NoModelBackend),
        DreamerClaimAuthoringStrategy::SinglePass,
        vault.dreamer_authority()?,
        model.clone(),
        oneiron::llm::HostInferenceBinding::Advertised {
            model,
            locality: oneiron::ModelLocality::OwnServer,
            keyless: false,
        },
        None,
        Box::new(AttemptPromotionSink::new(Arc::clone(vault))),
    )
    .with_dreamer_job_vault(Arc::clone(vault)))
}

/// One wake pass at `now` through the production factory's executor and
/// the engine's wake driver.
async fn run_wake_pass(vault: &Arc<Vault>, now: u64) -> StrengthTestResult<()> {
    let mut factory = production_factory(vault)?;
    let guard = BudgetGuard::new("wake".to_owned(), 10_000, BudgetExhaustionPolicy::Suspend);
    let mut executor = factory.executor(&guard)?;
    let mut driver = DreamerWakeDriver::new(vault, "wake", WakePassDeadline::new(180_000));
    driver
        .run_wake_pass(
            RunWakePass {
                trigger: WakeTrigger::Compaction,
                scope: DreamerConsolidationScope::Micro,
                local_node_id: load_or_mint_client_id(vault)?,
                lease_owner: "wake-worker".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                now,
                host_scope: None,
                destination_bound: None,
            },
            &mut executor,
            &WakeCancellation::new(),
        )
        .await?;
    Ok(())
}

#[tokio::test]
async fn the_strength_facet_archives_as_one_dreamer_batch_and_the_owner_revert_restores_it()
-> StrengthTestResult<()> {
    let dir = tempfile::tempdir()?;
    let queued = queued_strength(&dir, &STEWARD_VERBS)?;
    let claim = queued.observed.claim;

    run_wake_pass(&queued.vault, queued.now).await?;

    let batches = queued.vault.derive_batches_of(queued.dreamer)?;
    assert_eq!(batches.len(), 1, "one derive batch by the Dreamer");
    let record = queued
        .vault
        .derive_batch(batches[0])?
        .unwrap_or_else(|| panic!("the batch is recorded"));
    assert_eq!(record.actor, queued.dreamer, "the Dreamer commits it");
    assert_eq!(record.actor_class, "system");
    assert_eq!(record.run.as_deref(), Some(STRENGTH_RUN));
    assert_eq!(record.items.len(), 1);
    assert_eq!(record.items[0].kind, "archive");
    assert_eq!(record.items[0].rows, vec![claim]);
    assert!(!row_live(&queued.vault, claim)?, "the claim is archived");
    let snapshots = queued.vault.consolidation_strength_snapshots(&claim)?;
    assert_eq!(snapshots.len(), 1, "the Archive item keeps its snapshot");
    assert_ne!(
        snapshots[0].attempt, queued.observed.seed,
        "the archive names the strength attempt"
    );

    revert_as_owner(&queued.vault, batches[0])?;
    assert!(
        row_live(&queued.vault, claim)?,
        "the owner's revert restores the claim"
    );
    Ok(())
}

#[tokio::test]
async fn a_grant_narrowed_off_derive_archives_nothing_and_the_refusal_names_the_grant()
-> StrengthTestResult<()> {
    let dir = tempfile::tempdir()?;
    // The Dreamer keeps `read` and `archive` and loses `derive`: its rows no
    // longer land what it derives.
    let queued = queued_strength(&dir, &[STEWARD_READ_VERB, STEWARD_ARCHIVE_VERB])?;
    let claim = queued.observed.claim;

    run_wake_pass(&queued.vault, queued.now).await?;

    assert!(row_live(&queued.vault, claim)?, "nothing is archived");
    assert!(
        queued
            .vault
            .consolidation_strength_snapshots(&claim)?
            .is_empty()
    );
    let receipts = derive_item_receipts(&queued.vault, &claim)?;
    let [receipt] = receipts.as_slice() else {
        panic!("one refused Archive item: {receipts:?}");
    };
    assert_eq!(receipt.outcome, "deny");
    assert_eq!(receipt.reasons, ["gate.deny.derive.no_landing_rows"]);
    assert_eq!(
        receipt.grant_ref,
        Some(queued.grant.to_hex()),
        "the refusal names the narrowed grant"
    );
    Ok(())
}
