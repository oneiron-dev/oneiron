//! A stock vault's Dreamer reads nothing and lands nothing until the owner
//! grants the weave; after the grant, one wake pass lands its claim Auto
//! through the owned attempt sink.
use super::*;
use crate::dreamer_wake::{DreamerWakeDriver, RunWakePass, WakeCancellation, WakeTrigger};
use std::future::Future;
use std::task::{Context, Poll, Waker};

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..128 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("wake pass did not reach a boundary");
}

fn pass(
    vault: &std::sync::Arc<Vault>,
    backend: &ScriptedBackend,
    node_id: u64,
    now: u64,
) -> Result<crate::WakePassReport> {
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let mut sink = crate::dreamer_promotion::AttemptPromotionSink::new(vault.clone());
    let mut executor = ConsolidationExecutor {
        backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
        inference: test_inference_host(),
        scope: None,
    };
    let mut driver = DreamerWakeDriver::new(vault, "wake", WakePassDeadline::new(180_000));
    ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::SessionEnd,
            scope: DreamerConsolidationScope::Micro,
            local_node_id: node_id,
            lease_owner: "grant-test".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 500,
            now,
            host_scope: None,
        },
        &mut executor,
        &WakeCancellation::new(),
    ))
}

#[test]
fn the_owner_grant_lets_a_stock_vaults_dreamer_land_its_consolidation() -> Result<()> {
    // A stock vault: `Vault::open` seeds the shipped policy manifest, which
    // the legacy test opener clears.
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = std::sync::Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    crate::test_util::provision_engine_machines(&vault);
    authorize_test_inference(&vault)?;
    let reach = vault.dreamer_weave_reach()?;
    assert!(
        !reach.reads && !reach.lands_auto,
        "stock policy keeps the Dreamer out"
    );

    let node_id = crate::identity::load_or_mint_client_id(&vault)?;
    let conversation = seed_session(&vault, 0x6b, 1);
    let turn = seed_turn(&vault, &conversation, "user", "call me Oleksii", 10);
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    let enqueue = |run: &str, now: u64| -> Result<()> {
        let watermark = read_watermark(&vault, DreamerConsolidationScope::Micro)?;
        let dirty = scan_dirty_turns(&vault, DreamerConsolidationScope::Micro, &watermark, 10)?;
        enqueue_partition_attempts(
            &vault,
            DreamerConsolidationScope::Micro,
            &dirty,
            &watermark,
            run,
            now,
        )?;
        Ok(())
    };
    enqueue("run-ungranted", 20)?;
    let refused = ScriptedBackend::new(Vec::new());
    let report = pass(&vault, &refused, node_id, 21)?;
    // Without a read grant the source is unreadable: the attempt parks and
    // no model is called.
    assert_eq!(report.completed, 0);
    assert_eq!(refused.calls.load(Ordering::SeqCst), 0);

    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    assert!(vault.grant_dreamer_weave(&owner, 30)?);
    assert!(vault.dreamer_weave_reach()?.ready());
    // Re-granting finds its rows and changes nothing.
    assert!(!vault.grant_dreamer_weave(&owner, 31)?);
    assert!(vault.dreamer_weave_reach()?.ready());

    // A fresh turn after the grant dreams and lands.
    let later = seed_turn(&vault, &conversation, "user", "call me Oleksii", 40);
    enqueue("run-granted", 41)?;
    let backend = ScriptedBackend::new(vec![Ok(extraction_response(&subject, &later))]);
    let report = pass(&vault, &backend, node_id, 42)?;
    assert_eq!(report.completed, 1, "{report:?}");
    let landed: Vec<_> = vault
        .claims_for_subject(&subject)?
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).ok().flatten())
        .filter(|body| body.predicate == "profile.name")
        .collect();
    assert_eq!(landed.len(), 1);
    assert_eq!(landed[0].approval, ClaimApprovalStatus::Auto);
    let _ = turn;
    Ok(())
}
