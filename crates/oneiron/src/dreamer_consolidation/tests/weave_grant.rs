//! The Dreamer is warm by default (ARCH-0026): a fresh vault's wake pass
//! lands its claim Auto through the owned attempt sink with no grant step. A
//! vault seeded before the rows shipped reads nothing and lands nothing until
//! the owner grants the weave.
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

/// The Dreamer's actor-keyed rows removed: the shipped manifest as a release
/// before warm-by-default seeded it, or an owner pack written without them.
fn without_dreamer_rows(manifest: &[u8]) -> Result<Vec<u8>> {
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?.to_hex();
    let names_dreamer = |row: &Value| {
        row.as_map().is_some_and(|fields| {
            fields.iter().any(|(key, value)| {
                key.as_str() == Some("actor_ref") && value.as_str() == Some(&dreamer)
            })
        })
    };
    let strip = |rows: &mut Value| {
        if let Value::Array(list) = rows {
            list.retain(|row| !names_dreamer(row));
            if list.len() == 1 {
                *rows = list.remove(0);
            }
        }
    };
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut &manifest[..]).expect("map") else {
        panic!("policy manifest is a map");
    };
    entries.retain(|(key, value)| {
        !(key.as_str() == Some("scoped_grants")
            && value
                .as_array()
                .is_some_and(|rows| rows.iter().all(names_dreamer)))
    });
    for (key, value) in &mut entries {
        match key.as_str() {
            Some("actor_ceilings") => {
                if let Value::Array(rows) = value {
                    rows.retain(|row| !names_dreamer(row));
                }
            }
            Some("source_trust") => {
                if let Value::Map(sources) = value {
                    for (source, rows) in sources.iter_mut() {
                        if source.as_str() == Some("generated") {
                            strip(rows);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries)).expect("encode");
    Ok(data)
}

/// A vault seeded by a release before the Dreamer's rows shipped: its seeded
/// default has none, and it is still the untouched seed.
fn seeded_without_dreamer_rows(vault: &Vault) -> Result<()> {
    let id = crate::gate::default_policy_manifest_id()?;
    let old = without_dreamer_rows(&crate::gate::default_policy_manifest()?)?;
    crate::test_util::put_policy_manifest_bytes(vault, id, &old)?;
    vault.with_write_txn(|txn| {
        vault.store.sync_state.put(
            txn,
            &crate::gate::seeded_manifest_key(&id),
            blake3::hash(&old).as_bytes(),
        )?;
        Ok(())
    })
}

fn enqueue_micro(vault: &Vault, run: &str, now: u64) -> Result<()> {
    let watermark = read_watermark(vault, DreamerConsolidationScope::Micro)?;
    let dirty = scan_dirty_turns(vault, DreamerConsolidationScope::Micro, &watermark, 10)?;
    enqueue_partition_attempts(
        vault,
        DreamerConsolidationScope::Micro,
        &dirty,
        &watermark,
        run,
        now,
    )?;
    Ok(())
}

fn name_claims(vault: &Vault, subject: &EntityId) -> Result<Vec<ClaimBody>> {
    Ok(vault
        .claims_for_subject(subject)?
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).ok().flatten())
        .filter(|body| body.predicate == "profile.name")
        .collect())
}

#[test]
fn a_fresh_vaults_dreamer_is_warm_and_lands_with_no_grant_step() -> Result<()> {
    // A fresh vault: `Vault::open` seeds the shipped policy manifest, which
    // the legacy test opener clears.
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = std::sync::Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    crate::test_util::provision_engine_machines(&vault);
    authorize_test_inference(&vault)?;
    assert!(vault.dreamer_weave_reach()?.ready());

    let node_id = crate::identity::load_or_mint_client_id(&vault)?;
    let conversation = seed_session(&vault, 0x6c, 1);
    let turn = seed_turn(&vault, &conversation, "user", "call me Oleksii", 10);
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    enqueue_micro(&vault, "run-fresh", 20)?;
    let backend = ScriptedBackend::new(vec![Ok(extraction_response(&subject, &turn))]);
    let report = pass(&vault, &backend, node_id, 21)?;
    assert_eq!(report.completed, 1, "{report:?}");
    let landed = name_claims(&vault, &subject)?;
    assert_eq!(landed.len(), 1);
    assert_eq!(landed[0].approval, ClaimApprovalStatus::Auto);

    // The rows are already there: the owner's grant finds nothing to add, and
    // the seeded default keeps its standing.
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    assert!(!vault.grant_dreamer_weave(&owner, 30)?);
    Ok(())
}

#[test]
fn the_owner_grant_lets_a_vault_seeded_without_the_rows_land_its_consolidation() -> Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = std::sync::Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    crate::test_util::provision_engine_machines(&vault);
    authorize_test_inference(&vault)?;
    seeded_without_dreamer_rows(&vault)?;
    let reach = vault.dreamer_weave_reach()?;
    assert!(
        !reach.reads && !reach.lands_auto,
        "a policy without the rows keeps the Dreamer out"
    );

    let node_id = crate::identity::load_or_mint_client_id(&vault)?;
    let conversation = seed_session(&vault, 0x6b, 1);
    let turn = seed_turn(&vault, &conversation, "user", "call me Oleksii", 10);
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    enqueue_micro(&vault, "run-ungranted", 20)?;
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
    // An earlier owner edit survives the grant: it edits the live policy in
    // place, so no second retention vote makes the policy fail closed.
    vault.set_gate_decision_retention_secs(&owner, Some(86_400))?;
    assert!(vault.grant_dreamer_weave(&owner, 30)?);
    assert!(vault.dreamer_weave_reach()?.ready());
    assert_eq!(vault.gate_decision_retention_secs()?, Some(86_400));
    // Re-granting finds its rows and changes nothing.
    assert!(!vault.grant_dreamer_weave(&owner, 31)?);
    assert!(vault.dreamer_weave_reach()?.ready());

    // A fresh turn after the grant dreams and lands.
    let later = seed_turn(&vault, &conversation, "user", "call me Oleksii", 40);
    enqueue_micro(&vault, "run-granted", 41)?;
    let backend = ScriptedBackend::new(vec![Ok(extraction_response(&subject, &later))]);
    let report = pass(&vault, &backend, node_id, 42)?;
    assert_eq!(report.completed, 1, "{report:?}");
    let landed = name_claims(&vault, &subject)?;
    assert_eq!(landed.len(), 1);
    assert_eq!(landed[0].approval, ClaimApprovalStatus::Auto);
    let _ = turn;
    Ok(())
}

#[test]
fn the_grant_edits_the_owners_own_pack_and_leaves_the_seeded_default_sealed() -> Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    crate::test_util::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    seeded_without_dreamer_rows(&vault)?;
    let default_id = crate::gate::default_policy_manifest_id()?;
    let seeded = vault.get_raw(&default_id)?;
    // The owner's own trusted pack beside the untouched seeded default.
    let shipped = without_dreamer_rows(&crate::gate::default_policy_manifest()?)?;
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut shipped.as_slice()).expect("map")
    else {
        panic!("shipped policy is a map");
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("pack_id") {
            *value = Value::from("owner-pack");
        }
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries)).expect("encode");
    vault.install_owner_policy_manifest(&owner, EntityId::now(), data, 5)?;

    assert!(vault.grant_dreamer_weave(&owner, 6)?);
    assert!(vault.dreamer_weave_reach()?.ready());
    // The seeded default keeps its fallback standing: not one byte moved.
    assert_eq!(vault.get_raw(&default_id)?, seeded);
    Ok(())
}
