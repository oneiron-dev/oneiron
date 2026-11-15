//! The Dreamer is warm by default (ARCH-0026): a fresh vault's wake pass
//! lands its claim Auto through the owned attempt sink with no grant step. A
//! vault seeded before the rows shipped reads nothing and lands nothing until
//! the owner grants the weave.
use super::*;
use crate::dreamer_wake::{DreamerWakeDriver, RunWakePass, WakeCancellation, WakeTrigger};
use std::future::Future;
use std::task::{Context, Poll, Waker};

use crate::test_util::{seeded_without_dreamer_rows, without_dreamer_rows};

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
        roles: Default::default(),
        backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
        inference: test_inference_host(),
        scope: None,
        decisions: ConsolidationDecisions::shipped()?,
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
            destination_bound: None,
        },
        &mut executor,
        &WakeCancellation::new(),
    ))
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
    let turn = seed_turn(&vault, &conversation, "user", "call me Owen", 10);
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
    let turn = seed_turn(&vault, &conversation, "user", "call me Owen", 10);
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
    let later = seed_turn(&vault, &conversation, "user", "call me Owen", 40);
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

/// X02 (untangle slice 6.2): the strength archive takes back what the Dreamer
/// landed, so it is judged in its own write by the rows that let it land: the
/// Dreamer's Auto actor ceiling and its `Generated` permit. With either row
/// removed nothing is archived and no receipt is written; with the shipped
/// rows the claim is archived and its receipt names the rows and the policy
/// frontier it was judged under. Before, the archive judged nothing and
/// minted its own approved receipt. Slice 6.3 keeps this test, pointed at a
/// narrowed Steward grant.
#[test]
fn the_dreamers_steward_grant_replaces_its_three_rows() -> Result<()> {
    use crate::federation::grant_scope::{
        STEWARD_ARCHIVE_VERB, STEWARD_DERIVE_VERB, STEWARD_READ_VERB, STEWARD_VERBS,
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    crate::test_util::provision_engine_machines(&vault);
    let dreamer = vault.dreamer_authority()?.entity_ref();
    // No grant yet: the shipped rows decide.
    assert!(vault.dreamer_weave_reach()?.ready());

    vault.stand_steward_grant_for_test(dreamer, &STEWARD_VERBS)?;
    assert!(vault.dreamer_weave_reach()?.ready());

    vault.stand_steward_grant_for_test(dreamer, &[STEWARD_READ_VERB])?;
    let reach = vault.dreamer_weave_reach()?;
    assert!(reach.reads && !reach.lands_auto, "{reach:?}");

    vault.stand_steward_grant_for_test(dreamer, &[STEWARD_DERIVE_VERB, STEWARD_ARCHIVE_VERB])?;
    let reach = vault.dreamer_weave_reach()?;
    assert!(!reach.reads && reach.lands_auto, "{reach:?}");

    vault.mark_steward_opt_out_for_test(dreamer)?;
    let reach = vault.dreamer_weave_reach()?;
    assert!(!reach.reads && !reach.lands_auto, "{reach:?}");
    Ok(())
}

/// Untangle 6.3, census X04: the Dreamer's read key is held to its Steward
/// grant and its live MACHINE binding, as an ordinary agent's slip is held
/// to its issuance and revocation. Before any grant the key reads by the
/// rows; with the grant it reads; once the grant gives no `read` (or the
/// owner opted out) the same key reads nothing.
#[test]
fn the_dreamers_read_key_is_held_to_its_live_grant() -> Result<()> {
    use crate::federation::grant_scope::{STEWARD_DERIVE_VERB, STEWARD_VERBS};
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    crate::test_util::provision_engine_machines(&vault);
    let dreamer = vault.dreamer_authority()?;
    let conversation = seed_session(&vault, 0x6f, 1);
    let turn = seed_turn(&vault, &conversation, "user", "call me Owen", 10);
    let key = crate::claim::ScopedReadActorKey::for_engine_actor(dreamer).expect("dreamer key");
    assert_eq!(key.system_agent_guard(), Some(dreamer.entity_ref()));
    let reads = |vault: &Vault| -> Result<bool> {
        let read = vault.scoped_read(key.clone());
        let txn = vault.store.env.read_txn()?;
        Ok(read.entity_raw_live_in(&txn, &turn)?.is_some())
    };
    assert!(reads(&vault)?, "before any grant the rows let it read");

    vault.stand_steward_grant_for_test(dreamer.entity_ref(), &STEWARD_VERBS)?;
    assert!(reads(&vault)?, "the grant and the live binding let it read");

    vault.stand_steward_grant_for_test(dreamer.entity_ref(), &[STEWARD_DERIVE_VERB])?;
    assert!(!reads(&vault)?, "a grant without read reads nothing");

    vault.mark_steward_opt_out_for_test(dreamer.entity_ref())?;
    assert!(!reads(&vault)?, "an opt-out reads nothing");
    Ok(())
}

/// X02's test, pointed at a narrowed Steward grant (untangle 6.3; the X02
/// verdict, Engine and lead 16:5x). With the full grant the archive lands
/// and its receipt names the grant; with the grant narrowed to drop
/// `derive` (the `Generated` permit and the Auto ceiling it yields) nothing
/// is archived and no receipt is written.
#[test]
fn the_first_mint_copies_the_dreamers_rows() -> Result<()> {
    use crate::federation::SystemAgentGrantState;
    use crate::federation::grant_scope::STEWARD_VERBS;
    for rows in [true, false] {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device())?;
        crate::test_util::provision_engine_machines(&vault);
        vault.ensure_embedded_owner_actor().expect("embedded owner");
        if !rows {
            seeded_without_dreamer_rows(&vault)?;
        }
        let dreamer = vault.dreamer_authority()?.entity_ref();
        vault.provision_system_agent_grants()?;
        let state = {
            let txn = vault.store.env.read_txn()?;
            vault.system_agent_grant_state_in(&txn, dreamer)?
        };
        match (rows, state) {
            (true, Some(SystemAgentGrantState::Minted { grant })) => {
                let txn = vault.store.env.read_txn()?;
                let verbs = crate::federation::standing_steward_verbs_in(
                    &vault.store,
                    &txn,
                    grant,
                    dreamer,
                )?;
                let expected: std::collections::BTreeSet<String> = STEWARD_VERBS
                    .iter()
                    .map(|verb| (*verb).to_owned())
                    .collect();
                assert_eq!(verbs, expected);
                assert!(vault.dreamer_weave_reach()?.ready());
            }
            (false, Some(SystemAgentGrantState::OptedOut)) => {
                let reach = vault.dreamer_weave_reach()?;
                assert!(!reach.reads && !reach.lands_auto);
            }
            other => panic!("unexpected first mint: {other:?}"),
        }
        vault.provision_system_agent_grants()?;
        let again = {
            let txn = vault.store.env.read_txn()?;
            vault.system_agent_grant_state_in(&txn, dreamer)?
        };
        assert_eq!(again, state, "a second open mints nothing");
    }
    Ok(())
}
