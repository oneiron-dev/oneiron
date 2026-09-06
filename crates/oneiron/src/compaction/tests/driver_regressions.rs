//! Active-request identity, budget floors, and complete turn spans.

use super::*;

/// Exercise the real integration door and observe both storage and driver state.
fn refuse_wrong_request(
    vault: &Vault,
    driver: &mut CompactionDriver,
    session: EntityId,
    actor: WriteActor,
    request: &CompactionRequest,
) {
    let rows = stored_row_count(vault);
    let summaries = summary_row_count(vault);
    let markers = pending_embedding_marker_count(vault);
    let margin = *driver.margin();
    let product = driver.backend().compact(request).expect("backend product");
    let error = driver
        .integrate(vault, &session, actor, request, product, &[])
        .expect_err("a different request cannot consume the active flight");
    assert_eq!(
        invariant(error),
        "compaction result does not match the active request"
    );
    assert!(driver.is_compacting());
    assert_eq!(*driver.margin(), margin);
    assert_eq!(stored_row_count(vault), rows);
    assert_eq!(summary_row_count(vault), summaries);
    assert_eq!(pending_embedding_marker_count(vault), markers);
}

#[test]
fn an_abandoned_result_cannot_mint_or_clear_a_new_flight() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let mut driver = engine_driver(1_000);
    let window = host_window(&vault, 0x80, 1, 2);
    driver.evaluate_now(&vault, u64::MAX)?;
    let old = driver.request_for(&vault, &session, window.clone())?;
    driver.abandon();
    driver.evaluate_now(&vault, u64::MAX)?;

    // A crossing without an issued request cannot accept the old result.
    refuse_wrong_request(&vault, &mut driver, session, actor, &old);
    let current = driver.request_for(&vault, &session, window)?;
    assert_eq!(old.watermark, current.watermark);
    assert_eq!(old.window, current.window);
    assert_ne!(
        old, current,
        "even identical snapshots have distinct job identities"
    );
    refuse_wrong_request(&vault, &mut driver, session, actor, &old);

    let product = driver.backend().compact(&current)?;
    let plan = driver.integrate(&vault, &session, actor, &current, product, &[])?;
    assert_eq!(plan.epoch, 1);
    assert_eq!(summary_row_count(&vault), 1);
    assert!(!driver.is_compacting());
    Ok(())
}

#[test]
fn a_repeated_request_call_cannot_replace_the_issued_request() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let mut driver = engine_driver(1_000);
    driver.evaluate_now(&vault, u64::MAX)?;
    let window = host_window(&vault, 0x80, 1, 2);
    let request = driver.request_for(&vault, &session, window.clone())?;
    let mut changed = window.clone();
    changed[0].content = "replacement input".to_owned();
    let before = stored_row_count(&vault);
    for repeated in [window, changed] {
        let error = driver
            .request_for(&vault, &session, repeated)
            .expect_err("one request per crossing");
        assert_eq!(invariant(error), "compaction flight already has a request");
    }
    assert_eq!(stored_row_count(&vault), before);
    assert!(driver.is_compacting());
    let cloned = request.clone();
    assert_eq!(cloned, request);
    let product = driver.backend().compact(&cloned)?;
    let plan = driver.integrate(&vault, &session, actor, &cloned, product, &[])?;
    assert_eq!(
        plan.epoch, 1,
        "the original request, including a clone, still lands"
    );
    Ok(())
}

#[test]
fn a_completed_result_cannot_consume_a_later_flight() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let mut driver = engine_driver(1_000);
    driver.evaluate_now(&vault, u64::MAX)?;
    let old = driver.request_for(&vault, &session, host_window(&vault, 0x80, 1, 2))?;
    let product = driver.backend().compact(&old)?;
    driver.integrate(&vault, &session, actor, &old, product.clone(), &[])?;
    let rows = stored_row_count(&vault);
    let margin = *driver.margin();
    let error = driver
        .integrate(&vault, &session, actor, &old, product, &[])
        .expect_err("duplicate completion is refused in Idle");
    assert_eq!(invariant(error), "integrate is legal only while compacting");
    assert_eq!(stored_row_count(&vault), rows);
    assert_eq!(*driver.margin(), margin);

    driver.evaluate_now(&vault, u64::MAX)?;
    let current = driver.request_for(&vault, &session, host_window(&vault, 0x90, 3, 2))?;
    refuse_wrong_request(&vault, &mut driver, session, actor, &old);
    let product = driver.backend().compact(&current)?;
    let plan = driver.integrate(&vault, &session, actor, &current, product, &[])?;
    assert_eq!(plan.epoch, 2);
    assert_eq!(summary_row_count(&vault), 2);
    Ok(())
}

#[test]
fn a_replacement_driver_refuses_the_old_drivers_identical_snapshot() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let window = host_window(&vault, 0x80, 1, 2);
    let mut old_driver = engine_driver(1_000);
    old_driver.evaluate_now(&vault, u64::MAX)?;
    let old = old_driver.request_for(&vault, &session, window.clone())?;
    drop(old_driver);

    let mut driver = engine_driver(1_000);
    driver.evaluate_now(&vault, u64::MAX)?;
    let current = driver.request_for(&vault, &session, window)?;
    refuse_wrong_request(&vault, &mut driver, session, actor, &old);
    let product = driver.backend().compact(&current)?;
    let plan = driver.integrate(&vault, &session, actor, &current, product, &[])?;
    assert_eq!(plan.epoch, 1);
    Ok(())
}

#[test]
fn edited_request_fields_cannot_change_the_sealed_backend_input() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let mut driver = engine_driver(1_000);
    driver.evaluate_now(&vault, u64::MAX)?;
    let request = driver.request_for(&vault, &session, host_window(&vault, 0x80, 1, 2))?;
    let edits: [fn(&mut CompactionRequest); 6] = [
        |r| r.session_ref = entity(0x70),
        |r| r.window[0].content.push_str(" edited"),
        |r| r.window[1].turn += 1,
        |r| r.turn_start += 1,
        |r| r.summary_token_budget += 1,
        |r| r.watermark.learned_at += 1,
    ];
    for change in edits {
        let mut edited = request.clone();
        change(&mut edited);
        refuse_wrong_request(&vault, &mut driver, session, actor, &edited);
    }
    let product = driver.backend().compact(&request)?;
    driver.integrate(&vault, &session, actor, &request, product, &[])?;
    Ok(())
}

#[test]
fn small_budgets_and_zero_summary_shares_still_allow_nonblank_products() -> Result<()> {
    for budget in [1, 2, 3, 1_000] {
        // Direct MemoryProfile construction admits zero shares to the driver.
        // The persisted AGENT_DEF split validator remains unchanged.
        for split in [None, Some(ContextBudgetSplit::new(0.5, 0.25, 0.0, 0.25))] {
            let (_dir, vault) = open_vault();
            let session = mint_session(&vault, 10);
            let actor = loom_actor(&vault, 0x60);
            let mut profile = profile(budget, CompactionOwnership::Engine);
            profile.budget_split = split;
            let mut driver =
                CompactionDriver::for_profile(&profile, &cheap_registry())?.expect("engine driver");
            driver.evaluate_now(&vault, u64::MAX)?;
            let request = driver.request_for(&vault, &session, host_window(&vault, 0x80, 1, 1))?;
            let expected = if budget == 1_000 && split.is_none() {
                250
            } else {
                1
            };
            assert_eq!(request.summary_token_budget, expected);
            let plan = driver.integrate(
                &vault,
                &session,
                actor,
                &request,
                CompactionProduct {
                    summary_text: "x".to_owned(),
                    latency: Duration::from_millis(1),
                },
                &[],
            )?;
            assert_eq!(stored_summary_body(&vault, &plan.summary_id).text, "x");
            assert!(!driver.is_compacting());
        }
    }
    Ok(())
}

#[test]
fn request_refuses_gaps_reordering_and_wrong_durable_boundaries() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let mut driver = engine_driver(1_000);
    compact_once(
        &vault,
        &mut driver,
        session,
        actor,
        host_window(&vault, 0x80, 1, 4),
    )?;
    driver.evaluate_now(&vault, u64::MAX)?;
    let turn_ids = [put_turn(&vault, 0x90, 5), put_turn(&vault, 0x91, 6)];
    let before = stored_row_count(&vault);
    for turns in [
        vec![],
        vec![5, 7],
        vec![6, 5],
        vec![5, 6, 5],
        vec![4, 5],
        vec![6, 7],
    ] {
        let window = turns
            .iter()
            .map(|turn| window_row(turn_ids[0], *turn))
            .collect();
        let error = driver
            .request_for(&vault, &session, window)
            .expect_err("invalid span");
        let expected = match turns.as_slice() {
            [] => "compaction window carries no messages",
            [4, 5] | [6, 7] => "compaction window does not start at the next durable turn boundary",
            _ => "compaction window turns must be ordered and contiguous",
        };
        assert_eq!(invariant(error), expected);
        assert_eq!(stored_row_count(&vault), before);
        assert!(
            driver.is_compacting(),
            "invalid input does not consume the crossing"
        );
    }

    // Multiple messages per turn remain valid and produce the exact range.
    let window = vec![
        window_row(turn_ids[0], 5),
        window_row(turn_ids[0], 5),
        window_row(turn_ids[1], 6),
        window_row(turn_ids[1], 6),
    ];
    let request = driver.request_for(&vault, &session, window.clone())?;
    assert_eq!(request.window, window);
    assert_eq!(request.turn_start, 5);
    let product = driver.backend().compact(&request)?;
    let plan = driver.integrate(&vault, &session, actor, &request, product, &[])?;
    let body = stored_summary_body(&vault, &plan.summary_id);
    assert_eq!((body.turn_start, body.turn_end), (5, 6));
    assert_eq!(
        vault
            .edges_out(&plan.summary_id)?
            .iter()
            .filter(|edge| edge.kind == EdgeKind::DerivedFrom)
            .count(),
        2
    );
    Ok(())
}

#[test]
fn first_epoch_refuses_missing_turns_and_wrapping_turn_numbers() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let mut driver = engine_driver(1_000);
    driver.evaluate_now(&vault, u64::MAX)?;
    for turns in [[5, 7], [7, 5], [u64::MAX, 0]] {
        let window = turns
            .into_iter()
            .map(|turn| window_row(entity(0x80), turn))
            .collect();
        let error = driver
            .request_for(&vault, &session, window)
            .expect_err("invalid span");
        assert_eq!(
            invariant(error),
            "compaction window turns must be ordered and contiguous"
        );
    }
    let request = driver.request_for(&vault, &session, host_window(&vault, 0x80, 5, 2))?;
    assert_eq!(
        request.turn_start, 5,
        "the first epoch need not start at turn one"
    );
    Ok(())
}
