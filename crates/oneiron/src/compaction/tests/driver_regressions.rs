//! Active-request identity, budget floors, and complete turn spans.

use super::*;

/// Host fixture: settle Dreamer's complete-second boundary before another flight.
pub(super) fn advance_test_watermark(vault: &Vault, learned_at: u64) -> Result<()> {
    crate::dreamer_consolidation::advance_watermark(
        vault,
        crate::dreamer_runner::DreamerConsolidationScope::Micro,
        learned_at,
    )
}

#[test]
fn a_second_compaction_mints_epoch_two_and_starts_at_prior_turn_end_plus_one() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x65);
    let mut driver = engine_driver(1_000);

    let first = compact_once(
        &vault,
        &mut driver,
        session,
        actor,
        host_window(&vault, 0xC0, 1, 3),
    )?;
    assert_eq!(first.epoch, 1);

    // The DURABLE prior summary is the counter — no mutable session row.
    advance_test_watermark(&vault, 5)?;
    driver.evaluate_now(&vault, u64::MAX)?;
    let second_window = host_window(&vault, 0xD0, 4, 2);
    let request = driver.request_for(&vault, &session, second_window)?;
    assert_eq!(
        request.turn_start, 4,
        "the next span begins at the durable prior turn_end + 1"
    );

    let product = driver.backend().compact(&request)?;
    let second = driver.integrate(&vault, &session, actor, &request, product, &[])?;
    assert_eq!(second.epoch, 2);

    let body = stored_summary_body(&vault, &second.summary_id);
    assert_eq!((body.turn_start, body.turn_end), (4, 5));

    // The first keyframe is untouched: byte-stable from its mint moment.
    let first_body = stored_summary_body(&vault, &first.summary_id);
    assert_eq!(first_body.epoch, 1);
    assert_eq!((first_body.turn_start, first_body.turn_end), (1, 3));
    Ok(())
}

#[test]
fn finite_velocity_overflow_saturates_margin_and_starvation_deficit() -> Result<()> {
    let (_dir, vault) = open_vault();
    let mut driver = engine_driver(1_000);
    driver.observe_velocity(f64::MAX);
    assert_eq!(driver.margin().margin_tokens(), u64::MAX);
    assert_eq!(driver.margin().measured_velocity_tps(), u64::MAX);

    // Overflow in a product is valid; non-finite or negative input is not.
    let measured = *driver.margin();
    for invalid in [-1.0, f64::NEG_INFINITY, f64::INFINITY, f64::NAN] {
        driver.observe_velocity(invalid);
        assert_eq!(*driver.margin(), measured);
    }
    assert_eq!(driver.compact_at(), 500);
    assert!(matches!(
        driver.evaluate_now(&vault, 500)?,
        CompactionDirective::Begin { .. }
    ));
    assert_eq!(
        driver.starvation_check(Duration::from_secs(2), u64::MAX),
        Some(CompactionSignal::Starvation {
            deficit_tokens: u64::MAX,
            measured_latency_ms: driver.margin().measured_latency_ms(),
            measured_velocity_tps: u64::MAX,
        }),
        "positive projected overflow cannot become a zero-token deficit"
    );
    assert!(matches!(
        driver.starvation_check(Duration::ZERO, u64::MAX),
        Some(CompactionSignal::Starvation {
            deficit_tokens,
            ..
        }) if deficit_tokens == u64::MAX - 1_000
    ));
    Ok(())
}

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

    advance_test_watermark(&vault, 4)?;
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
    advance_test_watermark(&vault, 6)?;
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

#[test]
fn exact_context_token_budget_mints_the_unmodified_summary() -> Result<()> {
    let text = " \tRésumé テスト: keep <|endoftext|> as ordinary prose.\n";
    let tokens = crate::tokenizer::count_context_pack_tokens(text) as u64;
    assert!(tokens > 0);
    for split in [None, Some(ContextBudgetSplit::new(0.25, 0.125, 0.5, 0.125))] {
        let (_dir, vault) = open_vault();
        let session = mint_session(&vault, 10);
        let actor = loom_actor(&vault, 0x60);
        let mut profile = profile(
            tokens * if split.is_some() { 2 } else { 4 },
            CompactionOwnership::Engine,
        );
        profile.budget_split = split;
        let mut driver =
            CompactionDriver::for_profile(&profile, &cheap_registry())?.expect("engine driver");
        driver.evaluate_now(&vault, u64::MAX)?;
        let request = driver.request_for(&vault, &session, host_window(&vault, 0x80, 1, 2))?;
        assert_eq!(request.summary_token_budget, tokens);
        let plan = driver.integrate(
            &vault,
            &session,
            actor,
            &request,
            CompactionProduct {
                summary_text: text.to_owned(),
                latency: Duration::from_millis(9),
            },
            &[],
        )?;
        assert_eq!(stored_summary_body(&vault, &plan.summary_id).text, text);
        assert_eq!(summary_row_count(&vault), 1);
        assert_eq!(pending_embedding_marker_count(&vault), 1);
        assert_eq!(driver.margin().measured_latency_ms(), 9);
        assert!(!driver.is_compacting());
    }
    Ok(())
}

#[test]
fn over_budget_products_write_nothing_and_allow_same_flight_or_abandoned_retry() -> Result<()> {
    for abandon in [false, true] {
        let (_dir, vault) = open_vault();
        let session = mint_session(&vault, 10);
        let actor = loom_actor(&vault, 0x60);
        let mut driver = engine_driver(4);
        driver.evaluate_now(&vault, u64::MAX)?;
        let window = host_window(&vault, 0x80, 1, 2);
        let mut request = driver.request_for(&vault, &session, window.clone())?;
        assert_eq!(request.summary_token_budget, 1);
        // Exactly one token over the ceiling under the context tokenizer.
        let text = "x x";
        assert_eq!(crate::tokenizer::count_context_pack_tokens(text), 2);
        let rows = stored_row_count(&vault);
        let markers = pending_embedding_marker_count(&vault);
        let margin = *driver.margin();
        let error = driver
            .integrate(
                &vault,
                &session,
                actor,
                &request,
                CompactionProduct {
                    summary_text: text.to_owned(),
                    latency: Duration::from_secs(900),
                },
                &[],
            )
            .expect_err("the backend cannot exceed the sealed token allocation");
        assert_eq!(
            invariant(error),
            "compaction product summary_text exceeds summary_token_budget"
        );
        assert_eq!(stored_row_count(&vault), rows);
        assert_eq!(pending_embedding_marker_count(&vault), markers);
        assert_eq!(summary_row_count(&vault), 0);
        assert_eq!(*driver.margin(), margin);
        assert!(driver.is_compacting());
        assert_eq!(
            driver.evaluate_now(&vault, u64::MAX)?,
            CompactionDirective::Quiet
        );
        if abandon {
            driver.abandon();
            assert_eq!(
                driver.evaluate_now(&vault, u64::MAX)?,
                CompactionDirective::Begin {
                    watermark: request.watermark,
                }
            );
            let retry = driver.request_for(&vault, &session, window)?;
            assert_ne!(retry, request);
            request = retry;
        }
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
        assert_eq!(plan.epoch, 1);
        assert_eq!(stored_summary_body(&vault, &plan.summary_id).text, "x");
        assert!(!driver.is_compacting());
    }
    Ok(())
}

fn set_test_watermark(vault: &Vault, watermark: CompactionWatermark) -> Result<()> {
    match watermark.turn_id {
        None => advance_test_watermark(vault, watermark.learned_at),
        Some(turn_id) => crate::dreamer_consolidation::advance_watermark_to_turn(
            vault,
            crate::dreamer_runner::DreamerConsolidationScope::Micro,
            &crate::dreamer_consolidation::WorkingSetTurn {
                turn_id,
                learned_at: watermark.learned_at,
                role: crate::dreamer_runner::DreamerTurnRole::User,
                conversation: None,
            },
        ),
    }
}

#[test]
fn completed_watermark_suppresses_same_and_older_but_allows_newer_positions() -> Result<()> {
    let low = Some(entity(0x80));
    let mid = Some(entity(0x81));
    let high = Some(entity(0x82));
    for (completed_at, completed_id, observed_at, observed_id, newer) in [
        (0, None, 0, None, false),
        (0, None, 0, low, false),
        (0, None, 1, low, true),
        (10, mid, 10, mid, false),
        (10, mid, 10, low, false),
        (10, mid, 10, high, true),
        (10, mid, 10, None, true),
        (10, mid, 9, None, false),
        (10, mid, 11, low, true),
        (10, None, 10, high, false),
        (10, None, 10, None, false),
        (10, None, 11, low, true),
    ] {
        let (_dir, vault) = open_vault();
        let session = mint_session(&vault, 10);
        let actor = loom_actor(&vault, 0x60);
        let completed = CompactionWatermark {
            learned_at: completed_at,
            turn_id: completed_id,
        };
        set_test_watermark(&vault, completed)?;
        let mut driver = engine_driver(1_000);
        compact_once(
            &vault,
            &mut driver,
            session,
            actor,
            host_window(&vault, 0x90, 1, 2),
        )?;
        let observed = CompactionWatermark {
            learned_at: observed_at,
            turn_id: observed_id,
        };
        set_test_watermark(&vault, observed)?;
        let rows = stored_row_count(&vault);
        let markers = pending_embedding_marker_count(&vault);
        let margin = *driver.margin();
        let expected = if newer {
            CompactionDirective::Begin {
                watermark: observed,
            }
        } else {
            CompactionDirective::Quiet
        };
        assert_eq!(
            driver.observe_from_context_build(&vault, u64::MAX)?,
            expected
        );
        assert_eq!(driver.is_compacting(), newer);
        assert_eq!(
            driver.evaluate_now(&vault, u64::MAX)?,
            CompactionDirective::Quiet
        );
        assert_eq!(stored_row_count(&vault), rows);
        assert_eq!(pending_embedding_marker_count(&vault), markers);
        assert_eq!(*driver.margin(), margin);
    }
    Ok(())
}

#[test]
fn completion_fence_keeps_trigger_watermark_and_survives_newer_failed_flights() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let mut driver = engine_driver(1_000);
    advance_test_watermark(&vault, 10)?;
    driver.evaluate_now(&vault, u64::MAX)?;
    let first = driver.request_for(&vault, &session, host_window(&vault, 0x80, 1, 2))?;
    // Dreamer can advance while the host's backend is running. Completion
    // fences the request's W=10, not the now-current W=20.
    advance_test_watermark(&vault, 20)?;
    let product = driver.backend().compact(&first)?;
    driver.integrate(&vault, &session, actor, &first, product, &[])?;
    let newer = CompactionWatermark {
        learned_at: 20,
        turn_id: None,
    };
    assert_eq!(
        driver.evaluate_now(&vault, u64::MAX)?,
        CompactionDirective::Begin { watermark: newer }
    );
    let window = host_window(&vault, 0x90, 3, 2);
    let failed = driver.request_for(&vault, &session, window.clone())?;
    let rows = stored_row_count(&vault);
    let markers = pending_embedding_marker_count(&vault);
    let margin = *driver.margin();
    let error = driver
        .integrate(
            &vault,
            &session,
            actor,
            &failed,
            CompactionProduct {
                summary_text: String::new(),
                latency: Duration::from_secs(99),
            },
            &[],
        )
        .expect_err("failed work cannot advance the fence");
    assert_eq!(invariant(error), "compaction product summary_text is empty");
    assert!(driver.is_compacting());
    assert_eq!(stored_row_count(&vault), rows);
    assert_eq!(pending_embedding_marker_count(&vault), markers);
    assert_eq!(*driver.margin(), margin);
    driver.abandon();
    advance_test_watermark(&vault, 10)?;
    assert_eq!(
        driver.evaluate_now(&vault, u64::MAX)?,
        CompactionDirective::Quiet
    );
    assert!(!driver.is_compacting());
    advance_test_watermark(&vault, 20)?;
    assert_eq!(
        driver.evaluate_now(&vault, u64::MAX)?,
        CompactionDirective::Begin { watermark: newer }
    );
    // Abandoning even before request issuance must leave this boundary retryable.
    driver.abandon();
    assert_eq!(
        driver.evaluate_now(&vault, u64::MAX)?,
        CompactionDirective::Begin { watermark: newer }
    );
    let retry = driver.request_for(&vault, &session, window)?;
    let product = driver.backend().compact(&retry)?;
    let plan = driver.integrate(&vault, &session, actor, &retry, product, &[])?;
    assert_eq!(plan.epoch, 2);
    driver.abandon();
    assert_eq!(
        driver.evaluate_now(&vault, u64::MAX)?,
        CompactionDirective::Quiet
    );
    assert_eq!(summary_row_count(&vault), 2);
    Ok(())
}
