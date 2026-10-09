//! Active-request identity, budget floors, and complete turn spans.

use super::*;

/// Host fixture: settle Dreamer's complete-second boundary before another flight,
/// over the round a host scanned and queued.
pub(super) fn advance_test_watermark(vault: &Vault, learned_at: u64) -> Result<()> {
    let scope = crate::dreamer_runner::DreamerConsolidationScope::Micro;
    let watermark = crate::dreamer_consolidation::read_watermark(vault, scope)?;
    let queued =
        crate::dreamer_consolidation::scan_dirty_turns(vault, scope, &watermark, usize::MAX)?;
    crate::dreamer_consolidation::advance_watermark(vault, scope, learned_at, &queued)
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
fn working_outputs_decay_and_compaction_restores_exact_bytes() -> Result<()> {
    use crate::compaction::output::{
        OutputAffordance, OutputDecayPolicy, OutputTier, OutputWorkingContext, restore_output,
    };

    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x67);
    let mut driver = engine_driver(1_000);
    let mut outputs = OutputWorkingContext::default();
    let first_bytes = b"early output\0\xff exact";
    let first = outputs.record(&vault, 1, first_bytes, "early overview")?;
    let middle = outputs.record(&vault, 3, b"middle output", "middle overview")?;
    let tail = outputs.record(&vault, 8, b"tail output", "tail overview")?;
    let policy = OutputDecayPolicy {
        overview_after_turns: 2,
        stub_after_turns: 5,
    };
    let initial = outputs.assemble(&vault, 1, policy)?;
    assert_eq!(
        initial.len(),
        1,
        "future outputs are not in this turn's context"
    );
    assert_eq!(initial[0].tier, OutputTier::Full);
    assert_eq!(initial[0].bytes, first_bytes);
    let aged = outputs.assemble(&vault, 5, policy)?;
    assert_eq!(aged[0].tier, OutputTier::Overview);
    assert_eq!(aged[0].bytes, b"early overview");
    assert_eq!(aged[1].tier, OutputTier::Overview);
    let oldest = outputs.assemble(&vault, 8, policy)?;
    assert_eq!(oldest[0].tier, OutputTier::Stub);
    assert!(oldest[0].bytes.is_empty());

    driver.evaluate_now(&vault, u64::MAX)?;
    let request = driver.request_for(&vault, &session, host_window(&vault, 0xB0, 1, 3))?;
    let mut wrong = request.clone();
    wrong.turn_start += 1;
    let product = driver.backend().compact(&request)?;
    assert!(
        driver
            .integrate_with_outputs(&vault, actor, &wrong, product.clone(), &[], &mut outputs)
            .is_err()
    );
    assert_eq!(
        outputs.assemble(&vault, 3, policy)?[1].tier,
        OutputTier::Full
    );
    driver.integrate_with_outputs(&vault, actor, &request, product, &[], &mut outputs)?;
    let early_compacted = outputs.assemble(&vault, 3, policy)?;
    assert_eq!(early_compacted[0].tier, OutputTier::Stub);
    assert_eq!(early_compacted[1].tier, OutputTier::Stub);
    assert!(early_compacted[1].bytes.is_empty());
    let compacted = outputs.assemble(&vault, 8, policy)?;
    assert_eq!(compacted[0].tier, OutputTier::Stub);
    assert_eq!(compacted[1].tier, OutputTier::Stub);
    assert_eq!(compacted[2].tier, OutputTier::Full);
    assert_eq!(compacted[2].source, tail);
    assert_eq!(compacted[1].source, middle);
    let OutputAffordance::Reexpand(source) = compacted[0].affordances[0] else {
        panic!("stub must carry a typed reexpand action");
    };
    assert_eq!(source, first);
    assert_eq!(restore_output(&vault, source)?, first_bytes);
    // Persist the reference-only working state; no raw bytes enter its wire form.
    let saved = serde_json::to_vec(&outputs).expect("serialize working context");
    assert!(!saved.windows(first_bytes.len()).any(|w| w == first_bytes));
    let restored: OutputWorkingContext =
        serde_json::from_slice(&saved).expect("deserialize working context");
    assert_eq!(restored.assemble(&vault, 8, policy)?, compacted);
    Ok(())
}

#[test]
fn marker_failure_rolls_back_summary_and_leaves_request_retryable() -> Result<()> {
    use crate::code_run::{
        CodeRunDeterminism, CodeRunReplayRecord, CodeRunStepCheckpoint, ExecutorOutputSpan,
    };
    use crate::compaction::output::{OutputDecayPolicy, OutputTier, OutputWorkingContext};

    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x68);
    let mut driver = engine_driver(1000);
    let mut outputs = OutputWorkingContext::default();
    outputs.record(&vault, 1, b"first exact", "first short")?;
    outputs.record(&vault, 2, b"second exact", "second short")?;
    let policy = OutputDecayPolicy {
        overview_after_turns: 3,
        stub_after_turns: 6,
    };
    driver.evaluate_now(&vault, u64::MAX)?;
    let request = driver.request_for(&vault, &session, host_window(&vault, 0xB1, 1, 2))?;
    let product = driver.backend().compact(&request)?;
    let run = entity(0xB8);
    let mut replay = CodeRunReplayRecord::new(run, CodeRunDeterminism::new(1, [0x55; 32]));
    for seq in 0..3_u64 {
        replay.step_checkpoints.push(CodeRunStepCheckpoint::new(
            seq,
            format!("step-{seq}"),
            [0x33; 32],
            seq,
        )?);
    }
    vault.put_code_run_replay_record(&replay)?;
    let span = ExecutorOutputSpan::from_replay(&replay, &request)?;
    let before = summary_row_count(&vault);
    driver
        .integrate_with_coverage(
            &vault,
            actor,
            &request,
            product.clone(),
            &[],
            &span.fail_after_write_for_test(),
        )
        .expect_err("coverage write failure rolls back both coverage and SUMMARY");
    assert_eq!(summary_row_count(&vault), before);
    assert!(vault.code_run_compaction_coverage(run)?.is_empty());
    assert!(driver.is_compacting());
    assert_eq!(
        outputs
            .assemble(&vault, 2, policy)?
            .iter()
            .map(|v| v.tier)
            .collect::<Vec<_>>(),
        vec![OutputTier::Full, OutputTier::Full]
    );

    driver
        .integrate_with_coverage(
            &vault,
            actor,
            &request,
            product.clone(),
            &[],
            &span.wrong_range_for_test(),
        )
        .expect_err("a mismatched run-step range cannot bind this SUMMARY");
    assert_eq!(summary_row_count(&vault), before);
    assert!(vault.code_run_compaction_coverage(run)?.is_empty());

    let different_run = CodeRunReplayRecord::new(entity(0xB9), replay.determinism);
    let wrong = ExecutorOutputSpan::from_replay(
        &CodeRunReplayRecord {
            step_checkpoints: replay.step_checkpoints.clone(),
            ..different_run
        },
        &request,
    )?;
    driver
        .integrate_with_coverage(&vault, actor, &request, product.clone(), &[], &wrong)
        .expect_err("a different run's span cannot bind this SUMMARY");
    assert_eq!(summary_row_count(&vault), before);
    assert!(vault.code_run_compaction_coverage(run)?.is_empty());

    let plan = driver.integrate_with_coverage(&vault, actor, &request, product, &[], &span)?;
    assert_eq!(summary_row_count(&vault), before + 1);
    outputs.compact_span(request.turn_start, request.window.last().unwrap().turn);
    let coverage = vault.code_run_compaction_coverage(run)?;
    assert_eq!(coverage.len(), 1);
    assert_eq!(coverage[0].summary_id(), plan.summary_id);
    assert_eq!(coverage[0].epoch(), plan.epoch);
    assert!(coverage[0].covers(run, 1));
    assert!(coverage[0].covers(run, 2));
    assert!(!coverage[0].covers(run, 0));
    assert_eq!(
        outputs
            .assemble(&vault, 2, policy)?
            .iter()
            .map(|v| v.tier)
            .collect::<Vec<_>>(),
        vec![OutputTier::Stub, OutputTier::Stub]
    );
    Ok(())
}
