//! Symmetric blank-text refusal and fail-closed durable epoch advancement.

use super::*;

#[test]
fn whitespace_only_bodies_are_refused_by_both_codec_directions() -> Result<()> {
    for text in ["", " ", "\t\r\n", "\u{a0}\u{2003}\u{3000}"] {
        let mut body = sample_body();
        body.text = text.to_owned();
        let encoded_error = encode_epoch_summary_body(&body).expect_err("blank encode");
        let decoded_error =
            decode_epoch_summary_body(&unvalidated_encode(&body)).expect_err("blank decode");
        assert_eq!(invariant(encoded_error), "epoch summary text is empty");
        assert_eq!(invariant(decoded_error), "epoch summary text is empty");
    }
    let mut body = sample_body();
    body.text = " \tkept prose\n\u{a0}".to_owned();
    let bytes = encode_epoch_summary_body(&body)?;
    assert_eq!(
        decode_epoch_summary_body(&bytes)?,
        body,
        "do not trim usable prose"
    );
    assert_eq!(
        encode_epoch_summary_body(&decode_epoch_summary_body(&bytes)?)?,
        bytes
    );
    Ok(())
}

/// Seed coexisting durable rows, as seen after offline branches are imported.
/// This is fixture setup, not an acceptance proof: every assertion below uses
/// the native CompactionDriver request or integration door.
fn put_epoch_fixture(vault: &Vault, seed: u8, body: &EpochSummaryBody) -> Result<()> {
    vault.put_entity(
        &entity(seed),
        ENTITY_TYPE_SUMMARY,
        TimeRange { start: 1, end: 1 },
        1,
        &encode_epoch_summary_body(body)?,
    )
}

#[test]
fn conflicting_maximum_epochs_refuse_requests_in_either_entity_order() -> Result<()> {
    let conflicts: [fn(&mut EpochSummaryBody); 3] = [
        |body| body.text = "other branch".to_owned(),
        |body| body.turn_start += 1,
        |body| body.turn_end += 1,
    ];
    for conflict in conflicts {
        for reverse in [false, true] {
            let (_dir, vault) = open_vault();
            let session = mint_session(&vault, 10);
            let actor = loom_actor(&vault, 0x60);
            let mut driver = engine_driver(1_000);
            let plan = compact_once(
                &vault,
                &mut driver,
                session,
                actor,
                host_window(&vault, 0x80, 1, 2),
            )?;
            let mut first = stored_summary_body(&vault, &plan.summary_id);
            first.epoch = 2;
            first.turn_start = 3;
            first.turn_end = 4;
            let mut second = first.clone();
            conflict(&mut second);
            let branches = if reverse {
                [&second, &first]
            } else {
                [&first, &second]
            };
            put_epoch_fixture(&vault, 0x20, branches[0])?;
            put_epoch_fixture(&vault, 0x21, branches[1])?;
            // A later identical copy cannot erase the conflict already seen.
            put_epoch_fixture(&vault, 0x22, branches[0])?;
            driver.evaluate_now(&vault, u64::MAX)?;
            let window = host_window(&vault, 0x90, 5, 2);
            let before = stored_row_count(&vault);
            let error = driver
                .request_for(&vault, &session, window)
                .expect_err("neither conflicting maximum is a chosen lineage");
            assert_eq!(
                invariant(error),
                "conflicting summaries at the highest compaction epoch"
            );
            assert!(driver.is_compacting());
            assert_eq!(stored_row_count(&vault), before);
            assert_eq!(summary_row_count(&vault), 4);
        }
    }
    Ok(())
}

#[test]
fn a_conflict_arriving_after_request_issuance_refuses_the_mint_atomically() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let mut driver = engine_driver(1_000);
    let plan = compact_once(
        &vault,
        &mut driver,
        session,
        actor,
        host_window(&vault, 0x80, 1, 2),
    )?;
    driver.evaluate_now(&vault, u64::MAX)?;
    let request = driver.request_for(&vault, &session, host_window(&vault, 0x90, 3, 2))?;
    let mut branch = stored_summary_body(&vault, &plan.summary_id);
    branch.text = "conflicting offline compaction".to_owned();
    put_epoch_fixture(&vault, 0x20, &branch)?;
    let before = stored_row_count(&vault);
    let markers = pending_embedding_marker_count(&vault);
    let margin = *driver.margin();
    let product = driver.backend().compact(&request)?;
    let error = driver
        .integrate(&vault, &session, actor, &request, product, &[])
        .expect_err("mint must rescan the durable maximum inside its transaction");
    assert_eq!(
        invariant(error),
        "conflicting summaries at the highest compaction epoch"
    );
    assert_eq!(stored_row_count(&vault), before);
    assert_eq!(pending_embedding_marker_count(&vault), markers);
    assert_eq!(*driver.margin(), margin);
    assert!(driver.is_compacting());
    Ok(())
}

#[test]
fn identical_maximum_epoch_copies_allow_native_lineage_advancement() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let mut driver = engine_driver(1_000);
    let first = compact_once(
        &vault,
        &mut driver,
        session,
        actor,
        host_window(&vault, 0x80, 1, 2),
    )?;
    let body = stored_summary_body(&vault, &first.summary_id);
    put_epoch_fixture(&vault, 0x20, &body)?;
    let next = compact_once(
        &vault,
        &mut driver,
        session,
        actor,
        host_window(&vault, 0x90, 3, 2),
    )?;
    assert_eq!(next.epoch, 2);
    let next_body = stored_summary_body(&vault, &next.summary_id);
    assert_eq!((next_body.turn_start, next_body.turn_end), (3, 4));
    assert_eq!(stored_summary_body(&vault, &first.summary_id), body);
    Ok(())
}

#[test]
fn only_the_maximum_epoch_controls_conflict_refusal_regardless_of_row_order() -> Result<()> {
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let (_dir, vault) = open_vault();
        let session = mint_session(&vault, 10);
        let actor = loom_actor(&vault, 0x60);
        let mut first = sample_body();
        first.session = session.to_hex();
        first.actor = actor.entity_ref().to_hex();
        first.epoch = 2;
        first.turn_start = 3;
        first.turn_end = 4;
        let mut second = first.clone();
        second.text = "different lower branch".to_owned();
        let mut highest = first.clone();
        highest.epoch = 3;
        highest.turn_start = 5;
        highest.turn_end = 6;
        let bodies = [first, second, highest];
        for (seed, index) in [0x20, 0x21, 0x22].into_iter().zip(order) {
            put_epoch_fixture(&vault, seed, &bodies[index])?;
        }
        let mut driver = engine_driver(1_000);
        let plan = compact_once(
            &vault,
            &mut driver,
            session,
            actor,
            host_window(&vault, 0x80, 7, 2),
        )?;
        assert_eq!(plan.epoch, 4);
        let body = stored_summary_body(&vault, &plan.summary_id);
        assert_eq!((body.turn_start, body.turn_end), (7, 8));
    }
    Ok(())
}

#[test]
fn another_native_mint_cannot_make_an_inflight_request_overlap_the_lineage() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let window = host_window(&vault, 0x80, 1, 2);
    let mut slow = engine_driver(1_000);
    slow.evaluate_now(&vault, u64::MAX)?;
    let stale = slow.request_for(&vault, &session, window.clone())?;
    let mut fast = engine_driver(1_000);
    let first = compact_once(&vault, &mut fast, session, actor, window)?;
    assert_eq!(first.epoch, 1);

    let before = stored_row_count(&vault);
    let markers = pending_embedding_marker_count(&vault);
    let product = slow.backend().compact(&stale)?;
    let error = slow
        .integrate(&vault, &session, actor, &stale, product, &[])
        .expect_err("durable boundary changed while the backend ran");
    assert_eq!(
        invariant(error),
        "compaction window does not start at the next durable turn boundary"
    );
    assert_eq!(stored_row_count(&vault), before);
    assert_eq!(pending_embedding_marker_count(&vault), markers);
    assert!(slow.is_compacting());
    slow.abandon();
    let next = compact_once(
        &vault,
        &mut slow,
        session,
        actor,
        host_window(&vault, 0x90, 3, 2),
    )?;
    assert_eq!(next.epoch, 2);
    Ok(())
}

#[test]
fn an_exhausted_turn_boundary_is_refused_instead_of_reused() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let mut driver = engine_driver(1_000);
    let turn_id = put_turn(&vault, 0x80, 1);
    compact_once(
        &vault,
        &mut driver,
        session,
        actor,
        vec![window_row(turn_id, u64::MAX), window_row(turn_id, u64::MAX)],
    )?;
    driver.evaluate_now(&vault, u64::MAX)?;
    let error = driver
        .request_for(&vault, &session, vec![window_row(turn_id, u64::MAX)])
        .expect_err("there is no successor to the last u64 turn");
    assert_eq!(invariant(error), "compaction turn boundary is exhausted");
    assert_eq!(summary_row_count(&vault), 1);
    Ok(())
}

#[test]
fn an_exhausted_epoch_counter_cannot_mint_another_tied_epoch() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let mut body = sample_body();
    body.session = session.to_hex();
    body.actor = actor.entity_ref().to_hex();
    body.epoch = u64::MAX;
    put_epoch_fixture(&vault, 0x20, &body)?;
    let mut driver = engine_driver(1_000);
    let window = host_window(&vault, 0x80, body.turn_end + 1, 2);
    let before = stored_row_count(&vault);
    let markers = pending_embedding_marker_count(&vault);
    let error = compact_once(&vault, &mut driver, session, actor, window)
        .expect_err("an epoch increment must not saturate into a tie");
    assert_eq!(invariant(error), "compaction epoch counter is exhausted");
    assert_eq!(stored_row_count(&vault), before);
    assert_eq!(pending_embedding_marker_count(&vault), markers);
    assert!(driver.is_compacting());
    Ok(())
}
