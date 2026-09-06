//! Symmetric blank-text refusal and fail-closed durable epoch advancement.

use super::*;

#[test]
fn bootstrap_epoch_mint_preserves_zero_temporal_metadata_and_learned_index() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let turn = put_turn(&vault, 0x80, 0);
    let mut driver = engine_driver(1_000);
    assert_eq!(
        driver.evaluate_now(&vault, u64::MAX)?,
        CompactionDirective::Begin {
            watermark: CompactionWatermark {
                learned_at: 0,
                turn_id: None,
            },
        }
    );
    let request = driver.request_for(&vault, &session, vec![window_row(turn, 1)])?;
    let product = driver.backend().compact(&request)?;
    let plan = driver.integrate(&vault, &session, actor, &request, product, &[])?;

    let header = {
        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .entities
            .get(&rtxn, plan.summary_id.as_bytes())?
            .expect("committed summary");
        EntityMetadataHeader::parse(&raw).expect("summary header")
    };
    assert_eq!(
        (
            header.occurred_start,
            header.occurred_end,
            header.learned_at
        ),
        (0, 0, 0)
    );
    assert!(
        vault
            .entities_in_learned_range(0, 1)?
            .contains(&plan.summary_id)
    );
    assert!(
        !vault
            .entities_in_learned_range(1, 2)?
            .contains(&plan.summary_id)
    );
    Ok(())
}

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
fn hex_ref_casing_preserves_codec_and_native_epoch_lineage() -> Result<()> {
    for (uppercase_session, uppercase_actor, duplicate) in [
        (true, false, false),
        (true, false, true),
        (false, true, true),
        (true, true, true),
    ] {
        let (_dir, vault) = open_vault();
        // Fixed IDs ensure both references contain letters whose case changes.
        let session = entity(0xAB);
        vault.put_entity(
            &session,
            ENTITY_TYPE_SESSION,
            TimeRange { start: 1, end: 1 },
            1,
            b"case fixture session",
        )?;
        let actor = loom_actor(&vault, 0xCD);
        let mut body = sample_body();
        body.session = session.to_hex();
        body.actor = actor.entity_ref().to_hex();
        if duplicate {
            put_epoch_fixture(&vault, 0x20, &body)?;
        }
        if uppercase_session {
            body.session.make_ascii_uppercase();
        }
        if uppercase_actor {
            body.actor.make_ascii_uppercase();
        }
        let bytes = encode_epoch_summary_body(&body)?;
        assert_eq!(bytes, unvalidated_encode(&body));
        assert_eq!(decode_epoch_summary_body(&bytes)?, body);
        put_epoch_fixture(&vault, 0x21, &body)?;

        let mut driver = engine_driver(1_000);
        driver.evaluate_now(&vault, u64::MAX)?;
        let overlap = host_window(&vault, 0x80, body.turn_end, 2);
        let error = driver
            .request_for(&vault, &session, overlap)
            .expect_err("case variants must still enforce the prior boundary");
        assert_eq!(
            invariant(error),
            "compaction window does not start at the next durable turn boundary"
        );
        let window = host_window(&vault, 0x90, body.turn_end + 1, 2);
        let request = driver.request_for(&vault, &session, window)?;
        let product = driver.backend().compact(&request)?;
        let plan = driver.integrate(&vault, &session, actor, &request, product, &[])?;
        assert_eq!(plan.epoch, body.epoch + 1);
        let next = stored_summary_body(&vault, &plan.summary_id);
        assert_eq!(
            (next.turn_start, next.turn_end),
            (body.turn_end + 1, body.turn_end + 2)
        );
        assert_eq!(
            vault.get(&entity(0x21))?.expect("prior body unchanged"),
            bytes
        );
    }
    Ok(())
}

#[test]
fn conflicting_maximum_epochs_refuse_requests_in_either_entity_order() -> Result<()> {
    let conflicts: [fn(&mut EpochSummaryBody); 4] = [
        |body| body.text = "other branch".to_owned(),
        |body| body.turn_start += 1,
        |body| body.turn_end += 1,
        |body| body.actor = entity(0xAB).to_hex(),
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
            driver_regressions::advance_test_watermark(&vault, 6)?;
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
    driver_regressions::advance_test_watermark(&vault, 4)?;
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
    driver_regressions::advance_test_watermark(&vault, 4)?;
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
    driver_regressions::advance_test_watermark(&vault, 1)?;
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

/// Keep enough top-level identity to attribute a corrupt record to a session.
fn malformed_epoch_candidates(body: &EpochSummaryBody) -> Vec<Vec<u8>> {
    use rmpv::Value;

    let encoded = encode_epoch_summary_body(body).expect("valid baseline");
    let Value::Map(entries) = rmpv::decode::read_value(&mut encoded.as_slice()).expect("map")
    else {
        panic!("epoch body is a map");
    };
    let encode = |entries| {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).expect("encode fixture");
        bytes
    };
    let mut cases = Vec::new();
    for (key, value) in [
        ("v", Value::from(999)),
        ("epoch", Value::from("not an integer")),
        ("text", Value::from(" ")),
        ("actor", Value::from("not an entity ref")),
    ] {
        let mut damaged = entries.clone();
        damaged
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some(key))
            .expect("key")
            .1 = value;
        cases.push(encode(damaged));
    }
    let mut missing = entries.clone();
    missing.retain(|(key, _)| key.as_str() != Some("epoch"));
    cases.push(encode(missing));
    let mut unknown = entries.clone();
    unknown.push((Value::from("unknown"), Value::from(true)));
    cases.push(encode(unknown));
    let mut duplicate = entries.clone();
    duplicate.insert(
        0,
        (Value::from("session"), Value::from(entity(0xEF).to_hex())),
    );
    cases.push(encode(duplicate));
    let mut trailing = encoded.clone();
    trailing.push(0xc0);
    cases.push(trailing);
    // The pinned session/epoch prefix survives a truncated actor value.
    let truncated = encoded[..encoded.len() - 1].to_vec();
    cases.push(truncated.clone());
    // MessagePack admits map16/map32 headers even for eight entries.
    for header in [vec![0xde, 0, 8], vec![0xdf, 0, 0, 0, 8]] {
        let mut bytes = header;
        bytes.extend_from_slice(&truncated[1..]);
        cases.push(bytes);
    }
    cases
}

fn put_summary_bytes(vault: &Vault, bytes: &[u8]) -> Result<()> {
    vault.put_entity(
        &entity(0x20),
        ENTITY_TYPE_SUMMARY,
        TimeRange { start: 1, end: 1 },
        1,
        bytes,
    )
}

#[test]
fn identifiable_malformed_epochs_refuse_request_and_mint_without_writes() -> Result<()> {
    for at_mint in [false, true] {
        let (_dir, vault) = open_vault();
        let session = mint_session(&vault, 10);
        let actor = loom_actor(&vault, 0x60);
        let mut body = sample_body();
        body.session = session.to_hex().to_uppercase();
        body.actor = actor.entity_ref().to_hex();
        let window = host_window(&vault, 0x80, 1, 2);
        for bytes in malformed_epoch_candidates(&body) {
            // Issue against an ordinary SUMMARY, then replace it to exercise
            // the transaction's rescan independently of request validation.
            put_summary_bytes(&vault, b"ordinary summary")?;
            let mut driver = engine_driver(1_000);
            driver.evaluate_now(&vault, u64::MAX)?;
            let request = if at_mint {
                Some(driver.request_for(&vault, &session, window.clone())?)
            } else {
                None
            };
            put_summary_bytes(&vault, &bytes)?;
            let rows = stored_row_count(&vault);
            let markers = pending_embedding_marker_count(&vault);
            let margin = *driver.margin();
            let expected = invariant(decode_epoch_summary_body(&bytes).expect_err("malformed"));
            let error = if let Some(request) = &request {
                let product = driver.backend().compact(request)?;
                driver
                    .integrate(&vault, &session, actor, request, product, &[])
                    .expect_err("mint")
            } else {
                driver
                    .request_for(&vault, &session, window.clone())
                    .expect_err("request")
            };
            assert_eq!(invariant(error), expected);
            assert_eq!(stored_row_count(&vault), rows);
            assert_eq!(pending_embedding_marker_count(&vault), markers);
            assert_eq!(summary_row_count(&vault), 1);
            assert_eq!(
                vault.get(&entity(0x20))?.expect("corrupt row retained"),
                bytes
            );
            assert_eq!(*driver.margin(), margin);
            assert!(driver.is_compacting());
            driver.abandon();
            assert!(matches!(
                driver.evaluate_now(&vault, u64::MAX)?,
                CompactionDirective::Begin { .. }
            ));
        }
    }
    Ok(())
}

#[test]
fn ordinary_summaries_and_other_sessions_malformed_epochs_do_not_block_compaction() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x60);
    let mut ordinary = Vec::new();
    rmpv::encode::write_value(
        &mut ordinary,
        &rmpv::Value::Map(vec![
            (
                rmpv::Value::from("session"),
                rmpv::Value::from(session.to_hex()),
            ),
            (
                rmpv::Value::from("text"),
                rmpv::Value::from("ordinary witness summary"),
            ),
            (rmpv::Value::from("level"), rmpv::Value::from(0)),
        ]),
    )
    .expect("ordinary summary");
    let mut other = sample_body();
    other.session = entity(0xEE).to_hex();
    let mut bodies = malformed_epoch_candidates(&other);
    bodies.extend([ordinary, b"ordinary non-MessagePack prose".to_vec()]);
    for (index, bytes) in bodies.iter().enumerate() {
        vault.put_entity(
            &entity(0x20 + u8::try_from(index).expect("small fixture")),
            ENTITY_TYPE_SUMMARY,
            TimeRange { start: 1, end: 1 },
            1,
            bytes,
        )?;
    }
    let mut driver = engine_driver(1_000);
    let plan = compact_once(
        &vault,
        &mut driver,
        session,
        actor,
        host_window(&vault, 0x80, 1, 2),
    )?;
    assert_eq!(plan.epoch, 1);
    assert_eq!(summary_row_count(&vault), bodies.len() + 1);
    assert!(!driver.is_compacting());
    Ok(())
}
