use super::*;
use crate::error::GateError;

#[test]
fn breaker_window_boundary_is_strict() {
    let thresholds = GateBreakerThresholds {
        max_events: 2,
        window_secs: 10,
    };

    // A timestamp EXACTLY one window old is expired; one second younger is
    // live.
    let pruned = evaluate_gate_breaker_event(
        Some(gate_breaker_row_for_transition_test(
            thresholds,
            vec![90, 91],
            None,
        )),
        thresholds,
        GateBreakerCandidate::Auto,
        100,
    );
    assert_eq!(pruned.row().event_timestamps(), [91, 100]);
    assert_eq!(pruned.event_count(), 2);
    assert!(!pruned.tripped_now());
    assert_eq!(pruned.outcome(), GateBreakerCandidate::Auto);

    // Strictly greater than `max_events` trips; equal does not.
    let tripping = evaluate_gate_breaker_event(
        Some(gate_breaker_row_for_transition_test(
            thresholds,
            vec![95, 96],
            None,
        )),
        thresholds,
        GateBreakerCandidate::Auto,
        100,
    );
    assert_eq!(tripping.event_count(), 3);
    assert!(tripping.tripped_now());
    assert_eq!(tripping.outcome(), GateBreakerCandidate::Proposed);
    assert_eq!(tripping.row().tripped_at(), Some(100));
    assert_eq!(
        tripping.row().event_timestamps(),
        [95, 96, 100],
        "the timestamp that caused the trip stays in the row"
    );

    // An already-Proposed candidate is preserved, not rewritten to something
    // else, when it trips.
    let tripping_proposed = evaluate_gate_breaker_event(
        Some(gate_breaker_row_for_transition_test(
            thresholds,
            vec![95, 96],
            None,
        )),
        thresholds,
        GateBreakerCandidate::Proposed,
        100,
    );
    assert_eq!(tripping_proposed.outcome(), GateBreakerCandidate::Proposed);

    // Clock rollback clamps to `max(now, last)` so the log stays
    // nondecreasing.
    let rolled_back = evaluate_gate_breaker_event(
        Some(gate_breaker_row_for_transition_test(
            thresholds,
            vec![100],
            None,
        )),
        thresholds,
        GateBreakerCandidate::Auto,
        95,
    );
    assert_eq!(rolled_back.row().event_timestamps(), [100, 100]);

    // An already-tripped row short-circuits: unchanged bytes, demoted
    // candidate, and an `event_count` pinned to the stored log length.
    let short_circuit = evaluate_gate_breaker_event(
        Some(gate_breaker_row_for_transition_test(
            thresholds,
            vec![10, 11, 12],
            Some(12),
        )),
        GateBreakerThresholds {
            max_events: 9_999,
            window_secs: 1,
        },
        GateBreakerCandidate::Auto,
        10_000,
    );
    assert!(!short_circuit.rewritten());
    assert!(!short_circuit.tripped_now());
    assert_eq!(short_circuit.event_count(), 3);
    assert_eq!(short_circuit.outcome(), GateBreakerCandidate::Proposed);
    assert_eq!(short_circuit.row().event_timestamps(), [10, 11, 12]);
    assert_eq!(short_circuit.row().thresholds().max_events, 2);

    // A missing row is created under the live snapshot.
    let fresh = evaluate_gate_breaker_event(None, thresholds, GateBreakerCandidate::Auto, 100);
    assert_eq!(fresh.row().event_timestamps(), [100]);
    assert_eq!(fresh.row().thresholds(), thresholds);
    assert_eq!(fresh.row().tripped_at(), None);
}

#[test]
fn breaker_fail_closed_no_auto_accept() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let run = "breaker-fail-closed-run";
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &breaker_manifest(&[actor], Some((2, 600))),
    )?;

    // A row tripped many windows ago, whose whole event log has since aged
    // out. Time passing is exactly this shape from the row's side.
    let ancient = gate_breaker_row_for_transition_test(
        GateBreakerThresholds {
            max_events: 2,
            window_secs: 600,
        },
        vec![1, 2, 3],
        Some(3),
    );
    vault.with_write_txn(|wtxn| {
        put_gate_breaker_row_for_test(&vault.store, wtxn, run, &actor, &ancient)
    })?;
    let before = breaker_row_bytes(&vault, run, &actor)?.expect("seeded row");

    breaker_write(
        &vault,
        test_id(0x30),
        actor,
        0x50,
        run,
        ClaimApprovalStatus::Auto,
        3,
    )?;
    assert_eq!(
        breaker_row_bytes(&vault, run, &actor)?.as_deref(),
        Some(before.as_slice()),
        "time passing alone never untrips, and never rewrites the row"
    );
    assert!(vault.gate_breaker_run_projection(run)?.gate_breaker_paused);
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x30))?.approval,
        ClaimApprovalStatus::Proposed
    );

    // The demoted member is in ONE-1452's bundle and no non-owner path moves
    // it to Approved.
    let reviewer = WriteActor::new(actor, EdgeActorClass::Agent);
    let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
    assert_eq!(bundle.members.len(), 1);
    assert_eq!(bundle.members[0].claim_id, test_id(0x30));
    Ok(())
}

#[test]
fn breaker_survives_vault_reopen() -> Result<()> {
    let (tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let run = "breaker-reopen-run";
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &breaker_manifest(&[actor], Some((1, 600))),
    )?;
    breaker_write(
        &vault,
        test_id(0x30),
        actor,
        0x50,
        run,
        ClaimApprovalStatus::Auto,
        3,
    )?;
    breaker_write(
        &vault,
        test_id(0x31),
        actor,
        0x51,
        run,
        ClaimApprovalStatus::Auto,
        4,
    )?;
    assert!(vault.gate_breaker_run_projection(run)?.gate_breaker_paused);
    let before = breaker_row_bytes(&vault, run, &actor)?.expect("tripped row");
    drop(vault);

    let vault = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())
        .expect("reopen vault");
    assert!(vault.gate_breaker_run_projection(run)?.gate_breaker_paused);
    assert_eq!(
        breaker_row_bytes(&vault, run, &actor)?.as_deref(),
        Some(before.as_slice())
    );
    breaker_write(
        &vault,
        test_id(0x32),
        actor,
        0x52,
        run,
        ClaimApprovalStatus::Auto,
        5,
    )?;
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x32))?.approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}

#[test]
fn breaker_manifest_override_changes_trip_point() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &breaker_manifest(&[actor], Some((50, 300))),
    )?;
    assert_eq!(
        resolve(&vault)?.actor_burst_breaker_thresholds(),
        GateBreakerThresholds {
            max_events: 50,
            window_secs: 300,
        }
    );

    // The applied snapshot is what the row records.
    let run = "breaker-override-run";
    breaker_write(
        &vault,
        test_id(0x30),
        actor,
        0x50,
        run,
        ClaimApprovalStatus::Auto,
        3,
    )?;
    assert_eq!(
        breaker_row(&vault, run, &actor)?.expect("row").thresholds(),
        GateBreakerThresholds {
            max_events: 50,
            window_secs: 300,
        }
    );
    Ok(())
}

#[test]
fn breaker_malformed_override_uses_engine_defaults() -> Result<()> {
    let malformed = [
        // Zero, on either field.
        breaker_dial_entry(Value::from(0_u64), Value::from(600_u64)),
        breaker_dial_entry(Value::from(30_u64), Value::from(0_u64)),
        // Negative and fractional.
        breaker_dial_entry(Value::from(-1_i64), Value::from(600_u64)),
        breaker_dial_entry(Value::F64(1.5), Value::from(600_u64)),
        // Wrong types.
        breaker_dial_entry(Value::from("30"), Value::from(600_u64)),
        breaker_dial_entry(
            Value::Array(vec![Value::from(30_u64)]),
            Value::from(600_u64),
        ),
        // Overflowed `max_events`.
        breaker_dial_entry(Value::from(u64::from(u32::MAX) + 1), Value::from(600_u64)),
    ];
    for (index, dial) in malformed.into_iter().enumerate() {
        let (_tmp, vault) = temp_vault();
        let mut extra = vec![
            source_trust_entry(ClaimSource::Generated, 0),
            signatures_entry(),
        ];
        extra.push(dial);
        put_policy_manifest_bytes(&vault, test_id(0x70), &encode_policy_manifest(extra))?;
        let policy = resolve(&vault)?;
        assert_eq!(
            policy.actor_burst_breaker_thresholds(),
            GateBreakerThresholds::default(),
            "malformed dial {index} must take engine defaults, never disable accounting"
        );
        assert_eq!(
            GateBreakerThresholds::default(),
            GateBreakerThresholds {
                max_events: GATE_BREAKER_DEFAULT_MAX_EVENTS,
                window_secs: GATE_BREAKER_WINDOW_SECS,
            }
        );
        assert!(
            !policy.is_fail_closed(),
            "a malformed dial is not a malformed manifest"
        );
    }

    // A missing/unknown/partial shape is malformed the same way.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x71),
        &encode_policy_manifest(vec![(
            Value::from(GATE_BREAKER_POLICY_KEY),
            Value::Map(vec![(Value::from("max_events"), Value::from(30_u64))]),
        )]),
    )?;
    assert_eq!(
        resolve(&vault)?.actor_burst_breaker_thresholds(),
        GateBreakerThresholds::default()
    );
    Ok(())
}

#[test]
fn breaker_conflicting_manifest_overrides_use_defaults() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &encode_policy_manifest(vec![breaker_dial_entry(
            Value::from(50_u64),
            Value::from(300_u64),
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x71),
        &encode_policy_manifest(vec![breaker_dial_entry(
            Value::from(7_u64),
            Value::from(60_u64),
        )]),
    )?;
    assert_eq!(
        resolve(&vault)?.actor_burst_breaker_thresholds(),
        GateBreakerThresholds::default(),
        "two distinct valid dials resolve to engine defaults"
    );
    Ok(())
}

#[test]
fn breaker_malformed_plus_valid_uses_valid() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &encode_policy_manifest(vec![breaker_dial_entry(
            Value::from("nope"),
            Value::from(600_u64),
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x71),
        &encode_policy_manifest(vec![breaker_dial_entry(
            Value::from(50_u64),
            Value::from(300_u64),
        )]),
    )?;
    assert_eq!(
        resolve(&vault)?.actor_burst_breaker_thresholds(),
        GateBreakerThresholds {
            max_events: 50,
            window_secs: 300,
        },
        "a malformed manifest contributes no candidate at all"
    );
    Ok(())
}

#[test]
fn breaker_dial_changes_policy_frontier_and_stales_bundle() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let run = "breaker-frontier-run";
    put_policy_manifest_bytes(&vault, test_id(0x70), &encode_policy_manifest(vec![]))?;
    let absent = resolve(&vault)?.read_frontier_hash()?;

    park_consent_bundle_member(&vault, test_id(0x30), actor, 0x50, run, "proposal", 3)?;
    let reviewer = WriteActor::new(actor, EdgeActorClass::Agent);
    let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;

    // Edit ONLY the dial.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &encode_policy_manifest(vec![breaker_dial_entry(
            Value::from(50_u64),
            Value::from(300_u64),
        )]),
    )?;
    let present = resolve(&vault)?.read_frontier_hash()?;
    assert_ne!(absent, present);

    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &encode_policy_manifest(vec![breaker_dial_entry(
            Value::from(7_u64),
            Value::from(60_u64),
        )]),
    )?;
    assert_ne!(present, resolve(&vault)?.read_frontier_hash()?);

    // A bundle reviewed under the old dial is stale.
    let owner = consent_bundle_owner(&vault, test_id(0x60))?;
    assert!(matches!(
        vault.resolve_gate_consent_bundle(
            &owner,
            bundle.bundle_id,
            run,
            GateConsentBundleAction::Approve,
            9,
        ),
        Err(Error::Gate(GateError::GateConsentStale { .. }))
    ));
    Ok(())
}

#[test]
fn breaker_manifest_change_does_not_untrip() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let run = "breaker-manifest-change-run";
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &breaker_manifest(&[actor], Some((1, 600))),
    )?;
    breaker_write(
        &vault,
        test_id(0x30),
        actor,
        0x50,
        run,
        ClaimApprovalStatus::Auto,
        3,
    )?;
    breaker_write(
        &vault,
        test_id(0x31),
        actor,
        0x51,
        run,
        ClaimApprovalStatus::Auto,
        4,
    )?;
    let tripped = breaker_row_bytes(&vault, run, &actor)?.expect("tripped row");

    // Relax the dial, then remove it entirely.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &breaker_manifest(&[actor], Some((10_000, 1))),
    )?;
    assert!(vault.gate_breaker_run_projection(run)?.gate_breaker_paused);
    put_policy_manifest_bytes(&vault, test_id(0x70), &breaker_manifest(&[actor], None))?;
    assert!(vault.gate_breaker_run_projection(run)?.gate_breaker_paused);
    assert_eq!(
        breaker_row_bytes(&vault, run, &actor)?.as_deref(),
        Some(tripped.as_slice()),
        "the trip snapshot freezes until owner resolution deletes the row"
    );
    breaker_write(
        &vault,
        test_id(0x32),
        actor,
        0x52,
        run,
        ClaimApprovalStatus::Auto,
        5,
    )?;
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x32))?.approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}
