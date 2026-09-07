use super::*;

use crate::config::VaultConfig;
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::registry::{
    EntityClassification, TypeByteZone, entity_type_registry_entry, short_id_prefix,
    validate_public_entity_type,
};

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

use crate::test_util::entity as test_id;

fn all_dimension_budgets() -> Vec<EffectorBudget> {
    vec![
        EffectorBudget::sends(
            20,
            EffectorBudgetWindow::Calendar {
                period: CalendarPeriod::Day,
                tz: None,
            },
            EffectorBudgetOnExhaust::Suspend,
        ),
        EffectorBudget {
            reserve_policy: Some(EffectorBudgetReservePolicy::SettleOnly),
            channel_class: Some("slack".to_owned()),
            ..EffectorBudget::spend(
                10_000,
                "USD",
                EffectorBudgetWindow::Calendar {
                    period: CalendarPeriod::Month,
                    tz: Some("UTC".to_owned()),
                },
                EffectorBudgetOnExhaust::Suspend,
            )
        },
        EffectorBudget::rate(5, 60),
    ]
}

fn connector_key_op_receipt_count(vault: &Vault) -> Result<usize> {
    let receipts = vault.receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Gate))?;
    Ok(receipts
        .iter()
        .filter(|receipt| {
            receipt
                .policy_trace
                .iter()
                .any(|reason| reason.starts_with("gate.connector_key."))
        })
        .count())
}

#[test]
fn connector_key_codec_round_trips_all_dimensions() -> Result<()> {
    let actor_bound = ConnectorKeyRecord {
        actor_entity_ref: Some(test_id(0xA7)),
        ..ConnectorKeyRecord::active("slack", None, all_dimension_budgets(), 1_000)
    };
    let encoded = encode_connector_key_body(&actor_bound)?;
    assert_eq!(decode_connector_key_body(&encoded)?, actor_bound);

    let actor_agnostic = ConnectorKeyRecord::active("line", None, all_dimension_budgets(), 2_000);
    let encoded = encode_connector_key_body(&actor_agnostic)?;
    let decoded = decode_connector_key_body(&encoded)?;
    assert_eq!(decoded, actor_agnostic);
    assert!(decoded.charter.is_none());
    assert!(decoded.pending_charter.is_none());

    let suspended = ConnectorKeyRecord {
        status: ConnectorKeyStatus::Suspended,
        status_changed_at: Some(3_000),
        suspended_reason: Some("budget_exhausted:row:0".to_owned()),
        ..actor_agnostic
    };
    let encoded = encode_connector_key_body(&suspended)?;
    assert_eq!(decode_connector_key_body(&encoded)?, suspended);
    Ok(())
}

#[test]
fn suggested_budget_codec_round_trips_and_old_body_defaults_empty() -> Result<()> {
    let mut record = ConnectorKeyRecord::active("peer_link", None, Vec::new(), 1_000);
    let mut suggestion = EffectorBudget::sends(
        200,
        EffectorBudgetWindow::Rolling { duration_s: 3_600 },
        EffectorBudgetOnExhaust::Refuse,
    );
    suggestion.channel_class = Some("peer".to_owned());
    record.suggested_budgets.push(suggestion);

    let encoded = encode_connector_key_body(&record)?;
    let decoded = decode_connector_key_body(&encoded)?;
    assert_eq!(decoded.suggested_budgets.len(), 1);
    assert_eq!(decoded, record);

    let mut cursor = std::io::Cursor::new(encoded);
    let mut value = rmpv::decode::read_value(&mut cursor).expect("decode fixture");
    let rmpv::Value::Map(entries) = &mut value else {
        panic!("connector key body must be a map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("suggested_budgets"));
    let mut old_body = Vec::new();
    rmpv::encode::write_value(&mut old_body, &value).expect("encode old fixture");
    let old_decoded = decode_connector_key_body(&old_body)?;
    assert_eq!(old_decoded.suggested_budgets.len(), 0);
    Ok(())
}

#[test]
fn connector_key_codec_accepts_v1_body_without_suggested_budgets() -> Result<()> {
    let record = ConnectorKeyRecord::active("peer_link", None, Vec::new(), 1_000);
    let encoded = encode_connector_key_body(&record)?;
    let mut cursor = std::io::Cursor::new(encoded);
    let mut value = rmpv::decode::read_value(&mut cursor).expect("decode fixture");
    let rmpv::Value::Map(entries) = &mut value else {
        panic!("connector key body must be a map");
    };
    let (_, schema_version) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("schema_version"))
        .expect("schema_version key");
    *schema_version = rmpv::Value::from(1);
    entries.retain(|(key, _)| key.as_str() != Some("suggested_budgets"));
    let mut old_body = Vec::new();
    rmpv::encode::write_value(&mut old_body, &value).expect("encode v1 fixture");

    let decoded = decode_connector_key_body(&old_body)?;
    assert!(decoded.suggested_budgets.is_empty());
    Ok(())
}

#[test]
fn connector_key_codec_rejects_an_unsupported_version() -> Result<()> {
    let record = ConnectorKeyRecord::active("peer_link", None, Vec::new(), 1_000);
    let encoded = encode_connector_key_body(&record)?;
    let mut cursor = std::io::Cursor::new(encoded);
    let mut value = rmpv::decode::read_value(&mut cursor).expect("decode fixture");
    let rmpv::Value::Map(entries) = &mut value else {
        panic!("connector key body must be a map");
    };
    let (_, schema_version) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("schema_version"))
        .expect("schema_version key");
    // One past the current ceiling, expressed against the const so a future
    // additive bump cannot silently turn this into a no-op assertion.
    *schema_version = rmpv::Value::from(CONNECTOR_KEY_SCHEMA_VERSION + 1);
    let mut unsupported_body = Vec::new();
    rmpv::encode::write_value(&mut unsupported_body, &value).expect("encode unsupported fixture");

    assert!(matches!(
        decode_connector_key_body(&unsupported_body),
        Err(Error::InvalidConnectorKeyBody("unsupported schema version"))
    ));
    Ok(())
}

#[test]
fn connector_key_codec_rejects_missing_required_body_key() -> Result<()> {
    let record = ConnectorKeyRecord::active("peer_link", None, Vec::new(), 1_000);
    let encoded = encode_connector_key_body(&record)?;
    let mut cursor = std::io::Cursor::new(encoded);
    let mut value = rmpv::decode::read_value(&mut cursor).expect("decode fixture");
    let rmpv::Value::Map(entries) = &mut value else {
        panic!("connector key body must be a map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("connector"));
    let mut missing_connector = Vec::new();
    rmpv::encode::write_value(&mut missing_connector, &value).expect("encode malformed fixture");

    assert!(matches!(
        decode_connector_key_body(&missing_connector),
        Err(Error::InvalidConnectorKeyBody("body failed validation"))
    ));
    Ok(())
}

#[test]
fn unbudgeted_mint_normalizes_and_owner_add_enforces() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let minted = vault.mint_unbudgeted_connector_key(" Peer-Link ", None, 1_000)?;
    assert_eq!(minted.connector, "peer_link");
    assert_eq!(minted.status, ConnectorKeyStatus::Active);
    assert_eq!(minted.budgets.len(), 0);

    let (id, _) = vault
        .connector_key_for("peer-link", None)?
        .expect("minted key");
    let invalid_limit = EffectorBudget::rate(0, 3_600);
    assert!(matches!(
        vault.add_connector_key_budget(&id, invalid_limit, 1_000),
        Err(Error::InvalidConnectorKeyBody(
            "budget limit must be at least 1"
        ))
    ));
    let mut invalid_unit = EffectorBudget::rate(10, 3_600);
    invalid_unit.unit = Some("USD".to_owned());
    assert!(matches!(
        vault.add_connector_key_budget(&id, invalid_unit, 1_000),
        Err(Error::InvalidConnectorKeyBody(
            "unit only allowed on spend rows"
        ))
    ));

    let mut row = EffectorBudget::rate(2, 3_600);
    row.channel_class = Some(" Peer ".to_owned());
    let updated = vault.add_connector_key_budget(&id, row, 1_000)?;
    assert_eq!(updated.budgets.len(), 1);
    assert_eq!(updated.budgets[0].channel_class.as_deref(), Some("peer"));
    assert_eq!(
        vault
            .get_connector_key(&id)?
            .expect("stored key")
            .budgets
            .len(),
        1
    );
    let tally = vault.admit_connector_key_dispatches_at(
        &id,
        "peer",
        3,
        ConnectorDispatchTelemetry::default(),
        1_000,
    )?;
    assert_eq!(tally.admitted, 2);
    assert_eq!(tally.refused, 1);

    let full_id = test_id(0xA8);
    vault.register_connector_key(
        &full_id,
        ConnectorKeyRecord::active(
            "full_peer",
            None,
            vec![EffectorBudget::rate(1, 60); CONNECTOR_KEY_MAX_BUDGET_ROWS],
            1_000,
        ),
    )?;
    assert!(matches!(
        vault.add_connector_key_budget(&full_id, EffectorBudget::rate(1, 60), 1_000),
        Err(Error::InvalidConnectorKeyBody("too many budget rows"))
    ));
    Ok(())
}

#[test]
fn dispatch_batch_surfaces_budget_ladder_events() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xAE);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("peer", None, vec![EffectorBudget::rate(3, 60)], 1_000),
    )?;

    let below_threshold = vault.admit_connector_key_dispatches_at(
        &id,
        "peer",
        1,
        ConnectorDispatchTelemetry::default(),
        1_000,
    )?;
    assert!(below_threshold.ladder_events.is_empty());

    let threshold_crossing = vault.admit_connector_key_dispatches_at(
        &id,
        "peer",
        1,
        ConnectorDispatchTelemetry::default(),
        1_000,
    )?;
    assert_eq!(threshold_crossing.ladder_events.len(), 1);
    assert_eq!(
        threshold_crossing.ladder_events[0].threshold,
        BudgetThreshold::Silent50
    );
    Ok(())
}

#[test]
fn oversized_dispatch_batch_is_rejected() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xAD);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("peer", None, Vec::new(), 1_000),
    )?;

    assert!(matches!(
        vault.admit_connector_key_dispatches(
            &id,
            "peer",
            CONNECTOR_KEY_MAX_DISPATCH_BATCH + 1,
            ConnectorDispatchTelemetry::default(),
        ),
        Err(Error::InvalidConnectorKeyBody("dispatch batch too large"))
    ));
    Ok(())
}

#[test]
fn suggested_budget_is_inactive_until_acceptance() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xA9);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("peer_link", None, Vec::new(), 1_000),
    )?;
    let mut suggestion = EffectorBudget::sends(
        2,
        EffectorBudgetWindow::Rolling { duration_s: 3_600 },
        EffectorBudgetOnExhaust::Refuse,
    );
    suggestion.channel_class = Some("peer".to_owned());
    let staged = vault.suggest_connector_key_budget(&id, suggestion, 1_000)?;
    assert_eq!(staged.budgets.len(), 0);
    assert_eq!(staged.suggested_budgets.len(), 1);

    let uncapped = vault.admit_connector_key_dispatches_at(
        &id,
        "peer",
        3,
        ConnectorDispatchTelemetry::default(),
        1_000,
    )?;
    assert_eq!(uncapped.admitted, 3);
    assert_eq!(uncapped.refused, 0);
    let accepted = vault.accept_connector_key_budget_suggestion(&id, 0, 1_000)?;
    assert_eq!(accepted.budgets.len(), 1);
    assert_eq!(accepted.suggested_budgets.len(), 0);
    let capped = vault.admit_connector_key_dispatches_at(
        &id,
        "peer",
        3,
        ConnectorDispatchTelemetry::default(),
        1_000,
    )?;
    assert_eq!(capped.admitted, 2);
    assert_eq!(capped.refused, 1);

    let suspend = EffectorBudget::sends(
        1,
        EffectorBudgetWindow::Rolling { duration_s: 60 },
        EffectorBudgetOnExhaust::Suspend,
    );
    assert!(matches!(
        vault.suggest_connector_key_budget(&id, suspend, 1_000),
        Err(Error::InvalidConnectorKeyBody(
            "suggested budget rows must refuse on exhaust"
        ))
    ));
    let spend = EffectorBudget::spend(
        100,
        "USD",
        EffectorBudgetWindow::Rolling { duration_s: 60 },
        EffectorBudgetOnExhaust::Refuse,
    );
    assert!(matches!(
        vault.suggest_connector_key_budget(&id, spend, 1_000),
        Err(Error::InvalidConnectorKeyBody(
            "suggested budget rows must be sends or rate"
        ))
    ));
    Ok(())
}

#[test]
fn suggestion_accept_respects_active_row_cap() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xAA);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active(
            "capped_peer",
            None,
            vec![EffectorBudget::rate(1, 60); CONNECTOR_KEY_MAX_BUDGET_ROWS],
            1_000,
        ),
    )?;
    let staged = vault.suggest_connector_key_budget(&id, EffectorBudget::rate(2, 60), 1_000)?;
    assert_eq!(staged.budgets.len(), 16);
    assert_eq!(staged.suggested_budgets.len(), 1);
    assert!(matches!(
        vault.accept_connector_key_budget_suggestion(&id, 0, 1_000),
        Err(Error::InvalidConnectorKeyBody("too many budget rows"))
    ));
    let unchanged = vault.get_connector_key(&id)?.expect("stored key");
    assert_eq!(unchanged.budgets.len(), 16);
    assert_eq!(unchanged.suggested_budgets.len(), 1);
    Ok(())
}

#[test]
fn budget_mutations_and_dispatch_suspension_append_one_op_record_each() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xAC);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("peer_audit", None, Vec::new(), 1_000),
    )?;
    assert_eq!(connector_key_op_receipt_count(&vault)?, 1);

    let mut suspending = EffectorBudget::sends(
        1,
        EffectorBudgetWindow::Rolling { duration_s: 60 },
        EffectorBudgetOnExhaust::Suspend,
    );
    suspending.channel_class = Some("peer".to_owned());
    vault.add_connector_key_budget(&id, suspending, 1_010)?;
    assert_eq!(connector_key_op_receipt_count(&vault)?, 2);

    vault.suggest_connector_key_budget(&id, EffectorBudget::rate(10, 60), 1_020)?;
    assert_eq!(connector_key_op_receipt_count(&vault)?, 3);

    vault.accept_connector_key_budget_suggestion(&id, 0, 1_030)?;
    assert_eq!(connector_key_op_receipt_count(&vault)?, 4);

    let tally = vault.admit_connector_key_dispatches_at(
        &id,
        "peer",
        2,
        ConnectorDispatchTelemetry::default(),
        1_040,
    )?;
    assert_eq!(tally.admitted, 1);
    assert_eq!(tally.refused, 1);
    assert_eq!(connector_key_op_receipt_count(&vault)?, 5);
    Ok(())
}

#[test]
fn refuse_dispatch_stays_active_and_rolling_window_frees_budget() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xAB);
    let mut row = EffectorBudget::sends(
        5,
        EffectorBudgetWindow::Rolling { duration_s: 3_600 },
        EffectorBudgetOnExhaust::Refuse,
    );
    row.channel_class = Some("peer".to_owned());
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("peer_window", None, vec![row], 1_000),
    )?;

    let exhausted = vault.admit_connector_key_dispatches_at(
        &id,
        "peer",
        6,
        ConnectorDispatchTelemetry::default(),
        1_000,
    )?;
    assert_eq!(exhausted.admitted, 5);
    assert_eq!(exhausted.refused, 1);
    assert_eq!(
        vault.get_connector_key(&id)?.expect("stored key").status,
        ConnectorKeyStatus::Active
    );
    let fresh = vault.admit_connector_key_dispatches_at(
        &id,
        "peer",
        1,
        ConnectorDispatchTelemetry::default(),
        4_600,
    )?;
    assert_eq!(fresh.admitted, 1);
    assert_eq!(fresh.refused, 0);
    Ok(())
}

// --- ONE-1875: the engine clock owns admission accounting --------------------

fn dispatch_usage_row(vault: &Vault, id: &EntityId, row_index: u16) -> Result<ConnectorKeyUsage> {
    let rtxn = vault.store.env.read_txn()?;
    let stored = vault
        .store
        .vault_meta
        .get(&rtxn, &connector_key_usage_row_key(id, row_index))?;
    match stored {
        Some(bytes) => ConnectorKeyUsage::decode(&bytes),
        None => Ok(ConnectorKeyUsage::default()),
    }
}

fn observed_at(at: u64) -> ConnectorDispatchTelemetry {
    ConnectorDispatchTelemetry {
        caller_observed_at: Some(at),
    }
}

#[test]
fn caller_time_cannot_roll_budget_window() -> Result<()> {
    const FROZEN: u64 = 10_000;
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xB8);
    let mut row = EffectorBudget::sends(
        2,
        EffectorBudgetWindow::Rolling { duration_s: 3_600 },
        EffectorBudgetOnExhaust::Refuse,
    );
    row.channel_class = Some("peer".to_owned());
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("peer_clock", None, vec![row], 1_000),
    )?;

    let filled = vault.admit_connector_key_dispatches_at(
        &id,
        "peer",
        2,
        ConnectorDispatchTelemetry::default(),
        FROZEN,
    )?;
    assert_eq!(filled.admitted, 2);
    let exhausted_usage = dispatch_usage_row(&vault, &id, 0)?;

    // Extreme past and extreme future caller observations against the SAME
    // frozen engine sample: identical admission, identical usage, identical
    // window state. A far-future observation would have pruned the live
    // entries had it reached `touch`.
    for observed in [FROZEN + 1_000_000, u64::MAX, 1, 0] {
        let tally = vault.admit_connector_key_dispatches_at(
            &id,
            "peer",
            1,
            observed_at(observed),
            FROZEN,
        )?;
        assert_eq!(
            (tally.admitted, tally.refused),
            (0, 1),
            "caller time {observed} bought a dispatch"
        );
        assert_eq!(tally.accounted_at, FROZEN);
        assert_eq!(tally.caller_observed_at, Some(observed));
        assert_eq!(
            dispatch_usage_row(&vault, &id, 0)?,
            exhausted_usage,
            "caller time {observed} moved the window"
        );
    }

    // Only the engine sample rolls it.
    let rolled =
        vault.admit_connector_key_dispatches_at(&id, "peer", 1, observed_at(1), FROZEN + 3_601)?;
    assert_eq!((rolled.admitted, rolled.refused), (1, 0));
    Ok(())
}

#[test]
fn suspend_cap_uses_engine_clock() -> Result<()> {
    const FROZEN: u64 = 50_000;
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xB9);
    let mut row = EffectorBudget::sends(
        1,
        EffectorBudgetWindow::Rolling { duration_s: 60 },
        EffectorBudgetOnExhaust::Suspend,
    );
    row.channel_class = Some("peer".to_owned());
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("peer_suspend", None, vec![row], 1_000),
    )?;

    let tally = vault.admit_connector_key_dispatches_at(
        &id,
        "peer",
        2,
        ConnectorDispatchTelemetry::default(),
        FROZEN,
    )?;
    assert_eq!((tally.admitted, tally.refused), (1, 1));
    let suspended = vault.get_connector_key(&id)?.expect("stored key");
    assert_eq!(suspended.status, ConnectorKeyStatus::Suspended);
    assert_eq!(suspended.status_changed_at, Some(FROZEN));

    // Resume keeps usage (the hard cap is the window, not the status), so
    // while the engine clock is still inside the window a caller claiming the
    // window has passed re-exhausts and re-suspends instead of sending.
    vault.resume_connector_key(&id, FROZEN)?;
    let denied = vault.admit_connector_key_dispatches_at(
        &id,
        "peer",
        1,
        observed_at(FROZEN + 10_000),
        FROZEN + 30,
    )?;
    assert_eq!((denied.admitted, denied.refused), (0, 1));
    assert_eq!(
        vault.get_connector_key(&id)?.expect("stored key").status,
        ConnectorKeyStatus::Suspended
    );

    // The cap frees only once the ENGINE clock crosses the boundary.
    vault.resume_connector_key(&id, FROZEN + 61)?;
    let fresh =
        vault.admit_connector_key_dispatches_at(&id, "peer", 1, observed_at(1), FROZEN + 61)?;
    assert_eq!((fresh.admitted, fresh.refused), (1, 0));
    assert_eq!(
        vault.get_connector_key(&id)?.expect("stored key").status,
        ConnectorKeyStatus::Active
    );
    Ok(())
}

#[test]
fn telemetry_time_is_non_authoritative() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xBA);
    let mut row = EffectorBudget::sends(
        4,
        EffectorBudgetWindow::Rolling { duration_s: 3_600 },
        EffectorBudgetOnExhaust::Refuse,
    );
    row.channel_class = Some("peer".to_owned());
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("peer_telemetry", None, vec![row], 1_000),
    )?;

    // The public door takes no accounting time at all: it samples the engine
    // clock itself and only echoes the declared observation back.
    let declared = 1_234;
    let before = crate::unix_seconds_now();
    let tally = vault.admit_connector_key_dispatches(&id, "peer", 1, observed_at(declared))?;
    let after = crate::unix_seconds_now();
    assert_eq!(tally.admitted, 1);
    assert_eq!(tally.caller_observed_at, Some(declared));
    assert!(
        (before..=after).contains(&tally.accounted_at),
        "accounting time came from the engine clock"
    );
    // The debit itself is stamped with the engine sample, not the declaration.
    let accounted_at = tally.accounted_at;
    assert_eq!(
        dispatch_usage_row(&vault, &id, 0)?.entries,
        vec![(accounted_at, 1)]
    );

    // A far-future declaration is inert: it neither prunes the live entry nor
    // frees budget for the rest of the row.
    let stale_claim = observed_at(accounted_at + 86_400);
    let more =
        vault.admit_connector_key_dispatches_at(&id, "peer", 3, stale_claim, accounted_at)?;
    assert_eq!(more.admitted, 3);
    let usage = dispatch_usage_row(&vault, &id, 0)?;
    assert_eq!(usage.used(), 4, "the earlier debit survived the telemetry");
    assert!(usage.entries.iter().all(|(at, _)| *at == accounted_at));
    let refused =
        vault.admit_connector_key_dispatches_at(&id, "peer", 1, stale_claim, accounted_at)?;
    assert_eq!((refused.admitted, refused.refused), (0, 1));
    Ok(())
}

#[test]
fn batch_uses_one_engine_sample() -> Result<()> {
    const FROZEN: u64 = 70_000;
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xBB);
    let mut row = EffectorBudget::sends(
        3,
        EffectorBudgetWindow::Rolling { duration_s: 3_600 },
        EffectorBudgetOnExhaust::Suspend,
    );
    row.channel_class = Some("peer".to_owned());
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("peer_batch", None, vec![row], 1_000),
    )?;

    let tally = vault.admit_connector_key_dispatches_at(
        &id,
        "peer",
        5,
        observed_at(FROZEN - 900),
        FROZEN,
    )?;
    assert_eq!((tally.admitted, tally.refused), (3, 2));
    assert_eq!(tally.accounted_at, FROZEN);

    // Every debit in the batch carries the one sample…
    assert_eq!(
        dispatch_usage_row(&vault, &id, 0)?.entries,
        vec![(FROZEN, 1), (FROZEN, 1), (FROZEN, 1)]
    );
    // …and so do the suspension transition and its op record.
    let record = vault.get_connector_key(&id)?.expect("stored key");
    assert_eq!(record.status, ConnectorKeyStatus::Suspended);
    assert_eq!(record.status_changed_at, Some(FROZEN));
    let suspend_op = vault
        .receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Gate))?
        .into_iter()
        .find(|receipt| {
            receipt
                .policy_trace
                .iter()
                .any(|reason| reason == "gate.connector_key.dispatch_suspend")
        })
        .expect("dispatch suspend op record");
    assert_eq!(suspend_op.occurred_at, FROZEN);
    Ok(())
}

#[test]
fn charter_block_slots_round_trip_for_gov10() -> Result<()> {
    // GOV-01 mints records with both charter slots None, but the codec must
    // already round-trip filled blocks (GOV-10 relies on it).
    let compiled = CompiledConnectorPolicy {
        never_list: vec!["*:delete".to_owned(), "slack:call".to_owned()],
        channel_caps: vec![EffectorBudget::sends(
            3,
            EffectorBudgetWindow::Calendar {
                period: CalendarPeriod::Week,
                tz: None,
            },
            EffectorBudgetOnExhaust::Suspend,
        )],
    };
    let record = ConnectorKeyRecord {
        charter: Some(ConnectorCharterBlock {
            text: "never delete".to_owned(),
            text_hash: [0x11; 32],
            compiled: compiled.clone(),
            compiled_hash: [0x22; 32],
            stamped_aggregate: [0x33; 32],
            stamped_by: "owner:olety".to_owned(),
            stamped_at: 4_000,
        }),
        pending_charter: Some(PendingConnectorCharter {
            text: "never call".to_owned(),
            text_hash: [0x44; 32],
            compiled,
            compiled_hash: [0x55; 32],
            proposed_at: 4_100,
        }),
        ..ConnectorKeyRecord::active("slack", Some(test_id(0xB1)), Vec::new(), 1_000)
    };
    let encoded = encode_connector_key_body(&record)?;
    assert_eq!(decode_connector_key_body(&encoded)?, record);
    Ok(())
}

#[test]
fn connector_key_registry_entry_is_pinned() -> Result<()> {
    assert_eq!(ENTITY_TYPE_CONNECTOR_KEY, 70);
    let entry = entity_type_registry_entry(ENTITY_TYPE_CONNECTOR_KEY).expect("registered");
    assert_eq!(entry.kind, "CONNECTOR_KEY");
    assert_eq!(entry.type_byte, ENTITY_TYPE_CONNECTOR_KEY);
    assert_eq!(entry.short_id_prefix, Some("ck"));
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.zone, TypeByteZone::System);
    assert_eq!(short_id_prefix(ENTITY_TYPE_CONNECTOR_KEY)?, "ck");
    assert!(matches!(
        validate_public_entity_type(ENTITY_TYPE_CONNECTOR_KEY),
        Err(Error::MaintenanceKindNotWritable(70))
    ));
    Ok(())
}

#[test]
fn register_then_get_returns_normalized_record() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xC1);
    let mut record = ConnectorKeyRecord::active(
        " Slack-Chat ",
        Some(test_id(0xC2)),
        all_dimension_budgets(),
        1_000,
    );
    record.budgets[1].channel_class = Some(" Slack-Chat ".to_owned());

    let registered = vault.register_connector_key(&id, record)?;
    assert_eq!(registered.connector, "slack_chat");
    assert_eq!(
        registered.budgets[1].channel_class.as_deref(),
        Some("slack_chat")
    );

    let fetched = vault.get_connector_key(&id)?.expect("stored record");
    assert_eq!(fetched, registered);

    // Wrong-type read fails closed with the header's type byte.
    let other = test_id(0xC3);
    vault.mint_standing_outbound_grant(
        &other,
        &crate::genui::GrantMintIntent {
            principal_ref: "owner".to_owned(),
            origin_component_id: "ask-1".to_owned(),
            origin_action_id: "escalate_always_this_verb_class".to_owned(),
            origin_receipt_ref: None,
            scope: crate::genui::GrantMintIntentScope::VerbClass {
                verb_class: "send".to_owned(),
            },
        },
        10,
    )?;
    assert!(matches!(
        vault.get_connector_key(&other),
        Err(Error::InvalidEntityType(_))
    ));
    Ok(())
}

#[test]
fn register_enforces_tuple_uniqueness_until_revoked() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0xD1);
    vault.register_connector_key(
        &test_id(0xD2),
        ConnectorKeyRecord::active("line", Some(actor), Vec::new(), 1_000),
    )?;

    // Same (connector, actor) tuple: rejected.
    assert!(matches!(
        vault.register_connector_key(
            &test_id(0xD3),
            ConnectorKeyRecord::active("line", Some(actor), Vec::new(), 1_001),
        ),
        Err(Error::ConnectorKeyAlreadyExists)
    ));
    // Reusing the same entity id: rejected.
    assert!(matches!(
        vault.register_connector_key(
            &test_id(0xD2),
            ConnectorKeyRecord::active("email", Some(actor), Vec::new(), 1_001),
        ),
        Err(Error::ConnectorKeyAlreadyExists)
    ));
    // Same connector, different actor: fine.
    vault
        .register_connector_key(
            &test_id(0xD4),
            ConnectorKeyRecord::active("line", Some(test_id(0xD5)), Vec::new(), 1_002),
        )
        .expect("different actor tuple");
    // Actor-agnostic sibling: a distinct tuple, fine.
    vault
        .register_connector_key(
            &test_id(0xD6),
            ConnectorKeyRecord::active("line", None, Vec::new(), 1_003),
        )
        .expect("actor-agnostic tuple");

    // After revoke, the tuple frees up. (Seed 0xD8: [0xD7; 16] is the seeded
    // DEFAULT_POLICY_MANIFEST_ID and would collide on the entity-id check.)
    vault.revoke_connector_key(&test_id(0xD2), 1_010)?;
    vault
        .register_connector_key(
            &test_id(0xD8),
            ConnectorKeyRecord::active("line", Some(actor), Vec::new(), 1_011),
        )
        .expect("revoked tuple re-register");
    Ok(())
}

#[test]
fn register_rejects_non_active_status_and_prestamped_charter() {
    let (_tmp, vault) = temp_vault();
    let suspended = ConnectorKeyRecord {
        status: ConnectorKeyStatus::Suspended,
        status_changed_at: Some(1_000),
        suspended_reason: Some("owner".to_owned()),
        ..ConnectorKeyRecord::active("line", None, Vec::new(), 1_000)
    };
    assert!(matches!(
        vault.register_connector_key(&test_id(0x5E), suspended),
        Err(Error::InvalidConnectorKeyBody(
            "registration requires status active"
        ))
    ));

    let pre_stamped = ConnectorKeyRecord {
        pending_charter: Some(PendingConnectorCharter {
            text: "never delete".to_owned(),
            text_hash: [0; 32],
            compiled: CompiledConnectorPolicy {
                never_list: vec!["*:delete".to_owned()],
                channel_caps: Vec::new(),
            },
            compiled_hash: [0; 32],
            proposed_at: 1_000,
        }),
        ..ConnectorKeyRecord::active("line", None, Vec::new(), 1_000)
    };
    assert!(matches!(
        vault.register_connector_key(&test_id(0xE2), pre_stamped),
        Err(Error::InvalidConnectorKeyBody(
            "registration must not carry a charter"
        ))
    ));
}

#[test]
fn validation_rejects_malformed_budget_rows() {
    let day = || EffectorBudgetWindow::Calendar {
        period: CalendarPeriod::Day,
        tz: None,
    };
    let record =
        |budgets: Vec<EffectorBudget>| ConnectorKeyRecord::active("line", None, budgets, 1_000);

    // Spend without a unit.
    let mut spend_without_unit =
        EffectorBudget::spend(100, "USD", day(), EffectorBudgetOnExhaust::Refuse);
    spend_without_unit.unit = None;
    assert!(matches!(
        encode_connector_key_body(&record(vec![spend_without_unit])),
        Err(Error::InvalidConnectorKeyBody("spend rows require a unit"))
    ));

    // Lowercase 3-letter unit is a malformed ISO-4217 code, not a provider token.
    assert!(matches!(
        encode_connector_key_body(&record(vec![EffectorBudget::spend(
            100,
            "usd",
            day(),
            EffectorBudgetOnExhaust::Refuse,
        )])),
        Err(Error::InvalidConnectorKeyBody(
            "spend unit currency code must be uppercase"
        ))
    ));
    // Provider-unit tokens are valid (M8 widening).
    assert!(
        encode_connector_key_body(&record(vec![EffectorBudget::spend(
            100,
            "credits",
            day(),
            EffectorBudgetOnExhaust::Refuse,
        )]))
        .is_ok()
    );

    // Zero limit.
    assert!(matches!(
        encode_connector_key_body(&record(vec![EffectorBudget::sends(
            0,
            day(),
            EffectorBudgetOnExhaust::Refuse,
        )])),
        Err(Error::InvalidConnectorKeyBody(
            "budget limit must be at least 1"
        ))
    ));

    // Zero rolling duration.
    assert!(matches!(
        encode_connector_key_body(&record(vec![EffectorBudget::rate(5, 0)])),
        Err(Error::InvalidConnectorKeyBody(
            "rolling window duration must be at least 1s"
        ))
    ));

    // Non-UTC tz is a v1 validation error (honest forward-compat).
    assert!(matches!(
        encode_connector_key_body(&record(vec![EffectorBudget::sends(
            5,
            EffectorBudgetWindow::Calendar {
                period: CalendarPeriod::Day,
                tz: Some("Asia/Tokyo".to_owned()),
            },
            EffectorBudgetOnExhaust::Refuse,
        )])),
        Err(Error::InvalidConnectorKeyBody("calendar tz must be UTC"))
    ));

    // 17 budget rows.
    let seventeen = (0..17)
        .map(|_| EffectorBudget::rate(5, 60))
        .collect::<Vec<_>>();
    assert!(matches!(
        encode_connector_key_body(&record(seventeen)),
        Err(Error::InvalidConnectorKeyBody("too many budget rows"))
    ));
}

#[test]
fn calendar_window_start_fixtures() {
    // 2024-02-29T12:00:00Z (leap February).
    let leap_noon = 1_709_208_000;
    assert_eq!(
        calendar_window_start(CalendarPeriod::Day, leap_noon),
        1_709_164_800 // 2024-02-29T00:00:00Z
    );
    assert_eq!(
        calendar_window_start(CalendarPeriod::Month, leap_noon),
        1_706_745_600 // 2024-02-01T00:00:00Z
    );

    // Monday boundary: 2024-01-01 is a Monday.
    let monday = 1_704_067_200;
    assert_eq!(calendar_window_start(CalendarPeriod::Week, monday), monday);
    assert_eq!(
        calendar_window_start(CalendarPeriod::Week, monday + 6 * 86_400 + 3_600),
        monday
    );
    // One second before that Monday belongs to the previous (Christmas) week.
    assert_eq!(
        calendar_window_start(CalendarPeriod::Week, monday - 1),
        1_703_462_400 // Monday 2023-12-25T00:00:00Z
    );
    // Pre-1970-01-05 clamps to the epoch instead of underflowing.
    assert_eq!(calendar_window_start(CalendarPeriod::Week, 2 * 86_400), 0);

    // Dec -> Jan rollover.
    assert_eq!(
        calendar_window_start(CalendarPeriod::Month, monday - 1),
        1_701_388_800 // 2023-12-01T00:00:00Z
    );
    assert_eq!(
        calendar_window_start(CalendarPeriod::Month, monday + 14 * 86_400),
        monday // 2024-01-01T00:00:00Z
    );
}

#[test]
fn rolling_window_liveness_boundary() {
    let window = EffectorBudgetWindow::Rolling { duration_s: 60 };
    let mut usage = ConnectorKeyUsage {
        window_start: 0,
        entries: vec![(1_000, 1)],
        fired: Vec::new(),
    };
    // Live at ts + duration_s - 1.
    usage.touch(&window, 5, 1_059);
    assert_eq!(usage.used(), 1);
    // Dead at ts + duration_s.
    usage.touch(&window, 5, 1_060);
    assert_eq!(usage.used(), 0);
}

#[test]
fn calendar_rollover_resets_entries_and_fired() {
    let window = EffectorBudgetWindow::Calendar {
        period: CalendarPeriod::Day,
        tz: None,
    };
    let mut usage = ConnectorKeyUsage {
        window_start: 0,
        entries: vec![(1_000, 3)],
        fired: vec!["silent50".to_owned()],
    };
    // Same bucket: state survives.
    usage.touch(&window, 5, 2_000);
    assert_eq!(usage.used(), 3);
    assert_eq!(usage.fired, vec!["silent50".to_owned()]);
    // Next day: fresh window, fresh ladder.
    usage.touch(&window, 5, 86_400 + 1);
    assert_eq!(usage.window_start, 86_400);
    assert_eq!(usage.used(), 0);
    assert!(usage.fired.is_empty());
}

#[test]
fn usage_codec_round_trips() -> Result<()> {
    let usage = ConnectorKeyUsage {
        window_start: 86_400,
        entries: vec![(86_500, 1), (86_600, 250)],
        fired: vec!["silent50".to_owned(), "plan80".to_owned()],
    };
    assert_eq!(ConnectorKeyUsage::decode(&usage.encode()?)?, usage);
    assert!(ConnectorKeyUsage::decode(b"garbage").is_err());
    Ok(())
}

#[test]
fn spend_settle_accumulates_and_suspends_on_crossing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xF1);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active(
            "slack",
            None,
            vec![
                EffectorBudget::sends(
                    5,
                    EffectorBudgetWindow::Calendar {
                        period: CalendarPeriod::Day,
                        tz: None,
                    },
                    EffectorBudgetOnExhaust::Refuse,
                ),
                EffectorBudget::spend(
                    1_000,
                    "USD",
                    EffectorBudgetWindow::Calendar {
                        period: CalendarPeriod::Month,
                        tz: None,
                    },
                    EffectorBudgetOnExhaust::Suspend,
                ),
            ],
            1_000,
        ),
    )?;

    let read = vault.settle_connector_spend(&id, 1, 400, 1_100, "settle:one")?;
    assert_eq!(read.used, 400);
    assert_eq!(read.remaining, 600);
    assert_eq!(read.percent_used, 40);
    assert_eq!(
        vault.get_connector_key(&id)?.expect("record").status,
        ConnectorKeyStatus::Active
    );

    // Crossing the limit flips the key Suspended in the same txn; the row
    // reports zero remaining.
    let read = vault.settle_connector_spend(&id, 1, 700, 1_200, "settle:two")?;
    assert_eq!(read.used, 1_100);
    assert_eq!(read.remaining, 0);
    let record = vault.get_connector_key(&id)?.expect("record");
    assert_eq!(record.status, ConnectorKeyStatus::Suspended);
    assert_eq!(
        record.suspended_reason.as_deref(),
        Some("budget_exhausted:row:1")
    );

    // Settling a non-spend row / a missing row fails closed.
    assert!(matches!(
        vault.settle_connector_spend(&id, 0, 1, 1_300, "settle:three"),
        Err(Error::InvalidConnectorKeyBody(
            "spend settle on non-spend row"
        ))
    ));
    assert!(matches!(
        vault.settle_connector_spend(&id, 7, 1, 1_300, "settle:four"),
        Err(Error::InvalidConnectorKeyBody(
            "spend settle on missing row"
        ))
    ));
    Ok(())
}

#[test]
fn lifecycle_transitions_are_enforced() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xF5);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_000),
    )?;

    let suspended = vault.suspend_connector_key(&id, "owner", 1_010)?;
    assert_eq!(suspended.status, ConnectorKeyStatus::Suspended);
    assert_eq!(suspended.suspended_reason.as_deref(), Some("owner"));
    assert_eq!(suspended.status_changed_at, Some(1_010));
    // Suspend requires Active.
    assert!(matches!(
        vault.suspend_connector_key(&id, "owner", 1_011),
        Err(Error::InvalidConnectorKeyBody("illegal status transition"))
    ));

    let resumed = vault.resume_connector_key(&id, 1_020)?;
    assert_eq!(resumed.status, ConnectorKeyStatus::Active);
    assert!(resumed.suspended_reason.is_none());
    // Resume requires Suspended.
    assert!(matches!(
        vault.resume_connector_key(&id, 1_021),
        Err(Error::InvalidConnectorKeyBody("illegal status transition"))
    ));

    let revoked = vault.revoke_connector_key(&id, 1_030)?;
    assert_eq!(revoked.status, ConnectorKeyStatus::Revoked);
    // Revoked is terminal.
    assert!(matches!(
        vault.revoke_connector_key(&id, 1_031),
        Err(Error::InvalidConnectorKeyBody("illegal status transition"))
    ));
    assert!(matches!(
        vault.resume_connector_key(&id, 1_032),
        Err(Error::InvalidConnectorKeyBody("illegal status transition"))
    ));
    Ok(())
}

#[test]
fn receipted_ops_project_into_gate_receipts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xF7);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_000),
    )?;
    vault.suspend_connector_key(&id, "owner", 1_010)?;
    vault.resume_connector_key(&id, 1_020)?;

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    let grant_ref = format!("ckey:{}", id.to_hex());
    for op in [
        "gate.connector_key.register",
        "gate.connector_key.suspend",
        "gate.connector_key.resume",
    ] {
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.policy_trace.iter().any(|reason| reason == op))
            .unwrap_or_else(|| panic!("missing {op} receipt"));
        assert_eq!(
            receipt.fields.get("grant_ref").map(String::as_str),
            Some(grant_ref.as_str()),
            "{op} receipt must join the ckey lane"
        );
    }
    Ok(())
}

#[test]
fn connector_key_for_resolves_exact_actor_over_agnostic() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0xB1);
    let bound_id = test_id(0xB2);
    let agnostic_id = test_id(0xB3);
    vault.register_connector_key(
        &bound_id,
        ConnectorKeyRecord::active("line", Some(actor), Vec::new(), 1_000),
    )?;
    vault.register_connector_key(
        &agnostic_id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_001),
    )?;

    let (resolved, _) = vault
        .connector_key_for("line", Some(&actor))?
        .expect("actor-bound key governs");
    assert_eq!(resolved, bound_id);

    let (resolved, _) = vault
        .connector_key_for("line", None)?
        .expect("agnostic key governs");
    assert_eq!(resolved, agnostic_id);

    // An actor with no exact tuple falls back to the connector-wide key.
    let (resolved, _) = vault
        .connector_key_for("line", Some(&test_id(0xB4)))?
        .expect("agnostic fallback");
    assert_eq!(resolved, agnostic_id);

    // A revoked-only tuple still resolves (the status wall reports it).
    vault.revoke_connector_key(&bound_id, 1_010)?;
    vault.revoke_connector_key(&agnostic_id, 1_011)?;
    let (_, record) = vault
        .connector_key_for("line", Some(&actor))?
        .expect("revoked tuple still resolves");
    assert_eq!(record.status, ConnectorKeyStatus::Revoked);

    assert!(vault.connector_key_for("unknown", None)?.is_none());
    assert!(vault.connector_key_for("  ", None)?.is_none());
    Ok(())
}

#[test]
fn spend_settle_ledgers_on_the_engine_clock_and_records_cost_time() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xF9);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active(
            "slack",
            None,
            vec![
                EffectorBudget::spend(
                    1_000,
                    "USD",
                    EffectorBudgetWindow::Calendar {
                        period: CalendarPeriod::Day,
                        tz: None,
                    },
                    EffectorBudgetOnExhaust::Suspend,
                ),
                EffectorBudget::spend(
                    2_000,
                    "USD",
                    EffectorBudgetWindow::Calendar {
                        period: CalendarPeriod::Month,
                        tz: None,
                    },
                    EffectorBudgetOnExhaust::Suspend,
                ),
            ],
            1_000,
        ),
    )?;

    // Zero-amount settlements are rejected (nothing to record; keeps the
    // usage entry log bounded by the row limit).
    assert!(matches!(
        vault.settle_connector_spend(&id, 0, 0, 2_000, "settle:zero"),
        Err(Error::InvalidConnectorKeyBody(
            "settle amount must be at least 1"
        ))
    ));
    // Event identity is required and shape-checked.
    assert!(matches!(
        vault.settle_connector_spend(&id, 0, 10, 2_000, "  "),
        Err(Error::InvalidConnectorKeyBody(
            "settle event_ref must not be blank"
        ))
    ));
    assert!(matches!(
        vault.settle_connector_spend(&id, 0, 10, 2_000, "x".repeat(129).as_str()),
        Err(Error::InvalidConnectorKeyBody("settle event_ref too long"))
    ));

    // cost_occurred_at is a DECLARED fact, never a window selector: a
    // far-past, a far-future, a calendar-edge, and a first-touch-on-empty-row
    // declared time all debit the CURRENT engine-clock window and cannot
    // clear or shift prior usage.
    let now = crate::unix_seconds_now();
    let live_bucket = calendar_window_start(CalendarPeriod::Day, now);
    let day_edge = live_bucket + SECONDS_PER_DAY - 1;
    let declared_times = [
        (5_u64, "settle:first-touch-ancient"),
        (now + 10_000, "settle:far-future"),
        (day_edge, "settle:calendar-edge"),
        (1_100, "settle:far-past"),
    ];
    let mut expected_used = 0;
    for (declared, event_ref) in declared_times {
        expected_used += 100;
        let read = vault.settle_connector_spend(&id, 0, 100, declared, event_ref)?;
        assert_eq!(read.used, expected_used, "{event_ref} accumulates");
        assert!(
            read.window_start >= live_bucket && read.window_start <= crate::unix_seconds_now(),
            "{event_ref} landed in the live engine-clock bucket"
        );
    }
    assert_eq!(
        vault.get_connector_key(&id)?.expect("record").status,
        ConnectorKeyStatus::Active
    );

    // A replay of the SAME settlement is idempotent: nothing debits, the
    // current state echoes back.
    let replay = vault.settle_connector_spend(&id, 0, 100, 5, "settle:first-touch-ancient")?;
    assert_eq!(replay.used, expected_used, "replay settles nothing");
    // An honest retry whose DECLARED cost time drifted between attempts is
    // still the same settlement: idempotent, no second debit, and the first
    // write's recorded time stands (first-writer-wins).
    let drifted = vault.settle_connector_spend(&id, 0, 100, 6, "settle:first-touch-ancient")?;
    assert_eq!(
        drifted.used, expected_used,
        "drifted-time retry settles nothing"
    );
    let event_key = connector_key_settle_event_key(&id, "settle:first-touch-ancient");
    {
        let rtxn = vault.store.env.read_txn()?;
        let stored = vault
            .store
            .vault_meta
            .get(&rtxn, &event_key)?
            .expect("settlement event row");
        assert_eq!(
            &stored[stored.len() - 8..],
            &5_u64.to_be_bytes(),
            "first recorded cost time kept"
        );
    }
    // A replayed event id with different CONTENT (row or amount) fails
    // closed — a pre-claimed event_ref cannot force a silent no-op for a
    // different settlement.
    for (row, amount) in [(1_u16, 100_u64), (0, 999)] {
        assert!(
            matches!(
                vault.settle_connector_spend(&id, row, amount, 5, "settle:first-touch-ancient"),
                Err(Error::InvalidConnectorKeyBody(
                    "settle event replay with different settlement"
                ))
            ),
            "content-mismatched replay (row {row}, amount {amount}) must fail closed"
        );
    }
    Ok(())
}

#[test]
fn stored_form_must_be_canonical() -> Result<()> {
    // The read path (connector index, gate resolution, row matching) is
    // keyed on normalized channel strings, so validate rejects any record
    // whose STORED connector/channel_class is not already canonical — a
    // non-canonical stored key would exist but silently fail to govern.
    let non_canonical_connector =
        ConnectorKeyRecord::active(" Slack-Chat ", None, Vec::new(), 1_000);
    assert!(matches!(
        encode_connector_key_body(&non_canonical_connector),
        Err(Error::InvalidConnectorKeyBody(
            "connector must be stored normalized"
        ))
    ));

    let mut non_canonical_class = EffectorBudget::rate(5, 60);
    non_canonical_class.channel_class = Some("Slack-Chat".to_owned());
    let record = ConnectorKeyRecord::active("slack", None, vec![non_canonical_class], 1_000);
    assert!(matches!(
        encode_connector_key_body(&record),
        Err(Error::InvalidConnectorKeyBody(
            "channel_class must be stored normalized"
        ))
    ));

    // The Vault write door normalizes before validating, so messy owner
    // input still registers — stored canonical — and governs the normalized
    // effect (the AC15 gate test covers the governs half end-to-end).
    let (_tmp, vault) = temp_vault();
    let mut messy = ConnectorKeyRecord::active(" Slack-Chat ", None, Vec::new(), 1_000);
    messy.budgets = vec![EffectorBudget::rate(5, 60)];
    messy.budgets[0].channel_class = Some(" Slack-Chat ".to_owned());
    let registered = vault.register_connector_key(&test_id(0xE7), messy)?;
    assert_eq!(registered.connector, "slack_chat");
    assert_eq!(
        registered.budgets[0].channel_class.as_deref(),
        Some("slack_chat")
    );
    assert!(
        vault.connector_key_for("slack-chat", None)?.is_some(),
        "stored form == index form: the canonical lookup resolves the key"
    );
    Ok(())
}

// --- GOV-02 budget legibility + graceful wrap (ONE-1418) ---------------------

#[test]
fn effector_steering_templates_are_pinned_to_the_one_channel() {
    assert_eq!(
        EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE_ID,
        "effector_budget.plan.80"
    );
    assert_eq!(
        EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE_ID,
        "effector_budget.land.95"
    );
    assert!(effector_steering_signal(BudgetThreshold::Silent50).is_none());
    let plan = effector_steering_signal(BudgetThreshold::Plan80).expect("plan steering");
    assert_eq!(
        plan.channel,
        BudgetSignalDeliveryChannel::SteeringQueueNextTurn
    );
    assert_eq!(plan.template_id, EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE_ID);
    assert_eq!(plan.message, EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE);
    let land = effector_steering_signal(BudgetThreshold::Land95).expect("land steering");
    assert_eq!(
        land.channel,
        BudgetSignalDeliveryChannel::SteeringQueueNextTurn
    );
    assert_eq!(land.template_id, EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE_ID);
    assert_eq!(land.message, EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE);
}

#[test]
fn rolling_partial_expiry_rearms_only_unsatisfied_thresholds() {
    let window = EffectorBudgetWindow::Rolling { duration_s: 100 };
    let mut usage = ConnectorKeyUsage {
        window_start: 0,
        entries: vec![(50, 4), (150, 6)],
        fired: vec![
            "silent50".to_owned(),
            "plan80".to_owned(),
            "land95".to_owned(),
        ],
    };
    // now = 200: the (50, 4) entry is dead; used falls 10 -> 6 of limit 10
    // (100% -> 60%), re-arming Land95 + Plan80 but NOT Silent50 (M5a).
    usage.touch(&window, 10, 200);
    assert_eq!(usage.used(), 6);
    assert_eq!(usage.fired, vec!["silent50".to_owned()]);

    // Full expiry re-arms everything.
    usage.touch(&window, 10, 400);
    assert_eq!(usage.used(), 0);
    assert!(usage.fired.is_empty());
}

#[test]
fn rolling_full_expiry_lets_the_ladder_refire_on_the_next_charge() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let key_id = test_id(0xE5);
    let mut record = vault.register_connector_key(
        &key_id,
        ConnectorKeyRecord::active("line", None, vec![EffectorBudget::rate(2, 60)], 1_000),
    )?;

    // Seed an exhausted usage row whose entries have expired by `now`
    // (sleep-free liveness expiry).
    let seeded = ConnectorKeyUsage {
        window_start: 0,
        entries: vec![(1_000, 2)],
        fired: vec![
            "silent50".to_owned(),
            "plan80".to_owned(),
            "land95".to_owned(),
        ],
    };
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(
            wtxn,
            &connector_key_usage_row_key(&key_id, 0),
            &seeded.encode()?,
        )?;
        Ok(())
    })?;

    // The next charge sees a fresh window and the ladder re-fires from the
    // bottom: 1 of 2 = 50% -> Silent50 again.
    let outcome = vault.with_write_txn(|wtxn| {
        charge_effector_budgets(
            &vault.store,
            wtxn,
            &key_id,
            &mut record,
            "line",
            false,
            2_000,
        )
    })?;
    let EffectorBudgetChargeOutcome::Charged(charge) = outcome else {
        panic!("expected a charged outcome");
    };
    let fired: Vec<_> = charge
        .ladder_events
        .iter()
        .map(|event| event.threshold)
        .collect();
    assert_eq!(fired, vec![BudgetThreshold::Silent50]);
    assert_eq!(
        charge.read.rows[0].fired_thresholds,
        vec![BudgetThreshold::Silent50]
    );
    assert_eq!(charge.matched_rows, vec![0]);
    Ok(())
}

#[test]
fn effector_budget_read_resolves_actor_and_reflects_suspension() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0xB2);
    let bound_id = test_id(0xB3);
    let wide_id = test_id(0xB4);
    vault.register_connector_key(
        &bound_id,
        ConnectorKeyRecord::active(
            "line",
            Some(actor),
            vec![EffectorBudget::rate(5, 60)],
            1_000,
        ),
    )?;
    vault.register_connector_key(
        &wide_id,
        ConnectorKeyRecord::active("line", None, vec![EffectorBudget::rate(9, 60)], 1_001),
    )?;

    // Exact-actor key wins over the connector-wide key.
    let read = vault
        .effector_budget_read("line", Some(&actor))?
        .expect("exact-actor key");
    assert_eq!(read.key_ref, bound_id);
    assert_eq!(read.rows.len(), 1);
    assert_eq!(read.rows[0].limit, 5);
    assert_eq!(read.rows[0].used, 0);
    assert_eq!(read.rows[0].remaining, 5);

    let read = vault
        .effector_budget_read("line", None)?
        .expect("connector-wide key");
    assert_eq!(read.key_ref, wide_id);

    // Unknown connector: no meter.
    assert!(vault.effector_budget_read("unknown", None)?.is_none());

    // The read reflects suspension status.
    vault.suspend_connector_key(&bound_id, "owner", 1_010)?;
    let read = vault
        .effector_budget_read("line", Some(&actor))?
        .expect("suspended key still reads");
    assert_eq!(read.status, ConnectorKeyStatus::Suspended);
    Ok(())
}

// --- GOV-10 charter -> compiled policy (ONE-1417) -----------------------------

const CHARTER_FIXTURE_LF: &str = "\
# Herald charter
never delete on slack

never call
cap 5 sends per day on slack
cap 3 sends per 3600s on line
cap spend 100 USD per month on slack
cap spend 5000 JPY per day on line
rate 10 per 60s on email
";

#[test]
fn charter_compile_is_deterministic_and_normalizes_crlf() {
    let crlf = CHARTER_FIXTURE_LF.replace('\n', "\r\n");
    let first = compile_connector_charter(&crlf).expect("compiles");
    let second = compile_connector_charter(&crlf).expect("compiles");
    assert_eq!(first, second);
    assert_eq!(first.text_hash, second.text_hash);
    assert_eq!(first.compiled_hash, second.compiled_hash);

    // CRLF normalization: the LF variant hashes identically.
    let lf = compile_connector_charter(CHARTER_FIXTURE_LF).expect("compiles");
    assert_eq!(lf.text_hash, first.text_hash);
    assert_eq!(lf.compiled_hash, first.compiled_hash);
    assert_eq!(lf.compiled, first.compiled);

    // never_list is sorted + deduped; caps keep charter order.
    assert_eq!(
        first.compiled.never_list,
        vec!["*:call".to_owned(), "slack:delete".to_owned()]
    );
    assert_eq!(first.compiled.channel_caps.len(), 5);
    let caps = &first.compiled.channel_caps;
    assert_eq!(caps[0].dimension, EffectorBudgetDimension::Sends);
    assert_eq!(caps[0].channel_class.as_deref(), Some("slack"));
    assert_eq!(caps[0].limit, 5);
    assert_eq!(
        caps[0].window,
        EffectorBudgetWindow::Calendar {
            period: CalendarPeriod::Day,
            tz: None,
        }
    );
    assert_eq!(caps[0].on_exhaust, EffectorBudgetOnExhaust::Suspend);
    assert_eq!(
        caps[1].window,
        EffectorBudgetWindow::Rolling { duration_s: 3_600 }
    );
    // ISO-4217 major -> minor via the pinned exponent table: USD exponent 2.
    assert_eq!(caps[2].dimension, EffectorBudgetDimension::Spend);
    assert_eq!(caps[2].limit, 10_000);
    assert_eq!(caps[2].unit.as_deref(), Some("USD"));
    // JPY is on the explicit exponent-0 list.
    assert_eq!(caps[3].limit, 5_000);
    assert_eq!(caps[3].unit.as_deref(), Some("JPY"));
    assert_eq!(caps[4].dimension, EffectorBudgetDimension::Rate);
    assert_eq!(caps[4].on_exhaust, EffectorBudgetOnExhaust::Refuse);
    assert_eq!(
        caps[4].window,
        EffectorBudgetWindow::Rolling { duration_s: 60 }
    );

    // Keyword case variants compile to the SAME struct and compiled_hash
    // (text_hash may differ — the stamp binds both).
    let shouty = "\
# Herald charter
NEVER delete ON slack

Never call
Cap 5 SENDS Per Day On slack
CAP 3 sends per 3600s on line
cap SPEND 100 USD PER month on slack
cap spend 5000 JPY per DAY on line
RATE 10 per 60s ON email
";
    let shouty = compile_connector_charter(shouty).expect("compiles");
    assert_eq!(shouty.compiled, first.compiled);
    assert_eq!(shouty.compiled_hash, first.compiled_hash);
    assert_ne!(shouty.text_hash, first.text_hash);
}

#[test]
fn charter_compile_fails_closed_with_line_numbers() {
    let unrecognized = "never delete on slack\n\nnever\n";
    let issue = compile_connector_charter(unrecognized).expect_err("fail closed");
    assert_eq!(issue.line_number, 3);
    assert_eq!(issue.message, "unrecognized charter directive");

    let zero_limit = "cap 0 sends per day on slack";
    let issue = compile_connector_charter(zero_limit).expect_err("fail closed");
    assert_eq!(issue.line_number, 1);
    assert_eq!(issue.message, "invalid sends cap limit");

    let lowercase_currency = "# ok\ncap spend 5 usd per day on slack";
    let issue = compile_connector_charter(lowercase_currency).expect_err("fail closed");
    assert_eq!(issue.line_number, 2);
    assert_eq!(issue.message, "spend unit currency code must be uppercase");

    let zero_window = "rate 5 per 0s on slack";
    let issue = compile_connector_charter(zero_window).expect_err("fail closed");
    assert_eq!(issue.line_number, 1);
    assert_eq!(issue.message, "invalid window duration");

    // Provider-unit spend caps pass through opaque (M8).
    let provider = compile_connector_charter("cap spend 500 credits per day on slack")
        .expect("provider units compile");
    assert_eq!(provider.compiled.channel_caps[0].limit, 500);
    assert_eq!(
        provider.compiled.channel_caps[0].unit.as_deref(),
        Some("credits")
    );
}

#[test]
fn charter_never_list_matching_forms() {
    let block = |entries: &[&str]| ConnectorCharterBlock {
        text: "fixture".to_owned(),
        text_hash: [0; 32],
        compiled: CompiledConnectorPolicy {
            never_list: entries.iter().map(|entry| (*entry).to_owned()).collect(),
            channel_caps: Vec::new(),
        },
        compiled_hash: [0; 32],
        stamped_aggregate: [0; 32],
        stamped_by: "owner".to_owned(),
        stamped_at: 1,
    };
    // "*:{verb}" matches the verb on any channel.
    let any_channel = block(&["*:delete"]);
    assert!(charter_never_list_matches(&any_channel, "slack", "delete"));
    assert!(charter_never_list_matches(&any_channel, "line", " Delete "));
    assert!(!charter_never_list_matches(&any_channel, "slack", "send"));
    // "{channel}:*" matches every verb on the channel.
    let any_verb = block(&["slack:*"]);
    assert!(charter_never_list_matches(&any_verb, "slack", "send"));
    assert!(!charter_never_list_matches(&any_verb, "line", "send"));
    // Exact pair.
    let exact = block(&["slack:call"]);
    assert!(charter_never_list_matches(&exact, "slack", "call"));
    assert!(!charter_never_list_matches(&exact, "slack", "send"));
    assert!(!charter_never_list_matches(&exact, "line", "call"));

    // Ordinary connector keys are stored normalized, while the compiler keeps
    // the author's raw channel operand for hashing and auditability.
    let mixed_spelling = never_list_block(&["slack_chat:send"]);
    assert!(charter_never_list_matches(
        &mixed_spelling,
        "slack_chat",
        "send"
    ));
    assert!(!charter_never_list_matches(
        &mixed_spelling,
        "slack_chat_extra",
        "send"
    ));

    // Typed scoped-MCP calls use the raw ordinary channel, not ordinary
    // connector normalization: hyphen and underscore are distinct identities.
    let hyphen = never_list_block(&["scoped-channel:mcp:foo-bar:*"]);
    assert!(charter_never_list_matches_scoped_channel(
        &hyphen,
        "mcp:foo-bar",
        "send"
    ));
    assert!(!charter_never_list_matches_scoped_channel(
        &hyphen,
        "mcp:foo_bar",
        "send"
    ));
    let underscore = never_list_block(&["scoped-channel:mcp:foo_bar:*"]);
    assert!(charter_never_list_matches_scoped_channel(
        &underscore,
        "mcp:foo_bar",
        "send"
    ));
    assert!(!charter_never_list_matches_scoped_channel(
        &underscore,
        "mcp:foo-bar",
        "send"
    ));

    // A typed call must NOT read the normalized ordinary entry for a named
    // channel: that entry aliases `foo-bar` onto `foo_bar`, so reading it would
    // let one server's rule bind another server's calls.
    let normalized_ordinary = never_list_block(&["mcp:foo_bar:send"]);
    for channel in ["mcp:foo_bar", "mcp:foo-bar"] {
        assert!(
            !charter_never_list_matches_scoped_channel(&normalized_ordinary, channel, "send"),
            "normalized ordinary entry must not reach typed {channel}"
        );
    }
    // The whole-fleet wildcard names no channel spelling at all, so it cannot
    // alias anything and keeps binding every dispatch, typed included. The
    // tagged form may never carry a wildcard channel, so this is the ONLY way
    // `never <verb>` reaches a scoped call.
    let fleet_wide = never_list_block(&["*:send"]);
    for channel in ["mcp:foo-bar", "mcp:foo_bar"] {
        assert!(charter_never_list_matches_scoped_channel(
            &fleet_wide,
            channel,
            "send"
        ));
        assert!(!charter_never_list_matches_scoped_channel(
            &fleet_wide,
            channel,
            "read_file"
        ));
    }
    // A capability-only rule stays a different mode on this axis too.
    let capability_rule =
        never_list_block(&["capability-key:mcp:foo-bar:grant:ab12cd34ab12cd34ab12cd34ab12cd34"]);
    assert!(!charter_never_list_matches_scoped_channel(
        &capability_rule,
        "mcp:foo-bar",
        "send"
    ));
}

#[test]
fn charter_propose_approve_discard_lifecycle() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xC5);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("slack", None, Vec::new(), 1_000),
    )?;

    // Approve/discard without a staged proposal fail closed.
    assert!(matches!(
        vault.approve_connector_charter(&id, [0; 32], "owner", 1_001),
        Err(Error::ConnectorCharterMissing)
    ));
    assert!(matches!(
        vault.discard_connector_charter(&id, 1_001),
        Err(Error::ConnectorCharterMissing)
    ));

    // Propose stages the compile and NEVER changes enforcement state.
    let pending = vault.propose_connector_charter(&id, "never delete on slack", 1_002)?;
    let record = vault.get_connector_key(&id)?.expect("record");
    assert!(record.charter.is_none());
    assert_eq!(record.pending_charter.as_ref(), Some(&pending));

    // A malformed charter is rejected fail-closed and does not clobber the
    // staged proposal.
    assert!(matches!(
        vault.propose_connector_charter(&id, "cap 0 sends per day on slack", 1_003),
        Err(Error::ConnectorCharterCompile { line_number: 1, .. })
    ));
    assert_eq!(
        vault
            .get_connector_key(&id)?
            .expect("record")
            .pending_charter
            .as_ref(),
        Some(&pending)
    );

    // The human gate demands the out-of-band re-presented hash.
    assert!(matches!(
        vault.approve_connector_charter(&id, [0xAB; 32], "owner", 1_004),
        Err(Error::ConnectorCharterApprovalMismatch)
    ));
    assert!(matches!(
        vault.approve_connector_charter(&id, pending.compiled_hash, "  ", 1_004),
        Err(Error::InvalidConnectorKeyBody(
            "stamped_by must not be blank"
        ))
    ));
    let stamped =
        vault.approve_connector_charter(&id, pending.compiled_hash, "owner:olety", 1_005)?;
    let block = stamped.charter.as_ref().expect("stamped charter");
    assert!(stamped.pending_charter.is_none());
    assert_eq!(block.stamped_by, "owner:olety");
    assert_eq!(block.stamped_at, 1_005);
    assert_eq!(
        block.stamped_aggregate,
        charter_stamped_aggregate(&block.text_hash, &block.compiled_hash)
    );
    assert!(!charter_block_drifted(block)?);

    // Discard clears a re-staged proposal without touching the stamped block.
    vault.propose_connector_charter(&id, "never call", 1_006)?;
    let discarded = vault.discard_connector_charter(&id, 1_007)?;
    assert!(discarded.pending_charter.is_none());
    assert_eq!(discarded.charter, stamped.charter);

    // Every charter op is receipted with the ckey grant ref.
    let receipts = vault.receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Gate))?;
    let grant_ref = format!("ckey:{}", id.to_hex());
    for op in [
        "gate.connector_key.charter_propose",
        "gate.connector_key.charter_approve",
        "gate.connector_key.charter_discard",
    ] {
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.policy_trace.iter().any(|reason| reason == op))
            .unwrap_or_else(|| panic!("missing {op} receipt"));
        assert_eq!(
            receipt.fields.get("grant_ref").map(String::as_str),
            Some(grant_ref.as_str())
        );
    }

    // Charter ops on a revoked key fail closed.
    vault.revoke_connector_key(&id, 1_010)?;
    assert!(matches!(
        vault.propose_connector_charter(&id, "never call", 1_011),
        Err(Error::InvalidConnectorKeyBody("charter op on revoked key"))
    ));
    Ok(())
}

#[test]
fn cap_and_rate_reject_wildcard_channel_but_never_keeps_it() {
    // (a) The gate matches a cap row's `channel_class` by EXACT equality, so a
    // stored `"*"` never matches a real channel (slack/email) and would debit 0
    // forever. Every cap/rate arm must fail closed on the wildcard with a
    // line-numbered compile error.
    for line in [
        "cap 10 sends per day on *",
        "cap spend 100 USD per month on *",
        "rate 10 per 60s on *",
    ] {
        let issue = compile_connector_charter(line).expect_err("wildcard cap fails closed");
        assert_eq!(issue.line_number, 1, "{line}");
        assert_eq!(
            issue.message, "cap channel must not be the wildcard '*'",
            "{line}"
        );
    }

    // (b) `never <verb> on *` STILL compiles — "*" is a legitimate wildcard on
    // the never arm — and matches every real channel.
    let never_wild = compile_connector_charter("never send on *").expect("never wildcard compiles");
    assert_eq!(never_wild.compiled.never_list, vec!["*:send".to_owned()]);
    let block = ConnectorCharterBlock {
        text: "never send on *".to_owned(),
        text_hash: [0; 32],
        compiled: never_wild.compiled,
        compiled_hash: [0; 32],
        stamped_aggregate: [0; 32],
        stamped_by: "owner".to_owned(),
        stamped_at: 1,
    };
    assert!(charter_never_list_matches(&block, "slack", "send"));
    assert!(charter_never_list_matches(&block, "email", "send"));

    // (c) A real-channel cap still compiles and narrows to that channel.
    let real =
        compile_connector_charter("cap 10 sends per day on slack").expect("real channel compiles");
    assert_eq!(
        real.compiled.channel_caps[0].channel_class.as_deref(),
        Some("slack")
    );
}

#[test]
fn revoked_key_charter_ops_fail_closed_and_revoke_clears_pending() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xCA);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("slack", None, Vec::new(), 1_000),
    )?;
    let pending = vault.propose_connector_charter(&id, "never delete on slack", 1_001)?;

    // Revoke drops any staged pending_charter — a revoked key carries no
    // mutable charter state.
    let revoked = vault.revoke_connector_key(&id, 1_002)?;
    assert_eq!(revoked.status, ConnectorKeyStatus::Revoked);
    assert!(revoked.pending_charter.is_none());
    assert!(
        vault
            .get_connector_key(&id)?
            .expect("record")
            .pending_charter
            .is_none()
    );

    // Approve on a revoked key now errors (propose -> revoke -> approve).
    assert!(matches!(
        vault.approve_connector_charter(&id, pending.compiled_hash, "owner", 1_003),
        Err(Error::InvalidConnectorKeyBody("charter op on revoked key"))
    ));
    // Discard on a revoked key errors too.
    assert!(matches!(
        vault.discard_connector_charter(&id, 1_004),
        Err(Error::InvalidConnectorKeyBody("charter op on revoked key"))
    ));
    Ok(())
}

#[test]
fn malformed_never_list_entry_fails_closed_at_validation() {
    let charter = |never: Vec<String>| ConnectorKeyRecord {
        charter: Some(ConnectorCharterBlock {
            text: "fixture".to_owned(),
            text_hash: [0; 32],
            compiled: CompiledConnectorPolicy {
                never_list: never,
                channel_caps: Vec::new(),
            },
            compiled_hash: [0; 32],
            stamped_aggregate: [0; 32],
            stamped_by: "owner".to_owned(),
            stamped_at: 1,
        }),
        ..ConnectorKeyRecord::active("slack", None, Vec::new(), 1_000)
    };

    // No ':' — `charter_never_list_matches` silently skips it, so a stored
    // entry lacking a separator would fail OPEN (deny nothing).
    assert!(matches!(
        encode_connector_key_body(&charter(vec!["delete".to_owned()])),
        Err(Error::InvalidConnectorKeyBody(
            "never_list entry must be channel:verb"
        ))
    ));
    // Colons inside an ordinary channel are DATA: the verb is the LAST segment,
    // so this stored entry prohibits `x` on the whole `slack:call` connector.
    assert!(encode_connector_key_body(&charter(vec!["slack:call:x".to_owned()])).is_ok());
    // A capability rule must name one identity the engine can mint; a partial
    // wildcard fails closed instead of denying nothing.
    assert!(matches!(
        encode_connector_key_body(&charter(vec!["capability-key:mcp:acme:grant:*".to_owned()])),
        Err(Error::InvalidConnectorKeyBody(
            "never_list capability key invalid"
        ))
    ));
    // Same on the channel side of an ordinary rule.
    assert!(matches!(
        encode_connector_key_body(&charter(vec!["mcp*:acme:grant:ab12".to_owned()])),
        Err(Error::InvalidConnectorKeyBody(
            "never_list entry channel invalid"
        ))
    ));
    // Empty channel part.
    assert!(matches!(
        encode_connector_key_body(&charter(vec![":delete".to_owned()])),
        Err(Error::InvalidConnectorKeyBody(
            "never_list entry channel invalid"
        ))
    ));
    // Verb part carries a byte outside `[a-z0-9_]`.
    assert!(matches!(
        encode_connector_key_body(&charter(vec!["slack:call!".to_owned()])),
        Err(Error::InvalidConnectorKeyBody(
            "never_list entry verb invalid"
        ))
    ));
    // Well-formed entries (both wildcards) still validate.
    assert!(
        encode_connector_key_body(&charter(vec!["*:delete".to_owned(), "slack:*".to_owned()]))
            .is_ok()
    );
}

#[test]
fn never_list_entry_must_be_canonical_form() {
    let policy = |entry: &str| CompiledConnectorPolicy {
        never_list: vec![entry.to_owned()],
        channel_caps: Vec::new(),
    };

    // A merely well-SHAPED but non-canonical entry passes a shape-only check
    // yet at enforcement `charter_never_list_matches` compares the STORED
    // channel/verb by EXACT string against the effect's normalized channel and
    // lowercased verb — a non-canonical stored part never equals it, so the
    // prohibition fails OPEN. Every such entry MUST fail closed at validation.
    for entry in [
        "Slack:send",  // mixed-case channel
        "slack:SEND",  // mixed-case verb (parses to "send", but non-canonical)
        "SLACK:SEND",  // both non-canonical
        " slack:send", // leading-whitespace channel
        "slack :send", // trailing-whitespace channel
        "slack:send ", // trailing-whitespace verb
        // A colon-bearing ordinary channel carries the same canonicality duty:
        // enforcement compares the stored channel by exact string.
        "mcp:Acme:grant:ab12",
        "mcp:acme:grant:ab12 ",
        "mcp:my-server:grant:x",
        "Mcp:acme:grant:ab12",
    ] {
        assert!(
            matches!(
                validate_compiled_policy(&policy(entry)),
                Err(Error::InvalidConnectorKeyBody(_))
            ),
            "non-canonical never_list entry {entry:?} must fail closed"
        );
    }

    // The canonical forms the compiler emits still validate: the ordinary pair,
    // both wildcards, a colon-bearing ordinary channel, and one exact tagged
    // capability rule (ONE-1885).
    let capability_entry = format!(
        "capability-key:{}",
        ScopedCapabilityProvenance::mint("acme", &test_id(0xB4))
            .expect("safe canonical server")
            .connector()
    );
    for entry in [
        "slack:send",
        "*:send",
        "slack:*",
        "*:*",
        "mcp:acme:grant:ab12cd34",
        "mcp:*",
        "mcp:my_server:grant:x",
        "scoped-channel:mcp:my-server:*",
        capability_entry.as_str(),
    ] {
        assert!(
            validate_compiled_policy(&policy(entry)).is_ok(),
            "canonical never_list entry {entry:?} must validate"
        );
    }

    // An ordinary rule's verb is its LAST segment and its channel is everything
    // before it: a missing separator, an empty part, or a partial wildcard may
    // never reach a stored policy. A tagged rule must be one real capability
    // identity — nothing wildcard, truncated, or unsafe.
    for entry in [
        "send",
        ":send",
        "slack:",
        "",
        "mcp*:acme:grant:ab12",
        "mcp:acme*",
        "capability-key:mcp:acme:grant:*",
        "capability-key:mcp:acme:grant",
        "capability-key:mcp:*:grant:ab12cd34ab12cd34ab12cd34ab12cd34",
        "capability-key:mcp:acme:grant:ab12",
        "capability-key:",
        "scoped-channel:",
        "scoped-channel:mcp:Acme:*",
        "scoped-channel:mcp:acme:extra:*",
        "scoped-channel:mcp:acme*:send",
    ] {
        assert!(
            matches!(
                validate_compiled_policy(&policy(entry)),
                Err(Error::InvalidConnectorKeyBody(_))
            ),
            "malformed never_list entry {entry:?} must fail closed"
        );
    }
}

#[test]
fn crlf_imported_charter_block_does_not_false_drift() -> Result<()> {
    // The compiler stamps over the CRLF-normalized (LF) text. An imported block
    // that carries raw CRLF in `text` but whose stamp was computed over the LF
    // form must NOT read as drifted (which would degrade it to proposed-only).
    let crlf_text = "never delete on slack\r\nnever call\r\n";
    let compiled = compile_connector_charter(crlf_text).expect("compiles");
    let text_hash = compiled.text_hash;
    let compiled_hash = compiled.compiled_hash;
    let stamped_aggregate = charter_stamped_aggregate(&text_hash, &compiled_hash);
    let block = ConnectorCharterBlock {
        text: crlf_text.to_owned(),
        text_hash,
        compiled: compiled.compiled,
        compiled_hash,
        stamped_aggregate,
        stamped_by: "owner".to_owned(),
        stamped_at: 1,
    };
    assert!(
        !charter_block_drifted(&block)?,
        "CRLF block stamped over LF must not false-drift"
    );

    // Sanity: genuine text tampering with a stale stamp still drifts.
    let mut tampered = block;
    tampered.text = "never delete on slack\r\nnever send\r\n".to_owned();
    assert!(
        charter_block_drifted(&tampered)?,
        "mutated text must still drift"
    );
    Ok(())
}

// --- ONE-1885 first-colon never-list grammar ----------------------------------

/// Golden compiled-policy hash for a two-part-only never-list. Extending the
/// grammar to first-colon capability keys must NOT version the compiled domain,
/// the codec key order, the sort/dedup, or the stamp aggregate: a landed charter
/// keeps byte-identical stored policy, so a stamped block cannot silently drift
/// into proposed-only after an engine upgrade.
const LEGACY_TWO_PART_NEVER_HASH_V1: [u8; 32] = [
    0x80, 0xEB, 0xBA, 0xEC, 0x8C, 0xAC, 0xA5, 0xEE, 0xF5, 0x49, 0xC8, 0x85, 0x94, 0x32, 0xD6, 0xE6,
    0x01, 0x76, 0xA9, 0xAE, 0x5A, 0x52, 0xDF, 0x3B, 0xF3, 0xEF, 0x31, 0x99, 0x9D, 0x85, 0x07, 0x6A,
];

fn never_list_block(entries: &[&str]) -> ConnectorCharterBlock {
    ConnectorCharterBlock {
        text: "fixture".to_owned(),
        text_hash: [0; 32],
        compiled: CompiledConnectorPolicy {
            never_list: entries.iter().map(|entry| (*entry).to_owned()).collect(),
            channel_caps: Vec::new(),
        },
        compiled_hash: [0; 32],
        stamped_aggregate: [0; 32],
        stamped_by: "owner".to_owned(),
        stamped_at: 1,
    }
}

#[test]
fn legacy_two_part_never_hash_is_frozen() {
    let compiled =
        compile_connector_charter("never call\nnever delete on slack\nnever send on slack\n")
            .expect("legacy charter compiles");
    assert_eq!(
        compiled.compiled.never_list,
        vec![
            "*:call".to_owned(),
            "slack:delete".to_owned(),
            "slack:send".to_owned(),
        ]
    );
    assert!(compiled.compiled.channel_caps.is_empty());
    assert_eq!(
        compiled.compiled_hash, LEGACY_TWO_PART_NEVER_HASH_V1,
        "the two-part compiled policy hash is frozen"
    );
}

#[test]
fn scoped_capability_identity_requires_one_safe_server() {
    let grant_id = test_id(0xAB);
    let hex = grant_id.to_hex();

    let minted = ScopedCapabilityProvenance::mint("files", &grant_id).expect("safe server");
    assert_eq!(minted.server(), "files");
    assert_eq!(minted.connector(), format!("mcp:files:grant:{hex}"));
    assert_eq!(minted.grant_id(), grant_id);
    assert_eq!(minted.ordinary_channel(), "mcp:files");

    // Hyphen and underscore are both canonical identity bytes. Neither the
    // producer nor connector-key canonicalization may alias one to the other.
    let hyphen = ScopedCapabilityProvenance::mint("my-server", &grant_id)
        .expect("canonical hyphenated server");
    let underscore = ScopedCapabilityProvenance::mint("my_server", &grant_id)
        .expect("canonical underscored server");
    assert_eq!(hyphen.server(), "my-server");
    assert_eq!(hyphen.connector(), format!("mcp:my-server:grant:{hex}"));
    assert_eq!(hyphen.ordinary_channel(), "mcp:my-server");
    assert_eq!(underscore.server(), "my_server");
    assert_eq!(underscore.connector(), format!("mcp:my_server:grant:{hex}"));
    assert_ne!(hyphen, underscore);
    assert_eq!(
        normalize_connector_key(hyphen.connector()),
        hyphen.connector()
    );
    assert_eq!(
        normalize_connector_key(underscore.connector()),
        underscore.connector()
    );
    let (_tmp, vault) = temp_vault();
    let hyphen_key_id = test_id(0xAD);
    let underscore_key_id = test_id(0xAE);
    vault
        .register_connector_key(
            &hyphen_key_id,
            ConnectorKeyRecord::active(hyphen.connector(), None, Vec::new(), 10),
        )
        .expect("register hyphenated capability connector");
    vault
        .register_connector_key(
            &underscore_key_id,
            ConnectorKeyRecord::active(underscore.connector(), None, Vec::new(), 10),
        )
        .expect("register underscored capability connector");
    assert_eq!(
        vault
            .connector_key_for(hyphen.connector(), None)
            .expect("lookup hyphenated connector")
            .expect("hyphenated connector key")
            .0,
        hyphen_key_id
    );
    assert_eq!(
        vault
            .connector_key_for(underscore.connector(), None)
            .expect("lookup underscored connector")
            .expect("underscored connector key")
            .0,
        underscore_key_id
    );

    // Non-canonical and unsafe segments mint NOTHING. Admission never trims or
    // case-folds a server identifier into another authority.
    for unsafe_server in [
        "My-Server",
        "MY_SERVER",
        "FILES",
        "acme:extra",
        "acme:grant:ff",
        ":",
        " acme",
        "acme ",
        "ac me",
        "ac\tme",
        "ac\u{00a0}me",
        "\u{3000}acme",
        "*",
        "ac*",
        "*me",
        "acme?",
        "acme[1]",
        "",
        "   ",
        "acme/../etc",
        "acme\u{0000}",
    ] {
        assert!(
            ScopedCapabilityProvenance::mint(unsafe_server, &grant_id).is_none(),
            "unsafe scoped server {unsafe_server:?} must not mint a capability key"
        );
        assert!(
            canonical_scoped_server_segment(unsafe_server).is_none(),
            "unsafe scoped server {unsafe_server:?} must fail the shared rule"
        );
    }

    // Persisted parts are re-derived, never trusted, and retain the exact
    // admitted server punctuation through the round trip.
    assert_eq!(
        ScopedCapabilityProvenance::from_persisted_parts(
            &grant_id,
            "my-server",
            &format!("mcp:my-server:grant:{hex}")
        )
        .expect("consistent hyphenated parts"),
        hyphen
    );
    for (server, connector) in [
        ("My-Server", format!("mcp:my-server:grant:{hex}")),
        ("my-server", format!("mcp:my_server:grant:{hex}")),
        ("files", format!("mcp:other:grant:{hex}")),
        (
            "files",
            format!("mcp:files:grant:{}", test_id(0xAC).to_hex()),
        ),
        ("files", "mcp:files:grant:ab12".to_owned()),
        ("files:x", format!("mcp:files:x:grant:{hex}")),
    ] {
        assert!(
            ScopedCapabilityProvenance::from_persisted_parts(&grant_id, server, &connector)
                .is_none(),
            "inconsistent persisted provenance {server:?}/{connector} must fail closed"
        );
    }
}

#[test]
fn charter_compiles_the_never_key_capability_form() {
    let grant_id = test_id(0xC1);
    let hex = grant_id.to_hex();
    let key = format!("mcp:acme:grant:{hex}");

    // The operand names one identity the engine can actually produce, and it
    // compiles into the capability-only rule the typed matcher reads.
    let compiled =
        compile_connector_charter(&format!("never key {key}")).expect("capability form compiles");
    assert_eq!(
        compiled.compiled.never_list,
        vec![format!("capability-key:{key}")]
    );
    // Canonical hyphen and underscore server identities retain their exact
    // bytes and compile to distinct per-grant prohibitions.
    let hyphen = compile_connector_charter(&format!("never key mcp:my-server:grant:{hex}"))
        .expect("canonical hyphenated key compiles");
    let underscore = compile_connector_charter(&format!("never key mcp:my_server:grant:{hex}"))
        .expect("canonical underscored key compiles");
    assert_eq!(
        hyphen.compiled.never_list,
        vec![format!("capability-key:mcp:my-server:grant:{hex}")]
    );
    assert_eq!(
        underscore.compiled.never_list,
        vec![format!("capability-key:mcp:my_server:grant:{hex}")]
    );
    assert_ne!(hyphen.compiled, underscore.compiled);
    assert_eq!(
        hyphen.compiled.never_list[0],
        format!(
            "capability-key:{}",
            ScopedCapabilityProvenance::mint("my-server", &grant_id)
                .expect("safe server")
                .connector()
        ),
        "compiler and producer preserve the same exact identity bytes"
    );

    // Bare `never key` reads as the capability form with its operand missing.
    let issue = compile_connector_charter("never key").expect_err("bare never key fails closed");
    assert_eq!(issue.line_number, 1);
    assert_eq!(
        issue.message,
        "never key requires an mcp:<server>:grant:<id> capability key"
    );

    // Every operand that is not one canonical, safe, real capability identity
    // fails closed AT COMPILE with its line number: mixed-case aliases, partial
    // wildcards, unsafe servers (colon-forged, whitespace, glob), truncated or
    // over-long keys, and a grant id that is not a real id.
    // (Whitespace never reaches this seam: the directive is tokenized on
    // whitespace, so an unsafe spelling like `mcp:ac me:grant:<id>` is not even
    // a directive. The shared segment rule rejects it at every other seam.)
    for operand in [
        format!("MCP:acme:grant:{hex}"),
        format!("mcp:Acme:grant:{hex}"),
        format!("mcp:acme:Grant:{hex}"),
        format!("mcp:acme:grant:{}", hex.to_uppercase()),
        "mcp:acme:grant:*".to_owned(),
        format!("mcp:acme*:grant:{hex}"),
        format!("mcp:*:grant:{hex}"),
        format!("mcp::grant:{hex}"),
        format!("mcp:acme:grant:{hex}:extra"),
        format!("slack:acme:grant:{hex}"),
        format!("mcp:acme:key:{hex}"),
        "mcp:acme:grant:ab12".to_owned(),
        "mcp:acme".to_owned(),
        "mcp".to_owned(),
        "mcp:calendar:grant:foo".to_owned(),
    ] {
        let line = format!("# ok\nnever key {operand}");
        let issue = compile_connector_charter(&line).expect_err("fails closed");
        assert_eq!(issue.line_number, 2, "{operand}");
        assert_eq!(
            issue.message,
            "never key must name one canonical mcp:<server>:grant:<id> capability key",
            "{operand}"
        );
    }
    // `never key x y` is not a directive at all.
    assert_eq!(
        compile_connector_charter("never key mcp:acme grant")
            .expect_err("fails closed")
            .message,
        "unrecognized charter directive"
    );
}

#[test]
fn charter_compiles_ordinary_colon_bearing_channels() {
    // An ordinary connector's colons are DATA: the compiled entry's verb is its
    // last segment, so the whole `mcp:calendar` string is the channel.
    let compiled =
        compile_connector_charter("never send on mcp:calendar").expect("ordinary form compiles");
    assert_eq!(
        compiled.compiled.never_list,
        vec![
            "mcp:calendar:send".to_owned(),
            "scoped-channel:mcp:calendar:send".to_owned(),
        ]
    );
    let deeper = compile_connector_charter("never send on mcp:calendar:grant:foo")
        .expect("deeper ordinary connector compiles");
    assert_eq!(
        deeper.compiled.never_list,
        vec!["mcp:calendar:grant:foo:send".to_owned()]
    );
    let mixed_spelling = compile_connector_charter("never send on Slack-Chat")
        .expect("ordinary mixed spelling compiles");
    assert_eq!(
        mixed_spelling.compiled.never_list,
        vec!["slack_chat:send".to_owned()]
    );
    // Cap/rate channels are matched WHOLE and keep their colon-bearing form.
    let cap =
        compile_connector_charter("cap 10 sends per day on mcp:calendar").expect("cap compiles");
    assert_eq!(
        cap.compiled.channel_caps[0].channel_class.as_deref(),
        Some("mcp:calendar")
    );
}

#[test]
fn charter_scoped_channel_dual_entries_are_codec_and_hash_stable() -> Result<()> {
    let hyphen = compile_connector_charter("never send on mcp:foo-bar")
        .expect("hyphenated scoped channel compiles");
    let underscore = compile_connector_charter("never send on mcp:foo_bar")
        .expect("underscored scoped channel compiles");
    assert_eq!(
        hyphen.compiled.never_list,
        vec![
            "mcp:foo_bar:send".to_owned(),
            "scoped-channel:mcp:foo-bar:send".to_owned(),
        ]
    );
    assert_eq!(
        underscore.compiled.never_list,
        vec![
            "mcp:foo_bar:send".to_owned(),
            "scoped-channel:mcp:foo_bar:send".to_owned(),
        ]
    );
    assert_ne!(
        hyphen.compiled_hash, underscore.compiled_hash,
        "exact scoped spelling must affect the compiled policy hash"
    );
    assert_eq!(
        hyphen.compiled_hash,
        compile_connector_charter("never send on mcp:foo-bar")
            .expect("deterministic compile")
            .compiled_hash
    );

    let record = ConnectorKeyRecord {
        charter: Some(ConnectorCharterBlock {
            text: "never send on mcp:foo-bar".to_owned(),
            text_hash: hyphen.text_hash,
            compiled: hyphen.compiled.clone(),
            compiled_hash: hyphen.compiled_hash,
            stamped_aggregate: [0x33; 32],
            stamped_by: "owner".to_owned(),
            stamped_at: 1_000,
        }),
        ..ConnectorKeyRecord::active("mcp:foo_bar", None, Vec::new(), 1_000)
    };
    let encoded = encode_connector_key_body(&record)?;
    assert_eq!(decode_connector_key_body(&encoded)?, record);
    Ok(())
}

#[test]
fn charter_never_list_modes_are_distinct() {
    let grant_id = test_id(0xC2);
    let neighbour_id = test_id(0xC3);
    let capability =
        ScopedCapabilityProvenance::mint("acme", &grant_id).expect("safe canonical server");
    let neighbour =
        ScopedCapabilityProvenance::mint("acme", &neighbour_id).expect("safe canonical server");
    let capability_rule = format!("capability-key:{}", capability.connector());

    // `never key` names the exact real per-grant identity: that grant only.
    let exact = never_list_block(&[capability_rule.as_str()]);
    assert!(charter_never_list_matches_capability(&exact, &capability));
    assert!(!charter_never_list_matches_capability(&exact, &neighbour));
    // No prefix, suffix, or per-segment lookalike is a capability rule.
    let longer_key = format!("capability-key:mcp:acme:grant:{}0", grant_id.to_hex());
    for entry in [
        "capability-key:mcp:acme:grant",
        "capability-key:mcp:acme",
        longer_key.as_str(),
        capability.connector(),
        "mcp:acme:grant",
        "*:*",
    ] {
        assert!(
            !charter_never_list_matches_capability(&never_list_block(&[entry]), &capability),
            "{entry} must not carry capability authority"
        );
    }

    // `never key` is NOT an ordinary-channel rule: the ordinary matcher never
    // reads a capability entry, whatever channel or verb it is asked about.
    for (channel, verb) in [
        (capability.connector(), "read_file"),
        ("mcp:acme", "read_file"),
        ("mcp", "acme"),
        ("*", "*"),
    ] {
        assert!(
            !charter_never_list_matches(&exact, channel, verb),
            "capability rule must not match ordinary {channel}/{verb}"
        );
    }

    // The ordinary rule matches the COMPLETE connector string, colons included.
    let ordinary = never_list_block(&["mcp:calendar:send"]);
    assert!(charter_never_list_matches(
        &ordinary,
        "mcp:calendar",
        "send"
    ));
    assert!(!charter_never_list_matches(
        &ordinary,
        "mcp",
        "calendar:send"
    ));
    assert!(!charter_never_list_matches(
        &ordinary,
        "mcp:calendar:grant:foo",
        "send"
    ));
    let deeper = never_list_block(&["mcp:calendar:grant:foo:send"]);
    assert!(charter_never_list_matches(
        &deeper,
        "mcp:calendar:grant:foo",
        "send"
    ));
    assert!(!charter_never_list_matches(&deeper, "mcp:calendar", "send"));
    // An ordinary rule is not a capability rule either.
    assert!(!charter_never_list_matches_capability(&deeper, &capability));

    // Landed wildcard/verb semantics are unchanged.
    assert!(charter_never_list_matches(
        &never_list_block(&["*:delete"]),
        "mcp:calendar",
        " Delete "
    ));
    assert!(charter_never_list_matches(
        &never_list_block(&["slack:*"]),
        "slack",
        "send"
    ));
    assert!(!charter_never_list_matches(
        &never_list_block(&["slack:*"]),
        "line",
        "send"
    ));
}

// --- ONE-1886 registration lifecycle (pre-live-transport) ---------------------

/// A custody record whose value is a distinctive fixture: no connector-key
/// path may ever surface these bytes.
const CUSTODY_VALUE_FIXTURE: &[u8] = b"custody-value-never-read-here";

fn register_test_secret(vault: &Vault, name: &str) -> Result<EntityId> {
    vault.register_secret(crate::secret_custody::SecretCustodyRecord {
        schema_version: crate::secret_custody::SECRET_CUSTODY_SCHEMA_VERSION,
        name: name.to_owned(),
        class: crate::secret_custody::CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: CUSTODY_VALUE_FIXTURE.to_vec(),
        status: crate::secret_custody::SecretCustodyStatus::Active,
        registered_at: 1,
        rotated_at: None,
        rotation_generation: 0,
        bindings: Vec::new(),
        manifest_ref: "secrets.toml".to_owned(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: crate::secret_custody::SecretCustodyFloor::default(),
    })
}

fn catalog_entry(name: &str, connector: &str) -> ConnectorCatalogEntry {
    ConnectorCatalogEntry {
        name: name.to_owned(),
        connector: connector.to_owned(),
        summary: "Herald's outbound workspace".to_owned(),
        verbs: vec!["send".to_owned()],
        call_class: ConnectorCallClass::CounterpartyComm,
        // Deliberately stale: the registration door overwrites it.
        registered_at: 7,
    }
}

fn connector_key_op_reasons(vault: &Vault) -> Result<Vec<String>> {
    let receipts = vault.receipts(ReceiptQuery::new(50).with_kind(ReceiptKind::Gate))?;
    Ok(receipts
        .iter()
        .flat_map(|receipt| receipt.policy_trace.iter())
        .filter(|reason| reason.starts_with("gate.connector_key."))
        .cloned()
        .collect())
}

fn catalog_name_index_row(vault: &Vault, name: &str) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .get(&rtxn, &connector_catalog_name_index_key(name))?
        .map(|bytes| bytes.to_vec()))
}

fn send_admit_row_count(vault: &Vault, id: &EntityId) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    let prefix = connector_key_send_admit_key(id, "");
    let mut count = 0;
    for entry in vault.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
        entry?;
        count += 1;
    }
    Ok(count)
}

#[test]
fn secret_ref_round_trip_additive() -> Result<()> {
    let record = ConnectorKeyRecord {
        secret_ref: Some("slack/bot_token".to_owned()),
        key_generation: 7,
        catalog: Some(ConnectorCatalogEntry {
            registered_at: 1_000,
            ..catalog_entry("herald_slack", "slack")
        }),
        ..ConnectorKeyRecord::active("slack", None, all_dimension_budgets(), 1_000)
    };
    let encoded = encode_connector_key_body(&record)?;
    assert_eq!(decode_connector_key_body(&encoded)?, record);

    // The append is POSITIONAL: positions 0-10 are byte-identical to the
    // pinned v1/v2 key set, and the three new keys sit at 11-13.
    assert_eq!(
        CONNECTOR_KEY_BODY_KEYS[..11],
        [
            "schema_version",
            "connector",
            "actor_entity_ref",
            "status",
            "budgets",
            "registered_at",
            "status_changed_at",
            "suspended_reason",
            "charter",
            "pending_charter",
            "suggested_budgets",
        ]
    );
    let mut cursor = std::io::Cursor::new(encoded);
    let value = rmpv::decode::read_value(&mut cursor).expect("decode body");
    let rmpv::Value::Map(entries) = &value else {
        panic!("connector key body must be a map");
    };
    let keys: Vec<&str> = entries
        .iter()
        .map(|(key, _)| key.as_str().expect("string key"))
        .collect();
    assert_eq!(keys, CONNECTOR_KEY_BODY_KEYS.to_vec());

    // A stored 11-key legacy body decodes at the pre-live-transport defaults
    // and is otherwise unchanged — no bulk rewrite, no re-versioning.
    let legacy = ConnectorKeyRecord::active("peer_link", None, Vec::new(), 1_000);
    let encoded = encode_connector_key_body(&legacy)?;
    let mut cursor = std::io::Cursor::new(encoded);
    let mut value = rmpv::decode::read_value(&mut cursor).expect("decode fixture");
    let rmpv::Value::Map(entries) = &mut value else {
        panic!("connector key body must be a map");
    };
    let (_, schema_version) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("schema_version"))
        .expect("schema_version key");
    *schema_version = rmpv::Value::from(2);
    entries.retain(|(key, _)| {
        !matches!(
            key.as_str(),
            Some("secret_ref" | "key_generation" | "catalog")
        )
    });
    assert_eq!(entries.len(), 11);
    let mut old_body = Vec::new();
    rmpv::encode::write_value(&mut old_body, &value).expect("encode v2 fixture");

    let decoded = decode_connector_key_body(&old_body)?;
    assert_eq!(decoded.secret_ref, None);
    assert_eq!(decoded.key_generation, 0);
    assert_eq!(decoded.catalog, None);
    assert_eq!(decoded, legacy);
    Ok(())
}

#[test]
fn registration_fails_on_unresolved_secret_ref() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // Legacy door.
    let id = test_id(0x21);
    assert!(matches!(
        vault.register_connector_key(
            &id,
            ConnectorKeyRecord {
                secret_ref: Some("missing_secret".to_owned()),
                ..ConnectorKeyRecord::active("slack", None, Vec::new(), 1_000)
            },
        ),
        Err(Error::InvalidConnectorKeyBody(
            "secret_ref does not resolve"
        ))
    ));
    assert!(vault.get_connector_key(&id)?.is_none());
    assert!(vault.connector_key_for("slack", None)?.is_none());

    // Composed door: the SAME shared in-txn core, so the same ruled error.
    assert!(matches!(
        vault.register_connector(
            catalog_entry("herald_slack", "slack"),
            ConnectorKeySpec {
                secret_ref: Some("missing_secret".to_owned()),
                ..ConnectorKeySpec::new("slack")
            },
            1_000,
        ),
        Err(Error::InvalidConnectorKeyBody(
            "secret_ref does not resolve"
        ))
    ));
    // Nothing persisted: no key, no reserved name, no receipt.
    assert!(vault.describe_connector("herald_slack")?.is_none());
    assert!(catalog_name_index_row(&vault, "herald_slack")?.is_none());
    assert_eq!(connector_key_op_receipt_count(&vault)?, 0);

    // With the custody record live, both doors accept the same reference.
    register_test_secret(&vault, "live_secret")?;
    let registered = vault.register_connector_key(
        &id,
        ConnectorKeyRecord {
            secret_ref: Some("live_secret".to_owned()),
            ..ConnectorKeyRecord::active("slack", None, Vec::new(), 1_000)
        },
    )?;
    assert_eq!(registered.secret_ref.as_deref(), Some("live_secret"));
    let (composed_id, composed) = vault.register_connector(
        catalog_entry("herald_line", "line"),
        ConnectorKeySpec {
            secret_ref: Some("live_secret".to_owned()),
            ..ConnectorKeySpec::new("line")
        },
        1_001,
    )?;
    assert_eq!(composed.secret_ref.as_deref(), Some("live_secret"));
    assert!(vault.get_connector_key(&composed_id)?.is_some());
    Ok(())
}

#[test]
fn register_connector_is_atomic() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    register_test_secret(&vault, "slack_token")?;

    // Hyphen/underscore are the same registration; the entry's stale
    // `registered_at` is overwritten by the parameter.
    let (id, record) = vault.register_connector(
        catalog_entry("My-Connector", "My-Connector"),
        ConnectorKeySpec {
            secret_ref: Some("slack_token".to_owned()),
            ..ConnectorKeySpec::new("my_connector")
        },
        1_000,
    )?;
    let stored = vault.get_connector_key(&id)?.expect("stored key");
    assert_eq!(stored, record);
    assert_eq!(stored.connector, "my_connector");
    assert_eq!(stored.key_generation, 0);
    assert_eq!(stored.secret_ref.as_deref(), Some("slack_token"));
    let entry = stored.catalog.expect("catalog embedded on the key");
    assert_eq!(entry.name, "my_connector");
    assert_eq!(entry.connector, "my_connector");
    assert_eq!(entry.registered_at, 1_000, "the parameter dates the entry");

    // Permanent name index + generation-0 log row, both in the same commit.
    assert_eq!(
        catalog_name_index_row(&vault, "my_connector")?.as_deref(),
        Some(id.as_bytes().as_slice())
    );
    assert_eq!(
        vault
            .connector_key_generation(&id, 0)?
            .expect("generation 0"),
        ConnectorKeyGeneration {
            generation: 0,
            secret_ref: Some("slack_token".to_owned()),
            rotated_at: 1_000,
        }
    );
    assert_eq!(
        connector_key_op_reasons(&vault)?,
        vec!["gate.connector_key.register".to_owned()]
    );

    // The name is taken across vault history.
    assert!(matches!(
        vault.register_connector(
            catalog_entry("my-connector", "other"),
            ConnectorKeySpec::new("other"),
            1_010,
        ),
        Err(Error::ConnectorKeyAlreadyExists)
    ));

    // Blank / NUL names fail pre-write.
    for bad in ["   ", "bad\u{0}name"] {
        assert!(matches!(
            vault.register_connector(
                catalog_entry(bad, "line"),
                ConnectorKeySpec::new("line"),
                1_011,
            ),
            Err(Error::InvalidConnectorKeyBody(_))
        ));
    }
    assert!(vault.connector_key_for("line", None)?.is_none());

    // A forced leg failure (the tuple is already governed) reserves NOTHING.
    assert!(matches!(
        vault.register_connector(
            catalog_entry("second_name", "my_connector"),
            ConnectorKeySpec::new("my_connector"),
            1_020,
        ),
        Err(Error::ConnectorKeyAlreadyExists)
    ));
    assert!(catalog_name_index_row(&vault, "second_name")?.is_none());
    assert!(vault.describe_connector("second_name")?.is_none());

    // Legacy door: a carried catalog is rejected pre-write; catalog-free
    // registration still succeeds at generation 0.
    let legacy_id = test_id(0x31);
    assert!(matches!(
        vault.register_connector_key(
            &legacy_id,
            ConnectorKeyRecord {
                catalog: Some(catalog_entry("legacy", "line")),
                ..ConnectorKeyRecord::active("line", None, Vec::new(), 1_030)
            },
        ),
        Err(Error::InvalidConnectorKeyBody(
            "catalog requires composed registration"
        ))
    ));
    assert!(vault.get_connector_key(&legacy_id)?.is_none());
    assert!(catalog_name_index_row(&vault, "legacy")?.is_none());

    let legacy = vault.register_connector_key(
        &legacy_id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_030),
    )?;
    assert!(legacy.catalog.is_none());
    assert_eq!(legacy.key_generation, 0);
    assert!(vault.connector_key_generation(&legacy_id, 0)?.is_some());
    Ok(())
}

#[test]
fn rotate_connector_key_receipted_and_value_free() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    register_test_secret(&vault, "token_v1")?;
    register_test_secret(&vault, "token_v2")?;

    let (id, _) = vault.register_connector(
        catalog_entry("herald_slack", "slack"),
        ConnectorKeySpec {
            secret_ref: Some("token_v1".to_owned()),
            ..ConnectorKeySpec::new("slack")
        },
        1_000,
    )?;
    assert_eq!(
        vault
            .connector_key_generation(&id, 0)?
            .expect("generation 0 is point-readable at registration")
            .secret_ref
            .as_deref(),
        Some("token_v1")
    );

    let rotated = vault.rotate_connector_key(&id, "token_v2", 2_000)?;
    assert_eq!(rotated.secret_ref.as_deref(), Some("token_v2"));
    assert_eq!(rotated.key_generation, 1);
    assert_eq!(vault.get_connector_key(&id)?.expect("stored key"), rotated);
    assert_eq!(
        vault
            .connector_key_generation(&id, 1)?
            .expect("generation 1"),
        ConnectorKeyGeneration {
            generation: 1,
            secret_ref: Some("token_v2".to_owned()),
            rotated_at: 2_000,
        }
    );
    assert_eq!(
        connector_key_op_reasons(&vault)?
            .iter()
            .filter(|reason| *reason == "gate.connector_key.rotate")
            .count(),
        1
    );

    // Value-free: the key names a custody record, and no rotation surface
    // carries the value bytes.
    let leaked = format!("{rotated:?}");
    assert!(!leaked.contains(std::str::from_utf8(CUSTODY_VALUE_FIXTURE).expect("utf8 fixture")));

    // An unresolved reference is a ruled error and writes nothing.
    assert!(matches!(
        vault.rotate_connector_key(&id, "ghost_token", 3_000),
        Err(Error::InvalidConnectorKeyBody(
            "secret_ref does not resolve"
        ))
    ));
    assert_eq!(vault.get_connector_key(&id)?.expect("stored key"), rotated);
    assert!(vault.connector_key_generation(&id, 2)?.is_none());

    // A record that predates the generation log (a v1/v2 body decodes at
    // generation 0 with no log row) backfills its CURRENT generation on the
    // first rotation, so 0 AND 1 stay point-readable.
    let legacy_id = test_id(0x41);
    vault.register_connector_key(
        &legacy_id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_500),
    )?;
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, &connector_key_generation_key(&legacy_id, 0))?;
        wtxn.commit()?;
    }
    assert!(
        vault.connector_key_generation(&legacy_id, 0)?.is_none(),
        "fixture: the record now looks pre-log"
    );

    let rotated_legacy = vault.rotate_connector_key(&legacy_id, "token_v2", 2_500)?;
    assert_eq!(rotated_legacy.key_generation, 1);
    assert_eq!(
        vault
            .connector_key_generation(&legacy_id, 0)?
            .expect("generation 0 backfilled"),
        ConnectorKeyGeneration {
            generation: 0,
            secret_ref: None,
            rotated_at: 1_500,
        }
    );
    assert_eq!(
        vault
            .connector_key_generation(&legacy_id, 1)?
            .expect("generation 1")
            .secret_ref
            .as_deref(),
        Some("token_v2")
    );

    // A terminal key does not rotate.
    vault.revoke_connector_key(&legacy_id, 3_500)?;
    assert!(matches!(
        vault.rotate_connector_key(&legacy_id, "token_v1", 3_600),
        Err(Error::InvalidConnectorKeyBody(
            "cannot rotate a revoked key"
        ))
    ));
    Ok(())
}

#[test]
fn remove_connector_key_is_revoke_plus_permanent_catalog_history() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (id, _) = vault.register_connector(
        catalog_entry("herald_slack", "slack"),
        ConnectorKeySpec::new("slack"),
        1_000,
    )?;

    let removed = vault.remove_connector_key(&id, 2_000)?;
    assert_eq!(removed.status, ConnectorKeyStatus::Revoked);
    assert_eq!(removed.status_changed_at, Some(2_000));

    let ops = connector_key_op_reasons(&vault)?;
    assert_eq!(
        ops.iter()
            .filter(|reason| *reason == "gate.connector_key.remove")
            .count(),
        1,
        "removal appends exactly one remove record"
    );
    assert!(
        !ops.iter()
            .any(|reason| reason == "gate.connector_key.revoke"),
        "removal is its own op, never a revoke"
    );

    // The name-index row survives: the catalog keeps HISTORY.
    assert_eq!(
        catalog_name_index_row(&vault, "herald_slack")?.as_deref(),
        Some(id.as_bytes().as_slice())
    );
    assert!(
        vault.search_connector_catalog("herald")?.is_empty(),
        "the discovery lens is live-only"
    );
    assert!(vault.route_connector_call("herald_slack")?.is_none());
    let described = vault
        .describe_connector("herald_slack")?
        .expect("the history lens resolves a removed connector");
    assert_eq!(described.status, ConnectorKeyStatus::Revoked);
    assert_eq!(described.key_ref, id);

    // The name can never be recycled onto a different connector.
    assert!(matches!(
        vault.register_connector(
            catalog_entry("herald_slack", "line"),
            ConnectorKeySpec::new("line"),
            3_000,
        ),
        Err(Error::ConnectorKeyAlreadyExists)
    ));

    // Removing an already-terminal key inherits the illegal-transition error.
    assert!(matches!(
        vault.remove_connector_key(&id, 4_000),
        Err(Error::InvalidConnectorKeyBody("illegal status transition"))
    ));

    // The public revoke path still appends its own revoke record.
    let other = test_id(0x51);
    vault.register_connector_key(
        &other,
        ConnectorKeyRecord::active("email", None, Vec::new(), 1_000),
    )?;
    vault.revoke_connector_key(&other, 5_000)?;
    let ops = connector_key_op_reasons(&vault)?;
    assert_eq!(
        ops.iter()
            .filter(|reason| *reason == "gate.connector_key.revoke")
            .count(),
        1
    );
    Ok(())
}

#[test]
fn catalog_meta_verbs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    register_test_secret(&vault, "slack_token")?;
    let (slack_id, _) = vault.register_connector(
        ConnectorCatalogEntry {
            summary: "Talks to the Slack WORKSPACE".to_owned(),
            verbs: vec!["send".to_owned(), "read".to_owned()],
            ..catalog_entry("herald_slack", "slack")
        },
        ConnectorKeySpec {
            secret_ref: Some("slack_token".to_owned()),
            ..ConnectorKeySpec::new("slack")
        },
        1_000,
    )?;
    vault.register_connector(
        ConnectorCatalogEntry {
            summary: "Read-only market feed".to_owned(),
            call_class: ConnectorCallClass::ReadOnly,
            ..catalog_entry("market_feed", "market")
        },
        ConnectorKeySpec::new("market"),
        1_001,
    )?;

    // A hyphenated query finds the underscored name.
    let hits = vault.search_connector_catalog("herald-slack")?;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "herald_slack");
    // The summary matches case-insensitively.
    let hits = vault.search_connector_catalog("workspace")?;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "herald_slack");
    // A blank query lists the live catalog.
    assert_eq!(vault.search_connector_catalog("")?.len(), 2);
    assert!(vault.search_connector_catalog("nothing_here")?.is_empty());

    // describe: the entry plus VALUE-LESS key metadata.
    let described = vault
        .describe_connector("Herald-Slack")?
        .expect("describe normalizes its query");
    assert_eq!(described.key_ref, slack_id);
    assert_eq!(described.connector, "slack");
    assert_eq!(described.status, ConnectorKeyStatus::Active);
    assert_eq!(described.secret_ref.as_deref(), Some("slack_token"));
    assert_eq!(described.key_generation, 0);
    assert_eq!(described.registered_at, 1_000);
    assert!(described.budgeted_as_sends);
    assert!(
        !format!("{described:?}")
            .contains(std::str::from_utf8(CUSTODY_VALUE_FIXTURE).expect("utf8 fixture"))
    );

    // route: entry-wide classification, no verb parameter.
    let route = vault.route_connector_call("herald_slack")?.expect("route");
    assert_eq!(route.key_ref, slack_id);
    assert_eq!(route.call_class, ConnectorCallClass::CounterpartyComm);
    assert!(route.budgeted_as_sends);
    assert_eq!(route.verbs, vec!["send".to_owned(), "read".to_owned()]);
    assert!(
        !vault
            .route_connector_call("market_feed")?
            .expect("route")
            .budgeted_as_sends
    );

    // After removal the execution lens closes but history stays open.
    vault.remove_connector_key(&slack_id, 2_000)?;
    assert!(vault.route_connector_call("herald_slack")?.is_none());
    assert_eq!(
        vault
            .describe_connector("herald_slack")?
            .expect("history")
            .status,
        ConnectorKeyStatus::Revoked
    );

    // An unknown name has no lens at all.
    assert!(vault.describe_connector("nobody")?.is_none());
    assert!(vault.route_connector_call("nobody")?.is_none());
    Ok(())
}

#[test]
fn budget_rider_send_is_counterparty_only() -> Result<()> {
    // ARCH-0054: the Send class is counterparty communications ONLY.
    assert!(ConnectorCallClass::CounterpartyComm.debits_sends());
    assert!(!ConnectorCallClass::ReadOnly.debits_sends());
    assert!(!ConnectorCallClass::ScopedMcp.debits_sends());
    for class in [
        ConnectorCallClass::CounterpartyComm,
        ConnectorCallClass::ReadOnly,
        ConnectorCallClass::ScopedMcp,
    ] {
        assert_eq!(ConnectorCallClass::parse(class.as_str()), Some(class));
    }
    assert!(ConnectorCallClass::parse("send").is_none());

    let (_tmp, vault) = temp_vault();
    // A mixed-verb counterparty connector budgets its read-only verbs as
    // sends too: the classification is entry-wide, and over-budgeting is the
    // safe direction.
    vault.register_connector(
        ConnectorCatalogEntry {
            verbs: vec!["send".to_owned(), "search".to_owned()],
            ..catalog_entry("herald_slack", "slack")
        },
        ConnectorKeySpec::new("slack"),
        1_000,
    )?;
    let route = vault.route_connector_call("herald_slack")?.expect("route");
    assert!(route.budgeted_as_sends);
    assert_eq!(route.verbs.len(), 2, "no verb narrows the classification");

    // A scoped-MCP connector stays unbudgeted for Sends.
    vault.register_connector(
        ConnectorCatalogEntry {
            call_class: ConnectorCallClass::ScopedMcp,
            ..catalog_entry("mcp_tools", "mcp")
        },
        ConnectorKeySpec::new("mcp"),
        1_001,
    )?;
    assert!(
        !vault
            .route_connector_call("mcp_tools")?
            .expect("route")
            .budgeted_as_sends
    );

    // UNCLASSIFIED is unbudgeted: a catalog-free key has no route, so the
    // executor keeps the canon default. This says nothing about the
    // production scoped-MCP path, which is still wired to the existing
    // charger — that rewire is a named follow-on.
    let legacy_id = test_id(0x61);
    vault.register_connector_key(
        &legacy_id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_002),
    )?;
    assert!(
        vault
            .get_connector_key(&legacy_id)?
            .expect("stored key")
            .catalog
            .is_none()
    );
    assert!(vault.route_connector_call("line")?.is_none());
    Ok(())
}

#[test]
fn retried_send_debits_once() -> Result<()> {
    const FROZEN: u64 = 90_000;
    let (_tmp, vault) = temp_vault();
    let id = test_id(0x71);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active(
            "peer",
            None,
            vec![EffectorBudget::sends(
                5,
                EffectorBudgetWindow::Rolling { duration_s: 3_600 },
                EffectorBudgetOnExhaust::Refuse,
            )],
            1_000,
        ),
    )?;

    let ConnectorKeySendAdmission::Admitted(charge) =
        vault.admit_connector_key_send_at(&id, "peer", "task:alpha", FROZEN)?
    else {
        panic!("the first eligible call for a logical send admits");
    };
    assert_eq!(charge.sends_debit, 1);
    assert_eq!(charge.matched_rows, vec![0]);
    assert_eq!(
        dispatch_usage_row(&vault, &id, 0)?.entries,
        vec![(FROZEN, 1)]
    );
    assert_eq!(send_admit_row_count(&vault, &id)?, 1);

    // The same logical send again — whatever shape the attempt layer's retry
    // took — debits nothing.
    let ConnectorKeySendAdmission::Replayed(echo) =
        vault.admit_connector_key_send_at(&id, "peer", "task:alpha", FROZEN + 5)?
    else {
        panic!("a retried logical send replays");
    };
    assert_eq!(echo.sends_debit, 0);
    assert!(echo.matched_rows.is_empty());
    assert!(echo.ladder_events.is_empty());
    assert_eq!(echo.read.rows[0].used, 1);
    assert_eq!(
        dispatch_usage_row(&vault, &id, 0)?.entries,
        vec![(FROZEN, 1)],
        "a replay writes no usage entry"
    );
    assert_eq!(send_admit_row_count(&vault, &id)?, 1);

    // A DIFFERENT logical send admits independently.
    let ConnectorKeySendAdmission::Admitted(second) =
        vault.admit_connector_key_send_at(&id, "peer", "task:beta", FROZEN + 10)?
    else {
        panic!("a distinct logical send admits");
    };
    assert_eq!(second.sends_debit, 1);
    assert_eq!(
        dispatch_usage_row(&vault, &id, 0)?.entries,
        vec![(FROZEN, 1), (FROZEN + 10, 1)]
    );
    assert_eq!(send_admit_row_count(&vault, &id)?, 2);
    Ok(())
}

#[test]
fn logical_send_ref_is_validated() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0x81);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("peer", None, vec![EffectorBudget::rate(3, 60)], 1_000),
    )?;

    let too_long = "x".repeat(129);
    for (bad, reason) in [
        ("   ", "logical_send_ref must not be blank"),
        (too_long.as_str(), "logical_send_ref too long"),
        ("task\u{0}alpha", "logical_send_ref must not contain NUL"),
    ] {
        assert!(matches!(
            vault.admit_connector_key_send_at(&id, "peer", bad, 1_000),
            Err(Error::InvalidConnectorKeyBody(actual)) if actual == reason
        ));
    }
    // Rejected BEFORE any charge or dedupe write.
    assert!(dispatch_usage_row(&vault, &id, 0)?.entries.is_empty());
    assert_eq!(send_admit_row_count(&vault, &id)?, 0);

    // The effect channel is checked on the same pre-write pass.
    assert!(matches!(
        vault.admit_connector_key_send_at(&id, "  ", "task:alpha", 1_000),
        Err(Error::InvalidConnectorKeyBody(
            "effect channel must not be blank"
        ))
    ));
    assert_eq!(send_admit_row_count(&vault, &id)?, 0);

    // A ref at exactly the cap is fine.
    let at_cap = "y".repeat(128);
    assert!(matches!(
        vault.admit_connector_key_send_at(&id, "peer", &at_cap, 1_000)?,
        ConnectorKeySendAdmission::Admitted(_)
    ));
    Ok(())
}

#[test]
fn refusal_does_not_poison_replay() -> Result<()> {
    const FROZEN: u64 = 120_000;
    let (_tmp, vault) = temp_vault();
    let id = test_id(0x91);
    let mut row = EffectorBudget::sends(
        1,
        EffectorBudgetWindow::Rolling { duration_s: 60 },
        EffectorBudgetOnExhaust::Suspend,
    );
    row.channel_class = Some("peer".to_owned());
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("peer_send", None, vec![row], 1_000),
    )?;

    assert!(matches!(
        vault.admit_connector_key_send_at(&id, "peer", "task:one", FROZEN)?,
        ConnectorKeySendAdmission::Admitted(_)
    ));

    // The next logical send exhausts the hard cap: refused, key suspended,
    // receipted — and NO admission row is written.
    let ConnectorKeySendAdmission::Refused {
        reason,
        row_index,
        suspended,
        charge,
    } = vault.admit_connector_key_send_at(&id, "peer", "task:two", FROZEN + 1)?
    else {
        panic!("an exhausted send refuses");
    };
    assert_eq!(reason, "budget_exhausted:row:0");
    assert_eq!(row_index, Some(0));
    assert!(suspended);
    assert_eq!(charge.expect("evaluated meter").sends_debit, 0);
    assert_eq!(
        vault.get_connector_key(&id)?.expect("stored key").status,
        ConnectorKeyStatus::Suspended
    );
    assert!(
        connector_key_op_reasons(&vault)?
            .iter()
            .any(|reason| reason == "gate.connector_key.dispatch_suspend")
    );
    assert_eq!(send_admit_row_count(&vault, &id)?, 1);

    // A suspended key refuses inertly.
    let ConnectorKeySendAdmission::Refused {
        reason,
        row_index,
        suspended,
        charge,
    } = vault.admit_connector_key_send_at(&id, "peer", "task:two", FROZEN + 2)?
    else {
        panic!("a suspended key refuses");
    };
    assert_eq!(reason, "connector_key_not_active");
    assert_eq!(row_index, None);
    assert!(!suspended);
    assert!(charge.is_none());
    assert_eq!(send_admit_row_count(&vault, &id)?, 1);

    // After resume and a window rollover the SAME ref admits — the refusals
    // never consumed it — and only then replays.
    vault.resume_connector_key(&id, FROZEN + 3)?;
    let ConnectorKeySendAdmission::Admitted(charge) =
        vault.admit_connector_key_send_at(&id, "peer", "task:two", FROZEN + 61)?
    else {
        panic!("the rolled window admits the same logical send");
    };
    assert_eq!(charge.sends_debit, 1);
    assert_eq!(send_admit_row_count(&vault, &id)?, 2);
    assert!(matches!(
        vault.admit_connector_key_send_at(&id, "peer", "task:two", FROZEN + 62)?,
        ConnectorKeySendAdmission::Replayed(_)
    ));

    // A Refuse-policy row leaves the key state inert on refusal.
    let refuse_id = test_id(0x92);
    let mut row = EffectorBudget::sends(
        1,
        EffectorBudgetWindow::Rolling { duration_s: 60 },
        EffectorBudgetOnExhaust::Refuse,
    );
    row.channel_class = Some("peer".to_owned());
    vault.register_connector_key(
        &refuse_id,
        ConnectorKeyRecord::active("peer_refuse", None, vec![row], 1_000),
    )?;
    vault.admit_connector_key_send_at(&refuse_id, "peer", "task:a", FROZEN)?;
    let ConnectorKeySendAdmission::Refused { suspended, .. } =
        vault.admit_connector_key_send_at(&refuse_id, "peer", "task:b", FROZEN + 1)?
    else {
        panic!("an exhausted send refuses");
    };
    assert!(!suspended);
    assert_eq!(
        vault
            .get_connector_key(&refuse_id)?
            .expect("stored key")
            .status,
        ConnectorKeyStatus::Active
    );
    assert_eq!(send_admit_row_count(&vault, &refuse_id)?, 1);
    Ok(())
}
