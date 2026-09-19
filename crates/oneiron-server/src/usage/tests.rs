use super::*;
use std::sync::Arc;
fn ledger() -> (tempfile::TempDir, UsageLedger) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    (dir, UsageLedger::new(vault))
}
fn event(id: &str, currency: &str) -> UsageEvent {
    UsageEvent {
        owner: "owner-a".into(),
        vault_id: "vault-a".into(),
        idempotency_key: id.into(),
        source: None,
        event_type: UsageEventType::Inference,
        role: None,
        occurred_at: Some(100),
        agent_id: Some("agent".into()),
        model: Some("model".into()),
        service: None,
        token_counts: UsageTokenCounts {
            input_tokens: 1_000,
            ..Default::default()
        },
        cost_rates: UsageCostRates {
            currency: currency.into(),
            price_table_snapshot: "provider-2026-09".into(),
            input_per_million: 2_000_000_000,
            output_per_million: 0,
            cache_read_per_million: 0,
            cache_write_per_million: 0,
        },
        service_amount: 44_000_000,
    }
}
#[test]
fn stamped_money_roundtrips_and_rollups_do_not_mix_currencies_or_vaults() {
    let (_dir, ledger) = ledger();
    for currency in ["USD", "JPY"] {
        let e = event(currency, currency);
        let first = ledger
            .record_event(e.clone(), UsageMode::OneironCloud)
            .unwrap();
        assert_eq!(first.cost.amount, 46_000_000);
        let replay = ledger.record_event(e, UsageMode::OneironCloud).unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.cost, first.cost);
    }
    let mut e = event("other", "USD");
    e.vault_id = "vault-b".into();
    ledger.record_event(e, UsageMode::OneironCloud).unwrap();
    let a = ledger.vault_rollup("owner-a", "vault-a").unwrap().unwrap();
    let b = ledger.vault_rollup("owner-a", "vault-b").unwrap().unwrap();
    assert_eq!(a.counters.event_count, 2);
    assert_eq!(b.counters.event_count, 1);
    assert_eq!(a.counters.amounts_by_currency["USD"], 46_000_000);
    assert_eq!(a.counters.amounts_by_currency["JPY"], 46_000_000);
    assert!(ledger.vault_rollup("owner-b", "vault-a").unwrap().is_none());
}
#[test]
fn unmetered_modes_conflicts_overflow_and_invalid_keys() {
    let (_dir, ledger) = ledger();
    for mode in [UsageMode::Local, UsageMode::Byo] {
        assert!(
            !ledger
                .record_event(event("one", "USD"), mode)
                .unwrap()
                .recorded
        );
    }
    let mut e = event("one", "USD");
    ledger
        .record_event(e.clone(), UsageMode::OneironCloud)
        .unwrap();
    e.service_amount += 1;
    assert!(matches!(
        ledger.record_event(e, UsageMode::OneironCloud),
        Err(UsageError::IdempotencyConflict)
    ));
    let mut e = event("two", "USD");
    e.service_amount = u64::MAX;
    assert!(matches!(
        ledger.record_event(e, UsageMode::OneironCloud),
        Err(UsageError::Overflow)
    ));
    let mut e = event("three", "USD");
    e.owner = "x".repeat(256);
    assert!(matches!(
        ledger.record_event(e, UsageMode::OneironCloud),
        Err(UsageError::InvalidField { .. })
    ));
}
#[test]
fn cached_yen_limit_converts_once_and_uses_budget_guard_ladder() {
    let (_dir, ledger) = ledger();
    let original = Money {
        amount: 15_000,
        currency: "JPY".into(),
        price_table_snapshot: "limit".into(),
    };
    let rate = ExchangeRate {
        from_currency: "JPY".into(),
        to_currency: "USD".into(),
        numerator: 1,
        denominator: 150,
        observed_at: 99,
    };
    let limit = ledger
        .cache_budget_limit("owner-a", "vault-a", original, rate, 100)
        .unwrap();
    assert_eq!(limit.converted.amount, 100);
    assert_eq!(
        ledger
            .cached_budget_limit("owner-a", "vault-a")
            .unwrap()
            .unwrap(),
        limit
    );
    let guard = limit.guard("vault-budget");
    let mut thresholds = Vec::new();
    let mut leases = Vec::new();
    for _ in 0..100 {
        let a = guard.admit().unwrap();
        thresholds.extend(a.ladder_events.into_iter().map(|e| e.threshold));
        leases.push(a.lease);
    }
    assert_eq!(
        thresholds,
        vec![
            oneiron::llm::BudgetThreshold::Silent50,
            oneiron::llm::BudgetThreshold::Plan80,
            oneiron::llm::BudgetThreshold::Land95
        ]
    );
    assert!(matches!(
        guard.admit(),
        Err(oneiron::llm::BudgetDenied::Exhausted)
    ));
}

#[test]
fn restore_retains_money_facts_rebuilds_rollups_and_resets_host_budget() {
    let (dir, ledger) = ledger();
    let first = event("one", "USD");
    let second = event("two", "JPY");
    ledger
        .record_event(first.clone(), UsageMode::OneironCloud)
        .unwrap();
    ledger
        .record_event(second, UsageMode::OneironCloud)
        .unwrap();
    let before = ledger.vault_rollup("owner-a", "vault-a").unwrap();
    ledger
        .cache_budget_limit(
            "owner-a",
            "vault-a",
            Money {
                amount: 15000,
                currency: "JPY".into(),
                price_table_snapshot: "limit".into(),
            },
            ExchangeRate {
                from_currency: "JPY".into(),
                to_currency: "USD".into(),
                numerator: 1,
                denominator: 150,
                observed_at: 90,
            },
            100,
        )
        .unwrap();
    let snapshot = dir.path().join("checkpoint");
    ledger.vault.snapshot_checkpoint(&snapshot, 200).unwrap();
    let (restored, _) = oneiron::Vault::restore_checkpoint(
        &snapshot,
        &dir.path().join("restored"),
        oneiron::VaultConfig::device(),
        oneiron::recovery::checkpoint::RestoreReason::Restore,
        300,
    )
    .unwrap();
    let restored = UsageLedger::new(Arc::new(restored));
    assert!(
        restored
            .cached_budget_limit("owner-a", "vault-a")
            .unwrap()
            .is_none()
    );
    assert!(
        restored
            .vault
            .sync_state_get(&super::keys::vault_rollup_key("owner-a", "vault-a"))
            .unwrap()
            .is_none()
    );
    // A retry after restore rebuilds the view without counting the event twice.
    let replay = restored
        .record_event(first, UsageMode::OneironCloud)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.vault_rollup, before);
    assert_eq!(restored.vault_rollup("owner-a", "vault-a").unwrap(), before);
    restored
        .record_event(event("three", "USD"), UsageMode::OneironCloud)
        .unwrap();
    assert_eq!(
        restored
            .vault_rollup("owner-a", "vault-a")
            .unwrap()
            .unwrap()
            .counters
            .event_count,
        3
    );
    // The read door also rebuilds a missing derived view, without a new meter.
    restored
        .vault
        .sync_state_delete(&super::keys::vault_rollup_key("owner-a", "vault-a"))
        .unwrap();
    assert_eq!(
        restored
            .vault_rollup("owner-a", "vault-a")
            .unwrap()
            .unwrap()
            .counters
            .event_count,
        3
    );
}
