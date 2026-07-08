use super::*;
use std::sync::Mutex as StdMutex;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CapturedTelemetry {
    kind: &'static str,
    name: String,
    fields: BTreeMap<String, String>,
}

#[derive(Clone, Default)]
struct TelemetryCapture {
    records: Arc<StdMutex<Vec<CapturedTelemetry>>>,
}

impl TelemetryCapture {
    fn records(&self) -> Vec<CapturedTelemetry> {
        self.records.lock().unwrap().clone()
    }

    fn text_dump(&self) -> String {
        format!("{:?}", self.records())
    }
}

impl tracing::Subscriber for TelemetryCapture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut fields = BTreeMap::new();
        attrs.record(&mut TelemetryVisitor(&mut fields));
        self.records.lock().unwrap().push(CapturedTelemetry {
            kind: "span",
            name: attrs.metadata().name().to_owned(),
            fields,
        });
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = BTreeMap::new();
        event.record(&mut TelemetryVisitor(&mut fields));
        self.records.lock().unwrap().push(CapturedTelemetry {
            kind: "event",
            name: event.metadata().name().to_owned(),
            fields,
        });
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

struct TelemetryVisitor<'a>(&'a mut BTreeMap<String, String>);

impl tracing::field::Visit for TelemetryVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

fn test_ledger() -> (tempfile::TempDir, UsageLedger) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    (dir, UsageLedger::new(vault))
}

fn cloud_event(idempotency_key: &str) -> UsageEvent {
    UsageEvent {
        tenant_id: "tenant-a".to_owned(),
        vault_id: "vault-a".to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        source: Some(UsageMode::OneironCloud),
        event_type: UsageEventType::Inference,
        role: Some("orchestrator".to_owned()),
        occurred_at: Some(1_782_357_635),
        agent_id: Some("agent-a".to_owned()),
        model: Some("model-a".to_owned()),
        service: Some("inference".to_owned()),
        token_counts: UsageTokenCounts {
            input_tokens: 1_000,
            output_tokens: 500,
            cache_read_tokens: 2_000,
            cache_write_tokens: 1_000,
        },
        cost_rates: UsageCostRates {
            input_token_usd_per_million: 2.0,
            output_token_usd_per_million: 4.0,
            cache_read_token_usd_per_million: 0.5,
            cache_write_token_usd_per_million: 1.0,
        },
        service_cost_usd: 0.044,
        service_costs: Vec::new(),
    }
}

fn max_top_up_idempotency_key_len(tenant_id: &str) -> usize {
    (MAX_SYNC_STATE_KEY_LEN - CONSUMER_TOP_UP_PREFIX.len() - 1 - key_part_len(tenant_id)) / 2
}

fn tenant_id_over_tenant_rollup_key_limit() -> String {
    let tenant_id = "t".repeat((MAX_SYNC_STATE_KEY_LEN - USAGE_TENANT_ROLLUP_PREFIX.len()) / 2 + 1);
    assert!(tenant_id.len() <= MAX_DIMENSION_LEN);
    assert!(consumer_allowance_key_len(&tenant_id) <= MAX_SYNC_STATE_KEY_LEN);
    assert!(tenant_rollup_key_len(&tenant_id) > MAX_SYNC_STATE_KEY_LEN);
    tenant_id
}

fn vault_id_over_vault_rollup_key_limit(tenant_id: &str) -> String {
    let vault_id = "v".repeat(
        (MAX_SYNC_STATE_KEY_LEN - USAGE_VAULT_ROLLUP_PREFIX.len() - 1 - key_part_len(tenant_id))
            / 2
            + 1,
    );
    assert!(vault_id.len() <= MAX_DIMENSION_LEN);
    assert!(vault_rollup_key_len(tenant_id, &vault_id) > MAX_SYNC_STATE_KEY_LEN);
    vault_id
}

fn assert_storage_key_invalid_field(error: UsageError, expected_field: &'static str) {
    assert!(matches!(
        error,
        UsageError::InvalidField {
            field,
            message: "produces a storage key that is too long"
        } if field == expected_field
    ));
}

fn captured_usage_event(records: &[CapturedTelemetry]) -> &CapturedTelemetry {
    records
        .iter()
        .find(|record| {
            record.kind == "event"
                && record
                    .fields
                    .get("message")
                    .is_some_and(|message| message.contains("usage telemetry recorded"))
        })
        .expect("usage telemetry event")
}

fn captured_token_span<'a>(
    records: &'a [CapturedTelemetry],
    token_type: &str,
) -> &'a CapturedTelemetry {
    records
        .iter()
        .find(|record| {
            record.kind == "span"
                && record.name == "usage_token_type"
                && record
                    .fields
                    .get("token_type")
                    .is_some_and(|value| value == token_type)
        })
        .unwrap_or_else(|| panic!("usage token span {token_type}: {records:?}"))
}

fn assert_neutral_warning_telemetry(event: &CapturedTelemetry) {
    assert_eq!(event.fields["allowance_warning_level"], "none");
    assert_eq!(event.fields["allowance_warning_triggered"], "false");
    assert_eq!(
        event.fields["allowance_warning_threshold_ratio"],
        ALLOWANCE_NOTICE_THRESHOLD_RATIO.to_string()
    );
    assert_eq!(event.fields["allowance_warning_used_ratio"], "0.0");
}

fn corrupt_consumer_allowance(ledger: &UsageLedger, tenant_id: &str) {
    ledger
        .vault
        .sync_state_put(&consumer_allowance_key(tenant_id), b"not-msgpack")
        .expect("corrupt allowance row");
}

#[test]
fn cost_calculator_includes_token_cache_and_service_costs() {
    let cost = cloud_event("cost-key").cost_input().calculate().unwrap();

    assert_eq!(cost.token_cost_usd, 0.004);
    assert_eq!(cost.cache_cost_usd, 0.002);
    assert_eq!(cost.service_cost_usd, 0.044);
    assert_eq!(cost.cost_usd, 0.05);
    assert_eq!(cost.credit_units, cost.cost_usd / CREDIT_UNIT_USD);
}

#[test]
fn record_event_emits_usage_telemetry_fields_and_token_spans() {
    let (_dir, ledger) = test_ledger();
    ledger
        .top_up(
            ConsumerTopUpRequest {
                tenant_id: "tenant-a".to_owned(),
                idempotency_key: "telemetry-top-up".to_owned(),
                credit_units: 5.0,
            },
            UsageMode::OneironCloud,
        )
        .expect("top-up should create exhausted allowance warning");
    let capture = TelemetryCapture::default();

    tracing::subscriber::with_default(capture.clone(), || {
        ledger
            .record_event(cloud_event("telemetry-fields"), UsageMode::OneironCloud)
            .expect("usage event should record");
    });
    let records = capture.records();
    let event = captured_usage_event(&records);
    let prompt_span = captured_token_span(&records, "prompt");
    let completion_span = captured_token_span(&records, "completion");
    let cache_read_span = captured_token_span(&records, "cache_read");
    let cache_write_span = captured_token_span(&records, "cache_write");

    assert_eq!(event.fields["tenant_id"], "tenant-a");
    assert_eq!(event.fields["account_id"], "tenant-a");
    assert_eq!(event.fields["vault_id"], "vault-a");
    assert_eq!(event.fields["role"], "orchestrator");
    assert_eq!(event.fields["agent_id"], "agent-a");
    assert_eq!(event.fields["model"], "model-a");
    assert_eq!(event.fields["service"], "inference");
    assert_eq!(event.fields["provider_mode"], "oneiron_cloud");
    assert_eq!(event.fields["event_type"], "inference");
    assert_eq!(event.fields["prompt_tokens"], "1000");
    assert_eq!(event.fields["completion_tokens"], "500");
    assert_eq!(event.fields["cache_read_tokens"], "2000");
    assert_eq!(event.fields["cache_write_tokens"], "1000");
    assert_eq!(event.fields["cost_usd"], "0.05");
    assert_eq!(event.fields["credit_units"], "5.0");
    assert_eq!(event.fields["allowance_warning_level"], "exhausted");
    assert_eq!(event.fields["allowance_warning_triggered"], "true");
    assert_eq!(event.fields["recorded"], "true");
    assert_eq!(event.fields["replayed"], "false");
    assert_eq!(event.fields["debited"], "true");
    assert_eq!(prompt_span.fields["tokens"], "1000");
    assert_eq!(completion_span.fields["tokens"], "500");
    assert_eq!(cache_read_span.fields["tokens"], "2000");
    assert_eq!(cache_write_span.fields["tokens"], "1000");
}

#[test]
fn record_event_telemetry_does_not_log_payload_or_idempotency_text() {
    let (_dir, ledger) = test_ledger();
    let secret = "secret-prompt-payload-should-not-log";
    let mut event = cloud_event(secret);
    event.service_costs = vec![UsageServiceCost {
        service: secret.to_owned(),
        cost_usd: 0.001,
    }];
    let capture = TelemetryCapture::default();

    tracing::subscriber::with_default(capture.clone(), || {
        ledger
            .record_event(event, UsageMode::OneironCloud)
            .expect("usage event should record");
    });

    assert!(!capture.text_dump().contains(secret));
}

#[test]
fn record_event_uses_neutral_warning_when_allowance_lookup_fails_after_recording() {
    let (_dir, ledger) = test_ledger();
    corrupt_consumer_allowance(&ledger, "tenant-a");
    let capture = TelemetryCapture::default();

    let result = tracing::subscriber::with_default(capture.clone(), || {
        ledger.record_event(
            cloud_event("corrupt-allowance-record"),
            UsageMode::OneironCloud,
        )
    })
    .expect("usage event should record despite warning lookup failure");
    let records = capture.records();
    let event = captured_usage_event(&records);
    let rollup = ledger
        .tenant_rollup("tenant-a")
        .expect("tenant rollup read after recorded usage")
        .expect("tenant rollup persisted");

    assert!(result.recorded);
    assert!(!result.replayed);
    assert_eq!(rollup.counters.event_count, 1);
    assert_eq!(event.fields["recorded"], "true");
    assert_eq!(event.fields["replayed"], "false");
    assert_neutral_warning_telemetry(event);
}

#[test]
fn record_event_uses_neutral_warning_when_allowance_lookup_fails_after_replay() {
    let (_dir, ledger) = test_ledger();
    ledger
        .record_event(
            cloud_event("corrupt-allowance-replay"),
            UsageMode::OneironCloud,
        )
        .expect("initial usage event should record");
    corrupt_consumer_allowance(&ledger, "tenant-a");
    let capture = TelemetryCapture::default();

    let result = tracing::subscriber::with_default(capture.clone(), || {
        ledger.record_event(
            cloud_event("corrupt-allowance-replay"),
            UsageMode::OneironCloud,
        )
    })
    .expect("usage replay should succeed despite warning lookup failure");
    let records = capture.records();
    let event = captured_usage_event(&records);

    assert!(!result.recorded);
    assert!(result.replayed);
    assert_eq!(event.fields["recorded"], "false");
    assert_eq!(event.fields["replayed"], "true");
    assert_neutral_warning_telemetry(event);
}

#[test]
fn allowance_warning_exhausts_zero_allowance_without_usage() {
    let warning = ConsumerAllowanceWarning::for_usage(0.0, 0.0);

    assert_eq!(warning.level, ConsumerAllowanceWarningLevel::Exhausted);
    assert!(warning.triggered);
    assert_eq!(warning.threshold_ratio, 1.0);
    assert_eq!(warning.used_ratio, None);
}

#[test]
fn allowance_warning_uses_raw_ratio_for_thresholds() {
    let warning = ConsumerAllowanceWarning::for_usage(0.7999999999996, 1.0);

    assert_eq!(warning.level, ConsumerAllowanceWarningLevel::None);
    assert!(!warning.triggered);
    assert_eq!(warning.threshold_ratio, ALLOWANCE_NOTICE_THRESHOLD_RATIO);
    assert_eq!(warning.used_ratio, Some(0.8));
}

#[test]
fn consumer_usage_rejects_overlong_tenant_rollup_key() {
    let (_dir, ledger) = test_ledger();
    let tenant_id = tenant_id_over_tenant_rollup_key_limit();

    let err = ledger
        .consumer_usage(&tenant_id, None, UsageMode::OneironCloud)
        .expect_err("overlong tenant rollup key should validate before storage");

    assert_storage_key_invalid_field(err, "tenantId");
}

#[test]
fn consumer_usage_details_rejects_overlong_vault_rollup_key() {
    let (_dir, ledger) = test_ledger();
    let tenant_id = "tenant-a";
    let vault_id = vault_id_over_vault_rollup_key_limit(tenant_id);

    let err = ledger
        .consumer_usage_details(tenant_id, Some(&vault_id), UsageMode::OneironCloud)
        .expect_err("overlong vault rollup key should validate before storage");

    assert_storage_key_invalid_field(err, "vaultId");
}

#[test]
fn top_up_accepts_idempotency_key_at_encoded_storage_limit() {
    let (_dir, ledger) = test_ledger();
    let tenant_id = "tenant-a";
    let idempotency_key = "k".repeat(max_top_up_idempotency_key_len(tenant_id));
    assert_eq!(
        consumer_top_up_key_len(tenant_id, &idempotency_key),
        MAX_SYNC_STATE_KEY_LEN
    );

    let result = ledger
        .top_up(
            ConsumerTopUpRequest {
                tenant_id: tenant_id.to_owned(),
                idempotency_key: idempotency_key.clone(),
                credit_units: 1.0,
            },
            UsageMode::OneironCloud,
        )
        .expect("top-up at encoded key limit should record");

    assert!(result.recorded);
    assert!(!result.replayed);
    assert_eq!(result.top_up.idempotency_key, idempotency_key);
    assert_eq!(result.usage.allowance.allowance_credit_units, 1.0);
}

#[test]
fn top_up_rejects_idempotency_key_over_encoded_storage_limit() {
    let (_dir, ledger) = test_ledger();
    let tenant_id = "tenant-a";
    let idempotency_key = "k".repeat(max_top_up_idempotency_key_len(tenant_id) + 1);
    assert_eq!(
        consumer_top_up_key_len(tenant_id, &idempotency_key),
        MAX_SYNC_STATE_KEY_LEN + 2
    );

    let err = ledger
        .top_up(
            ConsumerTopUpRequest {
                tenant_id: tenant_id.to_owned(),
                idempotency_key,
                credit_units: 1.0,
            },
            UsageMode::OneironCloud,
        )
        .expect_err("oversized encoded top-up key should validate before storage");
    let usage = ledger
        .consumer_usage(tenant_id, None, UsageMode::OneironCloud)
        .expect("usage after rejected top-up");

    assert!(matches!(
        err,
        UsageError::InvalidField {
            field: "idempotencyKey",
            message: "produces a storage key that is too long"
        }
    ));
    assert_eq!(usage.allowance.allowance_credit_units, 0.0);
}

#[test]
fn top_up_rejects_overlong_response_rollup_key_before_recording() {
    let (_dir, ledger) = test_ledger();
    let tenant_id = tenant_id_over_tenant_rollup_key_limit();
    let idempotency_key = "k";
    assert!(consumer_top_up_key_len(&tenant_id, idempotency_key) <= MAX_SYNC_STATE_KEY_LEN);

    let err = ledger
        .top_up(
            ConsumerTopUpRequest {
                tenant_id: tenant_id.clone(),
                idempotency_key: idempotency_key.to_owned(),
                credit_units: 1.0,
            },
            UsageMode::OneironCloud,
        )
        .expect_err("overlong response rollup key should validate before write transaction");
    let allowance = ledger
        .consumer_allowance(&tenant_id)
        .expect("allowance should remain readable");
    let top_up_key = consumer_top_up_key(&tenant_id, idempotency_key);

    assert_storage_key_invalid_field(err, "tenantId");
    assert_eq!(allowance.credit_units, 0.0);
    assert!(ledger.vault.sync_state_get(&top_up_key).unwrap().is_none());
}

#[test]
fn top_up_rejects_amount_that_does_not_increase_normalized_allowance() {
    let (_dir, ledger) = test_ledger();
    let tenant_id = "tenant-a";
    let first = ledger
        .top_up(
            ConsumerTopUpRequest {
                tenant_id: tenant_id.to_owned(),
                idempotency_key: "large-top-up".to_owned(),
                credit_units: 1.0e296,
            },
            UsageMode::OneironCloud,
        )
        .expect("large finite top-up should record");

    let err = ledger
        .top_up(
            ConsumerTopUpRequest {
                tenant_id: tenant_id.to_owned(),
                idempotency_key: "precision-lost-top-up".to_owned(),
                credit_units: 1.0,
            },
            UsageMode::OneironCloud,
        )
        .expect_err("top-up must increase normalized allowance");
    let allowance = ledger
        .consumer_allowance(tenant_id)
        .expect("allowance should remain readable");
    let top_up_key = consumer_top_up_key(tenant_id, "precision-lost-top-up");

    assert!(matches!(
        err,
        UsageError::InvalidField {
            field: "creditUnits",
            message: "must increase allowance balance"
        }
    ));
    assert_eq!(
        allowance.credit_units,
        first.usage.allowance.allowance_credit_units
    );
    assert!(ledger.vault.sync_state_get(&top_up_key).unwrap().is_none());
}

#[test]
fn local_and_byo_server_modes_return_no_debit() {
    let (_dir, ledger) = test_ledger();

    let local_result = ledger
        .record_event(cloud_event("local-key"), UsageMode::Local)
        .expect("local usage");
    let byo_result = ledger
        .record_event(cloud_event("byo-key"), UsageMode::Byo)
        .expect("byo usage");

    assert_eq!(local_result.source, UsageMode::Local);
    assert_eq!(byo_result.source, UsageMode::Byo);
    assert!(local_result.debit.is_none());
    assert!(byo_result.debit.is_none());
    assert!(ledger.tenant_rollup("tenant-a").unwrap().is_none());
}

#[test]
fn oneiron_cloud_ignores_request_source_for_debit_decisions() {
    let (_dir, ledger) = test_ledger();
    let mut event = cloud_event("source-override-key");
    event.source = Some(UsageMode::Local);

    let result = ledger
        .record_event(event, UsageMode::OneironCloud)
        .expect("cloud usage with request source override");
    let rollup = ledger
        .tenant_rollup("tenant-a")
        .unwrap()
        .expect("tenant rollup");

    assert!(result.recorded);
    assert_eq!(result.source, UsageMode::OneironCloud);
    assert!(result.debit.is_some());
    assert_eq!(rollup.counters.event_count, 1);
}

#[test]
fn oneiron_cloud_records_idempotent_debit_once() {
    let (_dir, ledger) = test_ledger();
    let first = ledger
        .record_event(cloud_event("same-key"), UsageMode::OneironCloud)
        .expect("first usage event");
    let second = ledger
        .record_event(cloud_event("same-key"), UsageMode::OneironCloud)
        .expect("replayed usage event");
    let rollup = ledger
        .tenant_rollup("tenant-a")
        .unwrap()
        .expect("tenant rollup");

    assert!(first.recorded);
    assert!(!first.replayed);
    assert!(!second.recorded);
    assert!(second.replayed);
    assert_eq!(rollup.counters.event_count, 1);
    assert_eq!(rollup.counters.cost_usd, 0.05);
    assert_eq!(rollup.counters.credit_units, 5.0);
}

#[test]
fn record_event_rolls_back_rollups_when_batch_write_fails() {
    let (_dir, ledger) = test_ledger();
    let mut event = cloud_event("x");
    event.tenant_id = "t".repeat(123);
    event.vault_id = "v".repeat(123);

    let err = ledger
        .record_event(event.clone(), UsageMode::OneironCloud)
        .expect_err("oversized vault rollup key should fail");

    assert!(
        matches!(err, UsageError::Storage(_)),
        "expected storage error, got {err:?}"
    );
    assert!(ledger.tenant_rollup(&event.tenant_id).unwrap().is_none());
}

#[test]
fn rollups_include_agent_model_and_service_breakdowns() {
    let (_dir, ledger) = test_ledger();
    let mut second = cloud_event("second-key");
    second.agent_id = Some("agent-b".to_owned());
    second.model = Some("model-b".to_owned());
    second.service = Some("embedding".to_owned());

    ledger
        .record_event(cloud_event("first-key"), UsageMode::OneironCloud)
        .expect("first usage event");
    ledger
        .record_event(second, UsageMode::OneironCloud)
        .expect("second usage event");
    let vault_rollup = ledger
        .vault_rollup("tenant-a", "vault-a")
        .unwrap()
        .expect("vault rollup");

    assert_eq!(vault_rollup.counters.event_count, 2);
    assert_eq!(vault_rollup.agents["agent-a"].event_count, 1);
    assert_eq!(vault_rollup.agents["agent-b"].event_count, 1);
    assert_eq!(vault_rollup.models["model-a"].cost_usd, 0.05);
    assert_eq!(vault_rollup.models["model-b"].cost_usd, 0.05);
    assert_eq!(vault_rollup.services["inference"].credit_units, 5.0);
    assert_eq!(vault_rollup.services["embedding"].credit_units, 5.0);
}
