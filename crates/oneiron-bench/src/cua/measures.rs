//! Receipt observations, not replacements for the engine's success ledger.
use serde_json::{Value, json};

pub(super) fn unavailable() -> Value {
    json!({
        "elapsed_total_ms":null,"candidate_ms":null,"setup_ms":null,"drain_checker_ms":null,
        "first_useful_ms":null,"first_useful_reason":"no_settled_event_evidence",
        "physical_calls":null,"tokens_by_rung_stage":null,"usage_reason":"physical_receipt_join_unavailable",
        "admission_model_free":null,"admission_reason":"not_an_admission_phase",
        "execution_model_free":null,"execution_reason":"no_library_execution_receipt",
        "task_model_free":null,"task_model_free_reason":"whole_task_model_edge_ledger_unavailable",
        "field_provenance":null,"field_provenance_reason":"unavailable_e6",
        "ratified_planner_routing":null,"planner_routing_reason":"browser_planner_role_receipts_unavailable",
        "no_progress_detection":null,"no_progress_reason":"unavailable_e3",
        "cost_actual_usd":null,"cost_actual_reason":"no_provider_billing_evidence",
        "cost_estimated_usd":null,"cash_reservation_usd":null,
        "gpu_kernel_seconds":null,"gpu_reason":"no_kernel_telemetry",
        "allocated_card_seconds":null,"resident_card_seconds":null,
        "primitive_actions":null,"primitive_action_reason":"public_trace_completeness_unproven",
        "action_cap_overshoot":null,"receipt_engines":[],
        "author_yield":null,"author_reason":"S4_not_in_PR1",
        "amortisation_n_1_5_20":null,"amortisation_reason":"author_qualification_repair_resources_unavailable"
    })
}

fn walk(value: &Value, f: &mut impl FnMut(&Value)) {
    f(value);
    match value {
        Value::Object(map) => {
            for child in map.values() {
                walk(child, f)
            }
        }
        Value::Array(values) => {
            for child in values {
                walk(child, f)
            }
        }
        _ => {}
    }
}
pub(super) fn observe(receipts: &[Value], engine: &str) -> (Value, Value, Option<String>) {
    let mut measures = unavailable();
    // execute_code invokes a planner. This is not a TASK-before-planner door.
    measures["task_model_free"] = json!(false);
    let mut engines = std::collections::BTreeSet::new();
    let mut stops = Vec::new();
    let mut executions = Vec::new();
    for receipt in receipts {
        walk(receipt, &mut |node| {
            if let Some(map) = node.as_object() {
                if let Some(name) = map.get("engine").and_then(Value::as_str) {
                    if matches!(name, "chromium" | "lightpanda") {
                        engines.insert(name.to_owned());
                    }
                }
                if let Some(stop) = map.get("stop_cause").filter(|s| !s.is_null()) {
                    stops.push(stop.clone());
                }
                if let Some(fact) = map.get("model_free").and_then(Value::as_bool) {
                    executions.push(fact);
                }
            }
        });
    }
    if !executions.is_empty() {
        measures["execution_model_free"] = json!(executions.iter().all(|f| *f));
    }
    measures["receipt_engines"] = json!(engines);
    let stop = if engines.iter().any(|e| e != engine) {
        Some("browser_engine_mismatch".into())
    } else if engines.is_empty() {
        Some("browser_engine_unattested".into())
    } else {
        None
    };
    (measures, json!(stops), stop)
}

pub(super) fn first_useful(
    checker: &Value,
    fixture: &str,
    start_utc: f64,
    end_utc: f64,
    monotonic_seconds: f64,
    tolerance_ms: u64,
) -> Value {
    if fixture == "F1" {
        return json!({"ms":null,"reason":"unavailable_static_profile_reads_not_logged"});
    }
    let Some(event) = checker["first_useful_utc_seconds"].as_f64() else {
        return json!({"ms":null,"reason":"no_qualifying_successful_effect"});
    };
    let clock_difference_ms = ((end_utc - start_utc) - monotonic_seconds).abs() * 1000.0;
    let valid =
        clock_difference_ms <= tolerance_ms as f64 && event >= start_utc && event <= end_utc;
    json!({"ms":if valid {Some((event-start_utc)*1000.0)} else {None},
        "basis":"host_utc_event_interval","event":checker["first_useful_event"],
        "clock_difference_ms":clock_difference_ms,"clock_tolerance_ms":tolerance_ms,
        "clock_consistent":valid,"reason":if valid {None} else {Some("host_clock_inconsistent")}})
}

pub(super) fn observed_effects(receipts: &[Value]) -> usize {
    let mut effects = std::collections::BTreeSet::new();
    for receipt in receipts {
        walk(receipt, &mut |node| {
            if node["seq"].is_u64()
                && node["duration_ms"].is_u64()
                && node["verb"].is_string()
                && node["press"].is_string()
            {
                effects.insert(node.to_string());
            }
        });
    }
    effects.len()
}
