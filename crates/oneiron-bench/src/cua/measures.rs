//! Receipt observations, not replacements for the engine's success ledger.
use serde_json::{Value, json};

pub(super) fn unavailable() -> Value {
    json!({
        "elapsed_total_ms":null,"candidate_ms":null,"setup_ms":null,"drain_checker_ms":null,
        "timing_reason":"harness_phase_receipts_not_recorded",
        "first_useful_ms":null,"first_useful_reason":"no_settled_event_evidence",
        "physical_calls":null,"physical_calls_reason":"no_provider_reservation_receipt",
        "tokens_by_rung_stage":null,"usage_reason":"no_public_physical_rung_stage_join",
        "admission_model_free":null,"admission_reason":"no_e1_admission_replay_receipt",
        "execution_model_free":null,"execution_reason":"no_e2_library_execution_receipt",
        "task_model_free":null,"task_model_free_reason":"whole_task_model_edge_ledger_unavailable",
        "field_provenance":null,"field_provenance_reason":"unavailable_e6",
        "ratified_planner_routing":null,"planner_routing_reason":"no_public_e5_per_call_role_receipt",
        "no_progress_detection":null,"no_progress_reason":"no_engine_receipts_observed",
        "cost_actual_usd":null,"cost_actual_reason":"no_provider_billing_evidence",
        "cost_estimated_usd":null,"cost_estimated_reason":"no_usage_tariff_join_receipt",
        "cash_reservation_usd":null,"cash_reservation_reason":"no_provider_reservation_receipt",
        "gpu_kernel_seconds":null,"gpu_reason":"no_kernel_telemetry",
        "allocated_card_seconds":null,"resident_card_seconds":null,
        "card_seconds_reason":"no_allocation_or_residency_receipt",
        "primitive_actions":null,"primitive_action_reason":"public_trace_completeness_unproven",
        "action_cap_overshoot":null,"action_cap_reason":"public_trace_completeness_unproven",
        "receipt_engines":[],
        "author_yield":null,"author_reason":"unavailable_s4_author_qualification_receipt",
        "amortisation_n_1_5_20":null,"amortisation_reason":"author_qualification_repair_resources_unavailable"
    })
}

fn walk(value: &Value, f: &mut impl FnMut(&Value)) {
    f(value);
    match value {
        Value::Object(map) => {
            // MCP keeps host-recorded verb answers as JSON strings. Decode only
            // that envelope, never candidate prose, artifacts or page text.
            if map.get("kind").and_then(Value::as_str) == Some("agent_verb")
                && let Some(output) = map.get("output").and_then(Value::as_str)
                && let Ok(answer) = serde_json::from_str::<Value>(output)
            {
                walk(&answer, f);
            }
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
// E1's replay has no model_free flag. Read the same decision evidence as
// E2's library::model_free: providers, paired/person/image reads and presence.
fn receipt_model_free(receipt: &Value) -> Option<bool> {
    let mut rungs = Vec::new();
    for pin in receipt["providers"].as_array()? {
        rungs.push(pin["rung"].as_str()?);
    }
    for key in ["paired", "person", "images"] {
        if let Some(readings) = receipt.get(key).filter(|v| !v.is_null()) {
            for reading in readings.as_array()? {
                rungs.push(reading["provider"]["rung"].as_str()?);
            }
        }
    }
    if let Some(answered) = receipt["time"].get("answered").filter(|v| !v.is_null()) {
        rungs.push(answered.as_str()?);
    }
    Some(rungs.iter().all(|r| matches!(*r, "rule" | "human")))
}
fn decisions_model_free(decisions: &Value) -> Option<bool> {
    let mut free = true;
    for decision in decisions.as_array()? {
        if let Some(denied) = decision.get("strict_denied") {
            if denied["tokens"].as_u64() != Some(0)
                || !matches!(
                    denied["denied"].as_str(),
                    Some("rule_abstained" | "no_rule" | "image")
                )
                || !denied["question"].is_string()
            {
                return None;
            }
            continue;
        }
        free &= receipt_model_free(&decision["receipt"])?;
        if let Some(presence) = decision.get("presence").filter(|v| !v.is_null()) {
            free &= receipt_model_free(&presence["receipt"])?;
        }
        if let Some(rung) = decision.get("rung").filter(|v| !v.is_null()) {
            free &= matches!(rung.as_str()?, "rule" | "human");
        }
    }
    Some(free)
}

pub(super) fn observe(receipts: &[Value], engine: &str) -> (Value, Value, Option<String>) {
    let mut measures = unavailable();
    let mut engines = std::collections::BTreeSet::new();
    let mut stops = Vec::new();
    let mut executions = Vec::new();
    let mut admissions = Vec::new();
    let mut execution_evidence = Vec::new();
    let mut admission_evidence = Vec::new();
    let mut progress_evidence = Vec::new();
    let mut detected = false;
    for (receipt_index, receipt) in receipts.iter().enumerate() {
        walk(receipt, &mut |node| {
            let Some(map) = node.as_object() else { return };
            if let Some(name) = map.get("engine").and_then(Value::as_str)
                && matches!(name, "chromium" | "lightpanda")
            {
                engines.insert(name.to_owned());
            }
            if let Some(stop) = map.get("stop_cause").filter(|s| !s.is_null()) {
                stops.push(stop.clone());
            }
            // A batch's own stop, not a page comparison or the nested copy
            // of the cause inside its failed receipt.
            if node["completed"].is_u64() && node["elapsed_ms"].is_u64() {
                let cause = &node["stop_cause"];
                let failed = &node["failed_receipt"];
                let no_progress = cause["cause"] == "no_progress";
                detected |= no_progress;
                progress_evidence.push(json!({"receipt_index":receipt_index,
                    "stop_cause":cause,"failed_step":node["failed_step"],
                    "step":failed["step"],"failed_stop_cause":failed["stop_cause"],
                    "url":failed["observation"]["url"],
                    "title":failed["observation"]["title"]}));
            }
            if node["workflow"].is_string()
                && node["batch"].is_object()
                && let Some(fact) = node["model_free"].as_bool()
            {
                let unproven = !node["model_free_unproven"].is_null();
                execution_evidence.push(json!({"receipt_index":receipt_index,
                    "workflow":node["workflow"],"mode":node["mode"],
                    "model_free":fact,"model_free_unproven":node["model_free_unproven"]}));
                if !unproven {
                    executions.push(fact);
                }
            }
            if node["admitted"].is_boolean()
                && let Ok(proposal) = serde_json::from_value::<
                    oneiron::task_verb::sdk::BrowserLibraryProposeOutput,
                >(node.clone())
                && let Some(replay) = proposal.answer.replay
            {
                // The DTO restores skipped empty decisions (zero decisions is
                // model-free), without treating a malformed replay as empty.
                let decisions = json!(replay.decisions);
                let fact = decisions_model_free(&decisions);
                admission_evidence.push(json!({"receipt_index":receipt_index,
                    "admitted":node["admitted"],"replay_status":node["replay"]["status"],
                    "decisions":decisions,"model_free":fact}));
                admissions.push(fact);
            }
        });
    }
    if !execution_evidence.is_empty() {
        let complete = executions.len() == execution_evidence.len();
        if executions.contains(&false) || complete {
            measures["execution_model_free"] = json!(executions.iter().all(|f| *f));
            measures["execution_reason"] = Value::Null;
        } else {
            measures["execution_reason"] = json!("e2_model_free_unproven_receipt");
        }
        measures["execution_evidence"] = json!(execution_evidence);
    }
    if !admissions.is_empty() {
        if admissions.contains(&Some(false)) || admissions.iter().all(Option::is_some) {
            measures["admission_model_free"] = json!(admissions.iter().all(|f| *f == Some(true)));
            measures["admission_reason"] = Value::Null;
        } else {
            measures["admission_reason"] = json!("e1_replay_decision_receipt_incomplete");
        }
        measures["admission_evidence"] = json!(admission_evidence);
    }
    // A library run never proves whole-TASK freedom (E4). A positive model
    // observation can disprove it, but absent TASK/model-edge evidence is null.
    if measures["execution_model_free"] == false || measures["admission_model_free"] == false {
        measures["task_model_free"] = json!(false);
        measures["task_model_free_reason"] = json!("model_observed_in_browser_receipt");
    }
    measures["no_progress_detection"] = json!(detected);
    measures["no_progress_reason"] = json!(if detected {
        "engine_no_progress_stop_observed"
    } else {
        "no_no_progress_stop_in_checked_engine_receipts"
    });
    measures["no_progress_evidence"] = json!({"source":"engine-receipts.json",
        "receipts_checked":receipts.len(),"batches":progress_evidence});
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
