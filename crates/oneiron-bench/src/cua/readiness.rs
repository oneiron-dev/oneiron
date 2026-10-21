//! FIX 8326 readiness through the shipped served engine, never a CDP sidecar.
use std::{fs, path::Path, sync::{Arc, Mutex}, time::Duration};
use serde_json::{Value, json};
use tokio::time::Instant;
use super::{Result, config::Config, digest, fixture::{self, Fixture}, provider_gate::{Gate, Ledger},
    read, rows, served::Served, taskgen::{self, Cell, Plan}, write_json};

const CASES: [&str; 7] = ["public_get", "public_post", "private_refused", "direct_bridge_refused",
    "external_refused", "fresh_admission_replay", "forward_absent"];
const MARKER: &str = "CUA synthetic readiness";

fn row(name: &str, status: &str, cause: &str, evidence: Value) -> Value {
    json!({"case":name,"status":status,"cause":cause,"evidence":evidence})
}
/// Only host-recorded bridge answers count. A candidate's prose or stored JSON
/// is not an engine browser receipt. A cut step log cannot prove this matrix.
fn browser_answers(receipt: &Value) -> Result<Vec<Value>> {
    let steps = receipt["steps"].as_array().ok_or("engine_steps_missing")?;
    if receipt["bridge_calls"].as_u64() != Some(steps.len() as u64) {
        return Err("engine_step_coverage_unavailable".into());
    }
    let mut answers = Vec::new();
    for step in steps {
        if step["outcome"]["kind"] == "failed" {
            return Err(format!("engine_step_failed:{}",step["outcome"]["error"]));
        }
        if step["outcome"]["kind"] != "agent_verb" { continue }
        let answer: Value = serde_json::from_str(step["outcome"]["output"].as_str().ok_or("engine_output_missing")?)
            .map_err(|e| format!("engine_output_invalid:{e}"))?;
        if answer["session_manifest"].is_object() { answers.push(answer); }
    }
    if answers.is_empty() { return Err("engine_browser_receipt_missing".into()) }
    Ok(answers)
}
fn opened(answers: &[Value], url: &str, engine: &str) -> bool {
    answers.iter().any(|a| a["engine"] == engine && a["url"] == url
        && a["receipt"]["verb"] == "open" && a["receipt"]["url"] == url)
}
fn clock(answers: &[Value]) -> bool {
    answers.iter().any(|a| a["stop_cause"]["cause"] == "clock"
        || a["replay"]["stop_cause"]["cause"] == "clock" || a["timed_out"] == true)
}
fn public_event(events: &[Value], reset: &Value, method: &str, suffix: &str) -> bool {
    events.iter().any(|e| e["channel"] == "public" && e["run_id"] == reset["run_id"]
        && e["method"] == method && e["status"] == 200
        && e["path"].as_str().is_some_and(|p| p.ends_with(suffix)))
}
async fn probe(name: &str, served: &mut Served, fixture: &Fixture, cell: &Cell,
    reset: &Value, config: &Config, dir: &Path) -> Result<Value> {
    let deadline = Instant::now()+Duration::from_secs(cell.seconds);
    let entry = fixture::entry_url(reset)?;
    let bridge = config.browser["bench_fixture_forward"].as_str().ok_or("fixture_forward_missing")?;
    let target = match name {
        "private_refused" => "http://127.0.0.1:8766/health".to_owned(),
        "direct_bridge_refused" => format!("http://{bridge}{}",reset["entry"].as_str().ok_or("reset_entry_missing")?),
        "external_refused" => "https://example.com/".to_owned(),
        _ => entry.clone(),
    };
    let instruction = match name {
        "public_get" => format!("Open {entry} with self.browser.open. Wait for the page heading Company workspace. Stop. Do not mutate anything."),
        "public_post" => format!("Open {entry} with self.browser.open. Follow Your company. Find the Company name textbox and type exactly {MARKER:?}, replacing its text. Wait for Saved. Stop before Submit; never press it."),
        "fresh_admission_replay" => {
            let proposal = json!({"subgoal":"synthetic forward readiness navigation","params":[],
                "steps":[{"step":"open","url":entry}],
                "postcondition":[{"role":"heading","name":"Company workspace"}]});
            // Validate the exact engine DTO; do not implement admission here.
            let _:oneiron::task_verb::sdk::BrowserLibraryProposeInput = serde_json::from_value(proposal.clone()).map_err(|e| e.to_string())?;
            format!("Open {entry} with self.browser.open. On that same live browser call self.browser.library.propose exactly once with this input: {proposal}. Stop after its answer; do not repair or re-propose. No writes, sends or submits.")
        }
        _ => format!("Call self.browser.batch exactly once with {{\"no_model\":true,\"steps\":[{{\"step\":\"open\",\"url\":{}}}]}}. Stop after the answer, including refusal; no retry, fallback, other URL or follow-up browser call.",json!(target)),
    };
    let task = format!("Synthetic CUA transport readiness only. Use self.browser.* only; no fetch, page APIs, host access, sends or submits. {instruction} Return the actual engine answer, not your assessment.");
    write_json(&dir.join(format!("{name}-task.json")), &json!({"target":target,"task":task}))?;
    let receipt = served.finish(name,&task,deadline,Duration::from_millis(config.continuation_poll_ms)).await?;
    write_json(&dir.join(format!("{name}-engine.json")), &receipt)?;
    let answers = browser_answers(&receipt)?;
    if answers.iter().any(|a| a["engine"] != config.engine) { return Err("browser_engine_mismatch".into()) }
    if clock(&answers) { return Err("browser_timeout".into()) }
    let events = rows::load_values(&fixture.events)?;
    let evidence = match name {
        "public_get" => {
            if !opened(&answers,&entry,&config.engine) || !public_event(&events,reset,"GET","/api/data") {
                return Err("public_get_forward_evidence_missing".into());
            }
            json!({"entry_url":entry,"answers":answers})
        }
        "public_post" => {
            let state = fixture.snapshot(cell,deadline).await?;
            write_json(&dir.join("post-state.json"), &state)?;
            if !public_event(&events,reset,"POST","/api/field") || state["fields"]["company_name"] != MARKER
                || state["submit_count"] != 0 || state["send_count"] != 0 || state["wrong_target_count"] != 0
                || !events.iter().any(|e| e["method"] == "POST" && e["status"] == 200
                    && e["request_run_id"] == reset["run_id"] && e["payload"]["value"] == MARKER) {
                return Err("public_post_or_run_header_evidence_missing".into());
            }
            json!({"answers":answers,"snapshot":"post-state.json","x_cua_run_preserved":true})
        }
        "fresh_admission_replay" => {
            let admission = answers.iter().find(|a| a["admitted"] == true
                && a["replay_guest"].is_object() && a["replay"]["status"] == "done"
                && a["replay"]["receipts"].as_array().is_some_and(|rs| rs.iter().any(|r|
                    r["verb"] == "open" && r["url"] == entry && r["engine"] == config.engine)))
                .ok_or("fresh_admission_forward_unproven")?;
            json!({"entry_url":entry,"admission":admission})
        }
        _ => {
            // A navigation failure alone is NOT a refusal proof. Require the
            // engine's blocked egress row for this one-request durable run.
            let gates = served.gate_receipts(deadline).await?;
            write_json(&dir.join(format!("{name}-gates.json")), &gates)?;
            let run_id = receipt["run_id"].as_str().ok_or("engine_run_id_missing")?;
            let blocked = gates["output"].as_array().ok_or("gate_rows_missing")?.iter().find(|r|
                r["actor_ref"] == run_id && r["content_kind"] == "egress" && r["outcome"] == "block");
            let stopped = answers.iter().any(|a| a["completed"] == 0 && a["failed_step"] == 0
                && a["stop_cause"]["cause"] == "browser" && a["error"] == "browser_navigation");
            if blocked.is_none() || !stopped || answers.len() != 1 { return Err("destination_refusal_evidence_missing".into()) }
            json!({"target":target,"answers":answers,"blocked_egress":blocked})
        }
    };
    Ok(evidence)
}

pub(super) async fn run(plan_path: &Path, binary: &Path, pins: &Path, out: &Path) -> Result<()> {
    let _lock = rows::Lock::acquire(out)?;
    let absolute_out = out.canonicalize().map_err(|e| e.to_string())?;
    let out = absolute_out.as_path();
    let receipt_path = out.join("readiness.json");
    let started_path = out.join("readiness-started.json");
    if receipt_path.exists() || started_path.exists() { return Err("readiness_terminal_or_interrupted_no_retry".into()) }
    write_json(&started_path,&json!({"pid":std::process::id(),"cause":"readiness_started"}))?;
    let mut cases: Vec<_> = CASES.iter().map(|n| row(n,"unavailable","readiness_not_reached",Value::Null)).collect();
    let mut fixture = None;
    let mut served = None;
    let mut gate = None;
    let mut identity = Value::Null;
    let mut cash_lock = None;
    let execution: Result<()> = async {
        let plan: Plan = read(plan_path)?;
        super::run::validate_plan(&plan)?;
        let config = Config::load(pins,binary)?;
        identity = json!({"plan_digest":digest(&fs::read(plan_path).map_err(|e| e.to_string())?),
            "config_digest":digest(&fs::read(pins).map_err(|e| e.to_string())?),
            "engine":config.engine,"engine_binary_digest":config.engine_binary_digest,
            "driver_digest":config.driver_digest,"guest_image_digest":config.guest_image_digest});
        if taskgen::checker_digest(&plan.fixture_root)? != plan.checker_digest
            || taskgen::fixture_digest(&plan.fixture_root)? != plan.fixture_digest {
            return Err("frozen_fixture_or_checker_digest_mismatch".into());
        }
        let mut absent = config.browser.clone();
        absent.as_object_mut().ok_or("browser_config_malformed")?.remove("bench_fixture_forward");
        let cause = fixture::forward_target(&plan,&absent).err().ok_or("absent_forward_accepted")?;
        let cells: Vec<_> = plan.cells.iter().map(|c| json!({"cell":c.id,"status":"unavailable",
            "cause":"fixture_transport_unavailable","detail":cause})).collect();
        cases[6] = row(CASES[6],"pass","forward_absent_cells_unavailable",json!({"cells":cells,"layer":"harness_admission"}));
        fixture::forward_target(&plan,&config.browser)?;
        let cell = plan.cells.iter().find(|c| c.fixture == "F2" && c.arm == "C").ok_or("readiness_cell_missing")?;
        let arm = config.arms.get("C").ok_or("arm_unavailable")?;
        cash_lock = Some(rows::Lock::acquire(&config.cash_ledger.with_extension("lock-dir"))?);
        let ledger = Arc::new(Mutex::new(Ledger::open(&config.cash_ledger,
            identity["config_digest"].as_str().ok_or("config_digest_missing")?)?));
        if let Some(cause) = ledger.lock().map_err(|_| "cash_ledger_lock_failed")?.blocked(false) { return Err(format!("provider_gate:{}",serde_json::to_string(&cause).map_err(|e| e.to_string())?)) }
        gate = Some(Gate::start(&arm.routes,ledger.clone(),"readiness",&out.join("provider.jsonl")).await?);
        let deadline = Instant::now()+Duration::from_secs(config.startup_seconds);
        fixture = Some(Fixture::start(&plan,out,deadline).await?);
        let f = fixture.as_ref().ok_or("fixture_missing")?;
        let reset = f.reset(cell,deadline).await?;
        write_json(&out.join("reset.json"), &reset)?;
        served = Some(Served::fresh(binary,out,arm,&config.browser,&plan,
            deadline.saturating_duration_since(Instant::now()),Duration::from_millis(config.continuation_poll_ms)).await?);
        for (index, name) in CASES[..6].iter().enumerate() {
            let result = probe(name,served.as_mut().ok_or("served_missing")?,f,cell,&reset,&config,out).await;
            match result {
                Ok(evidence) => cases[index] = row(name,"pass","observed",evidence),
                Err(cause) => {
                    cases[index] = row(name,"failed",&cause,Value::Null);
                    // An incomplete candidate must be stopped before another
                    // case, never left running beside a new run or reset.
                    return Err(format!("readiness_stopped:{name}:{cause}"));
                }
            }
            if let Some(cause) = ledger.lock().map_err(|_| "cash_ledger_lock_failed")?.blocked(false) { return Err(format!("provider_gate:{}",serde_json::to_string(&cause).map_err(|e| e.to_string())?)) }
        }
        Ok(())
    }.await;
    if let Some(g) = gate.as_mut() { g.stop(); }
    let server_stop = match served.as_mut() { Some(s) => s.stop().await, None => Ok(()) };
    let fixture_stop = match fixture.as_mut() { Some(f) => f.stop().await, None => Ok(()) };
    let cleanup = json!({"served_stop":server_stop.as_ref().err(),"fixture_stop":fixture_stop.as_ref().err()});
    let failure = execution.err().or_else(|| server_stop.err()).or_else(|| fixture_stop.err());
    drop(cash_lock);
    if let Some(cause) = &failure {
        for case in &mut cases {
            if case["cause"] == "readiness_not_reached" {
                case["status"] = json!(if cause.contains("timeout") {"failed"} else {"unavailable"});
                case["cause"] = json!(cause);
            }
        }
    }
    let passed = failure.is_none() && cases.iter().all(|r| r["status"] == "pass");
    let public_success = cases[0]["status"] == "pass" && cases[1]["status"] == "pass";
    let receipt = json!({"schema":1,"matrix":"FIX 8326","identity":identity,
        "engine":identity["engine"],"engine_binary_digest":identity["engine_binary_digest"],
        "driver_digest":identity["driver_digest"],"guest_image_digest":identity["guest_image_digest"],
        "public_success":passed && public_success,"private_refused":passed && cases[2]["status"] == "pass",
        "direct_bridge_refused":passed && cases[3]["status"] == "pass",
        "external_refused":passed && cases[4]["status"] == "pass",
        "fresh_admission_replay":passed && cases[5]["status"] == "pass",
        "forward_absent_cells_unavailable":cases[6]["status"] == "pass",
        "passed":passed,"stop_cause":failure,"cleanup":cleanup,"cases":cases,
        "transport_evidence":out.join("transport.json").exists().then_some("transport.json"),
        "browser_setup_evidence":out.join("browser-setup.json").exists().then_some("browser-setup.json")});
    write_json(&receipt_path, &receipt)?;
    if passed { Ok(()) } else { Err(format!("readiness_failed:{}",receipt_path.display())) }
}
