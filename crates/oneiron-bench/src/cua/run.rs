//! One assigned trial, one original deadline and no failure retries.
use std::{collections::BTreeSet, fs, path::Path, sync::{Arc,Mutex}, time::{Duration,SystemTime,UNIX_EPOCH}};
use serde_json::{Value,json};
use tokio::time::Instant;
use super::{Result, check, config::Config, digest, fixture::{self,Fixture}, measures,
    provider_gate::{Gate, Ledger}, read, rows::{self,Row}, served::Served,
    taskgen::{self,Cell,Plan}, write_json};

fn validate_plan(plan: &Plan) -> Result<()> {
    if plan.schema != 1 || plan.checker_version != taskgen::CHECKER_VERSION || plan.cells.len() != 51 {
        return Err("frozen_plan_shape_mismatch".into());
    }
    let mut ids = BTreeSet::new();
    for cell in &plan.cells {
        if cell.id.is_empty() || !cell.id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b,b'-'|b'+'))
            || !ids.insert(&cell.id) || cell.version != "v0" || !(1..=3).contains(&cell.repetition)
            || !matches!(cell.arm.as_str(),"B"|"C"|"C+"|"D") || cell.public_task.contains("/state/") {
            return Err("frozen_cell_invalid".into());
        }
        let (seconds,actions) = match cell.fixture.as_str() {"F1"=>(420,120),"F2"=>(60,20),"F3"=>(300,60),"F4"=>(120,20),"F5"=>(600,60),_=>return Err("unknown_fixture".into())};
        if (cell.seconds,cell.actions) != (seconds,actions) { return Err("fixture_caps_mismatch".into()) }
        if cell.arm == "C+" && !matches!(cell.fixture.as_str(),"F2"|"F4") { return Err("c_plus_fixture_mismatch".into()) }
        let seeds = plan.evaluation_seeds.get(&cell.fixture).ok_or("evaluation_seeds_missing")?;
        if seeds.len() != 3 || seeds[cell.repetition as usize-1] != cell.seed { return Err("paired_seed_mismatch".into()) }
    }
    for fixture in ["F1","F2","F3","F4","F5"] {
        for arm in ["B","C","D"] {
            for repetition in 1..=3 {
                if plan.cells.iter().filter(|c| c.fixture == fixture && c.arm == arm && c.repetition == repetition).count() != 1 {
                    return Err("assigned_cell_coverage_mismatch".into());
                }
            }
        }
    }
    Ok(())
}
pub(super) async fn campaign(plan_path: &Path, binary: &Path, pins: &Path, out: &Path) -> Result<()> {
    let plan: Plan = read(plan_path)?; validate_plan(&plan)?;
    let plan_digest = digest(&fs::read(plan_path).map_err(|e| e.to_string())?);
    let config_bytes = fs::read(pins).map_err(|e| e.to_string())?;
    let config_digest = digest(&config_bytes);
    let _lock = rows::Lock::acquire(out)?;
    let archive = out.join("campaign.json");
    let frozen = json!({"plan_digest":plan_digest,"config_digest":config_digest,"plan":plan,
        "config":serde_json::from_slice::<Value>(&config_bytes).map_err(|e| e.to_string())?});
    if archive.exists() {
        if read::<Value>(&archive)? != frozen { return Err("resume_campaign_mismatch".into()) }
    } else { write_json(&archive,&frozen)?; }
    let config = Config::load(pins,binary);
    let identity_error = if taskgen::checker_digest(&plan.fixture_root)? != plan.checker_digest {
        Some("checker_digest_mismatch")
    } else if taskgen::fixture_digest(&plan.fixture_root)? != plan.fixture_digest {
        Some("fixture_digest_mismatch")
    } else { None };
    let terminal = rows::terminal(&out.join("rows.jsonl"),&plan_digest,&config_digest)?;
    let started: BTreeSet<_> = rows::load_values(&out.join("started.jsonl"))?.into_iter()
        .map(|r| r["key"].as_str().map(str::to_owned).ok_or("started_row_malformed".to_owned()))
        .collect::<Result<_>>()?;
    let _cash_lock = if let Ok(config) = &config {
        Some(rows::Lock::acquire(&config.cash_ledger.with_extension("lock-dir"))?)
    } else { None };
    let ledger = if let Ok(config) = &config {
        Some(Arc::new(Mutex::new(Ledger::open(&config.cash_ledger,&config_digest)?)))
    } else { None };
    for cell in &plan.cells {
        let key = digest(format!("{plan_digest}:{config_digest}:{}",cell.id).as_bytes());
        if terminal.contains_key(&key) { continue }
        let engine = config.as_ref().map(|c| c.engine.clone()).unwrap_or_else(|_| frozen["config"]["engine"].as_str().unwrap_or("unattested").into());
        let mut row = Row {key:key.clone(),cell:cell.clone(),plan_digest:plan_digest.clone(),config_digest:config_digest.clone(),
            engine,role:"generative_reasoner".into(),models:frozen["config"]["arms"][&cell.arm]["routes"].clone(),diagnostic_approximation:cell.arm != "B",status:"assigned".into(),
            harness_stop:None,engine_stop:Value::Null,checker:Value::Null,measures:measures::unavailable(),evidence:out.join(&key)};
        if started.contains(&key) {
            rows::blocked(&mut row,"interrupted","previous trial started without a terminal row; no rerun");
            row.status = "interrupted".into();
        } else if let Some(reason) = identity_error {
            rows::blocked(&mut row,reason,"frozen evidence changed; no candidate dispatched");
        } else {
            match &config {
                Err(error) => rows::blocked(&mut row,"runtime_config_unavailable",error),
                Ok(config) => match ledger.as_ref().and_then(|l| l.lock().ok().and_then(|l| l.blocked(cell.arm == "D"))) {
                    Some(stop) => {
                        row.status = "blocked".into();
                        row.harness_stop = Some(json!({"cause":stop,"scope":"campaign_provider_gate"}));
                    }
                    None => match fixture::transport_ready(config) {
                    Err(cause) => rows::blocked(&mut row,&cause,"FIX 8061: served dynamic PUBLIC-only fixture transport is not available; no file mount or guest bypass"),
                    Ok(()) => {
                        rows::append(&out.join("started.jsonl"),&json!({"key":key,"cell":cell.id}))?;
                        fs::create_dir(&row.evidence).map_err(|e| e.to_string())?;
                        let result = trial(&plan,config,binary,cell,&mut row,ledger.as_ref().ok_or("cash_ledger_missing")?.clone()).await;
                        if let Err(error) = result {
                            row.status = "failed".into();
                            if row.harness_stop.is_none() {
                                row.harness_stop = Some(json!({"cause":if error.contains("timeout") {"timeout"} else {"run_failed"},"detail":error}));
                            }
                        }
                    }
                    }
                }
            }
        }
        rows::append(&out.join("rows.jsonl"),&row)?;
    }
    Ok(())
}

async fn trial(plan: &Plan, config: &Config, binary: &Path, cell: &Cell, row: &mut Row,
    ledger: Arc<Mutex<Ledger>>) -> Result<()> {
    if config.navigation_evidence.is_none() { return Err("browser_navigation_unavailable".into()) }
    if config.action_policy == "require_hard_cap" { return Err("public_effect_stream_unavailable".into()) }
    let arm = config.arms.get(&cell.arm).ok_or("arm_unavailable")?;
    if arm.deployment_evidence.is_none() { return Err("model_deployment_unavailable".into()) }
    let started = Instant::now();
    let utc = || SystemTime::now().duration_since(UNIX_EPOCH).map(|v| v.as_secs_f64()).map_err(|e| e.to_string());
    let start_utc = utc()?;
    let deadline = started + Duration::from_secs(cell.seconds);
    let startup_deadline = deadline.min(started+Duration::from_secs(config.startup_seconds));
    write_json(&row.evidence.join("assignment.json"),cell)?;
    let mut gate = Gate::start(&arm.routes,ledger.clone(),&cell.id,&row.evidence.join("provider.jsonl")).await?;
    let mut fixture = match Fixture::start(plan,&row.evidence,startup_deadline).await {
        Ok(f) => f,
        Err(e) => {
            row.measures["elapsed_total_ms"] = json!(started.elapsed().as_secs_f64()*1000.0);
            return Err(e);
        }
    };
    let reset = match fixture.reset(cell,deadline).await {
        Ok(reset) => reset,
        Err(e) => {
            let _ = fixture.stop().await;
            row.measures["elapsed_total_ms"] = json!(started.elapsed().as_secs_f64()*1000.0);
            return Err(e);
        }
    };
    write_json(&row.evidence.join("reset.json"),&reset)?;
    let mut served = None;
    let mut setup_ms = 0.0;
    let mut candidate_ms = 0.0;
    let mut receipts = Vec::new();
    let mut artifact_files = json!({});
    let execution: Result<()> = async {
        served = Some(Served::fresh(binary,&row.evidence,arm,&config.browser,
            startup_deadline.saturating_duration_since(Instant::now()),Duration::from_millis(config.continuation_poll_ms)).await?);
        setup_ms = started.elapsed().as_secs_f64()*1000.0;
        let task = cell.public_task.replace("{entry_url}",&format!("http://172.30.91.1:8765{}",reset["entry"].as_str().ok_or("reset_entry_missing")?));
        let candidate_start = Instant::now();
        let bridge = served.as_mut().ok_or("served_bridge_missing")?;
        let result: Result<()> = async {
            loop {
                let result = bridge.execute(&cell.id,&task,deadline).await?;
                let status = result["result"]["status"].as_str().ok_or("executor_status_missing")?.to_owned();
                receipts.push(result.clone());
                if measures::observed_effects(&receipts) > cell.actions as usize {
                    return Err("action_cap_overshoot".into());
                }
                match status.as_str() {
                    "complete" => {
                        row.measures["executor_completed"] = json!(true);
                        if cell.fixture == "F1" { artifact_files = bridge.artifacts(&cell.id,&result,deadline).await?; }
                        break;
                    }
                    "yielded" => {}
                    "window_full" => tokio::time::sleep_until((Instant::now()+Duration::from_millis(config.continuation_poll_ms)).min(deadline)).await,
                    "waiting" => return Err("needs_you_no_send_approval".into()),
                    other => return Err(format!("executor_terminal_status:{other}")),
                }
                if Instant::now() >= deadline { return Err("timeout".into()) }
            }
            Ok(())
        }.await;
        candidate_ms = candidate_start.elapsed().as_secs_f64()*1000.0;
        result
    }.await;
    let completed = row.measures["executor_completed"].clone();
    if setup_ms == 0.0 { setup_ms = started.elapsed().as_secs_f64()*1000.0; }
    // No reset follows a still-live candidate. The engine owns its guest pipe.
    gate.stop();
    let stopped = match served.as_mut() { Some(s) => s.stop().await, None => Ok(()) };
    fixture.settle(Duration::from_secs(config.settle_seconds)).await;
    let capture_deadline = Instant::now()+Duration::from_secs(config.settle_seconds);
    let snapshot = fixture.snapshot(cell,capture_deadline).await;
    let fixture_stopped = fixture.stop().await;
    let capture_end = utc()?;
    let captured_seconds = started.elapsed().as_secs_f64();
    row.measures["elapsed_total_ms"] = json!(captured_seconds*1000.0);
    row.measures["candidate_ms"] = json!(candidate_ms);
    row.measures["setup_ms"] = json!(setup_ms);
    // Retain raw receipts even when final state or the checker is unavailable.
    write_json(&row.evidence.join("engine-receipts.json"),&receipts)?;
    let state = snapshot?;
    write_json(&row.evidence.join("state.json"),&state)?;
    let events = rows::load_values(&fixture.events)?;
    row.checker = check::evaluate(plan,&row.evidence,&reset,&state,&events,artifact_files,capture_deadline).await?;
    let (mut observed,engine_stop,browser_stop) = measures::observe(&receipts,&config.engine);
    observed["executor_completed"] = completed;
    observed["elapsed_total_ms"] = json!(started.elapsed().as_secs_f64()*1000.0);
    observed["setup_ms"] = json!(setup_ms); observed["candidate_ms"] = json!(candidate_ms);
    observed["drain_checker_ms"] = json!(started.elapsed().as_secs_f64()*1000.0-setup_ms-candidate_ms);
    observed["first_useful"] = measures::first_useful(&row.checker,&cell.fixture,start_utc,capture_end,captured_seconds,config.clock_tolerance_ms);
    observed["observed_distinct_effect_receipts_lower_bound"] = json!(measures::observed_effects(&receipts));
    observed["action_cap_overshoot"] = if measures::observed_effects(&receipts) > cell.actions as usize {json!(true)} else {Value::Null};
    let physical = rows::load_values(&config.cash_ledger)?;
    let calls: Vec<_> = physical.iter().filter(|r| r["cell"] == cell.id && r["inference"] == true).collect();
    observed["physical_calls"] = json!(calls.len());
    let reserved: u64 = calls.iter().filter_map(|r| r["reserved_microusd"].as_u64()).sum();
    observed["cash_reservation_usd"] = json!(reserved as f64/1_000_000.0);
    observed["campaign_cash_reservation_usd"] = json!(ledger.lock().map_err(|_| "cash_ledger_lock_failed")?.reserved() as f64/1_000_000.0);
    let provider_stop = ledger.lock().map_err(|_| "cash_ledger_lock_failed")?.blocked(cell.arm == "D");
    if let Some(stop) = provider_stop {
        row.harness_stop = Some(json!({"cause":stop,"scope":"provider_gate"}));
    }
    row.measures = observed; row.engine_stop = engine_stop;
    stopped?; fixture_stopped?; execution?;
    if row.harness_stop.is_some() { return Err("provider_gate_terminal".into()) }
    if let Some(reason) = browser_stop { return Err(reason) }
    // Until the engine transport lane proves cleanup and effect coverage,
    // even a checker pass is diagnostic, not a direction-screen pass.
    row.harness_stop = Some(json!({"cause":"evidence_incomplete","detail":"guest_teardown_and_primitive_effect_trace_unproven"}));
    row.status = "evidence_incomplete".into();
    Ok(())
}
