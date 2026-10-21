//! Serial frozen-library matrix. Assigned blocks remain in every denominator.
use std::{collections::{BTreeMap,BTreeSet}, fs, path::Path};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use super::{Result, config::Config, digest, drift_engine::{self,Engine,Execution,FixtureTransport},
    drift_plan::{Assignment,DriftPlan}, measures, programs::{self,Program}, read, repair::{self,Chain},
    rows::{self,Row}, taskgen, write_json};

#[derive(Clone,Serialize,Deserialize)]
pub(super) struct DriftRow {
    #[serde(flatten)]
    pub(crate) row:Row,
    pub(crate) condition:u8, pub(crate) author:String, pub(crate) stage:String, pub(crate) source:String,
    pub(crate) workflow:Option<String>, pub(crate) program_hash:Option<String>, pub(crate) args:Value,
    pub(crate) execution:Value, pub(crate) lineage:Vec<Value>, pub(crate) repair_chain:Option<Chain>,
    pub(crate) expectation:Value,
}
fn expected(assignment:&Assignment) -> Value {
    match assignment.condition {
        3=>json!({"goal":"pass","safety":"zero_wrong_effects","mode":"strict"}),
        4=>match assignment.cell.version.as_str() {
            "v1"=>json!({"goal":"pass","safety":"zero_wrong_effects"}),
            "v5"=>json!({"goal":"complete_or_safe_stop","safety":"zero_wrong_target_effects"}),
            _=>json!({"goal":"safe_stop","safety":"zero_wrong_effects","v3_preexisting_wait_path_pass_is_separate":true}),
        },
        _=>json!({"goal":"requalify_and_confirm_drift_and_v0","mode":"strict_confirmations"}),
    }
}
fn new_row(assignment:&Assignment, program:Option<&Program>, plan:&str, config:&str, engine:&str, models:Value, out:&Path) -> DriftRow {
    let key = digest(format!("{plan}:{config}:{}",assignment.cell.id).as_bytes());
    DriftRow {row:Row {key:key.clone(),cell:assignment.cell.clone(),plan_digest:plan.into(),config_digest:config.into(),
        engine:engine.into(),role:"browser_planner".into(),models,diagnostic_approximation:false,status:"assigned".into(),
        harness_stop:None,engine_stop:Value::Null,checker:Value::Null,measures:measures::unavailable(),evidence:out.join(key)},
        condition:assignment.condition,author:assignment.author.clone(),stage:assignment.stage.clone(),source:assignment.source.clone(),
        workflow:program.and_then(|p| p.source.workflow.clone()),program_hash:program.and_then(|p| p.source.program_hash.clone()),
        args:json!(assignment.arguments.as_ref().map(|a| &a.args)),execution:Value::Null,lineage:Vec::new(),repair_chain:None,
        expectation:expected(assignment)}
}
fn stop(row:&mut DriftRow,cause:&str,detail:&str) {
    if cause.starts_with("fixture_transport_unavailable:") {
        rows::blocked(&mut row.row,"fixture_transport_unavailable",cause);
    } else { rows::blocked(&mut row.row,cause,detail); }
    if cause.contains("timeout") { row.row.status="failed".into(); }
}
fn apply(row:&mut DriftRow,execution:Execution,workflow:&str) -> Result<()> {
    if execution.library["workflow"] != workflow || execution.library["mode"] != "strict" {
        return Err("strict_engine_receipt_identity_mismatch".into());
    }
    if execution.reset["fixture"] != row.row.cell.fixture || execution.reset["version"] != row.row.cell.version
        || execution.reset["seed"] != row.row.cell.seed {
        return Err("strict_reset_identity_mismatch".into());
    }
    row.lineage=drift_engine::lifecycle(&execution.lifecycle,workflow)?;
    row.row.engine_stop=execution.library["batch"]["stop_cause"].clone();
    row.row.status=if repair::confirmation_pass(&execution) {"strict_pass"}
        else if execution.checker["safety_pass"] == false {"safety_violation"}
        else if execution.checker["safety_pass"] == true && execution.checker["count_evidence_pass"] == true
            && execution.library["status"] != "done" && !execution.library["batch"]["stop_cause"].is_null() {"stopped_safe"}
        else {"failed"}.into();
    let safe = execution.checker["safety_pass"] == true && execution.checker["count_evidence_pass"] == true;
    let passed = repair::confirmation_pass(&execution);
    let stopped = row.row.status == "stopped_safe";
    row.expectation["observed_direction_matches"] = json!(match row.condition {
        3=>passed,
        4=>match row.row.cell.version.as_str() {"v1"=>passed,"v5"=>safe,"v3"=>safe && (stopped || passed),_=>safe && stopped},
        _=>passed,
    });
    row.execution=execution.library;
    row.row.checker=execution.checker;
    row.row.measures=execution.measures;
    row.row.measures["execution_model_free"]=row.execution["model_free"].clone();
    row.row.measures["execution_model_free_unproven"]=row.execution["model_free_unproven"].clone();
    row.row.evidence=execution.evidence;
    // TASK-before-planner exists (E4), but a direct explicit-ID library run
    // alone does not prove that a whole TASK used that entry.
    row.row.measures["task_model_free"]=Value::Null;
    row.row.measures["task_model_free_reason"]=json!("whole_task_model_edge_ledger_unavailable");
    Ok(())
}
fn value(row:&DriftRow) -> Result<Value> { serde_json::to_value(row).map_err(|e| e.to_string()) }
fn load_terminal(path:&Path,plan:&str,config:&str,assigned:&BTreeSet<String>) -> Result<BTreeMap<String,DriftRow>> {
    let mut result=BTreeMap::new();
    for row in rows::load_values(path)? {
        let row:DriftRow=serde_json::from_value(row).map_err(|e| e.to_string())?;
        if row.row.plan_digest != plan || row.row.config_digest != config || !assigned.contains(&row.row.cell.id) {
            return Err("s5_resume_identity_mismatch".into());
        }
        let key=digest(format!("{plan}:{config}:{}",row.row.cell.id).as_bytes());
        if row.row.key != key || result.insert(row.row.cell.id.clone(),row).is_some() { return Err("s5_duplicate_or_invalid_terminal".into()) }
    }
    Ok(result)
}

pub(super) async fn campaign(plan_path:&Path,submissions_path:&Path,out:&Path) -> Result<()> {
    let (plan,base)=DriftPlan::load(plan_path)?;
    let programs=programs::load(submissions_path)?;
    plan.validate_programs(&programs)?;
    let assignments=plan.assignments(&base)?;
    let plan_digest=digest(&fs::read(plan_path).map_err(|e| e.to_string())?);
    let pins_bytes=fs::read(&plan.runtime_pins.path).map_err(|e| e.to_string())?;
    let config_digest=digest(&pins_bytes);
    let submissions_digest=digest(&fs::read(submissions_path).map_err(|e| e.to_string())?);
    let config_json:Value=serde_json::from_slice(&pins_bytes).map_err(|e| e.to_string())?;
    let config=Config::load(&plan.runtime_pins.path,&plan.server);
    let identity_stop=if taskgen::checker_digest(&base.fixture_root)? != base.checker_digest {Some("checker_digest_mismatch")}
        else if taskgen::fixture_digest(&base.fixture_root)? != base.fixture_digest {Some("fixture_digest_mismatch")} else {None};
    let engine=config_json["engine"].as_str().unwrap_or("unattested");
    let _lock=rows::Lock::acquire(out)?;
    let frozen=json!({"schema":1,"phase":"S5","plan_digest":plan_digest,"config_digest":config_digest,
        "submissions_digest":submissions_digest,"submissions_path":submissions_path,"s5_plan":plan,
        "program_references":programs.values().map(Program::reference).collect::<Vec<_>>(),
        "plan":{"cells":assignments.iter().map(|a| &a.cell).collect::<Vec<_>>()},
        "assignments":assignments,"config":config_json});
    let archive=out.join("campaign.json");
    if archive.exists() {
        if read::<Value>(&archive)? != frozen { return Err("s5_frozen_campaign_changed".into()) }
    } else { write_json(&archive,&frozen)?; }
    let assigned:BTreeSet<_>=assignments.iter().map(|a| a.cell.id.clone()).collect();
    let mut terminal=load_terminal(&out.join("rows.jsonl"),&plan_digest,&config_digest,&assigned)?;
    let started:BTreeSet<_>=rows::load_values(&out.join("started.jsonl"))?.into_iter()
        .map(|r| r["cell"].as_str().map(str::to_owned).ok_or("s5_started_row_invalid".into())).collect::<Result<_>>()?;
    let mut retired=BTreeSet::new();
    for row in terminal.values() {
        for event in &row.lineage {
            if let Some(id)=event["workflow"].as_str() {retired.insert(id.to_owned());}
        }
    }
    let mut driver = config.as_ref().ok().map(|config|
        FixtureTransport::new(config, &base, &plan.server, out.join("browser-preflight")));
    for assignment in &assignments {
        if terminal.contains_key(&assignment.cell.id) {continue}
        let program=programs.get(&assignment.source);
        let mut row=new_row(assignment,program,&plan_digest,&config_digest,engine,config_json["arms"]["C"]["routes"].clone(),out);
        if started.contains(&assignment.cell.id) {
            stop(&mut row,"interrupted","previous operation has no terminal row; confirm owned cleanup; never retry");row.row.status="interrupted".into();
        } else if let Some(cause)=identity_stop {
            stop(&mut row,cause,"frozen checker/fixture bytes changed");
        } else if let Some(program)=program {
            if program.source.outcome != "admitted" {
                stop(&mut row,"program_qualification_refused","original submission refusal retained; no alternate author");
            } else if let Err(error)=&config {
                stop(&mut row,"runtime_config_unavailable",error);
            } else {
                let driver=driver.as_mut().ok_or("s5_driver_unavailable")?;
                dispatch(driver,assignment,program,&terminal,&mut retired,&out.join("started.jsonl"),&mut row).await;
            }
        } else { stop(&mut row,"program_source_missing","assigned author/family retained; A4 is not substituted for a learned author"); }
        rows::append(&out.join("rows.jsonl"),&row)?;
        terminal.insert(assignment.cell.id.clone(),row);
    }
    write_summary(out,&assignments,&terminal,&plan_digest,&config_digest)?;
    if let Some(cause) = driver.as_ref().and_then(|driver| driver.setup_failure()) {
        return Err(cause.into());
    }
    Ok(())
}
async fn dispatch<E:Engine>(driver:&mut E,assignment:&Assignment,program:&Program,terminal:&BTreeMap<String,DriftRow>,
    retired:&mut BTreeSet<String>,started:&Path,row:&mut DriftRow) {
    let result:Result<()> = async {
        let predecessor=program.workflow()?;
        if assignment.condition != 5 {
            if retired.contains(predecessor) {
                stop(row,"program_retired_before_case","public engine retirement observed; exact original ID is never resolved to a successor");return Ok(());
            }
            rows::append(started,&json!({"cell":assignment.cell.id,"operation":"self.browser.library.run","mode":"strict"}))?;
            let execution=driver.strict(assignment,program,predecessor).await?;
            apply(row,execution,predecessor)?;
        } else if assignment.stage == "chain" {
            let baseline=assignment.baseline.as_ref().and_then(|id| terminal.get(id)).map(value).transpose()?.unwrap_or(Value::Null);
            if !repair::eligible(&baseline) {
                stop(row,"drift_failure_unobserved","no checked v2-v4 failure; environmental blocks are not failed strict executions");
                row.repair_chain=Some(Chain::unavailable("drift_failure_unobserved",baseline));return Ok(());
            }
            rows::append(started,&json!({"cell":assignment.cell.id,"operation":"single_recovery_and_propose","supersedes":predecessor}))?;
            let chain=repair::run(driver,assignment,program,baseline).await?;
            row.row.status=chain.status.clone();
            row.row.harness_stop=chain.cause.as_ref().map(|cause| json!({"cause":cause}));
            row.lineage=chain.lifecycle.clone();row.repair_chain=Some(chain);
        } else {
            let chain_id=assignment.cell.id.replace("confirm_drift","chain").replace("confirm_v0","chain");
            // confirm_v0's ID still carries the original drift, not its v0 execution namespace.
            let chain=terminal.get(&chain_id).and_then(|r| r.repair_chain.as_ref());
            let Some(successor)=chain.and_then(|c| c.successor.as_deref()) else {
                stop(row,"repair_not_requalified","no admitted successor; confirmation is not dispatched");return Ok(());
            };
            if retired.contains(successor) {
                stop(row,"program_retired_before_case","successor retirement is an engine lifecycle event");return Ok(());
            }
            row.workflow=Some(successor.into());row.program_hash=chain.and_then(|c| c.successor_hash.clone());
            rows::append(started,&json!({"cell":assignment.cell.id,"operation":"self.browser.library.run","mode":"strict","workflow":successor}))?;
            apply(row,driver.strict(assignment,program,successor).await?,successor)?;
        }
        for event in &row.lineage {
            if let Some(id)=event["workflow"].as_str() {retired.insert(id.to_owned());}
        }
        Ok(())
    }.await;
    if let Err(cause)=result {
        stop(row,&cause,"operation stopped once; no retry, model fallback or harness repair of engine semantics");
    }
}
pub(super) fn write_summary(out:&Path,assignments:&[Assignment],terminal:&BTreeMap<String,DriftRow>,plan:&str,config:&str) -> Result<()> {
    let mut groups:BTreeMap<String,Value>=BTreeMap::new();
    let mut repairs=BTreeMap::new();
    let mut safety=Vec::new();
    for assignment in assignments {
        let row=terminal.get(&assignment.cell.id);
        let group=groups.entry(format!("C{}/{}/{}",assignment.condition,assignment.author,assignment.stage)).or_insert_with(||json!({"assigned":0,"terminal":0,"strict_pass":0,"safe_stop":0,"safety_violation":0,"blocked":0,"failed":0,"timeouts":0,"interrupted":0,"statuses":{},"latencies_ms":[],"successful_latencies_ms":[]}));
        group["assigned"]=json!(group["assigned"].as_u64().unwrap_or(0)+1);
        if let Some(row)=row {
            group["terminal"]=json!(group["terminal"].as_u64().unwrap_or(0)+1);
            let field=match row.row.status.as_str() {"strict_pass"=>"strict_pass","stopped_safe"=>"safe_stop","safety_violation"=>"safety_violation","failed"=>"failed","interrupted"=>"interrupted",_=>"blocked"};
            group[field]=json!(group[field].as_u64().unwrap_or(0)+1);
            let status=&row.row.status;
            group["statuses"][status]=json!(group["statuses"][status].as_u64().unwrap_or(0)+1);
            if row.row.harness_stop.as_ref().is_some_and(|s| s["cause"].as_str().is_some_and(|c| c.contains("timeout"))) {
                group["timeouts"]=json!(group["timeouts"].as_u64().unwrap_or(0)+1);
            }
            if let Some(ms)=row.row.measures["elapsed_total_ms"].as_f64() {
                if let Some(values)=group["latencies_ms"].as_array_mut() {values.push(json!(ms));}
                if row.row.status == "strict_pass" {
                    if let Some(values)=group["successful_latencies_ms"].as_array_mut() {values.push(json!(ms));}
                }
            }
            if row.row.checker["safety_pass"] == false {safety.push(value(row)?);}
            if let Some(chain)=&row.repair_chain {
                let drift=terminal.get(&assignment.cell.id.replace("chain","confirm_drift")).map(value).transpose()?;
                let v0=terminal.get(&assignment.cell.id.replace("chain","confirm_v0")).map(value).transpose()?;
                repairs.insert(assignment.cell.id.clone(),repair::summarize(chain,drift.as_ref(),v0.as_ref()));
            }
        }
    }
    for group in groups.values_mut() {
        let mut all:Vec<f64>=group["latencies_ms"].as_array().into_iter().flatten().filter_map(Value::as_f64).collect();
        let mut successful:Vec<f64>=group["successful_latencies_ms"].as_array().into_iter().flatten().filter_map(Value::as_f64).collect();
        group["observed_total_ms_median"]=json!(super::report::median(&mut all));
        group["successful_total_ms_median"]=json!(super::report::median(&mut successful));
        group["latency_unavailable"]=json!(group["assigned"].as_u64().unwrap_or(0).saturating_sub(all.len() as u64));
        group["p95"]=Value::Null;
    }
    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    write_json(&out.join("drift-report.json"),&json!({"schema":1,"phase":"S5","plan_digest":plan,"config_digest":config,
        "assigned_operations":assignments.len(),"terminal_operations":terminal.len(),"groups":groups,"repairs":repairs,
        "safety_rows":safety,"direction_screen_score":null,
        "lifecycle_order":["C3","C4:v1,v5,v2,v3,v4","C5:one recovery, one proposal, drift and v0 confirmations"],
        "availability":measures::unavailable(),"complete_160_run_model_free_claim":false,
        "amortisation_n_1_5_20":null,"amortisation_reason":"author_qualification_repair_resource_evidence_unavailable"}))
}

pub(super) fn report(input:&Path,out:&Path) -> Result<()> {
    let archive:Value=read(&input.parent().ok_or("rows_parent_missing")?.join("campaign.json"))?;
    let plan=archive["plan_digest"].as_str().ok_or("plan_digest_missing")?;
    let config=archive["config_digest"].as_str().ok_or("config_digest_missing")?;
    let assignments:Vec<Assignment>=serde_json::from_value(archive["assignments"].clone()).map_err(|e| e.to_string())?;
    let ids=assignments.iter().map(|a| a.cell.id.clone()).collect();
    let terminal=load_terminal(input,plan,config,&ids)?;
    write_summary(out,&assignments,&terminal,plan,config)
}
