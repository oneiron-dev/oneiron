//! Assigned denominators, separate safety axes and descriptive medians only.
use std::{collections::{BTreeMap,BTreeSet}, fs, path::Path};
use serde_json::{Value,json};
use super::{Result, read, rows::{self,Row}, write_json};
fn median(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() { return None }
    values.sort_by(f64::total_cmp);
    let mid = values.len()/2;
    Some(if values.len()%2 == 0 { (values[mid-1]+values[mid])/2.0 } else { values[mid] })
}
#[derive(Default)]
struct Group {
    assigned: usize, terminal:usize, completed:usize, safe:usize, unknown_safety:usize, safety_violations:usize,
    full:usize, state_only:usize, stopped_safe:usize, count_mismatch:usize, timeout:usize,
    statuses:BTreeMap<String,usize>, totals:Vec<f64>, candidates:Vec<f64>, successes:Vec<f64>,
}
impl Group {
    fn value(&mut self) -> Value {
        json!({"assigned":self.assigned,"terminal":self.terminal,"executor_completed":self.completed,
            "checker_full_pass":self.full,"state_only_pass":self.state_only,"safe_observed":self.safe,
            "safety_unavailable":self.unknown_safety,"safety_violations":self.safety_violations,"stopped_safe":self.stopped_safe,
            "count_evidence_mismatches":self.count_mismatch,"timeouts":self.timeout,"statuses":self.statuses,
            "latency_observations":self.totals.len(),"latency_unavailable":self.assigned-self.totals.len(),
            "total_ms_observed_median":median(&mut self.totals),
            "candidate_ms_observed_median":median(&mut self.candidates),
            "successful_total_ms_median":median(&mut self.successes),
            "all_assigned_latency_median":null,"all_assigned_latency_reason":"blocked_missing_or_failed_assignments_are_not_imputed",
            "p95":null,"p95_reason":"screen_too_small"})
    }
}
pub(super) fn generate(input:&Path,out:&Path) -> Result<()> {
    let campaign: Value = read(&input.parent().ok_or("rows_parent_missing")?.join("campaign.json"))?;
    let plan = campaign["plan_digest"].as_str().ok_or("plan_digest_missing")?;
    let config = campaign["config_digest"].as_str().ok_or("config_digest_missing")?;
    let terminal = rows::terminal(input,plan,config)?;
    let cells = campaign["plan"]["cells"].as_array().ok_or("assigned_cells_missing")?;
    let engine = campaign["config"]["engine"].as_str().unwrap_or("unattested");
    let mut groups:BTreeMap<String,Group> = BTreeMap::new();
    let mut keys = BTreeSet::new();
    let mut observations = Vec::new();
    let mut pairs:BTreeMap<String,BTreeMap<String,Value>> = BTreeMap::new();
    for cell in cells {
        let id = cell["id"].as_str().ok_or("assigned_id_missing")?;
        let key = super::digest(format!("{plan}:{config}:{id}").as_bytes());
        keys.insert(key.clone());
        let arm = cell["arm"].as_str().ok_or("arm_missing")?;
        let fixture = cell["fixture"].as_str().ok_or("fixture_missing")?;
        let update = |group:&mut Group,row:Option<&Row>| {
            group.assigned += 1;
            if let Some(row) = row {
                group.terminal += 1; *group.statuses.entry(row.status.clone()).or_default() += 1;
                group.completed += usize::from(row.measures["executor_completed"] == true);
                let full = row.checker["full_pass"] == true;
                group.full += usize::from(full);
                group.state_only += usize::from(row.checker["state_only_pass"] == true);
                group.safe += usize::from(row.checker["safety_pass"] == true);
                group.safety_violations += usize::from(row.checker["safety_pass"] == false);
                group.unknown_safety += usize::from(row.checker["safety_pass"].is_null());
                group.count_mismatch += usize::from(row.checker["count_evidence_pass"] == false);
                group.stopped_safe += usize::from(!full && row.checker["safety_pass"] == true);
                group.timeout += usize::from(row.harness_stop.as_ref().is_some_and(|s| s["cause"].as_str().is_some_and(|c| c.ends_with("timeout"))));
                if let Some(v) = row.measures["elapsed_total_ms"].as_f64() {
                    group.totals.push(v); if full && row.status == "diagnostic_pass" { group.successes.push(v); }
                }
                if let Some(v) = row.measures["candidate_ms"].as_f64() { group.candidates.push(v); }
            } else { *group.statuses.entry("not_terminal".into()).or_default() += 1; group.unknown_safety += 1; }
        };
        let row = terminal.get(&key);
        if row.is_some_and(|r| r.engine != engine) { return Err("mixed_browser_screen_refused".into()) }
        update(groups.entry(format!("{engine}/{arm}")).or_default(),row);
        update(groups.entry(format!("{engine}/{arm}/{fixture}")).or_default(),row);
        let outcome = row.map_or_else(||json!({"status":"not_terminal","checker":null}),|r|json!({"status":r.status,"checker":r.checker,"harness_stop":r.harness_stop,"measures":r.measures,"evidence":r.evidence}));
        pairs.entry(format!("{fixture}/{}",cell["seed"])).or_default().insert(arm.into(),outcome.clone());
        observations.push(json!({"assignment":cell,"outcome":outcome}));
    }
    if terminal.keys().any(|key| !keys.contains(key)) { return Err("unassigned_terminal_row".into()) }
    let summaries:BTreeMap<_,_> = groups.iter_mut().map(|(key,g)| (key.clone(),g.value())).collect();
    let report = json!({"schema":1,"plan_digest":plan,"config_digest":config,"engine":engine,
        "assigned":cells.len(),"terminal":terminal.len(),"groups":summaries,"paired_outcomes":pairs,
        "observations":observations,"direction_screen_score":null,
        "score_reason":"diagnostic_approximations_and_unavailable_evidence_are_not_a_ratified_screen",
        "availability":super::measures::unavailable(),"authoring_yield":null,
        "amortisation":{"1":null,"5":null,"20":null,"reason":"S4_S5_not_in_PR1"},
        "cost_actual_usd":null,"cost_estimated_usd":null,
        "cash_ledger":campaign["config"]["cash_ledger"],
        "cash_note":"The pinned persistent ledger retains conservative commitments including lost responses, not an invoice; per-cell reservations and cumulative campaign balance are distinct"});
    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    write_json(&out.join("report.json"),&report)?;
    let mut markdown = format!("# CUA PR1 diagnostics — {engine}\n\nAssigned: {}. Terminal: {}. No direction-screen score.\n\n",cells.len(),terminal.len());
    markdown.push_str("| Group | Assigned | Full checker pass | Safe observed | Safety unknown | Timeouts | Observed total median ms |\n|---|---:|---:|---:|---:|---:|---:|\n");
    for (key,g) in &summaries { markdown.push_str(&format!("| {key} | {} | {} | {} | {} | {} | {} |\n",g["assigned"],g["checker_full_pass"],g["safe_observed"],g["safety_unavailable"],g["timeouts"],g["total_ms_observed_median"])); }
    markdown.push_str("\nMedians cover observed rows only, including timed-out failures. Successful-row medians and missing counts are separate in report.json. No p95. Safety violations never become accuracy points. C/C+/D use generative_reasoner diagnostic approximations (unavailable_e5). F2 provenance: unavailable_e6. TASK-before-planner: unavailable_e4. Authoring yield, N=1/5/20 amortisation, actual billing and kernel GPU seconds are unavailable. Full assigned and paired outcomes, evidence paths and stop causes are in report.json.\n");
    fs::write(out.join("report.md"),markdown).map_err(|e| e.to_string())
}
