//! Frozen S5 selection, arguments, deadlines and published serial order.
use std::{collections::{BTreeMap,BTreeSet}, path::{Path,PathBuf}};
use serde::{Deserialize, Serialize};
use serde_json::{Value,json};
use super::{Result, config::Evidence, programs::{self,Program}, read, taskgen::{self,Cell,Plan}};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Arguments { pub(crate) seed:u64, pub(crate) args:BTreeMap<String,String> }
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Confirmation { pub(crate) drift:Arguments, pub(crate) regression:Arguments }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Evaluation {
    pub(crate) entry_param:String,
    pub(crate) replays:Vec<Arguments>,
    pub(crate) versions:BTreeMap<String,Arguments>,
    pub(crate) confirmations:BTreeMap<String,Confirmation>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DriftPlan {
    pub(crate) schema:u32, pub(crate) phase:String,
    pub(crate) base_plan:Evidence, pub(crate) runtime_pins:Evidence, pub(crate) server:PathBuf,
    pub(crate) conditions:Vec<u8>, pub(crate) authors:Vec<String>, pub(crate) fixtures:Vec<String>,
    pub(crate) drift_order:Vec<String>, pub(crate) recovery_arm:String,
    pub(crate) recovery_task:PathBuf, pub(crate) recovery_task_digest:String,
    pub(crate) evaluations:BTreeMap<String,Evaluation>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Assignment {
    pub(crate) cell:Cell, pub(crate) condition:u8, pub(crate) author:String, pub(crate) stage:String,
    pub(crate) source:String, pub(crate) arguments:Option<Arguments>, pub(crate) baseline:Option<String>,
}
impl DriftPlan {
    pub(crate) fn load(path:&Path) -> Result<(Self,Plan)> {
        let plan:Self = read(path)?;
        if plan.schema != 1 || plan.phase != "S5" || !plan.server.is_absolute()
            || plan.recovery_arm != "C" || plan.drift_order != ["v1","v5","v2","v3","v4"] {
            return Err("s5_plan_identity_or_order_invalid".into());
        }
        fn selection<T:Ord>(values:&[T], allowed:&[T]) -> bool {
            !values.is_empty() && values.iter().collect::<BTreeSet<_>>().len() == values.len()
                && values.iter().all(|value| allowed.contains(value))
        }
        if !selection(&plan.conditions,&[3,4,5]) || (plan.conditions.contains(&5) && !plan.conditions.contains(&4))
            || !selection(&plan.authors,&["A1".into(),"A2".into(),"A3".into(),"A4".into()])
            || !selection(&plan.fixtures,&["F1".into(),"F2".into(),"F3".into(),"F4".into(),"F5".into()]) {
            return Err("s5_explicit_selection_invalid".into());
        }
        let base:Plan = serde_json::from_value(plan.base_plan.load()?).map_err(|e| e.to_string())?;
        if base.schema != 1 || base.checker_version != taskgen::CHECKER_VERSION {
            return Err("s5_base_plan_invalid".into());
        }
        plan.runtime_pins.load()?;
        if super::digest(&std::fs::read(&plan.recovery_task).map_err(|e| e.to_string())?) != plan.recovery_task_digest {
            return Err("recovery_task_pin_mismatch".into());
        }
        Ok((plan,base))
    }
    pub(crate) fn validate_programs(&self, programs:&BTreeMap<String,Program>) -> Result<()> {
        let selected:BTreeSet<_> = self.fixtures.iter().flat_map(|f| self.authors.iter().map(move |a| programs::key(f,a))).collect();
        if self.evaluations.keys().any(|k| !selected.contains(k)) { return Err("unselected_evaluation".into()) }
        for source in &selected {
            let Some(program) = programs.get(source).filter(|p| p.source.outcome == "admitted") else { continue };
            let evaluation = self.evaluations.get(source).ok_or("admitted_program_evaluation_missing")?;
            if !program.params.contains(&evaluation.entry_param) { return Err("version_namespace_slot_missing".into()) }
            let proposal = program.source.proposal.as_ref().ok_or("proposal_missing")?.load()?;
            let open = proposal["steps"][0]["url"].as_str().ok_or("first_open_missing")?;
            if proposal["steps"][0]["step"] != "open" || !open.starts_with("http://127.0.0.1:8080/")
                || !open.contains(&format!("{{{{{}}}}}",evaluation.entry_param)) {
                return Err("frozen_program_fixture_origin_or_namespace_invalid".into());
            }
            if evaluation.replays.len() != 3
                || evaluation.versions.keys().map(String::as_str).collect::<BTreeSet<_>>() != BTreeSet::from(["v0","v1","v2","v3","v4","v5"])
                || evaluation.confirmations.keys().map(String::as_str).collect::<BTreeSet<_>>() != BTreeSet::from(["v2","v3","v4"]) {
                return Err("s5_argument_matrix_incomplete".into());
            }
            let mut replay_seeds = BTreeSet::new();
            for arguments in evaluation.replays.iter().chain(evaluation.versions.values())
                .chain(evaluation.confirmations.values().flat_map(|c| [&c.drift,&c.regression])) {
                if arguments.args.keys().cloned().collect::<BTreeSet<_>>() != program.params
                    || arguments.args.get(&evaluation.entry_param).map(String::as_str) != Some("{entry}") {
                    return Err("frozen_argument_schema_or_entry_invalid".into());
                }
            }
            for arguments in &evaluation.replays {
                if [program.source.solved_seed,program.source.qualification_seed].contains(&arguments.seed)
                    || !replay_seeds.insert(arguments.seed) {
                    return Err("evaluation_not_held_out".into());
                }
            }
            let v0 = &evaluation.versions["v0"];
            for arguments in evaluation.versions.values() {
                if arguments.seed != v0.seed || arguments.args != v0.args { return Err("unmatched_drift_data".into()) }
            }
            for confirmation in evaluation.confirmations.values() {
                if confirmation.drift.seed != confirmation.regression.seed || confirmation.drift.args != confirmation.regression.args
                    || [program.source.solved_seed,program.source.qualification_seed,v0.seed].contains(&confirmation.drift.seed)
                    || replay_seeds.contains(&confirmation.drift.seed) {
                    return Err("repair_confirmation_not_paired_held_out".into());
                }
            }
        }
        Ok(())
    }
    pub(crate) fn assignments(&self, base:&Plan) -> Result<Vec<Assignment>> {
        let mut assignments = Vec::new();
        // Every original is measured before any proposal can supersede it.
        for condition in [3,4,5].into_iter().filter(|c| self.conditions.contains(c)) {
            for fixture in &self.fixtures {
                let template = base.cells.iter().find(|c| &c.fixture == fixture && c.arm == "C").ok_or("fixture_caps_missing")?;
                let caps = match fixture.as_str() {"F1"=>(420,120),"F2"=>(60,20),"F3"=>(300,60),"F4"=>(120,20),"F5"=>(600,60),_=>return Err("unknown_fixture".into())};
                if (template.seconds,template.actions) != caps { return Err("fixture_caps_mismatch".into()) }
                for author in &self.authors {
                    if condition == 5 && !matches!(author.as_str(),"A1"|"A4") { continue }
                    let source = programs::key(fixture,author);
                    let evaluation = self.evaluations.get(&source);
                    let versions:Vec<_> = match condition {3=>vec!["v0","v0","v0"],4=>self.drift_order.iter().map(String::as_str).collect(),_=>vec!["v2","v3","v4"]};
                    for (index,version) in versions.into_iter().enumerate() {
                        let stages:&[&str] = if condition == 5 { &["chain","confirm_drift","confirm_v0"] } else { &["strict"] };
                        for stage in stages {
                            let mut cell = template.clone();
                            cell.id = format!("{source}-C{condition}-{}-{version}-{stage}",index+1);
                            cell.version = if *stage == "confirm_v0" {"v0"} else {version}.into();
                            cell.repetition = index as u32+1;
                            let arguments = evaluation.and_then(|e| match condition {
                                3=>e.replays.get(index),4=>e.versions.get(version),
                                5 if *stage == "chain"=>e.versions.get(version),
                                _=>e.confirmations.get(version).map(|c| if *stage == "confirm_v0" {&c.regression} else {&c.drift}),
                            }).cloned();
                            if let Some(arguments) = &arguments { cell.seed = arguments.seed; }
                            let baseline = if condition == 5 { Some(format!("{source}-C4-{}-{version}-strict",index+3)) } else {None};
                            assignments.push(Assignment {cell,condition,author:author.clone(),stage:(*stage).into(),source:source.clone(),arguments,baseline});
                        }
                    }
                }
            }
        }
        Ok(assignments)
    }
}
pub(super) fn strict_spec(workflow:&str, arguments:&Arguments, entry_param:&str, reset:&Value) -> Result<Value> {
    let entry = reset["entry"].as_str().ok_or("reset_entry_missing")?;
    if !entry.starts_with('/') || entry.starts_with("//") || entry.contains("..") || entry.contains('?') || entry.contains('#') {
        return Err("reset_entry_not_relative".into());
    }
    let mut args = arguments.args.clone();
    args.insert(entry_param.into(),entry.trim_start_matches('/').into());
    // Use the engine's E2 wire enum/DTO, not a harness mode implementation.
    let spec:oneiron::task_verb::sdk::BrowserLibraryRunInput = serde_json::from_value(json!({"workflow":workflow,"args":args,"mode":"strict"}))
        .map_err(|e| e.to_string())?;
    serde_json::to_value(spec).map_err(|e| e.to_string())
}
