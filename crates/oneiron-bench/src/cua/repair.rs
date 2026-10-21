//! One assisted recovery, one proposal, two independent strict confirmations.
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use super::{Result, drift_engine::{Engine,Execution}, drift_plan::Assignment, programs::{self,Program}};

#[derive(Clone,Serialize,Deserialize)]
pub(super) struct Chain {
    pub(crate) status:String, pub(crate) cause:Option<String>, pub(crate) baseline:Value,
    pub(crate) recovery:Value, pub(crate) admission:Value, pub(crate) successor:Option<String>,
    pub(crate) successor_hash:Option<String>, pub(crate) lifecycle:Vec<Value>,
}
impl Chain {
    pub(crate) fn unavailable(cause:&str, baseline:Value) -> Self {
        Self { status:"blocked".into(),cause:Some(cause.into()),baseline,recovery:Value::Null,
            admission:Value::Null,successor:None,successor_hash:None,lifecycle:Vec::new() }
    }
}
pub(super) fn safe_goal(checker:&Value) -> bool {
    checker["full_pass"] == true && checker["goal_pass"] == true
        && checker["safety_pass"] == true && checker["count_evidence_pass"] == true
}
pub(super) fn eligible(baseline:&Value) -> bool {
    // A transport/config block is not an observed v2-v4 failure.
    baseline["execution"].is_object() && baseline["checker"]["full_pass"] == false
        && baseline["checker"]["goal_pass"].is_boolean()
        && baseline["checker"]["count_evidence_pass"] == true
}
pub(super) async fn run<E:Engine>(engine:&mut E, assignment:&Assignment, program:&Program, baseline:Value) -> Result<Chain> {
    if assignment.condition != 5 || !matches!(assignment.author.as_str(),"A1"|"A4")
        || !matches!(assignment.cell.version.as_str(),"v2"|"v3"|"v4") {
        return Err("repair_assignment_ineligible".into());
    }
    if !eligible(&baseline) { return Ok(Chain::unavailable("drift_failure_unobserved",baseline)) }
    let mut chain = Chain::unavailable("recovery_not_completed",baseline);
    // The original matrix is already terminal. This is a fresh assisted
    // recovery/replan, never a claim that the failed guest stayed alive.
    let recovered = match engine.recover(assignment,program,&chain.baseline).await {
        Ok(value)=>value,
        Err(cause)=> { chain.status = if cause.contains("timeout") {"failed"} else {"blocked"}.into(); chain.cause=Some(cause); return Ok(chain) }
    };
    chain.recovery = json!({"kind":"fresh_assisted_recovery_replan","checker":recovered.execution.checker,
        "engine":recovered.execution.library,"reset":recovered.execution.reset,
        "measures":recovered.execution.measures,"evidence":recovered.execution.evidence,
        "author_trace":recovered.author_trace,"finishing_role":recovered.finishing_role,
        "task_model_free":false});
    if !safe_goal(&recovered.execution.checker) {
        chain.status="failed".into(); chain.cause=Some("recovery_checker_failed_no_proposal".into()); return Ok(chain);
    }
    let proposal = recovered.proposal.clone();
    let _:oneiron::task_verb::sdk::BrowserLibraryProposeInput = serde_json::from_value(proposal.clone())
        .map_err(|e| format!("repair_proposal_invalid:{e}"))?;
    let predecessor = program.workflow()?;
    let params:std::collections::BTreeSet<String> = serde_json::from_value::<Vec<String>>(proposal["params"].clone())
        .map_err(|e| e.to_string())?.into_iter().collect();
    if proposal["supersedes"] != predecessor || params != program.params {
        return Err("repair_supersedes_or_parameter_intent_changed".into());
    }
    let hash = programs::canonical_hash(&programs::body(&proposal))?;
    if program.source.program_hash.as_deref() == Some(hash.as_str()) {
        chain.status="failed".into(); chain.cause=Some("repair_unchanged_program".into()); return Ok(chain);
    }
    // Exactly one call. Requalification, fresh replay and E1 retirement are
    // exclusively the engine's propose operation, never a harness admission.
    let admission = match engine.propose(assignment,program,&recovered,proposal).await {
        Ok(value)=>value,
        Err(cause)=> { chain.status="failed".into();chain.cause=Some(cause);return Ok(chain) }
    };
    chain.admission=admission.clone();
    if admission["admitted"] != true {
        chain.status="refused".into(); chain.cause=Some("engine_requalification_refused".into()); return Ok(chain);
    }
    let id = admission["workflow"].as_str().ok_or("successor_id_missing")?;
    if !programs::hex_id(id) || id == predecessor { return Err("successor_id_invalid".into()) }
    // SupersedeOutcome is the engine's snake_case unit enum.
    let superseded = &admission["superseded"];
    if superseded == "dropped" {
        chain.status="failed".into();chain.cause=Some("same_byte_refile_not_repair".into());return Ok(chain);
    }
    if !matches!(superseded.as_str(),Some("retired"|"linked"))
        || admission["replay_guest"].is_null() {
        return Err("successor_lineage_or_requalification_evidence_missing".into());
    }
    chain.lifecycle.push(json!({"kind":"engine_supersede","predecessor":predecessor,"successor":id,
        "workflow":predecessor,"reason":if superseded == "retired" {Some(format!("superseded:{id}"))} else {None},
        "result":superseded,"source":"self.browser.library.propose"}));
    chain.successor=Some(id.into()); chain.successor_hash=Some(hash);
    chain.status="requalified_pending_confirmations".into(); chain.cause=None;
    Ok(chain)
}
pub(super) fn confirmation_pass(execution:&Execution) -> bool {
    safe_goal(&execution.checker) && execution.library["mode"] == "strict"
        && execution.library["model_free"] == true && execution.library["status"] == "done"
}
pub(super) fn summarize(chain:&Chain, drift:Option<&Value>, v0:Option<&Value>) -> Value {
    let pass = |row:Option<&Value>| row.is_some_and(|r| r["status"] == "strict_pass"
        && safe_goal(&r["checker"]) && r["execution"]["model_free"] == true);
    json!({"status":chain.status,"cause":chain.cause,"requalified":chain.successor.is_some(),
        "successor":chain.successor,"drift_confirmed":pass(drift),"v0_regression_free":pass(v0),
        "persistent_repair_pass":chain.successor.is_some() && pass(drift) && pass(v0),
        "baseline_safety":chain.baseline["checker"]["safety_pass"],
        "repair_does_not_erase_baseline_safety":true})
}
