//! References to publicly admitted engine records, never another program store.
use super::{Result, config::Evidence, digest, read};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Submission {
    pub(crate) fixture: String,
    pub(crate) author: String,
    pub(crate) outcome: String,
    pub(crate) workflow: Option<String>,
    pub(crate) program_hash: Option<String>,
    pub(crate) proposal: Option<Evidence>,
    pub(crate) admission: Evidence,
    pub(crate) qualification: Evidence,
    pub(crate) author_traces: Vec<Evidence>,
    pub(crate) solved_seed: u64,
    pub(crate) qualification_seed: u64,
    pub(crate) lineage: Vec<Evidence>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Submissions {
    pub(crate) schema: u32,
    pub(crate) submissions: Vec<Submission>,
}
#[derive(Clone)]
pub(super) struct Program {
    pub(crate) source: Submission,
    pub(crate) params: BTreeSet<String>,
    pub(crate) solved_args: BTreeMap<String, String>,
    pub(crate) qualification_args: BTreeMap<String, String>,
}
pub(super) fn key(fixture: &str, author: &str) -> String {
    format!("{fixture}-{author}")
}
pub(super) fn hex_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
pub(super) fn canonical_hash(value: &Value) -> Result<String> {
    serde_json_canonicalizer::to_vec(value)
        .map(|bytes| digest(&bytes))
        .map_err(|e| e.to_string())
}
pub(super) fn body(proposal: &Value) -> Value {
    json!({"subgoal":proposal["subgoal"],"params":proposal["params"],
        "steps":proposal["steps"],"postcondition":proposal["postcondition"]})
}
pub(super) fn args(value: &Value) -> Result<BTreeMap<String, String>> {
    serde_json::from_value(value.clone()).map_err(|e| format!("program_arguments_invalid:{e}"))
}
impl Program {
    pub(crate) fn workflow(&self) -> Result<&str> {
        self.source
            .workflow
            .as_deref()
            .ok_or("program_not_admitted".into())
    }
    pub(crate) fn reference(&self) -> Value {
        // The archived campaign stores references and hashes, not program bytes.
        serde_json::to_value(&self.source).unwrap_or(Value::Null)
    }
}
pub(super) fn load(path: &Path) -> Result<BTreeMap<String, Program>> {
    let supplied: Submissions = read(path)?;
    if supplied.schema != 1 {
        return Err("submission_schema_mismatch".into());
    }
    let mut programs = BTreeMap::new();
    let mut workflows = BTreeSet::new();
    for source in supplied.submissions {
        if !matches!(source.fixture.as_str(), "F1" | "F2" | "F3" | "F4" | "F5")
            || !matches!(source.author.as_str(), "A1" | "A2" | "A3" | "A4")
            || !matches!(source.outcome.as_str(), "admitted" | "refused")
        {
            return Err("submission_identity_invalid".into());
        }
        if source.author_traces.is_empty() {
            return Err("author_trace_missing".into());
        }
        for evidence in source.author_traces.iter().chain(source.lineage.iter()) {
            evidence.load()?;
        }
        let admission = source.admission.load()?;
        let qualification = source.qualification.load()?;
        let mut program = Program {
            source,
            params: BTreeSet::new(),
            solved_args: BTreeMap::new(),
            qualification_args: BTreeMap::new(),
        };
        if program.source.outcome == "admitted" {
            let id = program.workflow()?;
            if !hex_id(id)
                || !workflows.insert(id.to_owned())
                || admission["admitted"] != true
                || admission["workflow"] != id
                || !(qualification["full_pass"] == true
                    || (program.source.fixture == "F2" && qualification["state_only_pass"] == true))
                || qualification["safety_pass"] != true
                || qualification["count_evidence_pass"] != true
            {
                return Err("admitted_program_evidence_mismatch".into());
            }
            let proposal = program
                .source
                .proposal
                .as_ref()
                .ok_or("proposal_reference_missing")?
                .load()?;
            // Use the engine's closed proposal DTO to reject invented fields/steps.
            let _: oneiron::task_verb::sdk::BrowserLibraryProposeInput =
                serde_json::from_value(proposal.clone())
                    .map_err(|e| format!("proposal_wire_invalid:{e}"))?;
            if Some(canonical_hash(&body(&proposal))?) != program.source.program_hash {
                return Err("canonical_program_hash_mismatch".into());
            }
            program.params = serde_json::from_value::<Vec<String>>(proposal["params"].clone())
                .map_err(|e| e.to_string())?
                .into_iter()
                .collect();
            program.solved_args = args(&proposal["args"])?;
            program.qualification_args = args(&proposal["replay_args"])?;
            if program.solved_args.keys().cloned().collect::<BTreeSet<_>>() != program.params
                || program
                    .qualification_args
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    != program.params
                || program.solved_args == program.qualification_args
                || admission["replay_guest"].is_null()
            {
                return Err("held_out_admission_evidence_missing".into());
            }
        } else if admission["admitted"] != false
            || program.source.workflow.is_some()
            || program.source.program_hash.is_some()
        {
            return Err("refused_submission_mismatch".into());
        }
        if programs
            .insert(
                key(&program.source.fixture, &program.source.author),
                program,
            )
            .is_some()
        {
            return Err("duplicate_family_author_submission".into());
        }
    }
    Ok(programs)
}
