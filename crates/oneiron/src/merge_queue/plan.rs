//! The repository check plan a checked queue freezes from its approved
//! baseline (FIX 6868). The plan is a checked-in file read from the baseline
//! commit itself, never from the moving working directory; its exact bytes,
//! their digest and the decoded plan are frozen at the owner's init request.
//! A candidate's edit to the file changes no frozen plan.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::build_cache::DeclaredOutputPath;
use crate::contract_oracle::ContractSpec;
use crate::memory::code_view_doors::CodeBuildSpec;

/// Where a repository keeps its check plan, relative to its root.
pub const REPO_CHECK_PLAN_PATH: &str = ".oneiron/checks.json";

/// The only plan schema this engine reads.
const REPO_CHECK_PLAN_SCHEMA: u8 = 1;

/// A repository's declared checks: the ordered native fast and slow phase
/// commands, and the shared contract-output commands both phases also run.
/// No shell DSL: each command is an exact argv with an explicit environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoCheckPlan {
    pub schema_version: u8,
    pub fast: Vec<CodeBuildSpec>,
    pub slow: Vec<CodeBuildSpec>,
    /// Contract name -> the command whose output is that contract's
    /// observation. Its keys are exactly `contracts.outputs`.
    #[serde(default)]
    pub contract_outputs: BTreeMap<String, CodeBuildSpec>,
    #[serde(default)]
    pub contracts: ContractSpec,
}

impl RepoCheckPlan {
    /// Decodes plan bytes. A plan that does not decode is a configuration
    /// need, never a red verdict.
    ///
    /// # Errors
    /// The decode failure, as a configuration reason.
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|error| {
            format!(
                "{REPO_CHECK_PLAN_PATH} is not a check plan: line {} column {}",
                error.line(),
                error.column()
            )
        })
    }

    /// The plan's shape rules (CALL "new-plan validation"): schema 1, a
    /// nonempty fast and slow list, a command for all and only the declared
    /// contract outputs, exact argv, safe declared outputs and no secret.
    /// An empty list answers a configuration need, never an implicit pass.
    ///
    /// # Errors
    /// The first rule the plan breaks, as a configuration reason.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.schema_version != REPO_CHECK_PLAN_SCHEMA {
            return Err(format!(
                "{REPO_CHECK_PLAN_PATH} schema_version must be {REPO_CHECK_PLAN_SCHEMA}"
            ));
        }
        if self.fast.is_empty() {
            return Err(format!("{REPO_CHECK_PLAN_PATH} declares no fast command"));
        }
        if self.slow.is_empty() {
            return Err(format!("{REPO_CHECK_PLAN_PATH} declares no slow command"));
        }
        if !self
            .contract_outputs
            .keys()
            .eq(self.contracts.outputs.iter())
        {
            return Err(format!(
                "{REPO_CHECK_PLAN_PATH} contract_outputs must name all and only contracts.outputs"
            ));
        }
        let commands = self
            .fast
            .iter()
            .chain(&self.slow)
            .chain(self.contract_outputs.values());
        for command in commands {
            validate_command(command)?;
        }
        Ok(())
    }

    /// The ordered native commands of one phase.
    #[must_use]
    pub fn phase(&self, phase: super::CheckPhase) -> &[CodeBuildSpec] {
        match phase {
            super::CheckPhase::Fast => &self.fast,
            super::CheckPhase::Slow => &self.slow,
        }
    }
}

fn validate_command(command: &CodeBuildSpec) -> std::result::Result<(), String> {
    if command.argv.first().is_none_or(String::is_empty) {
        return Err(format!(
            "{REPO_CHECK_PLAN_PATH} has a command with no program"
        ));
    }
    if command
        .argv
        .iter()
        .chain(command.env_allowlist.keys())
        .chain(command.env_allowlist.values())
        .any(|text| text.contains('\0'))
        || command
            .env_allowlist
            .keys()
            .any(|key| key.is_empty() || key.contains('='))
    {
        return Err(format!(
            "{REPO_CHECK_PLAN_PATH} has an argv or environment entry the checker cannot pass"
        ));
    }
    for output in &command.declared_outputs {
        let path = DeclaredOutputPath::parse(output.clone()).map_err(|_| {
            format!("{REPO_CHECK_PLAN_PATH} declares an unsafe output path {output:?}")
        })?;
        if path
            .as_str()
            .split('/')
            .any(|part| part.eq_ignore_ascii_case(".git"))
        {
            return Err(format!(
                "{REPO_CHECK_PLAN_PATH} declares an output under git administration"
            ));
        }
    }
    // The checker injects no secret: a plan that names one needs a door
    // this checker does not have.
    if !command.secret_taint_refs.is_empty() {
        return Err(format!(
            "{REPO_CHECK_PLAN_PATH} names a secret; the queue checker injects none"
        ));
    }
    Ok(())
}

/// The plan an owner's init request froze: the exact bytes read from the
/// baseline commit and their blake3 digest. The decoded plan is read from
/// these bytes, so the two never disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenCheckPlan {
    pub bytes: Vec<u8>,
    /// Lowercase hex blake3 of `bytes`.
    pub digest: String,
}

impl FrozenCheckPlan {
    /// Freezes exact plan bytes.
    #[must_use]
    pub fn freeze(bytes: Vec<u8>) -> Self {
        let digest = blake3::hash(&bytes).to_hex().to_string();
        Self { bytes, digest }
    }

    /// The frozen plan, decoded and validated, after its bytes are checked
    /// against the frozen digest.
    ///
    /// # Errors
    /// A configuration reason: bytes that no longer match their digest, or a
    /// plan that does not decode or validate.
    pub fn plan(&self) -> std::result::Result<RepoCheckPlan, String> {
        if blake3::hash(&self.bytes).to_hex().as_str() != self.digest {
            return Err("the frozen check plan no longer matches its digest".to_owned());
        }
        let plan = RepoCheckPlan::decode(&self.bytes)?;
        plan.validate()?;
        Ok(plan)
    }
}
