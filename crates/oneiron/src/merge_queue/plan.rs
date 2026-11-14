//! The repository check plan a checked queue freezes from its approved
//! baseline (FIX 6868). The plan is a checked-in file read from the baseline
//! commit itself, never from the moving working directory; its exact bytes,
//! their digest and the decoded plan are frozen at the owner's init request.
//! A candidate's edit to the file changes no frozen plan.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::build_cache::DeclaredOutputPath;
use crate::build_cache::command_spec::CodeBuildSpec;
use crate::store::contract_oracle::ContractSpec;

#[doc(hidden)]
pub use oneiron_records::merge_queue::plan::{
    FrozenCheckPlan, REPO_CHECK_PLAN_PATH, RepoCheckPlan,
};
#[doc(hidden)]
use oneiron_records::merge_queue::plan::{REPO_CHECK_PLAN_SCHEMA, validate_command};
