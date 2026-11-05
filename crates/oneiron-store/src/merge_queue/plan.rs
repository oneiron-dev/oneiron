//! The repository check plan a checked queue freezes from its approved
//! baseline (FIX 6868). The plan is a checked-in file read from the baseline
//! commit itself, never from the moving working directory; its exact bytes,
//! their digest and the decoded plan are frozen at the owner's init request.
//! A candidate's edit to the file changes no frozen plan.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::contract_oracle::types::ContractSpec;

/// Where a repository keeps its check plan, relative to its root.
pub const REPO_CHECK_PLAN_PATH: &str = ".oneiron/checks.json";

/// The only plan schema this engine reads.
pub const REPO_CHECK_PLAN_SCHEMA: u8 = 1;

