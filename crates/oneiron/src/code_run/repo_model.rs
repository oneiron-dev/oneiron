//! Request content for an attached run's real model invocation (FIX 7176).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[doc(hidden)]
pub use oneiron_verb_wire::code_run::repo_model::RepoModelGenerateInput;
