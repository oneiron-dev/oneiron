//! Core half of `store::contract_oracle`: its store-layer items live in `oneiron_store::contract_oracle` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::contract_oracle::*;

use crate::error::{CodeError, Error, Result};
pub use graph::{AffectedTests, WorkspaceGraph};
use oneiron_store::contract_oracle::types;
pub use rust_api::{RustPublicNames, rust_public_names};
use std::path::{Component, Path, PathBuf};
pub use storage::ContractOracle;
pub use types::{
    CommandOutput, ContractBaseline, ContractDiff, ContractSnapshot, ContractSpec, ContractVerdict,
};
// The lift sweep's typed acceptance for this module's authored side
// tables (FIX 2680), named by their declarations.
pub(crate) use self::storage::contract_oracle_baseline_accepts_masked;
pub(crate) use self::storage::contract_oracle_verdict_accepts_masked;

mod rust_api;
mod storage;
