//! Context-pack request controls, record shapes, stats and projection types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use oneiron_contracts::code_run::vault_read::{
    ContextPackBudgetControls, ContextPackDepthControls, ContextPackMediaQuery,
    ContextPackRetrievalBudgetControls, ContextPackTypeRef, CoreContextPackRequest, MediaQueryKind,
};

#[doc(hidden)]
pub use oneiron_records::code_run::vault_read::context_pack::{
    CoreContextPackAccounting, CoreContextPackAccountingReason, CoreContextPackEdgeProvenance,
    CoreContextPackEdgeRecord, CoreContextPackEmpty, CoreContextPackEmptyReason,
    CoreContextPackEntityRecord, CoreContextPackItemTokenStats, CoreContextPackProjection,
    CoreContextPackResponse, CoreContextPackSectionTokenStats, CoreContextPackSignal,
    CoreContextPackStats, CoreContextPackTokenStats, CoreContextPackVad,
};
